//! Version-one storage contract for privacy-service replicas.
//!
//! All operations are scoped to authenticated tenant, principal and context.
//! Backends receive keyed equality indexes and authenticated ciphertext only.
//! Intern is atomic for the entire batch and retrying the same values is
//! idempotent, including after an uncertain commit. Retired contexts cannot be
//! reopened. Expired identities remain reserved and cannot be rebound.

mod migration;
pub mod openbao;
pub mod postgres;
pub use migration::{
    ContextState, LegacyImport, LegacyValue, MAX_IMPORT_BYTES, MAX_IMPORT_ENTRIES,
};

use aes_gcm::{
    aead::{Aead, Payload},
    Aes256Gcm, KeyInit, Nonce,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

/// Maximum references or values in one atomic storage operation.
pub const MAX_BATCH: usize = 256;
/// Maximum aggregate sealed bytes in an intern operation.
pub const MAX_BATCH_BYTES: usize = 1024 * 1024;
/// Maximum restored plaintext bytes, including duplicate expansion.
pub const MAX_RESPONSE_BYTES: usize = 1024 * 1024;

pub(crate) fn unique_refs(tokens: &[String]) -> Vec<String> {
    tokens
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect()
}

pub(crate) fn response_budget<'a>(entries: impl Iterator<Item = &'a Entry>) -> Result<(), Error> {
    let mut bytes = 0usize;
    for entry in entries {
        bytes = bytes
            .checked_add(entry.sealed.len())
            .ok_or(Error::Capacity)?;
        if bytes > MAX_BATCH_BYTES {
            return Err(Error::Capacity);
        }
    }
    Ok(())
}

/// Content-free failures. Backend diagnostics never escape this boundary.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    /// Invalid or oversized request.
    #[error("invalid token-store request")]
    Invalid,
    /// Context is permanently retired, or the requested identity expired.
    #[error("token context or identity is retired")]
    Retired,
    /// Backend unavailable; a failed commit may nevertheless have succeeded.
    #[error("token store unavailable; retry the same operation")]
    Unavailable,
    /// Bounded admission or compare-and-set budget exhausted.
    #[error("token store busy")]
    Busy,
    /// Backend's documented storage capacity was reached.
    #[error("token store capacity exceeded")]
    Capacity,
    /// Ciphertext or returned identity failed authentication.
    #[error("token integrity check failed")]
    Integrity,
}

/// Opaque storage scope; construct only from verified authentication context.
/// Token possession alone never supplies this authorization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scope {
    pub(crate) tenant: String,
    pub(crate) context: String,
}

/// A proposed identity. Contains no plaintext and is deliberately not Debug.
#[derive(Clone, Serialize, Deserialize)]
pub struct Entry {
    /// Keyed equality index scoped to tenant, principal and context.
    pub fingerprint: String,
    /// Stable public reference. No backend address is encoded in it.
    pub token: String,
    /// Authenticated encrypted original value.
    pub sealed: String,
    /// Absolute expiry in Unix milliseconds; expiry never frees the identity.
    pub expires_ms: i64,
}

/// Purpose-built backend contract. No operation enumerates a context for callers.
#[async_trait::async_trait]
pub trait TokenStore: Send + Sync {
    /// Stable, low-cardinality telemetry label.
    fn backend(&self) -> &'static str;
    /// Read-only readiness of every configured dependency, without creating a
    /// context or resolving customer data. Unsupported probes fail closed.
    async fn health(&self) -> Result<(), Error> {
        Err(Error::Invalid)
    }
    /// Atomically find or create every identity. Preserve request order and
    /// duplicates. An existing live identity wins over proposed ciphertext.
    async fn intern(&self, scope: &Scope, candidates: &[Entry]) -> Result<Vec<Entry>, Error>;
    /// Resolve only requested references, in order. Missing, foreign and expired
    /// references all return None. Never extend expiry as a side effect.
    async fn resolve(&self, scope: &Scope, tokens: &[String]) -> Result<Vec<Option<Entry>>, Error>;
    /// Permanently retire the context and destroy its ciphertext. Retryable.
    /// A successful result must fence concurrent and future interns.
    async fn retire(&self, scope: &Scope) -> Result<(), Error>;

    /// Clear expired ciphertext in bounded batches, preserving token/equality
    /// reservations. Return the number cleared; callers retry until zero.
    async fn purge_expired(&self, _scope: &Scope, _limit: usize) -> Result<usize, Error> {
        Err(Error::Invalid)
    }

    /// Atomic reuse with ordered legacy equality aliases. Aliases are keyed
    /// hashes, never plaintext. Backends without migration support use intern.
    async fn intern_with_aliases(
        &self,
        scope: &Scope,
        candidates: &[Entry],
        _aliases: &[Vec<String>],
    ) -> Result<Vec<Entry>, Error> {
        self.intern(scope, candidates).await
    }
    /// Read migration/retirement state without enumerating token mappings.
    async fn context_state(&self, _scope: &Scope) -> Result<ContextState, Error> {
        Err(Error::Invalid)
    }
    /// Atomically import a frozen legacy snapshot, preserving every label and
    /// equality alias. A repeated source digest is idempotent; other sources
    /// and already-active contexts are rejected. Retirement always wins.
    async fn import_legacy(&self, _scope: &Scope, _snapshot: &LegacyImport) -> Result<(), Error> {
        Err(Error::Invalid)
    }
    /// Record that the frozen source's ciphertext and history were destroyed.
    async fn complete_legacy_cleanup(&self, _scope: &Scope, _source: &str) -> Result<(), Error> {
        Err(Error::Invalid)
    }
}

pub(crate) fn validate(entries: &[Entry]) -> Result<(), Error> {
    if entries.len() > MAX_BATCH
        || entries.iter().map(|e| e.sealed.len()).sum::<usize>() > MAX_BATCH_BYTES
        || entries.iter().any(|e| {
            e.fingerprint.len() != 64
                || !e.fingerprint.bytes().all(|b| b.is_ascii_hexdigit())
                || e.token.is_empty()
                || e.token.len() > 128
                || e.sealed.is_empty()
        })
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

pub(crate) fn validate_refs(tokens: &[String]) -> Result<(), Error> {
    if tokens.len() > MAX_BATCH || tokens.iter().any(|t| t.is_empty() || t.len() > 128) {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn framed(parts: &[&str]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for p in parts {
        bytes.extend_from_slice(&(p.len() as u64).to_be_bytes());
        bytes.extend_from_slice(p.as_bytes());
    }
    bytes
}

/// Privacy-service facade: encryption, keyed indexes, deadlines and admission.
/// Key material must be durable and shared by authorized service replicas.
/// This facade does not authenticate callers: derive Scope from verified claims.
pub struct Vault {
    store: Arc<dyn TokenStore>,
    encryption_key: [u8; 32],
    index_key: [u8; 32],
    admission: tokio::sync::Semaphore,
    timeout: Duration,
}

impl Vault {
    /// Probe every backend dependency within one deadline. No context is minted.
    pub async fn health(&self) -> Result<(), Error> {
        tokio::time::timeout(self.timeout, self.store.health())
            .await
            .map_err(|_| Error::Unavailable)?
    }
    /// Stable commitment to key and routing configuration, stored by an operator
    /// in each backend before startup. Runtime credentials must not modify it.
    pub fn configuration_commitment(key: &[u8; 32], routing: &[u8]) -> String {
        let config_key = blake3::derive_key("censgate.token-store.v1.configuration", key);
        blake3::keyed_hash(&config_key, routing)
            .to_hex()
            .to_string()
    }
    /// Construct a bounded service facade. Reject zero capacity/time budgets.
    pub fn new(
        store: Arc<dyn TokenStore>,
        key: [u8; 32],
        concurrency: usize,
        timeout: Duration,
    ) -> Result<Self, Error> {
        if concurrency == 0 || timeout.is_zero() {
            return Err(Error::Invalid);
        }
        Ok(Self {
            store,
            encryption_key: blake3::derive_key("censgate.token-store.v1.encryption", &key),
            index_key: blake3::derive_key("censgate.token-store.v1.index", &key),
            admission: tokio::sync::Semaphore::new(concurrency),
            timeout,
        })
    }

    /// Bind caller context to verified tenant and principal. Context retains
    /// Platform's principal-wide vault identity across conversations.
    pub fn scope(&self, tenant: &str, principal: &str, context: &str) -> Result<Scope, Error> {
        if [tenant, principal, context]
            .iter()
            .any(|s| s.is_empty() || s.len() > 1024)
        {
            return Err(Error::Invalid);
        }
        Ok(Scope {
            tenant: blake3::keyed_hash(&self.index_key, &framed(&["tenant", tenant]))
                .to_hex()
                .to_string(),
            context: blake3::keyed_hash(
                &self.index_key,
                &framed(&["context", tenant, principal, context]),
            )
            .to_hex()
            .to_string(),
        })
    }

    /// Intern an ordered batch of (entity type, original) values. Results are
    /// withheld unless the complete operation succeeds; plaintext is never traced.
    #[tracing::instrument(skip_all, fields(backend = self.store.backend(), items = values.len()))]
    pub async fn intern(
        &self,
        scope: &Scope,
        values: &[(String, String)],
        retention: Duration,
    ) -> Result<Vec<String>, Error> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let _permit = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        if values.len() > MAX_BATCH
            || retention.is_zero()
            || values.iter().map(|(_, v)| v.len()).sum::<usize>() > MAX_BATCH_BYTES / 2
        {
            return Err(Error::Invalid);
        }
        let expires_ms = chrono::Utc::now()
            .timestamp_millis()
            .checked_add(i64::try_from(retention.as_millis()).map_err(|_| Error::Invalid)?)
            .ok_or(Error::Invalid)?;
        let mut candidates = Vec::with_capacity(values.len());
        let mut aliases = Vec::with_capacity(values.len());
        let mut dedupe: BTreeMap<String, Entry> = BTreeMap::new();
        for (kind, original) in values {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Unavailable);
            }
            if kind.is_empty()
                || kind.len() > 64
                || !kind
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit())
            {
                return Err(Error::Invalid);
            }
            let canonical = if kind == "PERSON" {
                person_key(original)
            } else {
                original.clone()
            };
            let fingerprint = blake3::keyed_hash(
                &self.index_key,
                &framed(&[&scope.tenant, &scope.context, kind, &canonical]),
            )
            .to_hex()
            .to_string();
            aliases.push(self.legacy_lookup_keys(scope, kind, original));
            if let Some(existing) = dedupe.get(&fingerprint) {
                candidates.push(existing.clone());
                continue;
            }
            let token = format!("[{}_{}]", kind, uuid::Uuid::new_v4().as_u128());
            let entry = self.seal_value(scope, fingerprint.clone(), token, original, expires_ms)?;
            dedupe.insert(fingerprint, entry.clone());
            candidates.push(entry);
        }
        validate(&candidates)?;
        let results = tokio::time::timeout_at(
            deadline,
            self.store.intern_with_aliases(scope, &candidates, &aliases),
        )
        .await
        .map_err(|_| Error::Unavailable)??;
        validate(&results).map_err(|_| Error::Integrity)?;
        if results.len() != candidates.len() {
            return Err(Error::Integrity);
        }
        // Authenticate even reused records before returning a reference.
        for ((entry, candidate), lookup) in results.iter().zip(&candidates).zip(&aliases) {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Unavailable);
            }
            let original = self.open(scope, entry)?;
            if entry.fingerprint != candidate.fingerprint
                && !self.authentic_legacy_match(scope, entry, &original, lookup)
            {
                return Err(Error::Integrity);
            }
            tokio::task::yield_now().await;
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        Ok(results.into_iter().map(|e| e.token).collect())
    }

    /// Selectively restore an authorized batch. Unknown references remain absent.
    #[tracing::instrument(skip_all, fields(backend = self.store.backend(), items = tokens.len()))]
    pub async fn resolve(
        &self,
        scope: &Scope,
        tokens: &[String],
    ) -> Result<Vec<Option<String>>, Error> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let _permit = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        validate_refs(tokens)?;
        let unique = unique_refs(tokens);
        let entries = tokio::time::timeout_at(deadline, self.store.resolve(scope, &unique))
            .await
            .map_err(|_| Error::Unavailable)??;
        if entries.len() != unique.len() {
            return Err(Error::Integrity);
        }
        response_budget(entries.iter().flatten())?;
        let mut found = BTreeMap::new();
        for (entry, token) in entries.iter().zip(&unique) {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Unavailable);
            }
            match entry {
                Some(e) if &e.token == token => {
                    found.insert(token.as_str(), self.open(scope, e)?);
                }
                Some(_) => return Err(Error::Integrity),
                None => {}
            }
            // Include crypto work in the deadline; no detached worker can
            // complete later and release a response after cancellation.
            tokio::task::yield_now().await;
        }
        let mut bytes = 0usize;
        for token in tokens {
            bytes = bytes
                .checked_add(found.get(token.as_str()).map_or(0, String::len))
                .ok_or(Error::Capacity)?;
            if bytes > MAX_RESPONSE_BYTES {
                return Err(Error::Capacity);
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        let result = tokens
            .iter()
            .map(|token| found.get(token.as_str()).cloned())
            .collect();
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        Ok(result)
    }

    /// Permanently retire an authorized context, with bounded admission/deadline.
    #[tracing::instrument(skip_all, fields(backend = self.store.backend()))]
    pub async fn retire(&self, scope: &Scope) -> Result<(), Error> {
        let _permit = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        tokio::time::timeout(self.timeout, self.store.retire(scope))
            .await
            .map_err(|_| Error::Unavailable)?
    }

    /// Bounded physical expiry cleanup; identity reservations remain permanent.
    #[tracing::instrument(skip_all,fields(backend=self.store.backend(),limit))]
    pub async fn purge_expired(&self, scope: &Scope, limit: usize) -> Result<usize, Error> {
        if limit == 0 || limit > MAX_BATCH {
            return Err(Error::Invalid);
        }
        let _permit = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        tokio::time::timeout(self.timeout, self.store.purge_expired(scope, limit))
            .await
            .map_err(|_| Error::Unavailable)?
    }

    fn seal_value(
        &self,
        scope: &Scope,
        fingerprint: String,
        token: String,
        original: &str,
        expires_ms: i64,
    ) -> Result<Entry, Error> {
        let cipher =
            Aes256Gcm::new_from_slice(&self.encryption_key).map_err(|_| Error::Integrity)?;
        let aad = framed(&[
            &scope.tenant,
            &scope.context,
            &fingerprint,
            &token,
            &expires_ms.to_string(),
        ]);
        let mut nonce = [0u8; 12];
        rand::rng().fill_bytes(&mut nonce);
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: original.as_bytes(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Integrity)?;
        let mut sealed = nonce.to_vec();
        sealed.extend(ciphertext);
        Ok(Entry {
            fingerprint,
            token,
            sealed: STANDARD.encode(sealed),
            expires_ms,
        })
    }

    fn open(&self, scope: &Scope, entry: &Entry) -> Result<String, Error> {
        let bytes = STANDARD
            .decode(&entry.sealed)
            .map_err(|_| Error::Integrity)?;
        if bytes.len() < 28 {
            return Err(Error::Integrity);
        }
        let nonce: [u8; 12] = bytes[..12].try_into().map_err(|_| Error::Integrity)?;
        let aad = framed(&[
            &scope.tenant,
            &scope.context,
            &entry.fingerprint,
            &entry.token,
            &entry.expires_ms.to_string(),
        ]);
        let cipher =
            Aes256Gcm::new_from_slice(&self.encryption_key).map_err(|_| Error::Integrity)?;
        let plain = cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: &bytes[12..],
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Integrity)?;
        String::from_utf8(plain).map_err(|_| Error::Integrity)
    }
}

fn person_key(value: &str) -> String {
    let value = value.trim();
    let value = ["'s", "’s", "'S", "’S"]
        .iter()
        .find_map(|suffix| {
            (value.len() > suffix.len())
                .then(|| value.strip_suffix(suffix))
                .flatten()
        })
        .unwrap_or(value);
    value.to_ascii_lowercase()
}
