//! Bounded, identity-preserving import of an externally fenced legacy snapshot.
use super::{framed, person_key, Entry, Error, Scope, Vault};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// One-time import limits; normal request limits remain substantially smaller.
pub const MAX_IMPORT_ENTRIES: usize = 16384;
/// Maximum aggregate legacy plaintext/ciphertext per import operation.
pub const MAX_IMPORT_BYTES: usize = 16 * 1024 * 1024;

/// Context lifecycle is separate from mapping presence: an empty migrated or
/// retired context must never be mistaken for an uninitialized namespace.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContextState {
    /// No target context exists.
    Absent,
    /// A context created through the native storage API, without legacy import.
    Active,
    /// Frozen source imported; cleanup completion survives retries/restarts.
    Imported { source: String, legacy_clean: bool },
    /// Permanently fenced against future interning/import.
    Retired,
}

/// Decrypted legacy material is confined to the privacy facade. Deliberately
/// not Debug or Serialize; never log this value or send it to a backend.
pub struct LegacyValue {
    pub token: String,
    pub kind: String,
    pub original: String,
    pub expires_ms: i64,
}

/// Backend import payload contains keyed hashes and authenticated ciphertext.
#[derive(Clone, Serialize, Deserialize)]
pub struct LegacyImport {
    pub source: String,
    pub entries: Vec<Entry>,
    /// Legacy by-value keys shared across entity types, including PERSON
    /// normalization. Every label remains resolvable, including duplicate aliases.
    pub aliases: BTreeMap<String, String>,
}

impl LegacyImport {
    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.source.len() != 64
            || self.entries.len() > MAX_IMPORT_ENTRIES
            || self.aliases.len() > self.entries.len() * 2
            || self.entries.iter().map(|e| e.sealed.len()).sum::<usize>() > MAX_IMPORT_BYTES
        {
            return Err(Error::Invalid);
        }
        let mut tokens = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for e in &self.entries {
            if e.fingerprint.len() != 64
                || e.token.len() > 128
                || e.sealed.is_empty()
                || !tokens.insert(e.token.as_str())
                || !keys.insert(e.fingerprint.as_str())
            {
                return Err(Error::Invalid);
            }
        }
        if self
            .aliases
            .iter()
            .any(|(key, token)| key.len() != 64 || !tokens.contains(token.as_str()))
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}

pub(crate) fn validate_aliases(candidates: &[Entry], aliases: &[Vec<String>]) -> Result<(), Error> {
    if !aliases.is_empty()
        && (aliases.len() != candidates.len()
            || aliases
                .iter()
                .any(|keys| keys.len() > 2 || keys.iter().any(|s| s.len() != 64)))
    {
        return Err(Error::Invalid);
    }
    Ok(())
}

fn token_kind(token: &str) -> Option<&str> {
    let body = token.strip_prefix('[')?.strip_suffix(']')?;
    let (kind, index) = body.rsplit_once('_')?;
    if kind.is_empty()
        || !kind
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b == b'_' || b.is_ascii_digit())
        || index.is_empty()
        || !index.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    Some(kind)
}

impl Vault {
    fn legacy_hash(&self, scope: &Scope, domain: &str, value: &str) -> String {
        blake3::keyed_hash(
            &self.index_key,
            &framed(&[domain, &scope.tenant, &scope.context, value]),
        )
        .to_hex()
        .to_string()
    }
    pub(crate) fn legacy_lookup_keys(&self, scope: &Scope, kind: &str, value: &str) -> Vec<String> {
        let mut keys = Vec::new();
        if kind == "PERSON" {
            keys.push(self.legacy_hash(scope, "legacy-value", &person_key(value)));
        }
        let exact = self.legacy_hash(scope, "legacy-value", value);
        if !keys.contains(&exact) {
            keys.push(exact);
        }
        keys
    }
    pub(crate) fn authentic_legacy_match(
        &self,
        scope: &Scope,
        entry: &Entry,
        original: &str,
        lookup: &[String],
    ) -> bool {
        entry.fingerprint == self.legacy_hash(scope, "legacy-token", &entry.token)
            && token_kind(&entry.token).is_some_and(|kind| {
                self.legacy_lookup_keys(scope, kind, original)
                    .iter()
                    .any(|key| lookup.contains(key))
            })
    }
    /// Read target lifecycle without loading mappings. Callers must authenticate
    /// the scope before invoking this method.
    pub async fn context_state(&self, scope: &Scope) -> Result<ContextState, Error> {
        let _permit = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        tokio::time::timeout(self.timeout, self.store.context_state(scope))
            .await
            .map_err(|_| Error::Unavailable)?
    }
    /// Import only a frozen snapshot. The gateway is responsible for fencing
    /// all legacy writers before calling this method. No migration reads occur
    /// on the normal intern/resolve path after activation and source cleanup.
    #[tracing::instrument(skip_all,fields(items=values.len()))]
    pub async fn import_legacy(
        &self,
        scope: &Scope,
        values: &[LegacyValue],
    ) -> Result<String, Error> {
        let deadline = tokio::time::Instant::now() + self.timeout;
        let _permit = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        if values.len() > MAX_IMPORT_ENTRIES
            || values.iter().map(|v| v.original.len()).sum::<usize>() > MAX_IMPORT_BYTES / 2
        {
            return Err(Error::Invalid);
        }
        // Match TokenSession::resume's stable numeric-label order exactly.
        let mut ordered: Vec<_> = values.iter().collect();
        ordered.sort_by_key(|v| {
            v.token
                .trim_end_matches(']')
                .rsplit('_')
                .next()
                .and_then(|s| s.parse::<u128>().ok())
                .unwrap_or(u128::MAX)
        });
        let mut source = blake3::Hasher::new_keyed(&self.index_key);
        source.update(&framed(&[
            "legacy-import-v1",
            &scope.tenant,
            &scope.context,
        ]));
        let mut entries = Vec::with_capacity(values.len());
        let mut aliases = BTreeMap::new();
        for v in ordered {
            if tokio::time::Instant::now() >= deadline {
                return Err(Error::Unavailable);
            }
            if token_kind(&v.token) != Some(v.kind.as_str()) {
                return Err(Error::Integrity);
            }
            source.update(&framed(&[
                &v.token,
                &v.kind,
                &v.original,
                &v.expires_ms.to_string(),
            ]));
            let fingerprint = self.legacy_hash(scope, "legacy-token", &v.token);
            entries.push(self.seal_value(
                scope,
                fingerprint,
                v.token.clone(),
                &v.original,
                v.expires_ms,
            )?);
            // The legacy map inserts exact first, then PERSON canonical into
            // the SAME map. Keeping that order preserves cross-kind reuse too.
            aliases
                .entry(self.legacy_hash(scope, "legacy-value", &v.original))
                .or_insert_with(|| v.token.clone());
            if v.kind == "PERSON" {
                aliases
                    .entry(self.legacy_hash(scope, "legacy-value", &person_key(&v.original)))
                    .or_insert_with(|| v.token.clone());
            }
            tokio::task::yield_now().await;
        }
        let snapshot = LegacyImport {
            source: source.finalize().to_hex().to_string(),
            entries,
            aliases,
        };
        snapshot.validate()?;
        tokio::time::timeout_at(deadline, self.store.import_legacy(scope, &snapshot))
            .await
            .map_err(|_| Error::Unavailable)??;
        if tokio::time::Instant::now() >= deadline {
            return Err(Error::Unavailable);
        }
        Ok(snapshot.source)
    }
    /// Complete the durable import checkpoint only after source destruction.
    pub async fn complete_legacy_cleanup(&self, scope: &Scope, source: &str) -> Result<(), Error> {
        let _permit = self.admission.try_acquire().map_err(|_| Error::Busy)?;
        tokio::time::timeout(
            self.timeout,
            self.store.complete_legacy_cleanup(scope, source),
        )
        .await
        .map_err(|_| Error::Unavailable)?
    }
}
