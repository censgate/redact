//! OpenBao KV v2 reference adapter. CAS provides atomicity across replicas.
//! This adapter deliberately exposes its whole-document cost and capacity limit;
//! use the indexed PostgreSQL adapter for growing contexts.
use crate::{
    response_budget, validate, validate_refs, ContextState, Entry, Error, LegacyImport, Scope,
    TokenStore,
};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};

const MAX_DOCUMENT: usize = 512 * 1024;
const ATTEMPTS: usize = 8;

#[derive(Clone, Default, Serialize, Deserialize)]
struct Document {
    #[serde(default)]
    retired: bool,
    #[serde(default)]
    entries: BTreeMap<String, Entry>,
    #[serde(default)]
    aliases: BTreeMap<String, String>,
    #[serde(default)]
    import_source: Option<String>,
    #[serde(default)]
    legacy_clean: bool,
    #[serde(default)]
    cleanup_through: u64,
    #[serde(default)]
    destroyed_through: u64,
}

/// KV v2 adapter. Credentials and endpoint are never included in Debug output.
pub struct OpenBao {
    client: Client,
    address: String,
    mount: String,
    prefix: String,
    token: String,
}

impl OpenBao {
    /// Construct with a dedicated KV mount credential. Client timeout bounds all
    /// HTTP operations. Production callers should use HTTPS and renewable auth.
    pub fn new(
        address: &str,
        mount: &str,
        prefix: &str,
        token: String,
        timeout: Duration,
    ) -> Result<Self, Error> {
        let url = reqwest::Url::parse(address).map_err(|_| Error::Invalid)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
            || token.is_empty()
            || timeout.is_zero()
            || [mount, prefix].iter().any(|s| {
                s.is_empty()
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            client: Client::builder()
                .timeout(timeout)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|_| Error::Unavailable)?,
            address: address.trim_end_matches('/').into(),
            mount: mount.into(),
            prefix: prefix.into(),
            token,
        })
    }

    fn url(&self, operation: &str, scope: &Scope) -> String {
        format!(
            "{}/v1/{}/{}/{}/{}/{}",
            self.address, self.mount, operation, self.prefix, scope.tenant, scope.context
        )
    }

    async fn read(&self, scope: &Scope) -> Result<(Document, u64), Error> {
        let response = self
            .client
            .get(self.url("data", scope))
            .header("X-Vault-Token", &self.token)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok((Document::default(), 0));
        }
        if !response.status().is_success() {
            return Err(Error::Unavailable);
        }
        let value = bounded_json(response).await?;
        let version = value
            .pointer("/data/metadata/version")
            .and_then(Value::as_u64)
            .ok_or(Error::Integrity)?;
        let doc = serde_json::from_value(
            value
                .pointer("/data/data")
                .cloned()
                .ok_or(Error::Integrity)?,
        )
        .map_err(|_| Error::Integrity)?;
        Ok((doc, version))
    }

    async fn cas(&self, scope: &Scope, doc: &Document, version: u64) -> Result<bool, Error> {
        let body = serde_json::to_vec(&json!({"options": {"cas": version}, "data": doc}))
            .map_err(|_| Error::Integrity)?;
        if body.len() > MAX_DOCUMENT {
            return Err(Error::Capacity);
        }
        let response = self
            .client
            .post(self.url("data", scope))
            .header("X-Vault-Token", &self.token)
            .header("Content-Type", "application/json")
            .body(body)
            .send()
            .await
            .map_err(|_| Error::Unavailable)?;
        if response.status().is_success() {
            return Ok(true);
        }
        if response.status() == StatusCode::PAYLOAD_TOO_LARGE {
            return Err(Error::Capacity);
        }
        if response.status() == StatusCode::TOO_MANY_REQUESTS {
            return Err(Error::Busy);
        }
        if response.status() == StatusCode::BAD_REQUEST {
            let body = bounded_json(response).await?;
            if body
                .get("errors")
                .and_then(Value::as_array)
                .is_some_and(|errors| {
                    errors
                        .iter()
                        .filter_map(Value::as_str)
                        .any(|s| s.contains("check-and-set"))
                })
            {
                return Ok(false);
            }
            // A deterministic backend request rejection is terminal. Only a
            // recognized CAS conflict retries this document automatically.
            return Err(Error::Invalid);
        }
        Err(Error::Unavailable)
    }

    async fn destroy_progress(&self, scope: &Scope) -> Result<(), Error> {
        // Keep the latest tombstone forever. Deleting metadata would allow
        // stale CAS=0 writers and future requests to recreate the context.
        // Persist progress after each bounded deletion. A timeout/restart never
        // replays all prior history from version one.
        for attempt in 0..ATTEMPTS {
            let (mut doc, version) = self.read(scope).await?;
            // Upgrade an old tombstone written before progress checkpoints.
            if doc.retired && doc.cleanup_through == 0 && version > 1 {
                doc.cleanup_through = version - 1;
            }
            if doc.destroyed_through >= doc.cleanup_through {
                return Ok(());
            }
            let end = (doc.destroyed_through + 256).min(doc.cleanup_through);
            let versions: Vec<u64> = ((doc.destroyed_through + 1)..=end).collect();
            let response = self
                .client
                .post(self.url("destroy", scope))
                .header("X-Vault-Token", &self.token)
                .json(&json!({"versions": versions}))
                .send()
                .await
                .map_err(|_| Error::Unavailable)?;
            if !response.status().is_success() {
                return Err(Error::Unavailable);
            }
            doc.destroyed_through = end;
            if !self.cas(scope, &doc, version).await? {
                backoff(attempt).await;
                continue;
            }
            if end >= doc.cleanup_through {
                return Ok(());
            }
        }
        Err(Error::Busy)
    }
}

async fn bounded_json(mut response: Response) -> Result<Value, Error> {
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Unavailable)? {
        if data.len() + chunk.len() > MAX_DOCUMENT + 4096 {
            return Err(Error::Capacity);
        }
        data.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&data).map_err(|_| Error::Integrity)
}

async fn backoff(attempt: usize) {
    use rand::RngExt;
    let millis = rand::rng().random_range(1..=(attempt as u64 + 1) * 5);
    tokio::time::sleep(Duration::from_millis(millis)).await;
}

#[async_trait::async_trait]
impl TokenStore for OpenBao {
    async fn purge_expired(&self, scope: &Scope, limit: usize) -> Result<usize, Error> {
        if limit == 0 || limit > crate::MAX_BATCH {
            return Err(Error::Invalid);
        }
        for attempt in 0..ATTEMPTS {
            let (mut doc, version) = self.read(scope).await?;
            let now = chrono::Utc::now().timestamp_millis();
            let mut cleared = 0;
            for entry in doc.entries.values_mut() {
                if entry.expires_ms <= now && !entry.sealed.is_empty() {
                    entry.sealed.clear();
                    cleared += 1;
                    if cleared == limit {
                        break;
                    }
                }
            }
            if cleared == 0 {
                self.destroy_progress(scope).await?;
                return Ok(0);
            }
            doc.cleanup_through = version;
            if self.cas(scope, &doc, version).await? {
                self.destroy_progress(scope).await?;
                return Ok(cleared);
            }
            backoff(attempt).await;
        }
        Err(Error::Busy)
    }
    fn backend(&self) -> &'static str {
        "openbao_kv2"
    }

    #[tracing::instrument(skip_all, fields(backend = "openbao_kv2", items = candidates.len()))]
    async fn intern(&self, scope: &Scope, candidates: &[Entry]) -> Result<Vec<Entry>, Error> {
        self.intern_with_aliases(scope, candidates, &[]).await
    }

    async fn intern_with_aliases(
        &self,
        scope: &Scope,
        candidates: &[Entry],
        aliases: &[Vec<String>],
    ) -> Result<Vec<Entry>, Error> {
        validate(candidates)?;
        crate::migration::validate_aliases(candidates, aliases)?;
        if candidates.is_empty() {
            return Ok(vec![]);
        }
        for attempt in 0..ATTEMPTS {
            let (mut doc, version) = self.read(scope).await?;
            if doc.retired {
                return Err(Error::Retired);
            }
            let now = chrono::Utc::now().timestamp_millis();
            let mut result = Vec::with_capacity(candidates.len());
            let mut response_bytes = 0usize;
            let mut changed = false;
            let mut by_token: BTreeMap<_, _> = doc
                .entries
                .values()
                .map(|e| (e.token.clone(), e.fingerprint.clone()))
                .collect();
            for (i, candidate) in candidates.iter().enumerate() {
                let legacy_token = aliases
                    .get(i)
                    .and_then(|keys| keys.iter().find_map(|key| doc.aliases.get(key)));
                let key = match legacy_token {
                    Some(token) => by_token.get(token).ok_or(Error::Integrity)?,
                    None => &candidate.fingerprint,
                };
                if let Some(existing) = doc.entries.get(key) {
                    if existing.expires_ms <= now {
                        return Err(Error::Retired);
                    }
                    response_bytes = response_bytes
                        .checked_add(existing.sealed.len())
                        .ok_or(Error::Capacity)?;
                    if response_bytes > crate::MAX_BATCH_BYTES {
                        return Err(Error::Capacity);
                    }
                    result.push(existing.clone());
                } else {
                    if candidate.expires_ms <= now {
                        return Err(Error::Retired);
                    }
                    response_bytes = response_bytes
                        .checked_add(candidate.sealed.len())
                        .ok_or(Error::Capacity)?;
                    if response_bytes > crate::MAX_BATCH_BYTES {
                        return Err(Error::Capacity);
                    }
                    if by_token.contains_key(&candidate.token) {
                        return Err(Error::Integrity);
                    }
                    doc.entries
                        .insert(candidate.fingerprint.clone(), candidate.clone());
                    by_token.insert(candidate.token.clone(), candidate.fingerprint.clone());
                    result.push(candidate.clone());
                    changed = true;
                }
            }
            if !changed || self.cas(scope, &doc, version).await? {
                return Ok(result);
            }
            backoff(attempt).await;
        }
        Err(Error::Busy)
    }

    #[tracing::instrument(skip_all, fields(backend = "openbao_kv2", items = tokens.len()))]
    async fn resolve(&self, scope: &Scope, tokens: &[String]) -> Result<Vec<Option<Entry>>, Error> {
        validate_refs(tokens)?;
        if tokens.is_empty() {
            return Ok(vec![]);
        }
        let (doc, _) = self.read(scope).await?;
        let now = chrono::Utc::now().timestamp_millis();
        let by_token: BTreeMap<_, _> = doc
            .entries
            .values()
            .filter(|e| !doc.retired && e.expires_ms > now)
            .map(|e| (e.token.as_str(), e))
            .collect();
        response_budget(
            tokens
                .iter()
                .filter_map(|token| by_token.get(token.as_str()).copied()),
        )?;
        Ok(tokens
            .iter()
            .map(|token| by_token.get(token.as_str()).map(|e| (*e).clone()))
            .collect())
    }

    #[tracing::instrument(skip_all, fields(backend = "openbao_kv2"))]
    async fn retire(&self, scope: &Scope) -> Result<(), Error> {
        for attempt in 0..ATTEMPTS {
            let (doc, version) = self.read(scope).await?;
            if doc.retired {
                return self.destroy_progress(scope).await;
            }
            let tombstone = Document {
                retired: true,
                entries: BTreeMap::new(),
                cleanup_through: version,
                ..Document::default()
            };
            if self.cas(scope, &tombstone, version).await? {
                return self.destroy_progress(scope).await;
            }
            backoff(attempt).await;
        }
        Err(Error::Busy)
    }

    async fn context_state(&self, scope: &Scope) -> Result<ContextState, Error> {
        let (doc, version) = self.read(scope).await?;
        Ok(if version == 0 {
            ContextState::Absent
        } else if doc.retired {
            ContextState::Retired
        } else if let Some(source) = doc.import_source {
            ContextState::Imported {
                source,
                legacy_clean: doc.legacy_clean,
            }
        } else {
            ContextState::Active
        })
    }
    async fn import_legacy(&self, scope: &Scope, snapshot: &LegacyImport) -> Result<(), Error> {
        snapshot.validate()?;
        for attempt in 0..ATTEMPTS {
            let (mut doc, version) = self.read(scope).await?;
            if doc.retired {
                return Err(Error::Retired);
            }
            if let Some(source) = doc.import_source {
                return if source == snapshot.source {
                    Ok(())
                } else {
                    Err(Error::Integrity)
                };
            }
            if !doc.entries.is_empty() {
                return Err(Error::Integrity);
            }
            doc.entries = snapshot
                .entries
                .iter()
                .map(|e| (e.fingerprint.clone(), e.clone()))
                .collect();
            doc.aliases = snapshot.aliases.clone();
            doc.import_source = Some(snapshot.source.clone());
            doc.legacy_clean = false;
            if self.cas(scope, &doc, version).await? {
                return Ok(());
            }
            backoff(attempt).await;
        }
        Err(Error::Busy)
    }
    async fn complete_legacy_cleanup(&self, scope: &Scope, source: &str) -> Result<(), Error> {
        for attempt in 0..ATTEMPTS {
            let (mut doc, version) = self.read(scope).await?;
            if doc.retired {
                return Err(Error::Retired);
            }
            if doc.import_source.as_deref() != Some(source) {
                return Err(Error::Integrity);
            }
            if doc.legacy_clean {
                return Ok(());
            }
            doc.legacy_clean = true;
            if self.cas(scope, &doc, version).await? {
                return Ok(());
            }
            backoff(attempt).await;
        }
        Err(Error::Busy)
    }
}
