//! OpenBao KV v2 reference adapter. CAS provides atomicity across replicas.
//! This adapter deliberately exposes its whole-document cost and capacity limit;
//! use the indexed PostgreSQL adapter for growing contexts.
use crate::{validate, validate_refs, Entry, Error, Scope, TokenStore};
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
        }
        Err(Error::Unavailable)
    }

    async fn destroy_before(&self, scope: &Scope, version: u64) -> Result<(), Error> {
        // Keep the latest tombstone forever. Deleting metadata would allow
        // stale CAS=0 writers and future requests to recreate the context.
        let mut start = 1;
        while start < version {
            let end = (start + 256).min(version);
            let versions: Vec<u64> = (start..end).collect();
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
            start = end;
        }
        Ok(())
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
    fn backend(&self) -> &'static str {
        "openbao_kv2"
    }

    #[tracing::instrument(skip_all, fields(backend = "openbao_kv2", items = candidates.len()))]
    async fn intern(&self, scope: &Scope, candidates: &[Entry]) -> Result<Vec<Entry>, Error> {
        validate(candidates)?;
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
            let mut changed = false;
            for candidate in candidates {
                if let Some(existing) = doc.entries.get(&candidate.fingerprint) {
                    if existing.expires_ms <= now {
                        return Err(Error::Retired);
                    }
                    result.push(existing.clone());
                } else {
                    if candidate.expires_ms <= now {
                        return Err(Error::Retired);
                    }
                    if doc.entries.values().any(|e| e.token == candidate.token) {
                        return Err(Error::Integrity);
                    }
                    doc.entries
                        .insert(candidate.fingerprint.clone(), candidate.clone());
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
                return self.destroy_before(scope, version).await;
            }
            let tombstone = Document {
                retired: true,
                entries: BTreeMap::new(),
            };
            if self.cas(scope, &tombstone, version).await? {
                return self.destroy_before(scope, version + 1).await;
            }
            backoff(attempt).await;
        }
        Err(Error::Busy)
    }
}
