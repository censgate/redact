//! Authenticated gateway adapter for bounded token-store operations.
use super::{CredentialLineage, LineagePersistError, TokenMapError, TokenMapStore};
use crate::redact::token::{Dek, TokenMapping};
use redact_token_store::{
    ContextState, Error, LegacyValue, Scope, TokenStore, Vault, MAX_BATCH, MAX_RESPONSE_BYTES,
};
use std::{
    collections::HashMap,
    sync::{Arc, LazyLock},
    time::Duration,
};

static REFERENCES: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"\[[A-Z][A-Z0-9_]*_[0-9]+\]").expect("static token expression")
});

/// Build bounded shard pools and validate their operator-installed generation.
pub async fn build(
    settings: &crate::config::IndexedTokenSettings,
    source: Arc<dyn TokenMapStore>,
    dek: Arc<Dek>,
    ttl_secs: u64,
) -> Result<IndexedStore, TokenMapError> {
    let routing = serde_json::to_vec(&(&settings.shard_ids, &settings.ownership))
        .map_err(|_| failure(Error::Invalid))?;
    let commitment = Vault::configuration_commitment(&dek.token_store_key(), &routing);
    let mut shards = Vec::new();
    for (id, env_name) in settings.shard_ids.iter().zip(&settings.connection_env) {
        let url = std::env::var(env_name).map_err(unavailable)?;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(16)
            .acquire_timeout(Duration::from_secs(2))
            .connect(&url)
            .await
            .map_err(unavailable)?;
        let shard = redact_token_store::postgres::Postgres::new(pool)
            .await
            .map_err(failure)?;
        shard
            .verify_configuration(&commitment, id)
            .await
            .map_err(failure)?;
        shards.push(Arc::new(shard));
    }
    let ownership: [usize; 256] = settings
        .ownership
        .clone()
        .try_into()
        .map_err(|_| failure(Error::Invalid))?;
    let target =
        redact_token_store::postgres::ShardedPostgres::new(shards, ownership).map_err(failure)?;
    IndexedStore::new(Arc::new(target), source, dek, Duration::from_secs(ttl_secs))
}

/// Purpose-built token store with a fenced legacy source and durable lineage.
/// All writers to the source must support freezing before constructing this
/// adapter. Existing processes must be drained before migration is enabled.
pub struct IndexedStore {
    vault: Vault,
    source: Arc<dyn TokenMapStore>,
    dek: Arc<Dek>,
    retention: Duration,
    backend: &'static str,
}
impl std::fmt::Debug for IndexedStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexedStore")
            .field("backend", &self.backend)
            .finish_non_exhaustive()
    }
}
fn failure(error: Error) -> TokenMapError {
    TokenMapError::Indexed(error)
}
fn unavailable(_: impl std::fmt::Display) -> TokenMapError {
    failure(Error::Unavailable)
}
fn source_failure(error: TokenMapError) -> TokenMapError {
    match error {
        TokenMapError::Indexed(error) => failure(error),
        TokenMapError::Conflict(_) => failure(Error::Integrity),
        TokenMapError::Disabled => failure(Error::Invalid),
        // Legacy transport diagnostics may include backend paths. Keep the
        // indexed boundary content-free while retaining typed outcomes.
        _ => failure(Error::Unavailable),
    }
}
impl IndexedStore {
    /// Maintenance worker entry point for an authorized subject-bound context.
    /// Retry bounded batches until zero; never delete expired identity reservations.
    pub async fn purge_expired(
        &self,
        tenant: &str,
        context: &str,
        limit: usize,
    ) -> Result<usize, TokenMapError> {
        let scope = self.prepare(tenant, context).await?;
        self.vault
            .purge_expired(&scope, limit)
            .await
            .map_err(failure)
    }
    /// Wrap a durable target and its legacy source after the writer drain barrier.
    pub fn new(
        target: Arc<dyn TokenStore>,
        source: Arc<dyn TokenMapStore>,
        dek: Arc<Dek>,
        retention: Duration,
    ) -> Result<Self, TokenMapError> {
        if retention.is_zero() || source.backend_name() == "off" || source.indexed().is_some() {
            return Err(failure(Error::Invalid));
        }
        let backend = target.backend();
        Ok(Self {
            vault: Vault::new(target, dek.token_store_key(), 64, Duration::from_secs(10))
                .map_err(failure)?,
            source,
            dek,
            retention,
            backend,
        })
    }
    fn scope(&self, tenant: &str, subject_bound_context: &str) -> Result<Scope, TokenMapError> {
        self.vault
            .scope(tenant, "gateway-subject-bound-v1", subject_bound_context)
            .map_err(failure)
    }
    async fn prepare(&self, tenant: &str, context: &str) -> Result<Scope, TokenMapError> {
        let scope = self.scope(tenant, context)?;
        let source = match self.vault.context_state(&scope).await.map_err(failure)? {
            ContextState::Imported {
                legacy_clean: true, ..
            }
            | ContextState::Retired => return Ok(scope),
            ContextState::Imported {
                source,
                legacy_clean: false,
            } => source,
            ContextState::Active => return Err(failure(Error::Integrity)),
            ContextState::Absent => {
                let frozen = self
                    .source
                    .freeze(tenant, context)
                    .await
                    .map_err(source_failure)?;
                if frozen.mappings.len() > redact_token_store::MAX_IMPORT_ENTRIES
                    || frozen
                        .mappings
                        .iter()
                        .map(|m| m.sealed_value.len())
                        .sum::<usize>()
                        > redact_token_store::MAX_IMPORT_BYTES
                {
                    return Err(failure(Error::Capacity));
                }
                let values: Vec<_> = frozen
                    .mappings
                    .iter()
                    .map(|m| {
                        Ok(LegacyValue {
                            token: m.token.clone(),
                            kind: m.entity_type.clone(),
                            original: self
                                .dek
                                .open(&m.sealed_value)
                                .map_err(|_| failure(Error::Integrity))?,
                            expires_ms: frozen.expires_ms,
                        })
                    })
                    .collect::<Result<_, TokenMapError>>()?;
                self.vault
                    .import_legacy(&scope, &values)
                    .await
                    .map_err(failure)?
            }
        };
        self.source
            .clear_frozen(tenant, context)
            .await
            .map_err(source_failure)?;
        self.vault
            .complete_legacy_cleanup(&scope, &source)
            .await
            .map_err(failure)?;
        Ok(scope)
    }
    /// Atomically assign durable identities to request-local placeholders.
    pub async fn commit(
        &self,
        tenant: &str,
        context: &str,
        mappings: &[TokenMapping],
    ) -> Result<HashMap<String, String>, TokenMapError> {
        tokio::time::timeout(Duration::from_secs(10), async {
            if mappings.len() > MAX_BATCH {
                return Err(failure(Error::Capacity));
            }
            let scope = self.prepare(tenant, context).await?;
            let values: Vec<_> = mappings
                .iter()
                .map(|m| {
                    Ok((
                        m.entity_type.clone(),
                        self.dek
                            .open(&m.sealed_value)
                            .map_err(|_| failure(Error::Integrity))?,
                    ))
                })
                .collect::<Result<_, TokenMapError>>()?;
            let tokens = self
                .vault
                .intern(&scope, &values, self.retention)
                .await
                .map_err(failure)?;
            Ok(mappings
                .iter()
                .zip(tokens)
                .map(|(m, t)| (m.token.clone(), t))
                .collect())
        })
        .await
        .map_err(unavailable)?
    }
    /// Fetch/decrypt distinct references only. Bounds input and expanded output.
    pub async fn lookup(
        &self,
        tenant: &str,
        context: &str,
        text: &str,
    ) -> Result<HashMap<String, String>, TokenMapError> {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        tokio::time::timeout_at(deadline, async {
            if text.len() > MAX_RESPONSE_BYTES {
                return Err(failure(Error::Capacity));
            }
            let mut refs = std::collections::BTreeMap::<String, usize>::new();
            for m in REFERENCES.find_iter(text) {
                *refs.entry(m.as_str().into()).or_default() += 1;
            }
            if refs.len() > MAX_BATCH {
                return Err(failure(Error::Capacity));
            }
            let scope = self.prepare(tenant, context).await?;
            let tokens: Vec<_> = refs.keys().cloned().collect();
            let originals = self.vault.resolve(&scope, &tokens).await.map_err(failure)?;
            let mut size = text.len();
            let mut lookup = HashMap::new();
            for (token, original) in tokens.into_iter().zip(originals) {
                if let Some(original) = original {
                    size = size
                        .checked_add(
                            original
                                .len()
                                .saturating_sub(token.len())
                                .checked_mul(refs[&token])
                                .ok_or_else(|| failure(Error::Capacity))?,
                        )
                        .ok_or_else(|| failure(Error::Capacity))?;
                    if size > MAX_RESPONSE_BYTES {
                        return Err(failure(Error::Capacity));
                    }
                    lookup.insert(token, original);
                }
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(failure(Error::Unavailable));
            }
            Ok(lookup)
        })
        .await
        .map_err(unavailable)?
    }
}
#[async_trait::async_trait]
impl TokenMapStore for IndexedStore {
    fn backend_name(&self) -> &'static str {
        self.backend
    }
    fn indexed(&self) -> Option<&IndexedStore> {
        Some(self)
    }
    async fn put(&self, _: &str, _: &str, _: &[TokenMapping]) -> Result<(), TokenMapError> {
        Err(failure(Error::Invalid))
    }
    async fn get(&self, _: &str, _: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        Err(failure(Error::Invalid))
    }
    async fn delete(&self, tenant: &str, context: &str) -> Result<(), TokenMapError> {
        self.purge(tenant, context).await
    }
    async fn purge(&self, tenant: &str, context: &str) -> Result<(), TokenMapError> {
        self.vault
            .retire(&self.scope(tenant, context)?)
            .await
            .map_err(failure)?;
        self.source
            .fence_for_erasure(tenant, context)
            .await
            .map_err(source_failure)?;
        self.source
            .clear_frozen(tenant, context)
            .await
            .map_err(source_failure)
    }
    async fn exists(&self, tenant: &str, context: &str) -> Result<bool, TokenMapError> {
        let state = self
            .vault
            .context_state(&self.scope(tenant, context)?)
            .await
            .map_err(failure)?;
        if state == ContextState::Absent {
            return self
                .source
                .exists(tenant, context)
                .await
                .map_err(source_failure);
        }
        if state == ContextState::Retired {
            self.vault
                .retire(&self.scope(tenant, context)?)
                .await
                .map_err(failure)?;
            self.source
                .fence_for_erasure(tenant, context)
                .await
                .map_err(source_failure)?;
            self.source
                .clear_frozen(tenant, context)
                .await
                .map_err(source_failure)?;
        }
        Ok(state != ContextState::Retired)
    }
    async fn get_lineage(
        &self,
        tenant: &str,
        subject: &str,
    ) -> Result<CredentialLineage, TokenMapError> {
        self.source.get_lineage(tenant, subject).await
    }
    async fn put_lineage(
        &self,
        tenant: &str,
        subject: &str,
        lineage: &CredentialLineage,
    ) -> Result<(), TokenMapError> {
        self.source.put_lineage(tenant, subject, lineage).await
    }
    async fn register_predecessor(
        &self,
        tenant: &str,
        current: &str,
        previous: &str,
    ) -> Result<CredentialLineage, LineagePersistError> {
        self.source
            .register_predecessor(tenant, current, previous)
            .await
    }
    async fn health(&self) -> Result<(), TokenMapError> {
        tokio::time::timeout(Duration::from_secs(2), async {
            self.vault.health().await.map_err(failure)?;
            self.source.health().await.map_err(source_failure)
        })
        .await
        .map_err(|_| failure(Error::Unavailable))?
    }
}

/// Replace generated references in JSON string values, preserving keys/types.
pub fn replace_payload(value: &mut serde_json::Value, replacements: &HashMap<String, String>) {
    match value {
        serde_json::Value::String(s) => *s = crate::redact::token::restore_text(s, replacements).0,
        serde_json::Value::Array(items) => {
            for item in items {
                replace_payload(item, replacements);
            }
        }
        serde_json::Value::Object(items) => {
            for item in items.values_mut() {
                replace_payload(item, replacements);
            }
        }
        _ => {}
    }
}
