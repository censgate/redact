// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! KV version 2 token-map backend.
//!
//! This backend speaks the HashiCorp Vault KV v2 HTTP API and therefore works
//! with both HashiCorp Vault and OpenBao. Auth is either a static bearer token
//! (`X-Vault-Token`, local-dev) or Kubernetes auth against a dedicated
//! token-map service (required for n-replica HPA). The ESO `external-secrets`
//! role must never be used here.
//!
//! Concurrent `put` calls use KV v2 compare-and-set (`options.cas`) with a
//! bounded, jittered retry loop so two writers merging into the same session
//! cannot silently discard each other's mappings.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use vaultrs::api::kv2::requests::{ReadSecretRequest, SetSecretRequestOptions};
use vaultrs::api::{self, kv2::responses::ReadSecretResponse};
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

use super::{
    lineage_tenant_path, merge_mappings, register_direct_predecessor, session_path,
    subject_closure, CredentialLineage, LineagePersistError, TenantLineageGraph, TokenMapError,
    TokenMapStore,
};
use crate::config::{VaultAuthMethod, VaultSettings};
use crate::redact::token::TokenMapping;

/// Maximum read→merge→CAS-write attempts before surfacing a conflict.
const PUT_CAS_ATTEMPTS: u32 = 8;
/// Cache OpenBao reachability so `/readyz` does not serialize on the leader.
const HEALTH_CACHE_TTL: Duration = Duration::from_secs(2);

/// Payload written under each session path.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    #[serde(default)]
    frozen: bool,
    #[serde(default)]
    cleanup_through: u64,
    #[serde(default)]
    destroyed_through: u64,
    mappings: Vec<TokenMapping>,
    expires_at: DateTime<Utc>,
}

enum AuthMode {
    Static,
    Kubernetes {
        address: String,
        namespace: Option<String>,
        mount: String,
        role: String,
        jwt_path: PathBuf,
    },
}

struct Inner {
    client: VaultClient,
    token_expires_at: Option<Instant>,
}

/// Token map backed by a Vault / OpenBao KV v2 mount.
pub struct Kv2Store {
    inner: RwLock<Inner>,
    auth: AuthMode,
    mount: String,
    path_prefix: String,
    ttl_secs: u64,
    health: Mutex<Option<(Instant, Result<(), String>)>>,
}

impl std::fmt::Debug for Kv2Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kv2Store")
            .field("mount", &self.mount)
            .field("path_prefix", &self.path_prefix)
            .field("ttl_secs", &self.ttl_secs)
            .finish_non_exhaustive()
    }
}

impl Kv2Store {
    /// Construct a store from gateway vault settings.
    pub fn from_settings(settings: &VaultSettings) -> Result<Self, TokenMapError> {
        let address = settings.address.as_deref().ok_or_else(|| {
            TokenMapError::Unavailable("vault_kv2 backend requires an address".to_string())
        })?;

        let auth = match settings.auth {
            VaultAuthMethod::Kubernetes => {
                let role = settings
                    .kubernetes_role
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        TokenMapError::Unavailable(
                            "vault_kv2 kubernetes auth requires a role".to_string(),
                        )
                    })?;
                if role == "external-secrets" {
                    return Err(TokenMapError::Unavailable(
                        "refusing Kubernetes auth role `external-secrets`; \
                         bind a dedicated redact-gateway role on the token-map service"
                            .to_string(),
                    ));
                }
                AuthMode::Kubernetes {
                    address: address.to_string(),
                    namespace: settings.namespace.clone(),
                    mount: settings.kubernetes_mount.clone(),
                    role: role.to_string(),
                    jwt_path: settings.jwt_path.clone(),
                }
            }
            VaultAuthMethod::Token => AuthMode::Static,
        };

        let token = match &auth {
            AuthMode::Static => settings.token.clone().unwrap_or_default(),
            AuthMode::Kubernetes { .. } => String::new(),
        };

        let mut builder = VaultClientSettingsBuilder::default();
        builder.address(address);
        builder.token(token);
        if let Some(namespace) = &settings.namespace {
            builder.set_namespace(namespace.clone());
        }

        let client_settings = builder.build().map_err(|e| {
            TokenMapError::Unavailable(format!("invalid vault client settings: {e}"))
        })?;
        let client = VaultClient::new(client_settings).map_err(|e| {
            TokenMapError::Unavailable(format!("could not build vault client: {e}"))
        })?;

        Ok(Self {
            inner: RwLock::new(Inner {
                client,
                token_expires_at: None,
            }),
            auth,
            mount: settings.mount.clone(),
            path_prefix: settings.path_prefix.clone(),
            ttl_secs: settings.ttl_secs,
            health: Mutex::new(None),
        })
    }

    fn path(&self, tenant: &str, session: &str) -> String {
        session_path(&self.path_prefix, tenant, session)
    }

    fn lineage_storage_path(&self, tenant: &str) -> String {
        lineage_tenant_path(&self.path_prefix, tenant)
    }

    async fn metadata_exists(&self, path: &str) -> Result<bool, TokenMapError> {
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        match kv2::read_metadata(&inner.client, &self.mount, path).await {
            Ok(_) => Ok(true),
            Err(ClientError::APIError { code: 404, .. }) => Ok(false),
            Err(err) => Err(map_client_error(err)),
        }
    }

    async fn read_graph_for_cas(
        &self,
        path: &str,
    ) -> Result<(TenantLineageGraph, u32), TokenMapError> {
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        let endpoint = ReadSecretRequest::builder()
            .mount(self.mount.as_str())
            .path(path)
            .build()
            .map_err(|e| TokenMapError::Backend(format!("invalid vault read request: {e}")))?;

        let response: ReadSecretResponse =
            match api::exec_with_result(&inner.client, endpoint).await {
                Ok(res) => res,
                Err(ClientError::APIError { code: 404, .. }) => {
                    return Ok((TenantLineageGraph::default(), 0))
                }
                Err(err) => return Err(map_client_error(err)),
            };

        let cas = version_to_cas(response.metadata.version)?;
        let graph: TenantLineageGraph = serde_json::value::from_value(response.data)
            .map_err(|e| TokenMapError::Backend(format!("invalid vault lineage payload: {e}")))?;
        Ok((graph, cas))
    }

    async fn put_graph_cas(
        &self,
        tenant: &str,
        mutate: impl Fn(&mut TenantLineageGraph) -> Result<CredentialLineage, LineagePersistError>,
    ) -> Result<CredentialLineage, LineagePersistError> {
        let path = self.lineage_storage_path(tenant);
        let mut last_cas_error = None;
        for attempt in 1..=PUT_CAS_ATTEMPTS {
            let (mut graph, cas) = self.read_graph_for_cas(&path).await?;
            let result = mutate(&mut graph)?;
            let options = SetSecretRequestOptions { cas };
            let write = {
                self.ensure_fresh_token().await?;
                let inner = self.inner.read().await;
                kv2::set_with_options(&inner.client, &self.mount, &path, &graph, options).await
            };
            match write {
                Ok(_) => return Ok(result),
                Err(err) if is_cas_conflict(&err) => {
                    last_cas_error = Some(err.to_string());
                    if attempt == PUT_CAS_ATTEMPTS {
                        break;
                    }
                    tokio::time::sleep(cas_backoff(attempt)).await;
                }
                Err(err) => return Err(map_client_error(err).into()),
            }
        }
        Err(TokenMapError::Backend(format!(
            "vault KV v2 lineage compare-and-set conflict after {PUT_CAS_ATTEMPTS} attempts: {}",
            last_cas_error.unwrap_or_else(|| "unknown check-and-set failure".to_string())
        ))
        .into())
    }

    fn token_still_valid(inner: &Inner) -> bool {
        inner
            .token_expires_at
            .is_some_and(|deadline| Instant::now() < deadline)
    }

    async fn ensure_fresh_token(&self) -> Result<(), TokenMapError> {
        {
            let inner = self.inner.read().await;
            if matches!(self.auth, AuthMode::Static) || Self::token_still_valid(&inner) {
                return Ok(());
            }
        }
        let mut inner = self.inner.write().await;
        self.ensure_token(&mut inner).await
    }

    async fn ensure_token(&self, inner: &mut Inner) -> Result<(), TokenMapError> {
        let AuthMode::Kubernetes {
            address,
            namespace,
            mount,
            role,
            jwt_path,
        } = &self.auth
        else {
            return Ok(());
        };
        if Self::token_still_valid(inner) {
            return Ok(());
        }
        let jwt = std::fs::read_to_string(jwt_path).map_err(|e| {
            TokenMapError::Unavailable(format!(
                "could not read Kubernetes service account JWT at {}: {e}",
                jwt_path.display()
            ))
        })?;
        let (token, lease_secs) =
            kubernetes_login(address, namespace.as_deref(), mount, role, jwt.trim()).await?;
        inner.client.set_token(&token);
        inner.token_expires_at = Some(Instant::now() + kubernetes_token_cache_ttl(lease_secs));
        Ok(())
    }

    async fn read_entry(&self, path: &str) -> Result<Option<StoredSession>, TokenMapError> {
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        match kv2::read::<StoredSession>(&inner.client, &self.mount, path).await {
            Ok(entry) => {
                if entry.frozen {
                    return Err(TokenMapError::Conflict("context migrated".into()));
                }
                if entry.expires_at <= Utc::now() {
                    // Treat as absent without calling delete_latest: a concurrent
                    // put can CAS-write a fresh version between this read and a
                    // delete, and delete_latest would then wipe the new data.
                    // The next put overwrites expired payloads via CAS.
                    Ok(None)
                } else {
                    Ok(Some(entry))
                }
            }
            Err(ClientError::APIError { code: 404, .. }) => Ok(None),
            Err(err) => Err(map_client_error(err)),
        }
    }

    /// Read session data and the KV v2 version needed for a CAS write.
    ///
    /// Uses the raw read endpoint (rather than [`kv2::read`]) so the version in
    /// response metadata is observed atomically with the payload. A missing key
    /// yields `cas = 0` ("create only"). Expired entries contribute no mappings
    /// but retain their version so the subsequent write still CAS-protects.
    async fn read_for_cas(&self, path: &str) -> Result<(Vec<TokenMapping>, u32), TokenMapError> {
        let (entry, cas) = self.read_snapshot(path, false).await?;
        if entry.frozen {
            return Err(TokenMapError::Conflict("context migrated".into()));
        }
        if entry.expires_at <= Utc::now() {
            Ok((Vec::new(), cas))
        } else {
            Ok((entry.mappings, cas))
        }
    }

    async fn read_snapshot(
        &self,
        path: &str,
        verify_missing: bool,
    ) -> Result<(StoredSession, u32), TokenMapError> {
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        let mut retry_missing = verify_missing;
        let response: ReadSecretResponse = loop {
            let endpoint = ReadSecretRequest::builder()
                .mount(self.mount.as_str())
                .path(path)
                .build()
                .map_err(|e| TokenMapError::Backend(format!("invalid vault read request: {e}")))?;

            match api::exec_with_result(&inner.client, endpoint).await {
                Ok(res) => break res,
                Err(ClientError::APIError { code: 404, .. }) => {
                    // A deleted latest version with surviving metadata cannot
                    // safely be interpreted as an empty source namespace.
                    if verify_missing {
                        match kv2::read_metadata(&inner.client, &self.mount, path).await {
                            Ok(_) => {
                                // A concurrent first writer may create data
                                // between the 404 and metadata read. Re-read
                                // once; a genuinely missing latest version still
                                // fails closed, never becoming an empty source.
                                if retry_missing {
                                    retry_missing = false;
                                    continue;
                                }
                                return Err(TokenMapError::Indexed(
                                    redact_token_store::Error::Integrity,
                                ));
                            }
                            Err(ClientError::APIError { code: 404, .. }) => {}
                            Err(err) => return Err(map_client_error(err)),
                        }
                    }
                    return Ok((
                        StoredSession {
                            mappings: Vec::new(),
                            expires_at: Utc::now(),
                            frozen: false,
                            cleanup_through: 0,
                            destroyed_through: 0,
                        },
                        0,
                    ));
                }
                Err(err) => return Err(map_client_error(err)),
            }
        };

        let cas = version_to_cas(response.metadata.version)?;
        let entry: StoredSession = serde_json::value::from_value(response.data)
            .map_err(|e| TokenMapError::Backend(format!("invalid vault session payload: {e}")))?;

        Ok((entry, cas))
    }
}

#[async_trait::async_trait]
impl TokenMapStore for Kv2Store {
    async fn fence_for_erasure(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        let path = self.path(tenant, session);
        for attempt in 1..=PUT_CAS_ATTEMPTS {
            self.ensure_fresh_token().await?;
            let inner = self.inner.read().await;
            // Metadata supplies the CAS revision even when the latest data is
            // deleted, malformed or unreadable. Erasure does not import it.
            let version = match kv2::read_metadata(&inner.client, &self.mount, &path).await {
                Ok(metadata) => metadata.current_version,
                Err(ClientError::APIError { code: 404, .. }) => 0,
                Err(err) => return Err(map_client_error(err)),
            };
            let cas = version_to_cas(version)?;
            if version > 0 {
                // A retry must retain progress, not reset it after every bounded
                // cleanup call. All versions after this cutoff are empty fences.
                if let Ok(entry) =
                    kv2::read_version::<StoredSession>(&inner.client, &self.mount, &path, version)
                        .await
                {
                    if entry.frozen
                        && entry.mappings.is_empty()
                        && entry.destroyed_through <= entry.cleanup_through
                        && entry.cleanup_through <= version
                    {
                        return Ok(());
                    }
                }
            }
            let fence = StoredSession {
                frozen: true,
                cleanup_through: version,
                destroyed_through: 0,
                mappings: Vec::new(),
                expires_at: Utc::now(),
            };
            match kv2::set_with_options(
                &inner.client,
                &self.mount,
                &path,
                &fence,
                SetSecretRequestOptions { cas },
            )
            .await
            {
                Ok(_) => return Ok(()),
                Err(err) if is_cas_conflict(&err) => {}
                Err(err) => return Err(map_client_error(err)),
            }
            drop(inner);
            tokio::time::sleep(cas_backoff(attempt)).await;
        }
        Err(TokenMapError::Indexed(redact_token_store::Error::Busy))
    }

    async fn freeze(
        &self,
        tenant: &str,
        session: &str,
    ) -> Result<super::FrozenSnapshot, TokenMapError> {
        let path = self.path(tenant, session);
        for attempt in 1..=PUT_CAS_ATTEMPTS {
            let (mut entry, cas) = self.read_snapshot(&path, true).await?;
            if entry.frozen {
                return Ok(super::FrozenSnapshot {
                    mappings: entry.mappings,
                    expires_ms: entry.expires_at.timestamp_millis(),
                });
            }
            // Cumulative legacy versions must retain all historical identities.
            // Pruned history or a dropped/rebound label requires offline recovery.
            if cas > 0 {
                self.ensure_fresh_token().await?;
                let inner = self.inner.read().await;
                let metadata = kv2::read_metadata(&inner.client, &self.mount, &path)
                    .await
                    .map_err(map_client_error)?;
                if cas > 2048
                    || metadata.oldest_version > 1
                    || metadata.versions.len() != cas as usize
                {
                    return Err(TokenMapError::Indexed(redact_token_store::Error::Integrity));
                }
                let current: std::collections::HashMap<_, _> =
                    entry.mappings.iter().map(|m| (&m.token, m)).collect();
                for version in 1..u64::from(cas) {
                    let previous: StoredSession =
                        kv2::read_version(&inner.client, &self.mount, &path, version)
                            .await
                            .map_err(map_client_error)?;
                    if previous.mappings.iter().any(|old| {
                        current.get(&old.token).is_none_or(|new| {
                            new.entity_type != old.entity_type
                                || new.sealed_value != old.sealed_value
                        })
                    }) {
                        return Err(TokenMapError::Indexed(redact_token_store::Error::Integrity));
                    }
                }
            }
            entry.frozen = true;
            self.ensure_fresh_token().await?;
            let result = {
                let inner = self.inner.read().await;
                kv2::set_with_options(
                    &inner.client,
                    &self.mount,
                    &path,
                    &entry,
                    SetSecretRequestOptions { cas },
                )
                .await
            };
            match result {
                Ok(_) => {
                    return Ok(super::FrozenSnapshot {
                        mappings: entry.mappings,
                        expires_ms: entry.expires_at.timestamp_millis(),
                    })
                }
                Err(err) if is_cas_conflict(&err) => tokio::time::sleep(cas_backoff(attempt)).await,
                Err(err) => return Err(map_client_error(err)),
            }
        }
        Err(TokenMapError::Indexed(redact_token_store::Error::Busy))
    }

    async fn clear_frozen(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        let path = self.path(tenant, session);
        for attempt in 1..=PUT_CAS_ATTEMPTS {
            let (mut entry, cas) = self.read_snapshot(&path, true).await?;
            if !entry.frozen {
                return Err(TokenMapError::Indexed(redact_token_store::Error::Integrity));
            }
            if entry.cleanup_through == 0 {
                entry.cleanup_through = u64::from(cas);
                entry.mappings.clear();
            } else if entry.destroyed_through == entry.cleanup_through {
                return Ok(());
            } else {
                let end = (entry.destroyed_through + 256).min(entry.cleanup_through);
                self.ensure_fresh_token().await?;
                let inner = self.inner.read().await;
                kv2::destroy_versions(
                    &inner.client,
                    &self.mount,
                    &path,
                    ((entry.destroyed_through + 1)..=end).collect(),
                )
                .await
                .map_err(map_client_error)?;
                entry.destroyed_through = end;
            }
            self.ensure_fresh_token().await?;
            let inner = self.inner.read().await;
            match kv2::set_with_options(
                &inner.client,
                &self.mount,
                &path,
                &entry,
                SetSecretRequestOptions { cas },
            )
            .await
            {
                Ok(_) => {}
                Err(err) if is_cas_conflict(&err) => {}
                Err(err) => return Err(map_client_error(err)),
            }
            drop(inner);
            tokio::time::sleep(cas_backoff(attempt)).await;
        }
        Err(TokenMapError::Indexed(redact_token_store::Error::Busy))
    }
    fn backend_name(&self) -> &'static str {
        "vault_kv2"
    }

    async fn put(
        &self,
        tenant: &str,
        session: &str,
        mappings: &[TokenMapping],
    ) -> Result<(), TokenMapError> {
        // Empty incoming set is a no-op: do not CAS-write just to refresh TTL.
        if mappings.is_empty() {
            return Ok(());
        }

        let path = self.path(tenant, session);
        let mut last_cas_error = None;

        for attempt in 1..=PUT_CAS_ATTEMPTS {
            let (existing, cas) = self.read_for_cas(&path).await?;
            let merged = merge_mappings(existing, mappings)?;
            let payload = StoredSession {
                frozen: false,
                cleanup_through: 0,
                destroyed_through: 0,
                mappings: merged,
                expires_at: Utc::now() + chrono::Duration::seconds(self.ttl_secs as i64),
            };
            let options = SetSecretRequestOptions { cas };

            let result = {
                self.ensure_fresh_token().await?;
                let inner = self.inner.read().await;
                kv2::set_with_options(&inner.client, &self.mount, &path, &payload, options).await
            };

            match result {
                Ok(_) => return Ok(()),
                Err(err) if is_cas_conflict(&err) => {
                    last_cas_error = Some(err.to_string());
                    if attempt == PUT_CAS_ATTEMPTS {
                        break;
                    }
                    tokio::time::sleep(cas_backoff(attempt)).await;
                }
                Err(err) => return Err(map_client_error(err)),
            }
        }

        Err(TokenMapError::Backend(format!(
            "vault KV v2 compare-and-set conflict after {PUT_CAS_ATTEMPTS} attempts: {}",
            last_cas_error.unwrap_or_else(|| "unknown check-and-set failure".to_string())
        )))
    }

    async fn get(&self, tenant: &str, session: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        let path = self.path(tenant, session);
        Ok(self
            .read_entry(&path)
            .await?
            .map(|entry| entry.mappings)
            .unwrap_or_default())
    }

    async fn exists(&self, tenant: &str, session: &str) -> Result<bool, TokenMapError> {
        self.metadata_exists(&self.path(tenant, session)).await
    }

    async fn delete(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        let path = self.path(tenant, session);
        if self.read_snapshot(&path, false).await?.0.frozen {
            return Err(TokenMapError::Conflict("context migrated".into()));
        }
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        match kv2::delete_latest(&inner.client, &self.mount, &path).await {
            Ok(()) => Ok(()),
            Err(ClientError::APIError { code: 404, .. }) => Ok(()),
            Err(err) => Err(map_client_error(err)),
        }
    }

    async fn purge(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        let path = self.path(tenant, session);
        if self.read_snapshot(&path, false).await?.0.frozen {
            return Err(TokenMapError::Conflict("context migrated".into()));
        }
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        match kv2::delete_metadata(&inner.client, &self.mount, &path).await {
            Ok(()) => Ok(()),
            Err(ClientError::APIError { code: 404, .. }) => Ok(()),
            Err(err) => Err(map_client_error(err)),
        }
    }

    async fn get_lineage(
        &self,
        tenant: &str,
        subject: &str,
    ) -> Result<CredentialLineage, TokenMapError> {
        let path = self.lineage_storage_path(tenant);
        let (graph, _) = self.read_graph_for_cas(&path).await?;
        let revision = graph
            .subjects
            .get(subject)
            .map(|row| row.revision)
            .unwrap_or(0);
        let predecessors = subject_closure(&graph, subject)
            .map_err(|err| TokenMapError::Backend(err.to_string()))?;
        Ok(CredentialLineage {
            predecessors,
            revision,
        })
    }

    async fn put_lineage(
        &self,
        tenant: &str,
        subject: &str,
        lineage: &CredentialLineage,
    ) -> Result<(), TokenMapError> {
        let subject = subject.to_string();
        let lineage = lineage.clone();
        self.put_graph_cas(tenant, move |graph| {
            graph.subjects.insert(subject.clone(), lineage.clone());
            Ok(lineage.clone())
        })
        .await
        .map(|_| ())
        .map_err(|err| match err {
            LineagePersistError::Store(store) => store,
            LineagePersistError::Register(_) => {
                TokenMapError::Backend("lineage compose failed during put_lineage".to_string())
            }
        })
    }

    async fn register_predecessor(
        &self,
        tenant: &str,
        current_subject: &str,
        previous_subject: &str,
    ) -> Result<CredentialLineage, LineagePersistError> {
        let current_subject = current_subject.to_string();
        let previous_subject = previous_subject.to_string();
        self.put_graph_cas(tenant, move |graph| {
            Ok(register_direct_predecessor(
                graph,
                &current_subject,
                &previous_subject,
            )?)
        })
        .await
    }

    async fn health(&self) -> Result<(), TokenMapError> {
        {
            let cache = self.health.lock().await;
            if let Some((at, result)) = cache.as_ref() {
                if at.elapsed() < HEALTH_CACHE_TTL {
                    return result.clone().map_err(TokenMapError::Unavailable);
                }
            }
        }

        let probed = {
            self.ensure_fresh_token().await?;
            let inner = self.inner.read().await;
            // OpenBao omits Vault enterprise replication fields. Check the
            // protocol's health status instead of deserializing those fields.
            // Unlike Client::status(), this rejects sealed/uninitialized states
            // rather than treating every successfully decoded enum as healthy.
            let endpoint = api::sys::requests::ReadHealthRequest::builder()
                .standbyok(true)
                .perfstandbyok(true)
                .build()
                .expect("static health request");
            api::exec_with_empty(&inner.client, endpoint)
                .await
                .map_err(|_| "token source is not ready".to_string())
        };

        *self.health.lock().await = Some((Instant::now(), probed.clone()));
        probed.map_err(TokenMapError::Unavailable)
    }
}

/// Cache a Kubernetes auth token strictly inside its lease.
///
/// `lease_duration == 0` means non-expiring; re-login hourly so a revoked
/// token does not live forever in process. Never cache past a positive lease
/// (the previous `max(80%, 30s)` floor reused expired sub-30s tokens).
fn kubernetes_token_cache_ttl(lease_secs: u64) -> Duration {
    if lease_secs == 0 {
        return Duration::from_secs(3600);
    }
    let eighty_pct = lease_secs.saturating_mul(4) / 5;
    let before_expiry = lease_secs.saturating_sub(1);
    Duration::from_secs(eighty_pct.clamp(1, before_expiry.max(1)))
}

fn cas_backoff(attempt: u32) -> Duration {
    let base_ms = 5u64.saturating_mul(u64::from(attempt));
    let jitter_ms = u64::from(rand::random::<u8>() % 20);
    Duration::from_millis(base_ms + jitter_ms)
}

async fn kubernetes_login(
    address: &str,
    namespace: Option<&str>,
    mount: &str,
    role: &str,
    jwt: &str,
) -> Result<(String, u64), TokenMapError> {
    let url = format!(
        "{}/v1/auth/{}/login",
        address.trim_end_matches('/'),
        mount.trim_matches('/')
    );
    let mut request = reqwest::Client::new()
        .post(url)
        .json(&serde_json::json!({ "role": role, "jwt": jwt }));
    if let Some(ns) = namespace {
        request = request.header("X-Vault-Namespace", ns);
    }
    let response = request
        .send()
        .await
        .map_err(|e| TokenMapError::Unavailable(format!("kubernetes auth login failed: {e}")))?;
    let status = response.status();
    let body: serde_json::Value = response.json().await.map_err(|e| {
        TokenMapError::Unavailable(format!("kubernetes auth login returned non-JSON: {e}"))
    })?;
    if !status.is_success() {
        return Err(TokenMapError::Unavailable(format!(
            "kubernetes auth login HTTP {status}: {}",
            body.get("errors")
                .cloned()
                .unwrap_or_else(|| serde_json::json!([]))
        )));
    }
    let token = body
        .pointer("/auth/client_token")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            TokenMapError::Unavailable(
                "kubernetes auth login missing auth.client_token".to_string(),
            )
        })?;
    let lease = body
        .pointer("/auth/lease_duration")
        .and_then(|v| v.as_u64())
        .unwrap_or(3600);
    Ok((token.to_string(), lease))
}

fn version_to_cas(version: u64) -> Result<u32, TokenMapError> {
    u32::try_from(version).map_err(|_| {
        TokenMapError::Backend(format!(
            "vault KV v2 version {version} exceeds compare-and-set u32 range"
        ))
    })
}

fn is_cas_conflict(err: &ClientError) -> bool {
    match err {
        ClientError::APIError { code: 400, errors } => errors
            .iter()
            .any(|msg| msg.to_ascii_lowercase().contains("check-and-set")),
        _ => false,
    }
}

fn map_client_error(err: ClientError) -> TokenMapError {
    match err {
        ClientError::RestClientError { source } => TokenMapError::Unavailable(format!("{source}")),
        ClientError::RestClientBuildError { source } => {
            TokenMapError::Unavailable(source.to_string())
        }
        ClientError::ResponseEmptyError => {
            TokenMapError::Unavailable("empty response from vault".to_string())
        }
        other => TokenMapError::Backend(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cas_backoff_grows_and_stays_small() {
        for attempt in 1..=PUT_CAS_ATTEMPTS {
            let d = cas_backoff(attempt);
            assert!(d >= Duration::from_millis(5));
            assert!(d < Duration::from_millis(200));
        }
    }

    #[test]
    fn kubernetes_token_cache_ttl_never_exceeds_a_positive_lease() {
        assert_eq!(kubernetes_token_cache_ttl(3600), Duration::from_secs(2880));
        assert_eq!(kubernetes_token_cache_ttl(20), Duration::from_secs(16));
        assert_eq!(kubernetes_token_cache_ttl(1), Duration::from_secs(1));
        assert_eq!(kubernetes_token_cache_ttl(0), Duration::from_secs(3600));
        for lease in [1_u64, 5, 20, 30, 60, 3600] {
            assert!(
                kubernetes_token_cache_ttl(lease) <= Duration::from_secs(lease),
                "cache ttl must be <= lease {lease}"
            );
        }
    }

    #[test]
    fn refuses_external_secrets_role() {
        let settings = VaultSettings {
            backend: crate::config::VaultBackend::VaultKv2,
            address: Some("http://127.0.0.1:8200".into()),
            auth: VaultAuthMethod::Kubernetes,
            kubernetes_role: Some("external-secrets".into()),
            ..VaultSettings::default()
        };
        let err = Kv2Store::from_settings(&settings).unwrap_err();
        assert!(err.to_string().contains("external-secrets"), "{err}");
    }
}
