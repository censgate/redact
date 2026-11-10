// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! KV version 2 token-map backend.
//!
//! This backend speaks the HashiCorp Vault KV v2 HTTP API and therefore works
//! with both HashiCorp Vault and OpenBao. Auth is either a static bearer token
//! (`X-Vault-Token`, local-dev) or Kubernetes auth against `openbao-tokens`
//! (required for n-replica HPA). The ESO `external-secrets` role must never be
//! used here.
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

pub use super::pruned::{
    check_context_epoch, prove_pruned_identity, pruned_evidence_digest, PathFingerprint,
    PrunedEvidence, PrunedHistoryPolicy, PrunedProof, PrunedRejection, PrunedVersion,
    BETA_MIGRATION_IDENTITY_EPOCH,
};

/// Maximum read→merge→CAS-write attempts before surfacing a conflict.
const PUT_CAS_ATTEMPTS: u32 = 8;
/// Maximum retained legacy versions a first-access import will read and compare.
/// Bounds the work of one request. This limits the *retained* suffix, not the
/// lifetime version counter: a mount that prunes to `max_versions` can carry a
/// context whose counter is far larger than this bound.
const MAX_RETAINED_LEGACY_VERSIONS: usize = 2048;

/// Guards applied to legacy KV v2 history before first-access import.
///
/// The default rejects pruned history and checks up to 2,048 retained versions.
/// Pruned imports require scoped evidence and a live identity proof.
/// Already-frozen snapshots are returned idempotently and
/// are not revalidated against this policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyHistoryPolicy {
    /// Missing history is rejected unless its identity can be proven.
    pub pruned: PrunedHistoryPolicy,
    /// Maximum retained versions to verify, for both complete and pruned history.
    pub max_retained_versions: usize,
}

impl Default for LegacyHistoryPolicy {
    fn default() -> Self {
        Self {
            pruned: PrunedHistoryPolicy::Reject,
            max_retained_versions: MAX_RETAINED_LEGACY_VERSIONS,
        }
    }
}

/// Structured event name for a proven pruned legacy import.
pub const PRUNED_IMPORT_EVENT: &str = "token_store_legacy_pruned_import";
/// OpenTelemetry counter for proven pruned legacy imports.
pub const PRUNED_IMPORT_METRIC: &str = "redact.gateway.tokenstore.legacy.pruned_imports";
/// Structured event for a rejected pruned identity proof.
pub const PRUNED_REJECTION_EVENT: &str = "token_store_legacy_pruned_rejected";
/// OpenTelemetry counter for rejected pruned identity proofs, by bounded reason.
pub const PRUNED_REJECTION_METRIC: &str = "redact.gateway.tokenstore.legacy.pruned_rejections";
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
    history_policy: LegacyHistoryPolicy,
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
        let mut history_policy = LegacyHistoryPolicy::default();
        if let Some(settings) = &settings.legacy_pruned_history {
            history_policy.pruned = PrunedHistoryPolicy::Proven(PrunedProof {
                evidence: PrunedEvidence::load(
                    &settings.evidence_file,
                    &settings.evidence_sha256,
                    Utc::now(),
                )?,
            });
        }
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
                         bind a dedicated redact-gateway role on openbao-tokens"
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
            history_policy,
            health: Mutex::new(None),
        })
    }

    /// Set the guards used to verify legacy history before it is frozen.
    /// This does not revalidate a snapshot that another caller already froze.
    pub fn with_history_policy(mut self, policy: LegacyHistoryPolicy) -> Self {
        self.history_policy = policy;
        self
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

    /// Verify the legacy KV v2 history before it is frozen for import.
    ///
    /// The latest version (`entry`, written at `cas`) is the only import
    /// source. Every retained version must be a subset of it. Missing history
    /// requires both a pinned operator attestation and the live metadata/TTL
    /// proof; a cumulative retained tail alone cannot exclude expiry resets.
    async fn verify_legacy_history(
        &self,
        path: &str,
        cas: u32,
        entry: &StoredSession,
    ) -> Result<HistoryCheck, TokenMapError> {
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        let metadata = kv2::read_metadata(&inner.client, &self.mount, path)
            .await
            .map_err(map_client_error)?;
        let is_pruned = metadata.oldest_version > 1
            || metadata
                .versions
                .keys()
                .filter_map(|v| v.parse::<u64>().ok())
                .min()
                .is_some_and(|v| v > 1);
        // With evidence configured, a key generation before the attested epoch
        // cannot be trusted even when its history is complete: the previous
        // gateway's writes in that window went to a store that was not carried
        // over. Without evidence there is no epoch and behavior is unchanged.
        if let (false, Some(epoch)) = (is_pruned, self.history_policy.pruned.identity_epoch()) {
            check_context_epoch(epoch, &metadata.created_time).map_err(|reason| {
                record_pruned_rejection(reason);
                TokenMapError::Indexed(redact_token_store::Error::Integrity)
            })?;
        }
        let pruned_proof = match &self.history_policy.pruned {
            PrunedHistoryPolicy::Proven(proof) if is_pruned => Some(proof),
            _ => None,
        };
        let integrity = || {
            if pruned_proof.is_some() {
                record_pruned_rejection(PrunedRejection::InvalidHistory);
            }
            TokenMapError::Indexed(redact_token_store::Error::Integrity)
        };
        let (oldest, retained) = match classify_retained_history(
            cas,
            metadata.current_version,
            metadata.oldest_version,
            &metadata.versions,
            &self.history_policy,
            Utc::now(),
        ) {
            RetainedHistory::Stale => return Ok(HistoryCheck::Stale),
            RetainedHistory::Invalid => return Err(integrity()),
            RetainedHistory::Contiguous { oldest, retained } => (oldest, retained),
        };
        let current: std::collections::HashMap<_, _> =
            entry.mappings.iter().map(|m| (&m.token, m)).collect();
        let mut proof_versions = Vec::with_capacity(retained);
        for version in oldest..u64::from(cas) {
            let previous: StoredSession =
                match kv2::read_version(&inner.client, &self.mount, path, version).await {
                    Ok(previous) => previous,
                    Err(err) => {
                        // A put or a peer freeze/cleanup can advance the key and
                        // prune this version after the metadata read. Retry the
                        // whole snapshot instead of failing a valid new suffix.
                        let metadata = kv2::read_metadata(&inner.client, &self.mount, path)
                            .await
                            .map_err(map_client_error)?;
                        if metadata.current_version > u64::from(cas) {
                            return Ok(HistoryCheck::Stale);
                        }
                        return Err(if pruned_proof.is_some() {
                            integrity()
                        } else {
                            map_client_error(err)
                        });
                    }
                };
            // Only an erasure fence or a freeze writes `frozen`, and both stop
            // later legacy puts. A frozen version under a live latest is not
            // legacy history.
            if previous.frozen {
                return Err(integrity());
            }
            // Tail consistency is necessary but cannot prove the missing prefix.
            if previous.mappings.iter().any(|old| {
                current.get(&old.token).is_none_or(|new| {
                    new.entity_type != old.entity_type || new.sealed_value != old.sealed_value
                })
            }) {
                return Err(integrity());
            }
            if pruned_proof.is_some() {
                proof_versions.push(PrunedVersion {
                    created_time: metadata
                        .versions
                        .get(&version.to_string())
                        .ok_or_else(integrity)?
                        .created_time
                        .clone(),
                    expires_at: previous.expires_at,
                });
            }
        }
        if let Some(proof) = pruned_proof {
            proof_versions.push(PrunedVersion {
                created_time: metadata
                    .versions
                    .get(&cas.to_string())
                    .ok_or_else(integrity)?
                    .created_time
                    .clone(),
                expires_at: entry.expires_at,
            });
            let live = PathFingerprint {
                current_version: metadata.current_version,
                oldest_version: metadata.oldest_version,
                key_created_time: metadata.created_time.clone(),
                updated_time: metadata.updated_time.clone(),
            };
            prove_pruned_identity(
                &proof.evidence,
                &pruned_evidence_digest(path),
                &live,
                &proof_versions,
                Utc::now(),
            )
            .map_err(|reason| {
                record_pruned_rejection(reason);
                TokenMapError::Indexed(redact_token_store::Error::Integrity)
            })?;
        }
        Ok(if oldest > 1 {
            HistoryCheck::Pruned {
                retained,
                oldest_retained: oldest,
            }
        } else {
            HistoryCheck::Complete
        })
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
                            Ok(metadata) => {
                                // A concurrent first writer may create data
                                // between the 404 and metadata read. Re-read
                                // once; a genuinely missing latest version still
                                // fails closed, never becoming an empty source.
                                if retry_missing {
                                    retry_missing = false;
                                    continue;
                                }
                                if metadata.oldest_version > 1
                                    && matches!(
                                        self.history_policy.pruned,
                                        PrunedHistoryPolicy::Proven(_)
                                    )
                                {
                                    record_pruned_rejection(PrunedRejection::InvalidHistory);
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
        let entry: StoredSession = match serde_json::value::from_value(response.data) {
            Ok(entry) => entry,
            Err(err) => {
                if verify_missing {
                    // Malformed/deleted latest payloads cannot bypass strict
                    // pruned rejection or its opt-in structural telemetry.
                    let metadata = kv2::read_metadata(&inner.client, &self.mount, path)
                        .await
                        .map_err(map_client_error)?;
                    if metadata.oldest_version > 1 {
                        if matches!(self.history_policy.pruned, PrunedHistoryPolicy::Proven(_)) {
                            record_pruned_rejection(PrunedRejection::InvalidHistory);
                        }
                        return Err(TokenMapError::Indexed(redact_token_store::Error::Integrity));
                    }
                }
                return Err(TokenMapError::Backend(format!(
                    "invalid vault session payload: {err}"
                )));
            }
        };

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
            // Verify complete history, or prove identity under scoped evidence
            // when the mount has pruned versions. CAS pins the verified snapshot.
            let mut pruned = None;
            if cas > 0 {
                match self.verify_legacy_history(&path, cas, &entry).await? {
                    HistoryCheck::Stale => {
                        tokio::time::sleep(cas_backoff(attempt)).await;
                        continue;
                    }
                    HistoryCheck::Complete => {}
                    HistoryCheck::Pruned {
                        retained,
                        oldest_retained,
                    } => pruned = Some((retained, oldest_retained)),
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
                    if let Some((retained, oldest_retained)) = pruned {
                        record_pruned_import(cas, retained, oldest_retained);
                    }
                    return Ok(super::FrozenSnapshot {
                        mappings: entry.mappings,
                        expires_ms: entry.expires_at.timestamp_millis(),
                    });
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
                self.ensure_fresh_token().await?;
                let inner = self.inner.read().await;
                // Versions the mount already pruned cannot be destroyed; skip
                // them so a long-lived pruned context finishes in few calls.
                let first_retained =
                    match kv2::read_metadata(&inner.client, &self.mount, &path).await {
                        Ok(metadata) => metadata
                            .versions
                            .keys()
                            .filter_map(|v| v.parse::<u64>().ok())
                            .min()
                            .unwrap_or(1),
                        Err(err) => return Err(map_client_error(err)),
                    };
                let (end, versions) = retained_cleanup_batch(
                    entry.destroyed_through,
                    entry.cleanup_through,
                    first_retained,
                );
                // With max_versions=1 even the last ciphertext-bearing version
                // can be pruned by the empty fence. OpenBao rejects an empty
                // destroy request; persist the completed cutoff directly.
                if !versions.is_empty() {
                    kv2::destroy_versions(&inner.client, &self.mount, &path, versions)
                        .await
                        .map_err(map_client_error)?;
                }
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

/// Outcome of the legacy history verification.
enum HistoryCheck {
    /// The full history from version 1 was retained and consistent.
    Complete,
    /// Earlier versions were pruned; the retained suffix was consistent.
    Pruned {
        retained: usize,
        oldest_retained: u64,
    },
    /// A writer advanced the secret between the read and the metadata read.
    Stale,
}

/// Result of inspecting KV v2 version metadata only (no payload reads).
#[derive(Debug, PartialEq, Eq)]
enum RetainedHistory {
    /// Retained versions `oldest..=cas` are contiguous, readable and live.
    Contiguous { oldest: u64, retained: usize },
    /// The metadata describes a different current version than the payload read.
    Stale,
    /// A gap, a deleted or destroyed version, or inconsistent metadata.
    Invalid,
}

/// Classify retained-version metadata. Content-free: it never sees payloads.
fn classify_retained_history(
    cas: u32,
    current_version: u64,
    oldest_version: u64,
    versions: &std::collections::HashMap<String, vaultrs::api::kv2::responses::SecretMetadata>,
    policy: &LegacyHistoryPolicy,
    now: DateTime<Utc>,
) -> RetainedHistory {
    let cas = u64::from(cas);
    if current_version != cas {
        // Newer than our payload read: the CAS write below would lose anyway.
        return if current_version > cas {
            RetainedHistory::Stale
        } else {
            RetainedHistory::Invalid
        };
    }
    if versions.is_empty() || versions.len() > policy.max_retained_versions {
        return RetainedHistory::Invalid;
    }
    let mut keys = Vec::with_capacity(versions.len());
    for (key, details) in versions {
        let Ok(number) = key.parse::<u64>() else {
            return RetainedHistory::Invalid;
        };
        if details.destroyed {
            return RetainedHistory::Invalid;
        }
        if !details.deletion_time.is_empty() {
            match DateTime::parse_from_rfc3339(&details.deletion_time) {
                Ok(deleted_at) if deleted_at.with_timezone(&Utc) > now => {}
                _ => return RetainedHistory::Invalid,
            }
        }
        keys.push(number);
    }
    keys.sort_unstable();
    let oldest = keys[0];
    let contiguous = oldest >= 1
        && keys.last() == Some(&cas)
        && keys.windows(2).all(|pair| pair[1] == pair[0] + 1);
    // `oldest_version` is 0 on a mount that never pruned this key.
    let reported_oldest = if oldest_version == 0 {
        1
    } else {
        oldest_version
    };
    if !contiguous || reported_oldest != oldest {
        return RetainedHistory::Invalid;
    }
    if oldest > 1 && matches!(policy.pruned, PrunedHistoryPolicy::Reject) {
        return RetainedHistory::Invalid;
    }
    RetainedHistory::Contiguous {
        oldest,
        retained: keys.len(),
    }
}

/// Return the cleanup checkpoint and bounded batch after skipping pruned versions.
/// An empty batch means the cutoff is already pruned or destroyed.
fn retained_cleanup_batch(
    destroyed_through: u64,
    cleanup_through: u64,
    first_retained: u64,
) -> (u64, Vec<u64>) {
    let start = destroyed_through.max(first_retained.saturating_sub(1).min(cleanup_through));
    let end = start.saturating_add(256).min(cleanup_through);
    if start >= end {
        return (end, Vec::new());
    }
    (end, ((start + 1)..=end).collect())
}

/// Emit the non-secret evidence that a pruned legacy history was imported.
/// Carries counts only: no path, tenant, session, token or value.
fn record_pruned_import(current_version: u32, retained: usize, oldest_retained: u64) {
    static COUNTER: std::sync::OnceLock<opentelemetry::metrics::Counter<u64>> =
        std::sync::OnceLock::new();
    COUNTER
        .get_or_init(|| {
            opentelemetry::global::meter("redact-gateway")
                .u64_counter(PRUNED_IMPORT_METRIC)
                .with_description("Legacy contexts imported from a proven pruned KV v2 history")
                .with_unit("{context}")
                .build()
        })
        .add(1, &[]);
    tracing::warn!(
        event = PRUNED_IMPORT_EVENT,
        retained_versions = retained as u64,
        oldest_retained_version = oldest_retained,
        current_version = u64::from(current_version),
        "proven pruned legacy token history imported"
    );
}

/// Report only a bounded reason: no path, tenant, session, token or value.
fn record_pruned_rejection(reason: PrunedRejection) {
    static COUNTER: std::sync::OnceLock<opentelemetry::metrics::Counter<u64>> =
        std::sync::OnceLock::new();
    COUNTER
        .get_or_init(|| {
            opentelemetry::global::meter("redact-gateway")
                .u64_counter(PRUNED_REJECTION_METRIC)
                .with_description("Pruned legacy identity proofs rejected")
                .with_unit("{context}")
                .build()
        })
        .add(1, &[opentelemetry::KeyValue::new("reason", reason.code())]);
    tracing::warn!(event = PRUNED_REJECTION_EVENT, reason = reason.code());
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

    #[test]
    fn settings_load_pinned_evidence_and_refuse_startup_on_load_errors() {
        use sha2::{Digest, Sha256};

        let file = tempfile::NamedTempFile::new().unwrap();
        let PrunedHistoryPolicy::Proven(proof) = proven_policy().pruned else {
            unreachable!();
        };
        let mut document = serde_json::to_value(&proof.evidence).unwrap();
        document["schema"] = serde_json::json!("redact-legacy-pruned-evidence-v1");
        let pin = |document: &serde_json::Value| {
            let bytes = serde_json::to_vec(document).unwrap();
            std::fs::write(file.path(), &bytes).unwrap();
            Sha256::digest(&bytes)
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        };
        let mut settings = VaultSettings {
            address: Some("http://127.0.0.1:8200".into()),
            legacy_pruned_history: Some(crate::config::LegacyPrunedHistorySettings {
                evidence_file: file.path().to_path_buf(),
                evidence_sha256: pin(&document),
            }),
            ..Default::default()
        };
        let store = Kv2Store::from_settings(&settings).unwrap();
        assert_eq!(
            store.history_policy.pruned,
            PrunedHistoryPolicy::Proven(proof)
        );
        settings
            .legacy_pruned_history
            .as_mut()
            .unwrap()
            .evidence_sha256 = "0".repeat(64);
        assert!(Kv2Store::from_settings(&settings).is_err());
        document["not_after"] = serde_json::json!(Utc::now() - chrono::Duration::seconds(1));
        settings
            .legacy_pruned_history
            .as_mut()
            .unwrap()
            .evidence_sha256 = pin(&document);
        assert!(Kv2Store::from_settings(&settings).is_err());
        settings
            .legacy_pruned_history
            .as_mut()
            .unwrap()
            .evidence_file = PathBuf::from("/nonexistent/evidence");
        let error = Kv2Store::from_settings(&settings).unwrap_err().to_string();
        assert!(!error.contains("/nonexistent"));
        assert!(!error.contains("classifier-test"));
    }

    fn proven_policy() -> LegacyHistoryPolicy {
        let now = Utc::now();
        LegacyHistoryPolicy {
            pruned: PrunedHistoryPolicy::Proven(PrunedProof {
                evidence: PrunedEvidence {
                    evidence_id: "classifier-test".into(),
                    generated_at: now,
                    not_after: now + chrono::Duration::hours(1),
                    identity_epoch: now - chrono::Duration::days(1),
                    entries: Default::default(),
                },
            }),
            ..Default::default()
        }
    }

    fn meta(
        numbers: &[u64],
    ) -> std::collections::HashMap<String, vaultrs::api::kv2::responses::SecretMetadata> {
        numbers
            .iter()
            .map(|n| {
                (
                    n.to_string(),
                    vaultrs::api::kv2::responses::SecretMetadata {
                        created_time: "2026-11-09T00:00:00Z".into(),
                        deletion_time: String::new(),
                        destroyed: false,
                    },
                )
            })
            .collect()
    }

    #[test]
    fn retained_history_classifies_complete_and_opt_in_pruned_suffixes() {
        let now = Utc::now();
        let policy = proven_policy();
        assert_eq!(
            classify_retained_history(3, 3, 0, &meta(&[1, 2, 3]), &policy, now),
            RetainedHistory::Contiguous {
                oldest: 1,
                retained: 3
            }
        );
        assert_eq!(
            classify_retained_history(3, 3, 1, &meta(&[1, 2, 3]), &policy, now),
            RetainedHistory::Contiguous {
                oldest: 1,
                retained: 3
            }
        );
        // Lifetime counter far above the retained-version bound is fine.
        assert_eq!(
            classify_retained_history(
                5000,
                5000,
                4991,
                &meta(&(4991..=5000).collect::<Vec<_>>()),
                &policy,
                now
            ),
            RetainedHistory::Contiguous {
                oldest: 4991,
                retained: 10
            }
        );
        assert_eq!(
            classify_retained_history(7, 7, 7, &meta(&[7]), &policy, now),
            RetainedHistory::Contiguous {
                oldest: 7,
                retained: 1
            }
        );
    }

    #[test]
    fn retained_history_rejects_gaps_flags_and_inconsistent_metadata() {
        let now = Utc::now();
        let policy = proven_policy();
        // Gap inside the suffix.
        assert_eq!(
            classify_retained_history(5, 5, 3, &meta(&[3, 5]), &policy, now),
            RetainedHistory::Invalid
        );
        // Latest version absent from the retained set.
        assert_eq!(
            classify_retained_history(5, 5, 3, &meta(&[3, 4]), &policy, now),
            RetainedHistory::Invalid
        );
        // Reported oldest disagrees with the map, or implies an unpruned key.
        assert_eq!(
            classify_retained_history(5, 5, 2, &meta(&[3, 4, 5]), &policy, now),
            RetainedHistory::Invalid
        );
        assert_eq!(
            classify_retained_history(5, 5, 0, &meta(&[3, 4, 5]), &policy, now),
            RetainedHistory::Invalid
        );
        // Empty, non-numeric, version 0, and over-bound retained sets.
        assert_eq!(
            classify_retained_history(1, 1, 0, &meta(&[]), &policy, now),
            RetainedHistory::Invalid
        );
        let mut odd = meta(&[1]);
        odd.extend(meta(&[2]).into_values().map(|v| ("x".to_string(), v)));
        assert_eq!(
            classify_retained_history(1, 1, 0, &odd, &policy, now),
            RetainedHistory::Invalid
        );
        assert_eq!(
            classify_retained_history(
                MAX_RETAINED_LEGACY_VERSIONS as u32 + 1,
                MAX_RETAINED_LEGACY_VERSIONS as u64 + 1,
                0,
                &meta(&(1..=MAX_RETAINED_LEGACY_VERSIONS as u64 + 1).collect::<Vec<_>>()),
                &policy,
                now
            ),
            RetainedHistory::Invalid
        );
        // Destroyed, deleted, unparseable deletion time (any retained version).
        for (n, flag) in [(1_u64, "destroyed"), (2, "deleted"), (3, "malformed")] {
            let mut versions = meta(&[1, 2, 3]);
            let details = versions.get_mut(&n.to_string()).unwrap();
            match flag {
                "destroyed" => details.destroyed = true,
                "deleted" => details.deletion_time = "2020-01-01T00:00:00Z".into(),
                _ => details.deletion_time = "not-a-time".into(),
            }
            assert_eq!(
                classify_retained_history(3, 3, 0, &versions, &policy, now),
                RetainedHistory::Invalid,
                "{flag}"
            );
        }
        // A scheduled deletion in the future is still readable.
        let mut scheduled = meta(&[1, 2]);
        scheduled.get_mut("1").unwrap().deletion_time =
            (now + chrono::Duration::days(1)).to_rfc3339();
        assert!(matches!(
            classify_retained_history(2, 2, 0, &scheduled, &policy, now),
            RetainedHistory::Contiguous { .. }
        ));
    }

    #[test]
    fn retained_history_distinguishes_a_concurrent_writer_from_corruption() {
        let now = Utc::now();
        let policy = proven_policy();
        assert_eq!(
            classify_retained_history(3, 4, 2, &meta(&[2, 3, 4]), &policy, now),
            RetainedHistory::Stale
        );
        assert_eq!(
            classify_retained_history(4, 3, 1, &meta(&[1, 2, 3]), &policy, now),
            RetainedHistory::Invalid
        );
    }

    #[test]
    fn default_history_policy_rejects_pruned_suffixes_only() {
        let policy = LegacyHistoryPolicy::default();
        assert_eq!(policy.pruned, PrunedHistoryPolicy::Reject);
        let now = Utc::now();
        for oldest in [0, 1] {
            assert_eq!(
                classify_retained_history(3, 3, oldest, &meta(&[1, 2, 3]), &policy, now),
                RetainedHistory::Contiguous {
                    oldest: 1,
                    retained: 3
                }
            );
        }
        for numbers in [&[3][..], &[2, 3][..]] {
            assert_eq!(
                classify_retained_history(3, 3, numbers[0], &meta(numbers), &policy, now),
                RetainedHistory::Invalid
            );
        }
        // Retry stale snapshots first: a peer may already have frozen the key.
        assert_eq!(
            classify_retained_history(3, 4, 3, &meta(&[3, 4]), &policy, now),
            RetainedHistory::Stale
        );
    }

    #[test]
    fn maximum_retained_versions_bounds_complete_and_pruned_history() {
        let now = Utc::now();
        let policy = LegacyHistoryPolicy {
            max_retained_versions: 2,
            ..proven_policy()
        };
        for oldest in [1, 5] {
            assert_eq!(
                classify_retained_history(
                    (oldest + 1) as u32,
                    oldest + 1,
                    oldest,
                    &meta(&[oldest, oldest + 1]),
                    &policy,
                    now,
                ),
                RetainedHistory::Contiguous {
                    oldest,
                    retained: 2,
                }
            );
            assert_eq!(
                classify_retained_history(
                    (oldest + 2) as u32,
                    oldest + 2,
                    oldest,
                    &meta(&[oldest, oldest + 1, oldest + 2]),
                    &policy,
                    now,
                ),
                RetainedHistory::Invalid
            );
        }
        let reject_all = LegacyHistoryPolicy {
            max_retained_versions: 0,
            ..Default::default()
        };
        assert_eq!(
            classify_retained_history(1, 1, 0, &meta(&[1]), &reject_all, now),
            RetainedHistory::Invalid
        );
    }

    #[test]
    fn retained_history_contiguity_includes_both_endpoints() {
        let now = Utc::now();
        let policy = proven_policy();
        assert_eq!(
            classify_retained_history(1, 1, 0, &meta(&[0, 1]), &policy, now),
            RetainedHistory::Invalid
        );
        assert_eq!(
            classify_retained_history(5, 5, 3, &meta(&[3, 4, 5, 6]), &policy, now),
            RetainedHistory::Invalid
        );
        let latest = u64::from(u32::MAX);
        assert_eq!(
            classify_retained_history(
                u32::MAX,
                latest,
                latest - 1,
                &meta(&[latest - 1, latest]),
                &policy,
                now,
            ),
            RetainedHistory::Contiguous {
                oldest: latest - 1,
                retained: 2,
            }
        );
    }

    #[test]
    fn cleanup_batch_skips_pruned_versions_and_handles_a_fully_pruned_cutoff() {
        // Empty fence at 2102 leaves 2098..=2102 on a five-version mount.
        let (end, versions) = retained_cleanup_batch(0, 2101, 2098);
        assert_eq!(end, 2101);
        assert_eq!(versions, vec![2098, 2099, 2100, 2101]);
        // max_versions=1: only the empty fence at 2102 is retained. Do not
        // issue an empty destroy request; checkpoint completion instead.
        assert_eq!(retained_cleanup_batch(0, 2101, 2102), (2101, vec![]));
        assert_eq!(retained_cleanup_batch(2101, 2101, 2102), (2101, vec![]));
        // An unpruned cutoff still destroys bounded, inclusive batches and
        // resumes at the first not-yet-destroyed version.
        assert_eq!(
            retained_cleanup_batch(0, 300, 1),
            (256, (1..=256).collect())
        );
        assert_eq!(
            retained_cleanup_batch(256, 300, 1),
            (300, (257..=300).collect())
        );
    }
}
