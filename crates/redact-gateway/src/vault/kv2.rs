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

use super::{merge_mappings, session_path, TokenMapError, TokenMapStore};
use crate::config::{VaultAuthMethod, VaultSettings};
use crate::redact::token::TokenMapping;

/// Maximum read→merge→CAS-write attempts before surfacing a conflict.
const PUT_CAS_ATTEMPTS: u32 = 8;
/// Cache OpenBao reachability so `/readyz` does not serialize on the leader.
const HEALTH_CACHE_TTL: Duration = Duration::from_secs(2);

/// Payload written under each session path.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
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
            health: Mutex::new(None),
        })
    }

    fn path(&self, tenant: &str, session: &str) -> String {
        session_path(&self.path_prefix, tenant, session)
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
                Err(ClientError::APIError { code: 404, .. }) => return Ok((Vec::new(), 0)),
                Err(err) => return Err(map_client_error(err)),
            };

        let cas = version_to_cas(response.metadata.version)?;
        let entry: StoredSession = serde_json::value::from_value(response.data)
            .map_err(|e| TokenMapError::Backend(format!("invalid vault session payload: {e}")))?;

        if entry.expires_at <= Utc::now() {
            Ok((Vec::new(), cas))
        } else {
            Ok((entry.mappings, cas))
        }
    }
}

#[async_trait::async_trait]
impl TokenMapStore for Kv2Store {
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

    async fn delete(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        let path = self.path(tenant, session);
        self.ensure_fresh_token().await?;
        let inner = self.inner.read().await;
        match kv2::delete_latest(&inner.client, &self.mount, &path).await {
            Ok(()) => Ok(()),
            Err(ClientError::APIError { code: 404, .. }) => Ok(()),
            Err(err) => Err(map_client_error(err)),
        }
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
            match inner.client.status().await {
                Ok(_) => Ok(()),
                Err(err) => Err(err.to_string()),
            }
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
