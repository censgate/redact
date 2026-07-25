// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! KV version 2 token-map backend.
//!
//! This backend speaks the HashiCorp Vault KV v2 HTTP API and therefore works
//! with both HashiCorp Vault and OpenBao. The configured auth token is treated
//! as an opaque bearer string (`X-Vault-Token`), so both `hvs.*` Vault tokens
//! and OpenBao token formats are accepted without special handling.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use vaultrs::client::{Client, VaultClient, VaultClientSettingsBuilder};
use vaultrs::error::ClientError;
use vaultrs::kv2;

use super::{merge_mappings, session_path, TokenMapError, TokenMapStore};
use crate::config::VaultSettings;
use crate::redact::token::TokenMapping;

/// Payload written under each session path.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredSession {
    mappings: Vec<TokenMapping>,
    expires_at: DateTime<Utc>,
}

/// Token map backed by a Vault / OpenBao KV v2 mount.
pub struct Kv2Store {
    client: VaultClient,
    mount: String,
    path_prefix: String,
    ttl_secs: u64,
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
        let token = settings.token.clone().unwrap_or_default();

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
            client,
            mount: settings.mount.clone(),
            path_prefix: settings.path_prefix.clone(),
            ttl_secs: settings.ttl_secs,
        })
    }

    fn path(&self, tenant: &str, session: &str) -> String {
        session_path(&self.path_prefix, tenant, session)
    }

    async fn read_entry(&self, path: &str) -> Result<Option<StoredSession>, TokenMapError> {
        match kv2::read::<StoredSession>(&self.client, &self.mount, path).await {
            Ok(entry) => {
                if entry.expires_at <= Utc::now() {
                    // Best-effort purge; absence is what callers observe.
                    let _ = kv2::delete_latest(&self.client, &self.mount, path).await;
                    Ok(None)
                } else {
                    Ok(Some(entry))
                }
            }
            Err(ClientError::APIError { code: 404, .. }) => Ok(None),
            Err(err) => Err(map_client_error(err)),
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
        let path = self.path(tenant, session);
        let existing = self
            .read_entry(&path)
            .await?
            .map(|entry| entry.mappings)
            .unwrap_or_default();
        let merged = merge_mappings(existing, mappings);
        let payload = StoredSession {
            mappings: merged,
            expires_at: Utc::now() + chrono::Duration::seconds(self.ttl_secs as i64),
        };
        kv2::set(&self.client, &self.mount, &path, &payload)
            .await
            .map_err(map_client_error)?;
        Ok(())
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
        match kv2::delete_latest(&self.client, &self.mount, &path).await {
            Ok(()) => Ok(()),
            Err(ClientError::APIError { code: 404, .. }) => Ok(()),
            Err(err) => Err(map_client_error(err)),
        }
    }

    async fn health(&self) -> Result<(), TokenMapError> {
        match self.client.status().await {
            Ok(_) => Ok(()),
            Err(err) => Err(TokenMapError::Unavailable(err.to_string())),
        }
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
