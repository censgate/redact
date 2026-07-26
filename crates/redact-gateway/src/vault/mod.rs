// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Pluggable token-map backends.
//!
//! Mappings stored here already contain AES-256-GCM ciphertext only. Backends
//! never see plaintext original values.

pub mod memory;

#[cfg(feature = "vault")]
pub mod kv2;

use std::sync::Arc;

use crate::config::{VaultBackend, VaultSettings};
use crate::redact::token::TokenMapping;

pub use memory::MemoryStore;

#[cfg(feature = "vault")]
pub use kv2::Kv2Store;

/// Failures from a [`TokenMapStore`] backend.
#[derive(Debug, thiserror::Error)]
pub enum TokenMapError {
    /// The configured backend cannot be reached or constructed.
    #[error("token map backend is unavailable: {0}")]
    Unavailable(String),

    /// The backend rejected or failed an operation.
    #[error("token map operation failed: {0}")]
    Backend(String),

    /// Tokenization persistence is intentionally disabled.
    #[error("token map is disabled")]
    Disabled,
}

/// Persistence for sealed token mappings, keyed by tenant and session.
#[async_trait::async_trait]
pub trait TokenMapStore: Send + Sync + std::fmt::Debug {
    /// Stable backend name for telemetry attributes: `"off"`, `"memory"`, `"vault_kv2"`.
    fn backend_name(&self) -> &'static str;

    /// Persist mappings for a session, merging with anything already stored.
    async fn put(
        &self,
        tenant: &str,
        session: &str,
        mappings: &[TokenMapping],
    ) -> Result<(), TokenMapError>;

    /// Load every mapping known for a session.
    async fn get(&self, tenant: &str, session: &str) -> Result<Vec<TokenMapping>, TokenMapError>;

    /// Forget a session.
    async fn delete(&self, tenant: &str, session: &str) -> Result<(), TokenMapError>;

    /// Cheap reachability probe used by the readiness endpoint.
    async fn health(&self) -> Result<(), TokenMapError>;
}

/// No-op backend used when tokenization persistence is turned off.
#[derive(Debug, Default)]
pub struct DisabledStore;

#[async_trait::async_trait]
impl TokenMapStore for DisabledStore {
    fn backend_name(&self) -> &'static str {
        "off"
    }

    async fn put(
        &self,
        _tenant: &str,
        _session: &str,
        _mappings: &[TokenMapping],
    ) -> Result<(), TokenMapError> {
        Err(TokenMapError::Disabled)
    }

    async fn get(&self, _tenant: &str, _session: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        Err(TokenMapError::Disabled)
    }

    async fn delete(&self, _tenant: &str, _session: &str) -> Result<(), TokenMapError> {
        Err(TokenMapError::Disabled)
    }

    async fn health(&self) -> Result<(), TokenMapError> {
        Ok(())
    }
}

/// Build the token-map backend selected by `settings`.
pub async fn build_store(
    settings: &VaultSettings,
) -> Result<Arc<dyn TokenMapStore>, TokenMapError> {
    match settings.backend {
        VaultBackend::Off => Ok(Arc::new(DisabledStore)),
        VaultBackend::Memory => Ok(Arc::new(MemoryStore::new(settings.ttl_secs))),
        VaultBackend::VaultKv2 => {
            #[cfg(feature = "vault")]
            {
                Ok(Arc::new(Kv2Store::from_settings(settings)?))
            }
            #[cfg(not(feature = "vault"))]
            {
                Err(TokenMapError::Unavailable(
                    "vault_kv2 backend requires the `vault` cargo feature".to_string(),
                ))
            }
        }
    }
}

/// Build the storage path for a tenant session under `prefix`.
///
/// Tenant and session identifiers are percent-encoded so `/`, `..`, and control
/// characters cannot escape the configured prefix.
pub fn session_path(prefix: &str, tenant: &str, session: &str) -> String {
    let prefix = prefix.trim_matches('/');
    format!(
        "{}/{}/{}",
        prefix,
        sanitize_path_segment(tenant),
        sanitize_path_segment(session)
    )
}

/// Merge `incoming` into `existing`.
///
/// The first writer to mint a token label owns it: when the same token appears
/// in both sides with different sealed values, the existing mapping is kept.
/// Silent "incoming wins" would let a concurrent allocator steal an index and
/// make restore return the wrong plaintext.
pub(crate) fn merge_mappings(
    existing: Vec<TokenMapping>,
    incoming: &[TokenMapping],
) -> Vec<TokenMapping> {
    let mut by_token = std::collections::HashMap::with_capacity(existing.len() + incoming.len());
    for mapping in existing {
        by_token.insert(mapping.token.clone(), mapping);
    }
    for mapping in incoming {
        match by_token.get(&mapping.token) {
            Some(prior) if prior.sealed_value != mapping.sealed_value => {
                // Keep the incumbent. The colliding mint is dropped; the
                // caller that minted it still restored within its own request
                // via the in-memory session, but later resumes see the first writer.
            }
            _ => {
                by_token.insert(mapping.token.clone(), mapping.clone());
            }
        }
    }
    by_token.into_values().collect()
}

fn sanitize_path_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' => out.push(byte as char),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "%{byte:02X}");
            }
        }
    }
    if out.is_empty() {
        "_".to_string()
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_path_joins_sanitized_segments() {
        assert_eq!(
            session_path("redact-gateway", "acme", "chat-1"),
            "redact-gateway/acme/chat-1"
        );
        assert_eq!(
            session_path("/redact-gateway/", "acme", "chat-1"),
            "redact-gateway/acme/chat-1"
        );
    }

    #[test]
    fn session_path_blocks_parent_traversal() {
        let escaped = session_path("redact-gateway", "../other", "sess");
        assert_eq!(escaped, "redact-gateway/%2E%2E%2Fother/sess");
        assert!(!escaped.split('/').any(|seg| seg == ".."));
        assert!(!escaped.contains("/../"));
    }

    #[test]
    fn session_path_blocks_slash_in_session() {
        let escaped = session_path("redact-gateway", "tenant", "a/b");
        assert_eq!(escaped, "redact-gateway/tenant/a%2Fb");
        assert_eq!(escaped.matches('/').count(), 2);
    }

    #[test]
    fn session_path_blocks_dotdot_segment() {
        let escaped = session_path("prefix", "..", "sess");
        assert_eq!(escaped, "prefix/%2E%2E/sess");
        assert!(!escaped.split('/').any(|seg| seg == ".."));
    }

    #[test]
    fn session_path_encodes_control_characters() {
        let escaped = session_path("p", "ten\0ant", "sess\n");
        assert!(escaped.contains("%00"));
        assert!(escaped.contains("%0A"));
        assert!(!escaped.contains('\0'));
        assert!(!escaped.contains('\n'));
    }

    #[test]
    fn merge_keeps_existing_mapping_on_token_collision() {
        let existing = vec![TokenMapping {
            token: "[EMAIL_ADDRESS_1]".into(),
            entity_type: "EMAIL_ADDRESS".into(),
            sealed_value: "seal-a".into(),
            created_at: chrono::Utc::now(),
        }];
        let incoming = [TokenMapping {
            token: "[EMAIL_ADDRESS_1]".into(),
            entity_type: "EMAIL_ADDRESS".into(),
            sealed_value: "seal-b".into(),
            created_at: chrono::Utc::now(),
        }];
        let merged = merge_mappings(existing, &incoming);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].sealed_value, "seal-a");
    }

    #[tokio::test]
    async fn disabled_store_rejects_mutations_but_is_healthy() {
        let store = DisabledStore;
        assert_eq!(store.backend_name(), "off");
        assert!(matches!(
            store.put("t", "s", &[]).await,
            Err(TokenMapError::Disabled)
        ));
        assert!(matches!(
            store.get("t", "s").await,
            Err(TokenMapError::Disabled)
        ));
        assert!(matches!(
            store.delete("t", "s").await,
            Err(TokenMapError::Disabled)
        ));
        store.health().await.unwrap();
    }

    #[tokio::test]
    async fn build_store_dispatches_memory_and_off() {
        let settings = VaultSettings {
            backend: VaultBackend::Off,
            ..VaultSettings::default()
        };
        assert_eq!(build_store(&settings).await.unwrap().backend_name(), "off");

        let settings = VaultSettings {
            backend: VaultBackend::Memory,
            ..VaultSettings::default()
        };
        assert_eq!(
            build_store(&settings).await.unwrap().backend_name(),
            "memory"
        );
    }
}
