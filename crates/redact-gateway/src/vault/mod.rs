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

use std::collections::BTreeMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

    /// Two writers minted the same token label for different plaintexts.
    #[error("token map conflict: {0}")]
    Conflict(String),

    /// Tokenization persistence is intentionally disabled.
    #[error("token map is disabled")]
    Disabled,
}

/// Maximum number of predecessor subjects stored for one credential.
pub const MAX_PREDECESSOR_SUBJECTS: usize = 32;

/// Durable predecessor subjects for one authenticated credential.
///
/// Persistence follows the token-map backend: process-local for `memory`
/// (lost on restart; suitable for tests), KV v2 for `vault_kv2` (survives
/// restart), and unavailable when the backend is `off`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLineage {
    /// Predecessor subject identifiers, oldest-link first, already transitive.
    #[serde(default)]
    pub predecessors: Vec<String>,
    /// Monotonic revision incremented on each successful register.
    #[serde(default)]
    pub revision: u64,
}

/// Why a predecessor register was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LineageRegisterError {
    /// Current and previous subjects are the same credential.
    #[error("a credential cannot be its own predecessor")]
    SelfLink,
    /// The previous chain already includes the current subject.
    #[error("predecessor chain would create a cycle")]
    Cycle,
    /// Deduped transitive list would exceed [`MAX_PREDECESSOR_SUBJECTS`].
    #[error("predecessor chain exceeds the stored bound")]
    BoundExceeded,
}

/// Failure from [`TokenMapStore::register_predecessor`].
#[derive(Debug, thiserror::Error)]
pub enum LineagePersistError {
    /// The composed graph is invalid.
    #[error(transparent)]
    Register(#[from] LineageRegisterError),
    /// The token-map backend could not load or persist lineage.
    #[error(transparent)]
    Store(#[from] TokenMapError),
}

/// Tenant-scoped predecessor graph stored as one KV record.
///
/// One document per tenant lets register CAS-serialize concurrent rotations
/// and reject cross-record cycles. Subject identifiers live in the payload,
/// never in the storage path.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantLineageGraph {
    /// Lineage keyed by authenticated subject.
    #[serde(default)]
    pub subjects: BTreeMap<String, CredentialLineage>,
}

/// Walk the tenant graph from `subject` along stored **direct** edges.
///
/// The result is a bounded, cycle-checked transitive closure. `subject` is
/// never included. A cycle back to `subject` is [`LineageRegisterError::Cycle`].
pub fn subject_closure(
    graph: &TenantLineageGraph,
    subject: &str,
) -> Result<Vec<String>, LineageRegisterError> {
    let mut predecessors = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut queue: std::collections::VecDeque<String> = graph
        .subjects
        .get(subject)
        .map(|row| row.predecessors.iter().cloned().collect())
        .unwrap_or_default();

    while let Some(next) = queue.pop_front() {
        if next == subject {
            return Err(LineageRegisterError::Cycle);
        }
        if !seen.insert(next.clone()) {
            continue;
        }
        predecessors.push(next.clone());
        if predecessors.len() > MAX_PREDECESSOR_SUBJECTS {
            return Err(LineageRegisterError::BoundExceeded);
        }
        if let Some(row) = graph.subjects.get(&next) {
            queue.extend(row.predecessors.iter().cloned());
        }
    }
    Ok(predecessors)
}

/// Record a direct predecessor edge and return the current subject's closure.
///
/// Ancestors keep their own direct edges; erase/verify recompute the full
/// closure so `A→B` then `B→C` still covers `C` when erasing as `A`.
pub fn register_direct_predecessor(
    graph: &mut TenantLineageGraph,
    current_subject: &str,
    previous_subject: &str,
) -> Result<CredentialLineage, LineageRegisterError> {
    if current_subject == previous_subject {
        return Err(LineageRegisterError::SelfLink);
    }
    if subject_closure(graph, previous_subject)?
        .iter()
        .any(|subject| subject == current_subject)
    {
        return Err(LineageRegisterError::Cycle);
    }

    let current = graph
        .subjects
        .entry(current_subject.to_string())
        .or_default();
    if !current.predecessors.iter().any(|s| s == previous_subject) {
        current.predecessors.push(previous_subject.to_string());
    }
    current.revision = current.revision.saturating_add(1);
    let revision = current.revision;
    let predecessors = subject_closure(graph, current_subject)?;
    Ok(CredentialLineage {
        predecessors,
        revision,
    })
}

/// Build the lineage stored for `current_subject` after proving `previous_subject`.
///
/// The stored list is `[previous] + predecessors(previous) + existing`,
/// deduped with order preserved. `current_subject` is never stored in its
/// own predecessor list.
pub fn compose_predecessor_lineage(
    current_subject: &str,
    current: &CredentialLineage,
    previous_subject: &str,
    previous: &CredentialLineage,
) -> Result<CredentialLineage, LineageRegisterError> {
    if current_subject == previous_subject {
        return Err(LineageRegisterError::SelfLink);
    }

    let mut predecessors =
        Vec::with_capacity(1 + previous.predecessors.len() + current.predecessors.len());
    predecessors.push(previous_subject.to_string());
    predecessors.extend(previous.predecessors.iter().cloned());
    predecessors.extend(current.predecessors.iter().cloned());

    let mut seen = std::collections::HashSet::new();
    predecessors.retain(|subject| seen.insert(subject.clone()));

    if predecessors
        .iter()
        .any(|subject| subject == current_subject)
    {
        return Err(LineageRegisterError::Cycle);
    }
    if predecessors.len() > MAX_PREDECESSOR_SUBJECTS {
        return Err(LineageRegisterError::BoundExceeded);
    }

    Ok(CredentialLineage {
        predecessors,
        revision: current.revision.saturating_add(1),
    })
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

    /// Permanently forget a session, including every stored version.
    ///
    /// Memory backends hard-delete the map. KV v2 backends delete metadata and
    /// all versions (not `delete_latest`). The off backend returns
    /// [`TokenMapError::Disabled`]. The default implementation delegates to
    /// [`Self::delete`].
    async fn purge(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        self.delete(tenant, session).await
    }

    /// Whether any backend record still exists for this session.
    ///
    /// Memory treats an unexpired entry as present. KV v2 queries **metadata**
    /// (not the live mapping list) so expired or soft-deleted versions still
    /// count as present until [`Self::purge`]. The default implementation
    /// falls back to a non-empty [`Self::get`].
    async fn exists(&self, tenant: &str, session: &str) -> Result<bool, TokenMapError> {
        Ok(!self.get(tenant, session).await?.is_empty())
    }

    /// Load the predecessor lineage for an authenticated subject.
    ///
    /// Missing entries are an empty lineage (revision 0). The off backend
    /// returns [`TokenMapError::Disabled`].
    async fn get_lineage(
        &self,
        tenant: &str,
        subject: &str,
    ) -> Result<CredentialLineage, TokenMapError>;

    /// Persist the predecessor lineage for an authenticated subject.
    async fn put_lineage(
        &self,
        tenant: &str,
        subject: &str,
        lineage: &CredentialLineage,
    ) -> Result<(), TokenMapError>;

    /// Atomically record that `current_subject` succeeds `previous_subject`.
    ///
    /// Implementations must serialize concurrent registrations for the same
    /// tenant (memory write lock or KV v2 CAS on the tenant graph) so a lost
    /// update cannot drop a predecessor from the erase closure.
    async fn register_predecessor(
        &self,
        tenant: &str,
        current_subject: &str,
        previous_subject: &str,
    ) -> Result<CredentialLineage, LineagePersistError> {
        let current = self.get_lineage(tenant, current_subject).await?;
        let previous = self.get_lineage(tenant, previous_subject).await?;
        let composed =
            compose_predecessor_lineage(current_subject, &current, previous_subject, &previous)?;
        self.put_lineage(tenant, current_subject, &composed).await?;
        Ok(composed)
    }

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

    async fn exists(&self, _tenant: &str, _session: &str) -> Result<bool, TokenMapError> {
        Err(TokenMapError::Disabled)
    }

    async fn get_lineage(
        &self,
        _tenant: &str,
        _subject: &str,
    ) -> Result<CredentialLineage, TokenMapError> {
        Err(TokenMapError::Disabled)
    }

    async fn put_lineage(
        &self,
        _tenant: &str,
        _subject: &str,
        _lineage: &CredentialLineage,
    ) -> Result<(), TokenMapError> {
        Err(TokenMapError::Disabled)
    }

    async fn register_predecessor(
        &self,
        _tenant: &str,
        _current_subject: &str,
        _previous_subject: &str,
    ) -> Result<CredentialLineage, LineagePersistError> {
        Err(TokenMapError::Disabled.into())
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

/// Build the storage path for a tenant's predecessor graph.
///
/// Uses a `_lineage` segment under `prefix` so lineage keys cannot collide
/// with session maps at `{prefix}/{tenant}/{session}`. The authenticated
/// subject is not placed in the path (OpenBao/Vault audit logs the URL).
pub fn lineage_tenant_path(prefix: &str, tenant: &str) -> String {
    let prefix = prefix.trim_matches('/');
    format!(
        "{}/_lineage/{}/graph",
        prefix,
        sanitize_path_segment(tenant)
    )
}

/// Hex SHA-256 of a credential subject for logs or leftover path segments.
pub fn subject_path_digest(subject: &str) -> String {
    Sha256::digest(subject.as_bytes())
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Merge `incoming` into `existing`.
///
/// The first writer to mint a token label owns it. When the same token appears
/// with a different sealed value, return [`TokenMapError::Conflict`] so the
/// losing request fails closed instead of persisting a local mapping that can
/// never be resumed correctly.
pub(crate) fn merge_mappings(
    existing: Vec<TokenMapping>,
    incoming: &[TokenMapping],
) -> Result<Vec<TokenMapping>, TokenMapError> {
    let mut by_token = std::collections::HashMap::with_capacity(existing.len() + incoming.len());
    for mapping in existing {
        by_token.insert(mapping.token.clone(), mapping);
    }
    for mapping in incoming {
        match by_token.get(&mapping.token) {
            Some(prior) if prior.sealed_value != mapping.sealed_value => {
                return Err(TokenMapError::Conflict(format!(
                    "token label {} was minted concurrently for a different value",
                    mapping.token
                )));
            }
            Some(prior) if prior.sealed_value == mapping.sealed_value => {}
            _ => {
                by_token.insert(mapping.token.clone(), mapping.clone());
            }
        }
    }
    Ok(by_token.into_values().collect())
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
        assert_eq!(
            lineage_tenant_path("redact-gateway", "acme"),
            "redact-gateway/_lineage/acme/graph"
        );
        assert_ne!(
            lineage_tenant_path("p", "acme"),
            session_path("p", "_lineage", "acme")
        );
        let digest = subject_path_digest("user@example.com");
        assert_eq!(digest.len(), 64);
        assert!(!digest.contains('@'));
        assert!(!digest.contains("example.com"));
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
    fn merge_rejects_token_collision_with_different_sealed_values() {
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
        let err = merge_mappings(existing, &incoming).unwrap_err();
        assert!(matches!(err, TokenMapError::Conflict(_)), "{err:?}");
    }

    #[test]
    fn merge_accepts_identical_sealed_values_for_same_token() {
        let existing = vec![TokenMapping {
            token: "[EMAIL_ADDRESS_1]".into(),
            entity_type: "EMAIL_ADDRESS".into(),
            sealed_value: "seal-a".into(),
            created_at: chrono::Utc::now(),
        }];
        let incoming = [TokenMapping {
            token: "[EMAIL_ADDRESS_1]".into(),
            entity_type: "EMAIL_ADDRESS".into(),
            sealed_value: "seal-a".into(),
            created_at: chrono::Utc::now(),
        }];
        let merged = merge_mappings(existing, &incoming).unwrap();
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
        assert!(matches!(
            store.purge("t", "s").await,
            Err(TokenMapError::Disabled)
        ));
        assert!(matches!(
            store.exists("t", "s").await,
            Err(TokenMapError::Disabled)
        ));
        assert!(matches!(
            store.get_lineage("t", "sub").await,
            Err(TokenMapError::Disabled)
        ));
        assert!(matches!(
            store
                .put_lineage("t", "sub", &CredentialLineage::default())
                .await,
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

    #[test]
    fn compose_lineage_is_transitive_and_rejects_cycles() {
        let previous = CredentialLineage {
            predecessors: vec!["caller-c".into()],
            revision: 1,
        };
        let composed = compose_predecessor_lineage(
            "caller-a",
            &CredentialLineage::default(),
            "caller-b",
            &previous,
        )
        .unwrap();
        assert_eq!(composed.predecessors, vec!["caller-b", "caller-c"]);
        assert_eq!(composed.revision, 1);

        let mut graph = TenantLineageGraph::default();
        let first = register_direct_predecessor(&mut graph, "caller-a", "caller-b").unwrap();
        assert_eq!(first.predecessors, vec!["caller-b"]);
        let mid = register_direct_predecessor(&mut graph, "caller-b", "caller-c").unwrap();
        assert_eq!(mid.predecessors, vec!["caller-c"]);
        assert_eq!(
            subject_closure(&graph, "caller-a").unwrap(),
            vec!["caller-b", "caller-c"]
        );

        assert_eq!(
            compose_predecessor_lineage(
                "caller-a",
                &CredentialLineage::default(),
                "caller-a",
                &CredentialLineage::default(),
            ),
            Err(LineageRegisterError::SelfLink)
        );

        let looping = CredentialLineage {
            predecessors: vec!["caller-a".into()],
            revision: 1,
        };
        assert_eq!(
            compose_predecessor_lineage(
                "caller-a",
                &CredentialLineage::default(),
                "caller-b",
                &looping,
            ),
            Err(LineageRegisterError::Cycle)
        );
    }
}
