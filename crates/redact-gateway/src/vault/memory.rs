// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Process-local token map.
//!
//! # Operational caveats
//!
//! This backend keeps sealed mappings in the address space of a single gateway
//! process. Tokens minted on one replica cannot be restored by another, and
//! everything is lost on restart. Use it for development and single-node
//! testing only; production multi-replica deployments should use the KV v2
//! backend.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;

use super::{
    merge_mappings, register_direct_predecessor, session_path, subject_closure, CredentialLineage,
    LineagePersistError, TenantLineageGraph, TokenMapError, TokenMapStore,
};
use crate::redact::token::TokenMapping;

/// One session's sealed mappings and when they should disappear.
#[derive(Debug, Clone)]
struct SessionEntry {
    mappings: Vec<TokenMapping>,
    expires_at: DateTime<Utc>,
}

/// In-memory [`TokenMapStore`] with lazy TTL expiry.
///
/// Expired entries are treated as absent and purged on the next access that
/// touches their key. There is no background sweeper.
pub struct MemoryStore {
    ttl: Duration,
    entries: RwLock<HashMap<String, SessionEntry>>,
    /// Tenant → predecessor graph. One lock serializes predecessor register.
    lineage: RwLock<HashMap<String, TenantLineageGraph>>,
    /// Optional clock override so expiry can be tested without sleeping.
    now: RwLock<Option<DateTime<Utc>>>,
}

impl std::fmt::Debug for MemoryStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryStore")
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

impl MemoryStore {
    /// Create a store whose entries live for `ttl_secs` after the last write.
    pub fn new(ttl_secs: u64) -> Self {
        Self::with_ttl(Duration::from_secs(ttl_secs))
    }

    /// Create a store with an explicit TTL duration.
    ///
    /// Prefer this in tests when a sub-second TTL is needed.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: RwLock::new(HashMap::new()),
            lineage: RwLock::new(HashMap::new()),
            now: RwLock::new(None),
        }
    }

    /// Override the clock used for expiry decisions.
    ///
    /// Intended for tests so TTL behaviour can be asserted without sleeping.
    pub async fn set_now_for_test(&self, now: DateTime<Utc>) {
        *self.now.write().await = Some(now);
    }

    /// Clear any test clock override.
    pub async fn clear_now_for_test(&self) {
        *self.now.write().await = None;
    }

    async fn current_time(&self) -> DateTime<Utc> {
        self.now.read().await.unwrap_or_else(Utc::now)
    }

    fn key(tenant: &str, session: &str) -> String {
        // Fixed synthetic prefix keeps keys aligned with session_path sanitization.
        session_path("_", tenant, session)
    }

    fn lineage_tenant_key(tenant: &str) -> String {
        tenant.to_string()
    }
}

#[async_trait::async_trait]
impl TokenMapStore for MemoryStore {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    async fn put(
        &self,
        tenant: &str,
        session: &str,
        mappings: &[TokenMapping],
    ) -> Result<(), TokenMapError> {
        let key = Self::key(tenant, session);
        let now = self.current_time().await;
        let expires_at = now
            + chrono::Duration::from_std(self.ttl)
                .map_err(|e| TokenMapError::Backend(format!("invalid TTL {:?}: {e}", self.ttl)))?;

        let mut guard = self.entries.write().await;
        if let Some(entry) = guard.get(&key) {
            if entry.expires_at <= now {
                guard.remove(&key);
            }
        }

        // Clone first so a merge conflict leaves the incumbent mappings intact.
        let existing = guard
            .get(&key)
            .map(|entry| entry.mappings.clone())
            .unwrap_or_default();
        let merged = merge_mappings(existing, mappings)?;
        guard.insert(
            key,
            SessionEntry {
                mappings: merged,
                expires_at,
            },
        );
        Ok(())
    }

    async fn get(&self, tenant: &str, session: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        let key = Self::key(tenant, session);
        let now = self.current_time().await;
        let mut guard = self.entries.write().await;
        match guard.get(&key) {
            Some(entry) if entry.expires_at > now => Ok(entry.mappings.clone()),
            Some(_) => {
                guard.remove(&key);
                Ok(Vec::new())
            }
            None => Ok(Vec::new()),
        }
    }

    async fn exists(&self, tenant: &str, session: &str) -> Result<bool, TokenMapError> {
        Ok(!self.get(tenant, session).await?.is_empty())
    }

    async fn delete(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        let key = Self::key(tenant, session);
        self.entries.write().await.remove(&key);
        Ok(())
    }

    async fn get_lineage(
        &self,
        tenant: &str,
        subject: &str,
    ) -> Result<CredentialLineage, TokenMapError> {
        let tenant_key = Self::lineage_tenant_key(tenant);
        let guard = self.lineage.read().await;
        let Some(graph) = guard.get(&tenant_key) else {
            return Ok(CredentialLineage::default());
        };
        let revision = graph
            .subjects
            .get(subject)
            .map(|row| row.revision)
            .unwrap_or(0);
        let predecessors = subject_closure(graph, subject)
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
        let tenant_key = Self::lineage_tenant_key(tenant);
        let mut guard = self.lineage.write().await;
        guard
            .entry(tenant_key)
            .or_default()
            .subjects
            .insert(subject.to_string(), lineage.clone());
        Ok(())
    }

    async fn register_predecessor(
        &self,
        tenant: &str,
        current_subject: &str,
        previous_subject: &str,
    ) -> Result<CredentialLineage, LineagePersistError> {
        let tenant_key = Self::lineage_tenant_key(tenant);
        let mut guard = self.lineage.write().await;
        let graph = guard.entry(tenant_key).or_default();
        Ok(register_direct_predecessor(
            graph,
            current_subject,
            previous_subject,
        )?)
    }

    async fn health(&self) -> Result<(), TokenMapError> {
        Ok(())
    }
}
