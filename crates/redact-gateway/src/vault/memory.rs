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
    map_doc_limit_from_env, map_doc_session, place_mappings, register_direct_predecessor,
    session_path, subject_closure, CredentialLineage, LineagePersistError, TenantLineageGraph,
    TokenMapError, TokenMapStore, MAP_DOC_SLOTS,
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
    map_doc_limit: usize,
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
            .field("map_doc_limit", &self.map_doc_limit)
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
        Self::with_doc_limit(ttl, map_doc_limit_from_env())
    }

    /// Create a store that opens another document after `limit` mappings.
    pub fn with_doc_limit(ttl: Duration, limit: usize) -> Self {
        Self {
            ttl,
            map_doc_limit: limit,
            entries: RwLock::new(HashMap::new()),
            lineage: RwLock::new(HashMap::new()),
            now: RwLock::new(None),
        }
    }

    fn doc_key(&self, tenant: &str, session: &str, index: usize) -> Result<String, TokenMapError> {
        Ok(Self::key(tenant, &map_doc_session(session, index)?))
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
        if mappings.is_empty() {
            return Ok(());
        }
        let now = self.current_time().await;
        let expires_at = now
            + chrono::Duration::from_std(self.ttl)
                .map_err(|e| TokenMapError::Backend(format!("invalid TTL {:?}: {e}", self.ttl)))?;
        let mut keys = Vec::with_capacity(MAP_DOC_SLOTS);
        for index in 0..MAP_DOC_SLOTS {
            keys.push(self.doc_key(tenant, session, index)?);
        }

        let mut guard = self.entries.write().await;
        let mut loaded = Vec::with_capacity(MAP_DOC_SLOTS);
        let mut last = None;
        for (index, key) in keys.iter().enumerate() {
            match guard.get(key) {
                Some(entry) if entry.expires_at > now => {
                    loaded.push(Some(entry.mappings.clone()));
                    last = Some(index);
                }
                Some(_) => {
                    guard.remove(key);
                    loaded.push(None);
                }
                None => loaded.push(None),
            }
        }
        let docs: Vec<Vec<TokenMapping>> = match last {
            None => Vec::new(),
            Some(last) => loaded
                .into_iter()
                .take(last + 1)
                .map(|mappings| mappings.unwrap_or_default())
                .collect(),
        };
        let Some(placement) = place_mappings(&docs, mappings, self.map_doc_limit)? else {
            return Ok(());
        };
        // Refresh documents this write does not replace so their TTL stays
        // aligned with the tail. One lock makes the set atomic.
        for (index, key) in keys.iter().enumerate().take(docs.len()) {
            if index == placement.index {
                continue;
            }
            if let Some(entry) = guard.get_mut(key) {
                entry.expires_at = expires_at;
            }
        }
        guard.insert(
            keys[placement.index].clone(),
            SessionEntry {
                mappings: placement.mappings,
                expires_at,
            },
        );
        Ok(())
    }

    async fn get(&self, tenant: &str, session: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        let now = self.current_time().await;
        let mut guard = self.entries.write().await;
        let mut out = Vec::new();
        for index in 0..MAP_DOC_SLOTS {
            let key = self.doc_key(tenant, session, index)?;
            match guard.get(&key) {
                Some(entry) if entry.expires_at > now => out.extend(entry.mappings.clone()),
                Some(_) => {
                    guard.remove(&key);
                }
                None => {}
            }
        }
        Ok(out)
    }

    async fn exists(&self, tenant: &str, session: &str) -> Result<bool, TokenMapError> {
        Ok(!self.get(tenant, session).await?.is_empty())
    }

    async fn delete(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        let mut guard = self.entries.write().await;
        for index in 0..MAP_DOC_SLOTS {
            guard.remove(&self.doc_key(tenant, session, index)?);
        }
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
