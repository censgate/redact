//! Indexed PostgreSQL backend. Every key includes the tenant and context.
//! A short per-context row lock orders intern against retirement across replicas.
//! Resolution uses a bounded indexed query and does not lock unrelated contexts.
use crate::{
    response_budget, unique_refs, validate, validate_refs, Entry, Error, Scope, TokenStore,
};
use sqlx::{PgPool, Postgres as Pg, Row, Transaction};
use std::{collections::BTreeMap, sync::Arc};

// Keep point lookups parameterized per requested key. OFFSET 0 prevents the
// planner from flattening the lateral subquery into a context-wide join under
// RLS. The execution-plan regression counts visited rows, not just output rows.
const RESOLVE_QUERY: &str = "SELECT e.fingerprint,e.token,CASE WHEN sum(octet_length(e.sealed)) OVER () <= 1048576 THEN e.sealed END AS sealed,e.expires_ms FROM (SELECT DISTINCT unnest($3::text[]) AS token) requested CROSS JOIN LATERAL (SELECT fingerprint,token,sealed,expires_ms FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND token=requested.token OFFSET 0) e WHERE e.expires_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint AND EXISTS (SELECT 1 FROM redact_tokens_v1.contexts WHERE tenant=$1 AND context=$2 AND NOT retired)";

const RETIRE_DELETE_QUERY: &str = "DELETE FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND (tenant || ':' || context)=($1 || ':' || $2)";

const INTERN_LOOKUP_QUERY: &str = "SELECT e.fingerprint,e.token,CASE WHEN sum(octet_length(e.sealed)) OVER () <= 1048576 THEN e.sealed END AS sealed,e.expires_ms FROM (SELECT DISTINCT unnest($3::text[]) AS fingerprint) requested CROSS JOIN LATERAL (SELECT fingerprint,token,sealed,expires_ms FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND fingerprint=requested.fingerprint OFFSET 0) e";

/// Operator-applied schema. Runtime startup never changes schema or privileges.
pub const SCHEMA: &str = include_str!("schema.sql");

/// One dedicated database shard with a bounded, caller-configured pool.
pub struct Postgres {
    pool: PgPool,
}

impl Postgres {
    /// Reject superuser, BYPASSRLS and table-owner runtime connections.
    /// Set a finite pool acquire_timeout and max_connections at construction.
    pub async fn new(pool: PgPool) -> Result<Self, Error> {
        let unsafe_role: bool = sqlx::query_scalar("SELECT rolsuper OR rolbypassrls OR EXISTS (SELECT 1 FROM pg_tables WHERE schemaname='redact_tokens_v1' AND tableowner=current_user) FROM pg_roles WHERE rolname=current_user")
            .fetch_one(&pool).await.map_err(|_| Error::Unavailable)?;
        if unsafe_role {
            return Err(Error::Invalid);
        }
        Ok(Self { pool })
    }

    async fn begin(&self, scope: &Scope) -> Result<Transaction<'_, Pg>, Error> {
        let mut tx = self.pool.begin().await.map_err(|_| Error::Unavailable)?;
        sqlx::query("SELECT set_config('redact.tenant', $1, true)")
            .bind(&scope.tenant)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        Ok(tx)
    }

    async fn lock(tx: &mut Transaction<'_, Pg>, scope: &Scope) -> Result<bool, Error> {
        sqlx::query("INSERT INTO redact_tokens_v1.contexts (tenant, context) VALUES ($1,$2) ON CONFLICT DO NOTHING")
            .bind(&scope.tenant).bind(&scope.context).execute(&mut **tx).await.map_err(|_| Error::Unavailable)?;
        sqlx::query_scalar("SELECT retired FROM redact_tokens_v1.contexts WHERE tenant=$1 AND context=$2 FOR UPDATE")
            .bind(&scope.tenant).bind(&scope.context).fetch_one(&mut **tx).await.map_err(|_| Error::Unavailable)
    }
}

fn entry(row: sqlx::postgres::PgRow) -> Result<Entry, Error> {
    Ok(Entry {
        fingerprint: row.try_get("fingerprint").map_err(|_| Error::Integrity)?,
        token: row.try_get("token").map_err(|_| Error::Integrity)?,
        sealed: row
            .try_get::<Option<String>, _>("sealed")
            .map_err(|_| Error::Integrity)?
            .ok_or(Error::Capacity)?,
        expires_ms: row.try_get("expires_ms").map_err(|_| Error::Integrity)?,
    })
}

#[async_trait::async_trait]
impl TokenStore for Postgres {
    fn backend(&self) -> &'static str {
        "postgres"
    }

    #[tracing::instrument(skip_all, fields(backend = "postgres", items = candidates.len()))]
    async fn intern(&self, scope: &Scope, candidates: &[Entry]) -> Result<Vec<Entry>, Error> {
        validate(candidates)?;
        if candidates.is_empty() {
            return Ok(vec![]);
        }
        let mut tx = self.begin(scope).await?;
        if Self::lock(&mut tx, scope).await? {
            return Err(Error::Retired);
        }
        let now: i64 =
            sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint")
                .fetch_one(&mut *tx)
                .await
                .map_err(|_| Error::Unavailable)?;
        let fingerprints: Vec<_> = candidates.iter().map(|e| e.fingerprint.as_str()).collect();
        let rows = sqlx::query(INTERN_LOOKUP_QUERY)
            .bind(&scope.tenant)
            .bind(&scope.context)
            .bind(&fingerprints)
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let mut found = BTreeMap::new();
        for row in rows {
            let e = entry(row)?;
            if e.expires_ms <= now {
                return Err(Error::Retired);
            }
            found.insert(e.fingerprint.clone(), e);
        }
        let mut inserts = BTreeMap::new();
        for e in candidates {
            if !found.contains_key(&e.fingerprint) {
                if e.expires_ms <= now {
                    return Err(Error::Retired);
                }
                inserts
                    .entry(e.fingerprint.clone())
                    .or_insert_with(|| e.clone());
            }
        }
        if !inserts.is_empty() {
            let keys: Vec<_> = inserts.values().map(|e| e.fingerprint.as_str()).collect();
            let tokens: Vec<_> = inserts.values().map(|e| e.token.as_str()).collect();
            let sealed: Vec<_> = inserts.values().map(|e| e.sealed.as_str()).collect();
            let expiry: Vec<_> = inserts.values().map(|e| e.expires_ms).collect();
            sqlx::query("INSERT INTO redact_tokens_v1.entries (tenant,context,fingerprint,token,sealed,expires_ms) SELECT $1,$2,* FROM unnest($3::text[],$4::text[],$5::text[],$6::bigint[])")
                .bind(&scope.tenant).bind(&scope.context).bind(keys).bind(tokens).bind(sealed).bind(expiry)
                .execute(&mut *tx).await.map_err(|e| if e.as_database_error().is_some_and(|e| e.is_unique_violation()) { Error::Integrity } else { Error::Unavailable })?;
            found.extend(inserts);
        }
        response_budget(candidates.iter().filter_map(|e| found.get(&e.fingerprint)))?;
        let result = candidates
            .iter()
            .map(|e| found.get(&e.fingerprint).cloned().ok_or(Error::Integrity))
            .collect::<Result<Vec<_>, _>>()?;
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        Ok(result)
    }

    #[tracing::instrument(skip_all, fields(backend = "postgres", items = tokens.len()))]
    async fn resolve(&self, scope: &Scope, tokens: &[String]) -> Result<Vec<Option<Entry>>, Error> {
        validate_refs(tokens)?;
        if tokens.is_empty() {
            return Ok(vec![]);
        }
        let mut tx = self.begin(scope).await?;
        let rows = sqlx::query(RESOLVE_QUERY)
            .bind(&scope.tenant)
            .bind(&scope.context)
            .bind(unique_refs(tokens))
            .fetch_all(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        let mut found = BTreeMap::new();
        for row in rows {
            let e = entry(row)?;
            found.insert(e.token.clone(), e);
        }
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        response_budget(tokens.iter().filter_map(|token| found.get(token)))?;
        Ok(tokens
            .iter()
            .map(|token| found.get(token).cloned())
            .collect())
    }

    #[tracing::instrument(skip_all, fields(backend = "postgres"))]
    async fn retire(&self, scope: &Scope) -> Result<(), Error> {
        let mut tx = self.begin(scope).await?;
        Self::lock(&mut tx, scope).await?;
        sqlx::query(
            "UPDATE redact_tokens_v1.contexts SET retired=true WHERE tenant=$1 AND context=$2",
        )
        .bind(&scope.tenant)
        .bind(&scope.context)
        .execute(&mut *tx)
        .await
        .map_err(|_| Error::Unavailable)?;
        sqlx::query(RETIRE_DELETE_QUERY)
            .bind(&scope.tenant)
            .bind(&scope.context)
            .execute(&mut *tx)
            .await
            .map_err(|_| Error::Unavailable)?;
        tx.commit().await.map_err(|_| Error::Unavailable)
    }
}

/// Explicit virtual-bucket routing across independent database shards. The
/// 256-entry ownership table partitions keyed tenant/principal contexts so large
/// tenants can span shards. It must be shared by all replicas and remain stable.
/// Changing ownership requires a fenced, offline migration; this type does not
/// claim to implement online rebalancing. Public tokens contain no shard address.
pub struct ShardedPostgres {
    shards: Vec<Arc<Postgres>>,
    ownership: [usize; 256],
}

impl ShardedPostgres {
    /// Construct a complete routing map; never infer ownership from shard count.
    pub fn new(shards: Vec<Arc<Postgres>>, ownership: [usize; 256]) -> Result<Self, Error> {
        if shards.is_empty() || ownership.iter().any(|i| *i >= shards.len()) {
            return Err(Error::Invalid);
        }
        Ok(Self { shards, ownership })
    }
    fn shard(&self, scope: &Scope) -> Result<&Postgres, Error> {
        let bucket = usize::from_str_radix(scope.context.get(..2).ok_or(Error::Invalid)?, 16)
            .map_err(|_| Error::Invalid)?;
        Ok(&self.shards[self.ownership[bucket]])
    }
}

#[async_trait::async_trait]
impl TokenStore for ShardedPostgres {
    fn backend(&self) -> &'static str {
        "postgres_sharded"
    }
    async fn intern(&self, scope: &Scope, entries: &[Entry]) -> Result<Vec<Entry>, Error> {
        self.shard(scope)?.intern(scope, entries).await
    }
    async fn resolve(&self, scope: &Scope, tokens: &[String]) -> Result<Vec<Option<Entry>>, Error> {
        self.shard(scope)?.resolve(scope, tokens).await
    }
    async fn retire(&self, scope: &Scope) -> Result<(), Error> {
        self.shard(scope)?.retire(scope).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires isolated migrated TOKEN_STORE_PG_URL"]
    async fn selective_lookups_do_not_scan_context() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&std::env::var("TOKEN_STORE_PG_URL").unwrap())
            .await
            .unwrap();
        let store = Postgres::new(pool.clone()).await.unwrap();
        let scope = Scope {
            tenant: "synthetic_plan_tenant".into(),
            context: uuid::Uuid::new_v4().to_string(),
        };
        for start in (0..10000).step_by(200) {
            let entries: Vec<_> = (start..start + 200)
                .map(|n| Entry {
                    fingerprint: format!("{n:064x}"),
                    token: format!("[PERSON_{n}]"),
                    sealed: "synthetic ciphertext".into(),
                    expires_ms: chrono::Utc::now().timestamp_millis() + 60000,
                })
                .collect();
            store.intern(&scope, &entries).await.unwrap();
        }
        let mut tx = store.begin(&scope).await.unwrap();
        fn work(node: &serde_json::Value, removed: &mut u64) {
            let scan = node["Relation Name"]
                .as_str()
                .is_some_and(|s| s.starts_with("entries_"));
            *removed += (node["Rows Removed by Filter"].as_u64().unwrap_or(0)
                + if scan {
                    node["Actual Rows"].as_u64().unwrap_or(0)
                } else {
                    node["Rows Removed by Join Filter"].as_u64().unwrap_or(0)
                })
                * node["Actual Loops"].as_u64().unwrap_or(1);
            if let Some(children) = node["Plans"].as_array() {
                for child in children {
                    work(child, removed);
                }
            }
        }
        for (name, query, key) in [
            ("resolve", RESOLVE_QUERY, "[PERSON_9999]".to_owned()),
            ("reuse", INTERN_LOOKUP_QUERY, format!("{:064x}", 9999)),
        ] {
            let explain = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {query}");
            let plan: serde_json::Value = sqlx::query_scalar(&explain)
                .bind(&scope.tenant)
                .bind(&scope.context)
                .bind(vec![key])
                .fetch_one(&mut *tx)
                .await
                .unwrap();
            let mut visited = 0;
            work(&plan[0]["Plan"], &mut visited);
            println!("Selective {name}: mapping_rows_visited={visited}");
            assert!(
                visited < 100,
                "fixed-size {name} scanned historical mappings: {visited}"
            );
        }
        tx.rollback().await.unwrap();
        store.retire(&scope).await.unwrap();
        // Fill every partition with unrelated scopes, then inspect retirement
        // under the restricted role before ANALYZE can mask a missing index.
        let entries: Vec<_> = (0..8)
            .map(|n| Entry {
                fingerprint: format!("{n:064x}"),
                token: format!("[PERSON_{n}]"),
                sealed: "synthetic ciphertext".into(),
                expires_ms: chrono::Utc::now().timestamp_millis() + 60000,
            })
            .collect();
        for n in 0..512 {
            let foreign = Scope {
                tenant: format!("synthetic_tenant_{n}"),
                context: format!("synthetic_context_{n}"),
            };
            store.intern(&foreign, &entries).await.unwrap();
        }
        let target = Scope {
            tenant: "synthetic_retirement_tenant".into(),
            context: "synthetic_retirement_context".into(),
        };
        store.intern(&target, &entries).await.unwrap();
        let mut tx = store.begin(&target).await.unwrap();
        let query = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {RETIRE_DELETE_QUERY}");
        let plan: serde_json::Value = sqlx::query_scalar(&query)
            .bind(&target.tenant)
            .bind(&target.context)
            .fetch_one(&mut *tx)
            .await
            .unwrap();
        let mut visited = 0;
        work(&plan[0]["Plan"], &mut visited);
        println!("Scoped retirement: mapping_rows_visited={visited}");
        assert_eq!(visited, 8, "retirement scanned unrelated contexts");
        tx.rollback().await.unwrap();
        store.retire(&target).await.unwrap();
    }
}
