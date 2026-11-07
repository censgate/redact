//! Indexed PostgreSQL backend. Every key includes the tenant and context.
//! A short per-context row lock orders intern against retirement across replicas.
//! Resolution uses a bounded indexed query and does not lock unrelated contexts.
use crate::{
    response_budget, unique_refs, validate, validate_refs, ContextState, Entry, Error,
    LegacyImport, Scope, TokenStore,
};
use sqlx::{PgPool, Postgres as Pg, Row, Transaction};
use std::{collections::BTreeMap, sync::Arc};

// Keep point lookups parameterized per requested key. OFFSET 0 prevents the
// planner from flattening the lateral subquery into a context-wide join under
// RLS. The execution-plan regression counts visited rows, not just output rows.
const RESOLVE_QUERY: &str = "SELECT e.fingerprint,e.token,CASE WHEN sum(octet_length(e.sealed)) OVER () <= 1048576 THEN e.sealed END AS sealed,e.expires_ms FROM (SELECT DISTINCT unnest($3::text[]) AS token) requested CROSS JOIN LATERAL (SELECT fingerprint,token,sealed,expires_ms FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND token=requested.token OFFSET 0) e WHERE e.expires_ms > (extract(epoch FROM clock_timestamp()) * 1000)::bigint AND EXISTS (SELECT 1 FROM redact_tokens_v1.contexts WHERE tenant=$1 AND context=$2 AND NOT retired)";

const RETIRE_SELECT_QUERY: &str = "SELECT fingerprint FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND (tenant||':'||context)=($1||':'||$2) LIMIT 256 FOR UPDATE SKIP LOCKED";

const INTERN_LOOKUP_QUERY: &str = "SELECT e.fingerprint,e.token,CASE WHEN sum(octet_length(e.sealed)) OVER () <= 1048576 THEN e.sealed END AS sealed,e.expires_ms FROM (SELECT DISTINCT unnest($3::text[]) AS fingerprint) requested CROSS JOIN LATERAL (SELECT fingerprint,token,sealed,expires_ms FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND fingerprint=requested.fingerprint OFFSET 0) e";
const ALIAS_LOOKUP_QUERY:&str="SELECT a.alias,e.fingerprint,e.token,CASE WHEN sum(octet_length(e.sealed)) OVER () <= 1048576 THEN e.sealed END AS sealed,e.expires_ms FROM (SELECT DISTINCT unnest($3::text[]) AS alias) requested CROSS JOIN LATERAL (SELECT alias,token FROM redact_tokens_v1.aliases WHERE tenant=$1 AND context=$2 AND alias=requested.alias OFFSET 0) a CROSS JOIN LATERAL (SELECT fingerprint,token,sealed,expires_ms FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND token=a.token OFFSET 0) e";

/// Operator-applied schema. Runtime startup never changes schema or privileges.
pub const SCHEMA: &str = include_str!("schema.sql");

/// One dedicated database shard with a bounded, caller-configured pool.
pub struct Postgres {
    pool: PgPool,
}

impl Postgres {
    /// Verify operator-installed key/routing commitment and logical shard ID.
    /// An absent row, changed key or moved bucket fails closed before traffic.
    pub async fn verify_configuration(
        &self,
        commitment: &str,
        shard_id: &str,
    ) -> Result<(), Error> {
        let row: Option<(String, String)> = sqlx::query_as(
            "SELECT commitment,shard_id FROM redact_tokens_v1.configuration WHERE singleton",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| Error::Unavailable)?;
        if row
            .as_ref()
            .is_some_and(|(c, s)| c == commitment && s == shard_id)
        {
            Ok(())
        } else {
            Err(Error::Integrity)
        }
    }
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

    async fn lock(tx: &mut Transaction<'_, Pg>, scope: &Scope) -> Result<(bool, bool), Error> {
        sqlx::query("INSERT INTO redact_tokens_v1.contexts (tenant, context) VALUES ($1,$2) ON CONFLICT DO NOTHING")
            .bind(&scope.tenant).bind(&scope.context).execute(&mut **tx).await.map_err(|_| Error::Unavailable)?;
        sqlx::query_as("SELECT retired,has_aliases FROM redact_tokens_v1.contexts WHERE tenant=$1 AND context=$2 FOR UPDATE")
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
        self.intern_with_aliases(scope, candidates, &[]).await
    }

    async fn intern_with_aliases(
        &self,
        scope: &Scope,
        candidates: &[Entry],
        aliases: &[Vec<String>],
    ) -> Result<Vec<Entry>, Error> {
        validate(candidates)?;
        crate::migration::validate_aliases(candidates, aliases)?;
        if candidates.is_empty() {
            return Ok(vec![]);
        }
        let mut tx = self.begin(scope).await?;
        let (retired, has_aliases) = Self::lock(&mut tx, scope).await?;
        if retired {
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
        let mut legacy = BTreeMap::new();
        if has_aliases && !aliases.is_empty() {
            let keys: Vec<_> = aliases.iter().flatten().collect();
            let rows = sqlx::query(ALIAS_LOOKUP_QUERY)
                .bind(&scope.tenant)
                .bind(&scope.context)
                .bind(keys)
                .fetch_all(&mut *tx)
                .await
                .map_err(|_| Error::Unavailable)?;
            for row in rows {
                let alias: String = row.try_get("alias").map_err(|_| Error::Integrity)?;
                let e = entry(row)?;
                legacy.insert(alias, e);
            }
        }
        let legacy_for = |i: usize| {
            aliases
                .get(i)
                .and_then(|keys| keys.iter().find_map(|k| legacy.get(k)))
        };
        let mut inserts = BTreeMap::new();
        for (i, e) in candidates.iter().enumerate() {
            if let Some(legacy) = legacy_for(i) {
                if legacy.expires_ms <= now {
                    return Err(Error::Retired);
                }
                continue;
            }
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
        response_budget(
            candidates
                .iter()
                .enumerate()
                .filter_map(|(i, e)| legacy_for(i).or_else(|| found.get(&e.fingerprint))),
        )?;
        let result = candidates
            .iter()
            .enumerate()
            .map(|(i, e)| {
                legacy_for(i)
                    .or_else(|| found.get(&e.fingerprint))
                    .cloned()
                    .ok_or(Error::Integrity)
            })
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
        // Commit the write fence first. Each subsequent batch commits physical
        // cleanup progress, so a deadline cannot repeatedly roll back all work.
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        for _ in 0..8 {
            let mut tx = self.begin(scope).await?;
            let keys: Vec<String> = sqlx::query_scalar(RETIRE_SELECT_QUERY)
                .bind(&scope.tenant)
                .bind(&scope.context)
                .fetch_all(&mut *tx)
                .await
                .map_err(|_| Error::Unavailable)?;
            if keys.is_empty() {
                // Another cleanup worker may own a remaining row. Never claim
                // physical completion based only on SKIP LOCKED's empty result.
                let remains:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND (tenant||':'||context)=($1||':'||$2))")
                    .bind(&scope.tenant).bind(&scope.context).fetch_one(&mut *tx).await.map_err(|_|Error::Unavailable)?;
                return if remains { Err(Error::Busy) } else { Ok(()) };
            }
            for key in keys {
                // Point deletion also cascades through the token-leading alias
                // index; it cannot scan unrelated contexts in this partition.
                sqlx::query("DELETE FROM redact_tokens_v1.entries WHERE fingerprint=$3 AND tenant=$1 AND context=$2")
                    .bind(&scope.tenant).bind(&scope.context).bind(key).execute(&mut *tx).await.map_err(|_|Error::Unavailable)?;
            }
            tx.commit().await.map_err(|_| Error::Unavailable)?;
        }
        Err(Error::Busy)
    }

    async fn purge_expired(&self, scope: &Scope, limit: usize) -> Result<usize, Error> {
        if limit == 0 || limit > crate::MAX_BATCH {
            return Err(Error::Invalid);
        }
        let mut tx = self.begin(scope).await?;
        Self::lock(&mut tx, scope).await?;
        let changed=sqlx::query("WITH expired AS (SELECT fingerprint FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND (tenant||':'||context)=($1||':'||$2) AND sealed <> '' AND expires_ms <= (extract(epoch FROM clock_timestamp())*1000)::bigint ORDER BY expires_ms,fingerprint LIMIT $3 FOR UPDATE) UPDATE redact_tokens_v1.entries e SET sealed='' FROM expired x WHERE e.tenant=$1 AND e.context=$2 AND e.fingerprint=x.fingerprint")
            .bind(&scope.tenant).bind(&scope.context).bind(limit as i64).execute(&mut *tx).await.map_err(|_|Error::Unavailable)?.rows_affected();
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        Ok(changed as usize)
    }

    async fn context_state(&self, scope: &Scope) -> Result<ContextState, Error> {
        let mut tx = self.begin(scope).await?;
        let row:Option<(bool,Option<String>,bool)>=sqlx::query_as("SELECT retired,import_source,legacy_clean FROM redact_tokens_v1.contexts WHERE tenant=$1 AND context=$2").bind(&scope.tenant).bind(&scope.context).fetch_optional(&mut *tx).await.map_err(|_|Error::Unavailable)?;
        tx.commit().await.map_err(|_| Error::Unavailable)?;
        Ok(match row {
            None => ContextState::Absent,
            Some((true, _, _)) => ContextState::Retired,
            Some((false, Some(source), legacy_clean)) => ContextState::Imported {
                source,
                legacy_clean,
            },
            Some(_) => ContextState::Active,
        })
    }

    async fn import_legacy(&self, scope: &Scope, snapshot: &LegacyImport) -> Result<(), Error> {
        snapshot.validate()?;
        let mut tx = self.begin(scope).await?;
        if Self::lock(&mut tx, scope).await?.0 {
            return Err(Error::Retired);
        }
        let source: Option<String> = sqlx::query_scalar(
            "SELECT import_source FROM redact_tokens_v1.contexts WHERE tenant=$1 AND context=$2",
        )
        .bind(&scope.tenant)
        .bind(&scope.context)
        .fetch_one(&mut *tx)
        .await
        .map_err(|_| Error::Unavailable)?;
        if let Some(source) = source {
            return if source == snapshot.source {
                Ok(())
            } else {
                Err(Error::Integrity)
            };
        }
        let populated:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM redact_tokens_v1.entries WHERE tenant=$1 AND context=$2 AND (tenant||':'||context)=($1||':'||$2))").bind(&scope.tenant).bind(&scope.context).fetch_one(&mut *tx).await.map_err(|_|Error::Unavailable)?;
        if populated {
            return Err(Error::Integrity);
        }
        for batch in snapshot.entries.chunks(crate::MAX_BATCH) {
            let keys: Vec<_> = batch.iter().map(|e| &e.fingerprint).collect();
            let tokens: Vec<_> = batch.iter().map(|e| &e.token).collect();
            let sealed: Vec<_> = batch.iter().map(|e| &e.sealed).collect();
            let expiry: Vec<_> = batch.iter().map(|e| e.expires_ms).collect();
            sqlx::query("INSERT INTO redact_tokens_v1.entries (tenant,context,fingerprint,token,sealed,expires_ms) SELECT $1,$2,* FROM unnest($3::text[],$4::text[],$5::text[],$6::bigint[])").bind(&scope.tenant).bind(&scope.context).bind(keys).bind(tokens).bind(sealed).bind(expiry).execute(&mut *tx).await.map_err(|_|Error::Integrity)?;
        }
        let pairs: Vec<_> = snapshot.aliases.iter().collect();
        for batch in pairs.chunks(crate::MAX_BATCH) {
            let keys: Vec<_> = batch.iter().map(|(key, _)| *key).collect();
            let tokens: Vec<_> = batch.iter().map(|(_, token)| *token).collect();
            sqlx::query("INSERT INTO redact_tokens_v1.aliases (tenant,context,alias,token) SELECT $1,$2,* FROM unnest($3::text[],$4::text[])").bind(&scope.tenant).bind(&scope.context).bind(keys).bind(tokens).execute(&mut *tx).await.map_err(|_|Error::Integrity)?;
        }
        sqlx::query("UPDATE redact_tokens_v1.contexts SET import_source=$3,legacy_clean=false,has_aliases=$4 WHERE tenant=$1 AND context=$2").bind(&scope.tenant).bind(&scope.context).bind(&snapshot.source).bind(!snapshot.aliases.is_empty()).execute(&mut *tx).await.map_err(|_|Error::Unavailable)?;
        tx.commit().await.map_err(|_| Error::Unavailable)
    }

    async fn complete_legacy_cleanup(&self, scope: &Scope, source: &str) -> Result<(), Error> {
        let mut tx = self.begin(scope).await?;
        let changed=sqlx::query("UPDATE redact_tokens_v1.contexts SET legacy_clean=true WHERE tenant=$1 AND context=$2 AND import_source=$3 AND NOT retired").bind(&scope.tenant).bind(&scope.context).bind(source).execute(&mut *tx).await.map_err(|_|Error::Unavailable)?.rows_affected();
        if changed != 1 {
            return Err(Error::Integrity);
        }
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
    async fn purge_expired(&self, scope: &Scope, limit: usize) -> Result<usize, Error> {
        self.shard(scope)?.purge_expired(scope, limit).await
    }
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
    async fn intern_with_aliases(
        &self,
        scope: &Scope,
        candidates: &[Entry],
        aliases: &[Vec<String>],
    ) -> Result<Vec<Entry>, Error> {
        self.shard(scope)?
            .intern_with_aliases(scope, candidates, aliases)
            .await
    }
    async fn context_state(&self, scope: &Scope) -> Result<ContextState, Error> {
        self.shard(scope)?.context_state(scope).await
    }
    async fn import_legacy(&self, scope: &Scope, snapshot: &LegacyImport) -> Result<(), Error> {
        self.shard(scope)?.import_legacy(scope, snapshot).await
    }
    async fn complete_legacy_cleanup(&self, scope: &Scope, source: &str) -> Result<(), Error> {
        self.shard(scope)?
            .complete_legacy_cleanup(scope, source)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    #[ignore = "requires two isolated databases"]
    async fn independent_shards_preserve_routing_and_fail_closed() {
        let mut stores = Vec::new();
        let mut pools = Vec::new();
        for name in ["TOKEN_STORE_PG_URL", "TOKEN_STORE_PG_URL_2"] {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&std::env::var(name).unwrap())
                .await
                .unwrap();
            let store = Arc::new(Postgres::new(pool.clone()).await.unwrap());
            store
                .verify_configuration(&"a".repeat(64), "synthetic-shard")
                .await
                .unwrap();
            assert_eq!(
                store
                    .verify_configuration(&"b".repeat(64), "synthetic-shard")
                    .await,
                Err(Error::Integrity)
            );
            assert_eq!(
                store
                    .verify_configuration(&"a".repeat(64), "wrong-shard")
                    .await,
                Err(Error::Integrity)
            );
            assert!(
                sqlx::query("UPDATE redact_tokens_v1.configuration SET shard_id='changed'")
                    .execute(&pool)
                    .await
                    .is_err()
            );
            pools.push(pool);
            stores.push(store);
        }
        let ownership = std::array::from_fn(|n| n % 2);
        let router = ShardedPostgres::new(stores.clone(), ownership).unwrap();
        let peer = ShardedPostgres::new(stores.clone(), ownership).unwrap();
        let scopes = [
            Scope {
                tenant: "synthetic-routing-tenant".into(),
                context: format!("00{}", uuid::Uuid::new_v4()),
            },
            Scope {
                tenant: "synthetic-routing-tenant".into(),
                context: format!("01{}", uuid::Uuid::new_v4()),
            },
        ];
        let proposed = Entry {
            fingerprint: "c".repeat(64),
            token: "[PERSON_1]".into(),
            sealed: "synthetic routing ciphertext".into(),
            expires_ms: chrono::Utc::now().timestamp_millis() + 60000,
        };
        for (index, scope) in scopes.iter().enumerate() {
            router
                .intern(scope, std::slice::from_ref(&proposed))
                .await
                .unwrap();
            assert!(peer
                .resolve(scope, std::slice::from_ref(&proposed.token))
                .await
                .unwrap()[0]
                .is_some());
            assert!(stores[1 - index]
                .resolve(scope, std::slice::from_ref(&proposed.token))
                .await
                .unwrap()[0]
                .is_none());
        }
        pools[0].close().await;
        assert!(matches!(
            router
                .resolve(&scopes[0], std::slice::from_ref(&proposed.token))
                .await,
            Err(Error::Unavailable)
        ));
        assert!(router
            .resolve(&scopes[1], std::slice::from_ref(&proposed.token))
            .await
            .unwrap()[0]
            .is_some());
        router.retire(&scopes[1]).await.unwrap();
    }
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
        assert_eq!(store.retire(&scope).await, Err(Error::Busy));
        assert!(store.resolve(&scope, &["[PERSON_1]".into()]).await.unwrap()[0].is_none());
        for attempt in 0..8 {
            match store.retire(&scope).await {
                Ok(()) => break,
                Err(Error::Busy) if attempt < 7 => {}
                other => panic!("retirement did not converge: {other:?}"),
            }
        }
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
        let query = format!("EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON) {RETIRE_SELECT_QUERY}");
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
