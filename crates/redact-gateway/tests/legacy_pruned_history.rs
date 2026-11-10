//! Legacy KV v2 history that the mount pruned (`max_versions`) is importable
//! only with scoped operator evidence and a live identity proof. The default
//! rejects missing history. Real OpenBao and PostgreSQL.
#![cfg(feature = "vault")]
use redact_gateway::{
    redact::token::{Dek, TokenMapping},
    vault::{
        indexed::IndexedStore, prove_pruned_identity, pruned_evidence_digest, session_path,
        Kv2Store, LegacyHistoryPolicy, PathFingerprint, PrunedEvidence, PrunedHistoryPolicy,
        PrunedProof, PrunedRejection, PrunedVersion, TokenMapError, TokenMapStore,
        BETA_MIGRATION_IDENTITY_EPOCH,
    },
};
use redact_token_store::{postgres::Postgres, Error, TokenStore};
use serde_json::json;
use std::{sync::Arc, time::Duration};

const TENANT: &str = "synthetic-tenant";

struct Source {
    settings: redact_gateway::config::VaultSettings,
    credential: String,
    client: reqwest::Client,
    key: Arc<Dek>,
    mappings: Vec<TokenMapping>,
}

impl Source {
    fn new() -> Self {
        let credential =
            std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap())
                .unwrap()
                .trim()
                .to_string();
        let key = Arc::new(Dek::from_bytes([7; 32]));
        // Sealing is randomized: seal each identity once so versions that
        // carry the same identity carry byte-identical ciphertext.
        let mappings = (0..=16)
            .map(|n| TokenMapping {
                token: format!("[PERSON_{n}]"),
                entity_type: "PERSON".into(),
                sealed_value: key.seal(&format!("Synthetic Original {n}")).unwrap(),
                created_at: chrono::Utc::now(),
            })
            .collect();
        Self {
            mappings,
            settings: redact_gateway::config::VaultSettings {
                backend: redact_gateway::config::VaultBackend::VaultKv2,
                address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
                token: Some(credential.clone()),
                path_prefix: format!("pruned-{}", uuid::Uuid::new_v4()),
                ..Default::default()
            },
            credential,
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            key,
        }
    }
    fn store(&self) -> Arc<Kv2Store> {
        Arc::new(Kv2Store::from_settings(&self.settings).unwrap())
    }
    fn proven_store(&self, evidence: PrunedEvidence) -> Arc<Kv2Store> {
        Arc::new(
            Kv2Store::from_settings(&self.settings)
                .unwrap()
                .with_history_policy(LegacyHistoryPolicy {
                    pruned: PrunedHistoryPolicy::Proven(PrunedProof { evidence }),
                    ..Default::default()
                }),
        )
    }
    /// Like the operator inventory: pin only live key metadata, after writes
    /// and before first access. The synthetic writer/rollback history is known.
    async fn evidence(&self, contexts: &[&str]) -> PrunedEvidence {
        let now = chrono::Utc::now();
        self.evidence_at(contexts, now - chrono::Duration::days(1))
            .await
    }
    async fn evidence_at(
        &self,
        contexts: &[&str],
        identity_epoch: chrono::DateTime<chrono::Utc>,
    ) -> PrunedEvidence {
        let mut entries = std::collections::HashMap::new();
        for context in contexts {
            let metadata = self.metadata(context).await;
            let path = session_path(&self.settings.path_prefix, TENANT, context);
            entries.insert(pruned_evidence_digest(&path), fingerprint(&metadata));
        }
        let now = chrono::Utc::now();
        PrunedEvidence {
            evidence_id: "synthetic-operator-review".into(),
            generated_at: now,
            not_after: now + chrono::Duration::hours(1),
            identity_epoch,
            entries,
        }
    }
    fn url(&self, operation: &str, context: &str) -> String {
        format!(
            "{}/v1/secret/{operation}/{}",
            self.settings.address.as_ref().unwrap(),
            session_path(&self.settings.path_prefix, TENANT, context)
        )
    }
    fn mapping(&self, n: usize) -> TokenMapping {
        self.mappings[n].clone()
    }
    async fn send(&self, request: reqwest::RequestBuilder) -> serde_json::Value {
        let response = request
            .header("X-Vault-Token", &self.credential)
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        response.json().await.unwrap_or(json!(null))
    }
    async fn max_versions(&self, context: &str, n: u64) {
        self.send(
            self.client
                .post(self.url("metadata", context))
                .json(&json!({"max_versions": n})),
        )
        .await;
    }
    async fn write(&self, context: &str, rows: &[TokenMapping]) {
        self.send(self.client.post(self.url("data", context)).json(&json!({
            "data": {"mappings": rows, "expires_at": chrono::Utc::now() + chrono::Duration::hours(1)}
        })))
        .await;
    }
    /// Legacy `put` semantics: version n holds identities 1..=n.
    async fn write_cumulative(&self, context: &str, versions: usize) {
        for n in 1..=versions {
            let rows: Vec<_> = (1..=n).map(|i| self.mapping(i)).collect();
            self.write(context, &rows).await;
        }
    }
    async fn metadata(&self, context: &str) -> serde_json::Value {
        self.send(self.client.get(self.url("metadata", context)))
            .await["data"]
            .clone()
    }
    async fn latest(&self, context: &str) -> serde_json::Value {
        self.send(self.client.get(self.url("data", context))).await["data"]["data"].clone()
    }
}

fn integrity<T>(result: Result<T, TokenMapError>) -> bool {
    match result {
        Err(TokenMapError::Indexed(Error::Integrity)) => true,
        Err(other) => {
            eprintln!("unexpected error: {other:?}");
            false
        }
        Ok(_) => false,
    }
}

fn fingerprint(metadata: &serde_json::Value) -> PathFingerprint {
    PathFingerprint {
        current_version: metadata["current_version"].as_u64().unwrap(),
        oldest_version: metadata["oldest_version"].as_u64().unwrap(),
        key_created_time: metadata["created_time"].as_str().unwrap().into(),
        updated_time: metadata["updated_time"].as_str().unwrap().into(),
    }
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn proven_pruned_cumulative_history_is_accepted_from_the_latest_version() {
    let source = Source::new();
    let context = uuid::Uuid::new_v4().to_string();
    source.max_versions(&context, 3).await;
    source.write_cumulative(&context, 8).await;
    let store = source.proven_store(source.evidence(&[&context]).await);
    let before = source.metadata(&context).await;
    assert_eq!(before["current_version"], 8);
    assert_eq!(before["oldest_version"], 6, "mount must have pruned 1..=5");
    let frozen = store.freeze(TENANT, &context).await.unwrap();
    let mut tokens: Vec<_> = frozen.mappings.iter().map(|m| m.token.clone()).collect();
    tokens.sort();
    let mut expected: Vec<_> = (1..=8).map(|n| format!("[PERSON_{n}]")).collect();
    expected.sort();
    assert_eq!(tokens, expected, "import source is the cumulative latest");
    assert_eq!(source.latest(&context).await["frozen"], true);
    // A second first-access is idempotent: it returns the frozen snapshot and
    // writes nothing more.
    let version = source.metadata(&context).await["current_version"].clone();
    let again = store.freeze(TENANT, &context).await.unwrap();
    assert_eq!(again.mappings.len(), 8);
    assert_eq!(source.metadata(&context).await["current_version"], version);
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn default_policy_rejects_pruned_cumulative_history_without_freezing() {
    let source = Source::new();
    let store = source.store();
    let context = uuid::Uuid::new_v4().to_string();
    source.max_versions(&context, 3).await;
    source.write_cumulative(&context, 8).await;
    let before = source.metadata(&context).await;
    assert_eq!(before["oldest_version"], 6);
    assert!(integrity(store.freeze(TENANT, &context).await));
    assert_eq!(source.metadata(&context).await, before);
    assert_ne!(source.latest(&context).await["frozen"], true);
    // Rejection must leave the source unchanged and eligible for a valid proof.
    assert_eq!(
        source
            .proven_store(source.evidence(&[&context]).await)
            .freeze(TENANT, &context)
            .await
            .unwrap()
            .mappings
            .len(),
        8
    );
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn single_retained_version_cleanup_completes_without_an_empty_destroy_request() {
    let source = Source::new();
    let context = uuid::Uuid::new_v4().to_string();
    source.max_versions(&context, 1).await;
    source.write_cumulative(&context, 4).await;
    let store = source.proven_store(source.evidence(&[&context]).await);
    assert_eq!(
        store.freeze(TENANT, &context).await.unwrap().mappings.len(),
        4
    );
    store.clear_frozen(TENANT, &context).await.unwrap();
    let latest = source.latest(&context).await;
    assert_eq!(latest["mappings"], json!([]));
    assert_eq!(latest["cleanup_through"], latest["destroyed_through"]);
    let metadata = source.metadata(&context).await;
    assert_eq!(metadata["versions"].as_object().unwrap().len(), 1);
    assert!(
        metadata["oldest_version"].as_u64().unwrap() > latest["cleanup_through"].as_u64().unwrap()
    );
    // Completion is idempotent and must retain the fence against future puts.
    store.clear_frozen(TENANT, &context).await.unwrap();
    assert_eq!(source.metadata(&context).await, metadata);
    assert!(store
        .put(TENANT, &context, &[source.mapping(5)])
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn racing_put_and_freeze_preserve_every_committed_mapping() {
    let source = Source::new();
    for _ in 0..16 {
        let context = uuid::Uuid::new_v4().to_string();
        source.max_versions(&context, 3).await;
        source.write_cumulative(&context, 8).await;
        let evidence = source.evidence(&[&context]).await;
        let freezer = source.proven_store(evidence.clone());
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let writer = source.store();
        let writer_barrier = barrier.clone();
        let writer_context = context.clone();
        let mapping = source.mapping(9);
        let worker = tokio::spawn(async move {
            writer_barrier.wait().await;
            let mut committed = 0_u64;
            // Repeated CAS puts can prune a historical version while the
            // independent freezer is reading it. Once frozen, puts must stop.
            for _ in 0..12 {
                match writer
                    .put(TENANT, &writer_context, std::slice::from_ref(&mapping))
                    .await
                {
                    Ok(()) => committed += 1,
                    Err(TokenMapError::Conflict(_)) => break,
                    Err(_) => panic!("unexpected legacy put failure"),
                }
            }
            committed
        });
        barrier.wait().await;
        let mut outcome = None;
        for _ in 0..4 {
            match freezer.freeze(TENANT, &context).await {
                Ok(snapshot) => {
                    outcome = Some(Ok(snapshot));
                    break;
                }
                Err(TokenMapError::Indexed(Error::Busy)) => continue,
                Err(TokenMapError::Indexed(Error::Integrity)) => {
                    outcome = Some(Err(()));
                    break;
                }
                Err(_) => panic!("unexpected freeze failure during concurrent pruning"),
            }
        }
        let outcome = outcome.expect("freeze remained busy after bounded puts");
        let committed = worker.await.unwrap();
        match outcome {
            Ok(frozen) => {
                for n in 1..=8 {
                    assert!(frozen
                        .mappings
                        .iter()
                        .any(|m| m.token == format!("[PERSON_{n}]")));
                }
                assert_eq!(
                    frozen.mappings.iter().any(|m| m.token == "[PERSON_9]"),
                    committed > 0,
                    "freeze must include every successful put"
                );
                assert_eq!(source.latest(&context).await["frozen"], true);
            }
            Err(()) => {
                assert!(
                    committed > 0,
                    "rejection must be due to a committed racing write"
                );
                let metadata = source.metadata(&context).await;
                // Only the writer advanced the version; no rejected freeze wrote.
                assert_eq!(metadata["current_version"], 8 + committed);
                let latest = source.latest(&context).await;
                assert_ne!(latest["frozen"], true);
                let rows: Vec<TokenMapping> =
                    serde_json::from_value(latest["mappings"].clone()).unwrap();
                assert!(rows.iter().any(|m| m.token == "[PERSON_9]"));
                let path = session_path(&source.settings.path_prefix, TENANT, &context);
                assert_eq!(
                    prove_pruned_identity(
                        &evidence,
                        &pruned_evidence_digest(&path),
                        &fingerprint(&metadata),
                        &[],
                        chrono::Utc::now()
                    ),
                    Err(PrunedRejection::FingerprintMismatch)
                );
            }
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn unproven_pruned_histories_reject_without_a_fence_or_new_version() {
    let source = Source::new();
    for case in ["no_entry", "fingerprint_drift", "before_epoch", "expired"] {
        let context = uuid::Uuid::new_v4().to_string();
        source.max_versions(&context, 3).await;
        source.write_cumulative(&context, 8).await;
        let mut evidence = source.evidence(&[&context]).await;
        match case {
            "no_entry" => evidence.entries.clear(),
            "fingerprint_drift" => {
                source
                    .write(
                        &context,
                        &(1..=9).map(|n| source.mapping(n)).collect::<Vec<_>>(),
                    )
                    .await
            }
            "before_epoch" => evidence.identity_epoch = chrono::Utc::now(),
            "expired" => evidence.not_after = chrono::Utc::now() - chrono::Duration::seconds(1),
            _ => unreachable!(),
        }
        let before = source.metadata(&context).await;
        let store = source.proven_store(evidence);
        assert!(integrity(store.freeze(TENANT, &context).await), "{case}");
        assert_eq!(source.metadata(&context).await, before, "{case}");
        assert_ne!(source.latest(&context).await["frozen"], true, "{case}");
    }
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn expiry_reset_before_the_retained_tail_is_not_importable() {
    let mut source = Source::new();
    source.settings.ttl_secs = 1;
    // Both sequences use production Kv2Store::put, including the expiry reset.
    let writer = source.store();
    let pruned = uuid::Uuid::new_v4().to_string();
    let complete = uuid::Uuid::new_v4().to_string();
    source.max_versions(&pruned, 1).await;
    // The complete key uses the mount's default max_versions, retaining v1/v2.
    let value_a = source.mapping(1);
    let mut value_b = source.mapping(1);
    value_b.sealed_value = source.key.seal("Synthetic Value B").unwrap();
    for context in [&pruned, &complete] {
        writer
            .put(TENANT, context, std::slice::from_ref(&value_a))
            .await
            .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    for context in [&pruned, &complete] {
        writer
            .put(TENANT, context, std::slice::from_ref(&value_b))
            .await
            .unwrap();
    }
    let before = source.metadata(&pruned).await;
    assert_eq!(before["current_version"], 2);
    assert_eq!(before["oldest_version"], 2);
    assert_eq!(before["versions"].as_object().unwrap().len(), 1);
    let latest = source.latest(&pruned).await;
    let rows: Vec<TokenMapping> = serde_json::from_value(latest["mappings"].clone()).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].token, "[PERSON_1]");
    assert_eq!(rows[0].sealed_value, value_b.sealed_value);

    assert!(integrity(writer.freeze(TENANT, &pruned).await));
    assert_eq!(source.metadata(&pruned).await, before);
    let evidence = source.evidence(&[&pruned]).await;
    let path = session_path(&source.settings.path_prefix, TENANT, &pruned);
    let versions = [PrunedVersion {
        created_time: before["versions"]["2"]["created_time"]
            .as_str()
            .unwrap()
            .into(),
        expires_at: serde_json::from_value(latest["expires_at"].clone()).unwrap(),
    }];
    assert_eq!(
        prove_pruned_identity(
            &evidence,
            &pruned_evidence_digest(&path),
            &fingerprint(&before),
            &versions,
            chrono::Utc::now()
        ),
        Err(PrunedRejection::TtlBelowExposure)
    );
    let proven = source.proven_store(evidence);
    assert!(integrity(proven.freeze(TENANT, &pruned).await));
    assert_eq!(source.metadata(&pruned).await, before);
    assert_ne!(source.latest(&pruned).await["frozen"], true);

    let before_complete = source.metadata(&complete).await;
    assert_eq!(before_complete["current_version"], 2);
    assert!(before_complete["oldest_version"].as_u64().unwrap() <= 1);
    assert_eq!(before_complete["versions"].as_object().unwrap().len(), 2);
    assert!(integrity(writer.freeze(TENANT, &complete).await));
    assert_eq!(source.metadata(&complete).await, before_complete);
    assert_ne!(source.latest(&complete).await["frozen"], true);
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn pruned_history_that_is_not_safe_stays_an_integrity_failure() {
    let source = Source::new();
    for case in [
        "non_cumulative",
        "rebound",
        "destroyed_retained",
        "deleted_retained",
        "deleted_latest",
    ] {
        let context = uuid::Uuid::new_v4().to_string();
        source.max_versions(&context, 3).await;
        // Versions 1..=6 are cumulative; the retained suffix is 4..=6.
        source.write_cumulative(&context, 6).await;
        match case {
            // The latest forgot identities that a retained version holds.
            "non_cumulative" => source.write(&context, &[source.mapping(6)]).await,
            // The latest rebinds a label held by a retained version.
            "rebound" => {
                let mut rows: Vec<_> = (1..=6).map(|i| source.mapping(i)).collect();
                rows[4].sealed_value = source.key.seal("Synthetic Rebound").unwrap();
                source.write(&context, &rows).await;
            }
            "destroyed_retained" => {
                source
                    .send(
                        source
                            .client
                            .post(source.url("destroy", &context))
                            .json(&json!({"versions":[5]})),
                    )
                    .await;
            }
            "deleted_retained" => {
                source
                    .send(
                        source
                            .client
                            .post(source.url("delete", &context))
                            .json(&json!({"versions":[5]})),
                    )
                    .await;
            }
            "deleted_latest" => {
                source
                    .send(source.client.delete(source.url("data", &context)))
                    .await;
            }
            _ => unreachable!(),
        }
        let store = source.proven_store(source.evidence(&[&context]).await);
        let before = source.metadata(&context).await["current_version"].clone();
        let result = store.freeze(TENANT, &context).await;
        if case == "deleted_latest" {
            // The unreadable latest is rejected fail-closed (OpenBao's reply
            // for a deleted version is surfaced as a backend failure).
            assert!(result.is_err(), "{case} must not import");
        } else {
            assert!(integrity(result), "{case} must be an integrity failure");
        }
        // Rejection is read-only: no fence, no new version.
        assert_eq!(
            source.metadata(&context).await["current_version"],
            before,
            "{case}"
        );
        if case != "deleted_latest" {
            assert_ne!(source.latest(&context).await["frozen"], true, "{case}");
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn unpruned_history_still_verifies_every_version() {
    let source = Source::new();
    let store = source.store();
    // Complete history imports as before.
    let ok = uuid::Uuid::new_v4().to_string();
    source.write_cumulative(&ok, 4).await;
    assert!(
        source.metadata(&ok).await["oldest_version"]
            .as_u64()
            .unwrap()
            <= 1
    );
    assert_eq!(store.freeze(TENANT, &ok).await.unwrap().mappings.len(), 4);
    // A rebound label inside a complete history is still rejected.
    let bad = uuid::Uuid::new_v4().to_string();
    source.write_cumulative(&bad, 3).await;
    let mut rows: Vec<_> = (1..=3).map(|i| source.mapping(i)).collect();
    rows[0].sealed_value = source.key.seal("Synthetic Rebound").unwrap();
    source.write(&bad, &rows).await;
    assert!(integrity(store.freeze(TENANT, &bad).await));
    // A first-time context with no history is an empty snapshot.
    let none = uuid::Uuid::new_v4().to_string();
    assert!(store
        .freeze(TENANT, &none)
        .await
        .unwrap()
        .mappings
        .is_empty());
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn lifetime_counter_beyond_the_old_bound_imports_and_cleans_up_when_pruned() {
    let source = Source::new();
    let context = uuid::Uuid::new_v4().to_string();
    source.max_versions(&context, 5).await;
    // One identity rewritten 2,100 times: a lifetime counter above the former
    // 2,048 bound, but only five retained versions.
    for _ in 0..2100 {
        source.write(&context, &[source.mapping(1)]).await;
    }
    let store = source.proven_store(source.evidence(&[&context]).await);
    let before = source.metadata(&context).await;
    assert_eq!(before["current_version"], 2100);
    assert_eq!(before["oldest_version"], 2096);
    let frozen = store.freeze(TENANT, &context).await.unwrap();
    assert_eq!(frozen.mappings.len(), 1);
    // Cleanup skips versions the mount already pruned, so one call finishes.
    store.clear_frozen(TENANT, &context).await.unwrap();
    let latest = source.latest(&context).await;
    assert_eq!(latest["mappings"], json!([]));
    assert_eq!(latest["cleanup_through"], latest["destroyed_through"]);
    let metadata = source.metadata(&context).await;
    for (version, details) in metadata["versions"].as_object().unwrap() {
        if version.parse::<u64>().unwrap() <= latest["cleanup_through"].as_u64().unwrap() {
            assert_eq!(details["destroyed"], true, "version {version} survived");
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated token-store PostgreSQL and OpenBao"]
async fn racing_first_accesses_import_a_pruned_history_exactly_once() {
    let source = Source::new();
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&std::env::var("TOKEN_STORE_PG_URL").unwrap())
        .await
        .unwrap();
    let target: Arc<dyn TokenStore> = Arc::new(Postgres::new(pool).await.unwrap());
    let context = uuid::Uuid::new_v4().to_string();
    source.max_versions(&context, 3).await;
    source.write_cumulative(&context, 8).await;
    assert_eq!(source.metadata(&context).await["oldest_version"], 6);
    let evidence = source.evidence(&[&context]).await;
    // Two independent replicas, each with its own source client.
    let replicas: Vec<Arc<IndexedStore>> = (0..2)
        .map(|_| {
            Arc::new(
                IndexedStore::new(
                    target.clone(),
                    source.proven_store(evidence.clone()),
                    source.key.clone(),
                    Duration::from_secs(3600),
                )
                .unwrap(),
            )
        })
        .collect();
    let mut workers = tokio::task::JoinSet::new();
    for n in 0..8 {
        let replica = replicas[n % 2].clone();
        let context = context.clone();
        let probe = source.mapping(3);
        workers.spawn(async move {
            // Busy is the typed retry signal for a peer holding the fence.
            for _ in 0..20 {
                match replica
                    .commit(TENANT, &context, std::slice::from_ref(&probe))
                    .await
                {
                    Err(TokenMapError::Indexed(Error::Busy)) => {
                        tokio::time::sleep(Duration::from_millis(25)).await
                    }
                    other => return other,
                }
            }
            Err(TokenMapError::Indexed(Error::Busy))
        });
    }
    let mut durable = std::collections::BTreeSet::new();
    while let Some(result) = workers.join_next().await {
        let committed = result
            .unwrap()
            .unwrap_or_else(|e| panic!("race failed: {e:?}"));
        durable.extend(committed.into_values());
    }
    assert_eq!(
        durable.len(),
        1,
        "every racer must see one durable identity"
    );
    // Every legacy identity, including those only in the pruned-away versions'
    // successor, is served from the target.
    let text = (1..=8)
        .map(|n| format!("[PERSON_{n}]"))
        .collect::<Vec<_>>()
        .join(" ");
    let resolved = replicas[0].lookup(TENANT, &context, &text).await.unwrap();
    for n in 1..=8 {
        assert_eq!(
            resolved.get(&format!("[PERSON_{n}]")).map(String::as_str),
            Some(format!("Synthetic Original {n}").as_str())
        );
    }
    // The source was fenced once and cleared: later access never re-imports it.
    let latest = source.latest(&context).await;
    assert_eq!(latest["frozen"], true);
    assert_eq!(latest["mappings"], json!([]));
    assert_eq!(latest["cleanup_through"], latest["destroyed_through"]);
    let version = source.metadata(&context).await["current_version"].clone();
    let fresh = IndexedStore::new(
        target,
        source.store(),
        source.key.clone(),
        Duration::from_secs(3600),
    )
    .unwrap();
    let again = fresh.lookup(TENANT, &context, &text).await.unwrap();
    assert_eq!(again, resolved);
    assert_eq!(source.metadata(&context).await["current_version"], version);
}

fn beta_epoch() -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(BETA_MIGRATION_IDENTITY_EPOCH)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn unpruned_pre_epoch_context_fails_closed_only_when_an_epoch_is_configured() {
    let source = Source::new();
    let context = uuid::Uuid::new_v4().to_string();
    // Full history from version 1: the strict guard alone would accept it.
    source.write_cumulative(&context, 4).await;
    let before = source.metadata(&context).await;
    assert!(before["oldest_version"].as_u64().unwrap() <= 1);
    // The key was created "now", so an epoch an hour ahead makes it pre-epoch.
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    let strict_epoch = source.proven_store(source.evidence_at(&[], future).await);
    assert!(integrity(strict_epoch.freeze(TENANT, &context).await));
    // Rejection writes nothing: no fence, no new version.
    assert_eq!(source.metadata(&context).await, before);
    assert_ne!(source.latest(&context).await["frozen"], true);
    // Without evidence there is no epoch: behavior is unchanged (accepted).
    let unconfigured = source.store();
    assert_eq!(
        unconfigured
            .freeze(TENANT, &context)
            .await
            .unwrap()
            .mappings
            .len(),
        4
    );
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn unpruned_post_epoch_context_is_accepted_with_the_beta_epoch() {
    let source = Source::new();
    let context = uuid::Uuid::new_v4().to_string();
    source.write_cumulative(&context, 4).await;
    assert!(
        source.metadata(&context).await["oldest_version"]
            .as_u64()
            .unwrap()
            <= 1
    );
    let store = source.proven_store(source.evidence_at(&[], beta_epoch()).await);
    assert_eq!(
        store.freeze(TENANT, &context).await.unwrap().mappings.len(),
        4
    );
    assert_eq!(source.latest(&context).await["frozen"], true);
    // A first-time context has no source key and is unaffected by the epoch.
    let none = uuid::Uuid::new_v4().to_string();
    assert!(store
        .freeze(TENANT, &none)
        .await
        .unwrap()
        .mappings
        .is_empty());
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn pruned_post_epoch_context_with_a_valid_proof_is_accepted_and_pre_epoch_is_not() {
    let source = Source::new();
    let accepted = uuid::Uuid::new_v4().to_string();
    let rejected = uuid::Uuid::new_v4().to_string();
    for context in [&accepted, &rejected] {
        source.max_versions(context, 3).await;
        source.write_cumulative(context, 8).await;
        assert_eq!(source.metadata(context).await["oldest_version"], 6);
    }
    let store = source.proven_store(
        source
            .evidence_at(&[&accepted, &rejected], beta_epoch())
            .await,
    );
    assert_eq!(
        store
            .freeze(TENANT, &accepted)
            .await
            .unwrap()
            .mappings
            .len(),
        8
    );
    // Same pinned fingerprint and TTLs, but the epoch is after key creation.
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    let late = source.proven_store(source.evidence_at(&[&rejected], future).await);
    let before = source.metadata(&rejected).await;
    assert!(integrity(late.freeze(TENANT, &rejected).await));
    assert_eq!(source.metadata(&rejected).await, before);
}
