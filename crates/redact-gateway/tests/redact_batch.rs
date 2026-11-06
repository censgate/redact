//! Synthetic contract/failure tests. Fixture recognizers are not NER perf evidence.
mod support;

use axum::http::StatusCode;
use redact_core::{AnalyzerEngine, EntityType, Recognizer, RecognizerResult};
use redact_gateway::config::{ResolvedConfig, VaultBackend};
use redact_gateway::redact::token::TokenMapping;
use redact_gateway::routes::{
    create_router, AppState, MAX_BATCH_TEXT_BYTES, MAX_BATCH_TOTAL_BYTES,
};
use redact_gateway::vault::{CredentialLineage, MemoryStore, TokenMapError, TokenMapStore};
use redact_gateway::GatewayServer;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use support::*;
use tokio::sync::{Barrier, Notify};

#[derive(Debug, Default)]
struct FixtureRecognizer {
    seen: AtomicUsize,
}
impl Recognizer for FixtureRecognizer {
    fn name(&self) -> &str {
        "synthetic-contract"
    }
    fn supported_entities(&self) -> &[EntityType] {
        &[EntityType::Person]
    }
    fn analyze(&self, text: &str, _: &str) -> anyhow::Result<Vec<RecognizerResult>> {
        self.seen.fetch_add(1, Ordering::SeqCst);
        if text.contains("inject-error") {
            anyhow::bail!("synthetic detector error with request content");
        }
        if text.contains("slow-leaf") {
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        Ok(["person-a", "person-b", "person-c", "person-d"]
            .iter()
            .flat_map(|name| {
                text.match_indices(name).map(move |(start, _)| {
                    RecognizerResult::new(
                        EntityType::Person,
                        start,
                        start + name.len(),
                        0.99,
                        "synthetic-contract",
                    )
                })
            })
            .collect())
    }
}

#[derive(Debug)]
struct TestStore {
    inner: MemoryStore,
    writes: AtomicUsize,
    gate_reads: AtomicUsize,
    gate: Barrier,
    fail_read: bool,
    fail_write: bool,
    conflict: bool,
    pause_write: bool,
    write_started: Notify,
}
impl Default for TestStore {
    fn default() -> Self {
        Self {
            inner: MemoryStore::new(3600),
            writes: AtomicUsize::new(0),
            gate_reads: AtomicUsize::new(0),
            gate: Barrier::new(4),
            fail_read: false,
            fail_write: false,
            conflict: false,
            pause_write: false,
            write_started: Notify::new(),
        }
    }
}
#[async_trait::async_trait]
impl TokenMapStore for TestStore {
    fn backend_name(&self) -> &'static str {
        "memory"
    }
    async fn put(
        &self,
        tenant: &str,
        session: &str,
        mappings: &[TokenMapping],
    ) -> Result<(), TokenMapError> {
        self.writes.fetch_add(1, Ordering::SeqCst);
        if self.pause_write {
            self.write_started.notify_one();
            std::future::pending::<()>().await;
        }
        if self.fail_write {
            return Err(TokenMapError::Backend(
                "injected vault 5xx request content".into(),
            ));
        }
        if self.conflict {
            return Err(TokenMapError::Conflict(
                "injected conflict request content".into(),
            ));
        }
        self.inner.put(tenant, session, mappings).await
    }
    async fn get(&self, tenant: &str, session: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        if self.fail_read {
            return Err(TokenMapError::Backend(
                "injected read request content".into(),
            ));
        }
        let snapshot = self.inner.get(tenant, session).await;
        if self
            .gate_reads
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok()
        {
            self.gate.wait().await;
        }
        snapshot
    }
    async fn delete(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        self.inner.delete(tenant, session).await
    }
    async fn get_lineage(
        &self,
        tenant: &str,
        subject: &str,
    ) -> Result<CredentialLineage, TokenMapError> {
        self.inner.get_lineage(tenant, subject).await
    }
    async fn put_lineage(
        &self,
        tenant: &str,
        subject: &str,
        lineage: &CredentialLineage,
    ) -> Result<(), TokenMapError> {
        self.inner.put_lineage(tenant, subject, lineage).await
    }
    async fn health(&self) -> Result<(), TokenMapError> {
        Ok(())
    }
}
async fn harness(store: Arc<TestStore>) -> (AppState, axum::Router, Arc<FixtureRecognizer>) {
    let mut config = ResolvedConfig::default();
    config.vault.backend = VaultBackend::Memory;
    // Batch integrity must hold even under a legacy non-fail-closed profile.
    config.policy = Arc::new(policy_with(tokenize_profile(false)));
    let recognizer = Arc::new(FixtureRecognizer::default());
    let mut engine = AnalyzerEngine::new();
    engine
        .recognizer_registry_mut()
        .add_recognizer(recognizer.clone());
    let mut state = GatewayServer::with_engine(config, Arc::new(engine))
        .await
        .unwrap()
        .state();
    state.tokens = store;
    // The concurrency proof needs overlapping writers. Production default is 1.
    state.batch_admission = Arc::new(tokio::sync::Semaphore::new(4));
    (state.clone(), create_router(state), recognizer)
}
async fn batch(router: axum::Router, texts: Value) -> TestResponse {
    post_json(
        router,
        "/v1/redact",
        json!({"texts": texts, "session_id": "batch-synthetic"}),
    )
    .await
}

#[tokio::test]
async fn c1_single_parity_and_session_effects() {
    let store = Arc::new(TestStore::default());
    let (_, router, _) = harness(store.clone()).await;
    let single = post_json(
        router.clone(),
        "/v1/redact",
        json!({"text":"person-a", "session_id":"legacy-synthetic", "unknown_additive":true}),
    )
    .await;
    let batched = batch(router.clone(), json!(["person-a"])).await;
    assert_eq!(single.status, StatusCode::OK);
    assert_eq!(batched.status, StatusCode::OK);
    assert_eq!(single.json()["text"], batched.json()["texts"][0]);
    assert_eq!(single.json()["outcome"], batched.json()["outcome"]);
    assert!(batched.json().get("text").is_none());
    assert_eq!(
        store
            .inner
            .get("default", "legacy-synthetic")
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        store
            .inner
            .get("default", "batch-synthetic")
            .await
            .unwrap()
            .len(),
        1
    );
    let follow = post_json(
        router,
        "/v1/redact",
        json!({"text":"person-a person-b", "session_id":"batch-synthetic"}),
    )
    .await;
    assert_eq!(follow.json()["text"], "[PERSON_1] [PERSON_2]");
}

#[tokio::test]
async fn c2_c3_c4_c5_order_reuse_no_bypass_and_unicode() {
    let store = Arc::new(TestStore::default());
    let (_, router, recognizer) = harness(store.clone()).await;
    let response = batch(
        router,
        json!([
            "person-b",
            "\"person-a\"\n雪\\",
            "[PERSON_99] person-b",
            "",
            " ",
            "meta:person-a"
        ]),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(
        response.json()["texts"],
        json!([
            "[PERSON_1]",
            "\"[PERSON_2]\"\n雪\\",
            "[PERSON_99] [PERSON_1]",
            "",
            " ",
            "meta:[PERSON_2]"
        ])
    );
    assert_eq!(store.writes.load(Ordering::SeqCst), 1);
    assert_eq!(
        store
            .inner
            .get("default", "batch-synthetic")
            .await
            .unwrap()
            .len(),
        2
    );
    assert_eq!(recognizer.seen.load(Ordering::SeqCst), 4); // engine skips empty/whitespace text
}

#[tokio::test]
async fn c6_shapes_and_byte_bounds_fail_before_detection() {
    let (_, router, recognizer) = harness(Arc::new(TestStore::default())).await;
    for body in [
        json!({}),
        json!({"text":"x", "texts":["x"]}),
        json!({"texts":[]}),
        json!({"texts":"x"}),
        json!({"texts":[null]}),
        json!({"text":null,"texts":["x"]}),
        json!({"texts":null,"text":"x"}),
        json!({"texts":vec!["x";801]}),
        json!({"texts":["x".repeat(MAX_BATCH_TEXT_BYTES+1)]}),
        json!({"texts":vec!["x".repeat(MAX_BATCH_TEXT_BYTES); MAX_BATCH_TOTAL_BYTES/MAX_BATCH_TEXT_BYTES+1]}),
    ] {
        let response = post_json(router.clone(), "/v1/redact", body).await;
        assert!(response.status.is_client_error(), "{}", response.body);
    }
    assert_eq!(recognizer.seen.load(Ordering::SeqCst), 0);
    for n in [139, 347, 800] {
        let texts: Vec<_> = (0..n).map(|i| format!("synthetic leaf {i}")).collect();
        let response = batch(router.clone(), json!(texts)).await;
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(response.json()["texts"], json!(texts));
    }
}

#[tokio::test]
async fn c7_concurrent_shared_session_person_collisions_retry_and_reuse() {
    let store = Arc::new(TestStore::default());
    store.gate_reads.store(4, Ordering::SeqCst);
    let (state, router, _) = harness(store.clone()).await;
    let mut tasks = Vec::new();
    for person in ["person-a", "person-b", "person-c", "person-d"] {
        let router = router.clone();
        tasks.push(tokio::spawn(async move {
            batch(router, json!([person, "person-a"])).await
        }));
    }
    for task in tasks {
        assert_eq!(task.await.unwrap().status, StatusCode::OK);
    }
    let mappings = store.inner.get("default", "batch-synthetic").await.unwrap();
    assert_eq!(mappings.len(), 4);
    let mut labels = std::collections::BTreeSet::new();
    let mut values = std::collections::BTreeSet::new();
    for mapping in mappings {
        assert!(labels.insert(mapping.token));
        assert!(values.insert(state.dek.open(&mapping.sealed_value).unwrap()));
    }
    assert!(store.writes.load(Ordering::SeqCst) > 4);
}

#[tokio::test]
async fn c8_capability_and_rollback() {
    let (state, router, _) = harness(Arc::new(TestStore::default())).await;
    let status = get_path(router.clone(), "/v1/compliance/status").await;
    assert_eq!(status.json()["capabilities"]["redact_texts_v1"], true);
    let mut config = (*state.config()).clone();
    config.server.redact_batch_enabled = false;
    state.config.store(config);
    assert_eq!(
        get_path(router.clone(), "/v1/compliance/status")
            .await
            .json()["capabilities"]["redact_texts_v1"],
        false
    );
    assert_eq!(
        batch(router.clone(), json!(["person-a"])).await.status,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_json(router, "/v1/redact", json!({"text":"person-a"}))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn c9_detector_vault_and_conflict_failures_are_atomic_and_sanitized() {
    for store in [
        TestStore {
            fail_read: true,
            ..Default::default()
        },
        TestStore {
            fail_write: true,
            ..Default::default()
        },
        TestStore {
            conflict: true,
            ..Default::default()
        },
        TestStore::default(),
    ] {
        let store = Arc::new(store);
        let (_, router, _) = harness(store.clone()).await;
        let response = batch(router, json!(["person-a", "inject-error"])).await;
        assert!(response.status.is_server_error());
        assert!(response.json().get("texts").is_none());
        assert!(!response.body.contains("request content"));
        assert!(!response.body.contains("person-a"));
        assert!(store
            .inner
            .get("default", "batch-synthetic")
            .await
            .unwrap()
            .is_empty());
        if !store.fail_read {
            assert_eq!(store.writes.load(Ordering::SeqCst), 0);
        }
    }
    for conflict in [false, true] {
        let store = Arc::new(TestStore {
            fail_write: !conflict,
            conflict,
            ..Default::default()
        });
        let (_, router, _) = harness(store.clone()).await;
        let response = batch(router, json!(["person-a", "person-b"])).await;
        assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!response.body.contains("request content"));
        assert_eq!(
            store.writes.load(Ordering::SeqCst),
            if conflict { 8 } else { 1 }
        );
        assert!(store
            .inner
            .get("default", "batch-synthetic")
            .await
            .unwrap()
            .is_empty());
    }
}

#[tokio::test]
async fn c9_deadline_between_leaves_and_cancel_pending_write() {
    let store = Arc::new(TestStore::default());
    let (_, router, recognizer) = harness(store.clone()).await;
    let mut texts = vec!["slow-leaf person-a".to_string()];
    texts.extend((0..32).map(|i| format!("leaf-{i}")));
    let response = post_json_with_headers(
        router,
        "/v1/redact",
        json!({"texts": texts, "session_id":"batch-synthetic"}),
        &[("x-censgate-redact-timeout-ms", "1")],
    )
    .await;
    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    // The in-flight micro-batch finishes; the next chunk and the write do not start.
    assert_eq!(recognizer.seen.load(Ordering::SeqCst), 32);
    assert_eq!(store.writes.load(Ordering::SeqCst), 0);
    let paused = Arc::new(TestStore {
        pause_write: true,
        ..Default::default()
    });
    let (_, router, _) = harness(paused.clone()).await;
    let task = tokio::spawn(async move { batch(router, json!(["person-a", "person-b"])).await });
    paused.write_started.notified().await;
    task.abort();
    assert!(matches!(task.await, Err(err) if err.is_cancelled()));
    assert!(paused
        .inner
        .get("default", "batch-synthetic")
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn admission_rejects_a_second_batch_before_detection_or_write() {
    let store = Arc::new(TestStore::default());
    let (mut state, _, recognizer) = harness(store.clone()).await;
    state.batch_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.batch_queue = std::time::Duration::ZERO;
    let router = create_router(state);
    let running = tokio::spawn({
        let router = router.clone();
        async move { batch(router, json!(["slow-leaf person-a", "slow-leaf person-b"])).await }
    });
    let started = tokio::time::Instant::now();
    while recognizer.seen.load(Ordering::SeqCst) == 0 {
        if started.elapsed() > std::time::Duration::from_secs(2) {
            panic!("admitted batch did not start");
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let rejected = batch(router, json!(["person-c"])).await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.json()["error"]["type"], "overload");
    assert!(!rejected.body.contains("person-c"));
    let admitted = running.await.unwrap();
    assert_eq!(admitted.status, StatusCode::OK);
    assert_eq!(recognizer.seen.load(Ordering::SeqCst), 2);
    assert_eq!(store.writes.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn session_documents_reuse_tokens_and_reject_an_oversized_request() {
    let store = Arc::new(TestStore::default());
    let (mut state, _, _) = harness(store).await;
    let maps = Arc::new(MemoryStore::with_doc_limit(
        std::time::Duration::from_secs(3600),
        2,
    ));
    state.tokens = maps.clone();
    let router = create_router(state);
    let first = batch(router.clone(), json!(["person-a person-b"])).await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(first.json()["texts"][0], "[PERSON_1] [PERSON_2]");
    let second = batch(router.clone(), json!(["person-c person-d"])).await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    assert_eq!(second.json()["texts"][0], "[PERSON_3] [PERSON_4]");
    let reused = batch(router.clone(), json!(["person-a person-c"])).await;
    assert_eq!(reused.status, StatusCode::OK, "{}", reused.body);
    assert_eq!(reused.json()["texts"][0], "[PERSON_1] [PERSON_3]");
    assert_eq!(
        maps.get("default", "batch-synthetic").await.unwrap().len(),
        4
    );

    let oversized = post_json(
        router,
        "/v1/redact",
        json!({"texts":["person-a person-b person-c"], "session_id":"fresh-synthetic"}),
    )
    .await;
    assert_eq!(oversized.status, StatusCode::CONFLICT);
    assert_eq!(oversized.json()["error"]["type"], "session_map_full");
    assert!(!oversized.body.contains("person-a"));
    assert!(maps
        .get("default", "fresh-synthetic")
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn admission_waits_in_a_bounded_queue() {
    let store = Arc::new(TestStore {
        pause_write: true,
        ..TestStore::default()
    });
    let (mut state, _, _) = harness(store.clone()).await;
    state.batch_admission = Arc::new(tokio::sync::Semaphore::new(1));
    state.batch_queue = std::time::Duration::from_secs(2);
    state.batch_queue_depth = 1;
    state.batch_waiters = Arc::new(AtomicUsize::new(0));
    let waiters = state.batch_waiters.clone();
    let router = create_router(state);
    let running = tokio::spawn({
        let router = router.clone();
        async move { batch(router, json!(["person-a"])).await }
    });
    tokio::time::timeout(
        std::time::Duration::from_secs(2),
        store.write_started.notified(),
    )
    .await
    .expect("admitted batch did not reach the write");
    let queued = tokio::spawn({
        let router = router.clone();
        async move {
            post_json(
                router,
                "/v1/redact",
                json!({"texts":["person-c"], "session_id":"queue-synthetic"}),
            )
            .await
        }
    });
    let started = tokio::time::Instant::now();
    while waiters.load(Ordering::SeqCst) == 0 {
        if started.elapsed() > std::time::Duration::from_secs(2) {
            panic!("second batch did not wait");
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let rejected = post_json(
        router,
        "/v1/redact",
        json!({"texts":["person-d"], "session_id":"overflow-synthetic"}),
    )
    .await;
    assert_eq!(rejected.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(rejected.json()["error"]["type"], "overload");
    assert!(!rejected.body.contains("person-d"));
    running.abort();
    queued.abort();
}
