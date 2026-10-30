// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Parallel `/v1/redact` calls on one session must not fail because two
//! requests minted the same token label.
//!
//! Every request resumes the session, mints labels from a per-request counter
//! and then merges its new mappings into the store. Requests that all read the
//! session before any of them writes therefore mint the same label (and seal
//! with a fresh random nonce, so even identical values differ as ciphertext).
//! The store rejects the late writers as a merge conflict; the handler must
//! re-read and re-mint instead of surfacing a 503.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::StatusCode;
use redact_gateway::redact::token::TokenMapping;
use redact_gateway::routes::{create_router, AppState};
use redact_gateway::vault::{CredentialLineage, MemoryStore, TokenMapError, TokenMapStore};
use serde_json::json;
use support::*;
use tokio::sync::Barrier;

const PARALLEL: usize = 4;
const SESSION: &str = "shared-session";

/// Delegates to a [`MemoryStore`] but, once armed, holds the first
/// `PARALLEL` reads at a barrier so every request observes the same snapshot
/// before any request writes. This makes the interleaving deterministic.
#[derive(Debug)]
struct GatedStore {
    inner: MemoryStore,
    barrier: Barrier,
    gated_reads_left: AtomicUsize,
    put_calls: AtomicUsize,
    always_conflict: bool,
}

impl GatedStore {
    fn new(always_conflict: bool) -> Self {
        Self {
            inner: MemoryStore::new(3600),
            barrier: Barrier::new(PARALLEL),
            gated_reads_left: AtomicUsize::new(0),
            put_calls: AtomicUsize::new(0),
            always_conflict,
        }
    }

    fn arm(&self) {
        self.gated_reads_left.store(PARALLEL, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl TokenMapStore for GatedStore {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    async fn put(
        &self,
        tenant: &str,
        session: &str,
        mappings: &[TokenMapping],
    ) -> Result<(), TokenMapError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        if self.always_conflict {
            return Err(TokenMapError::Conflict("forced".to_string()));
        }
        self.inner.put(tenant, session, mappings).await
    }

    async fn get(&self, tenant: &str, session: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        let gated = self
            .gated_reads_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        let snapshot = self.inner.get(tenant, session).await;
        if gated {
            self.barrier.wait().await;
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

async fn harness(store: Arc<GatedStore>, fail_closed: bool) -> (AppState, axum::Router) {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.vault.backend = redact_gateway::config::VaultBackend::Memory;
    config.policy = Arc::new(policy_with(tokenize_profile(fail_closed)));
    let mut state = state_for(config).await;
    state.tokens = store;
    let router = create_router(state.clone());
    (state, router)
}

async fn redact(router: axum::Router, email: &str) -> TestResponse {
    post_json(
        router,
        "/v1/redact",
        json!({"text": format!("mail {email}"), "session_id": SESSION}),
    )
    .await
}

fn token_in(response: &TestResponse) -> String {
    let body = response.json();
    let text = body["text"].as_str().unwrap();
    let open = text.find('[').expect("a token in the redacted text");
    let close = text.find(']').expect("a closing bracket");
    text[open..=close].to_string()
}

/// Every stored label maps to one plaintext, and the store never holds two
/// rows for one label.
fn stored_plaintexts(state: &AppState, mappings: &[TokenMapping]) -> BTreeMap<String, String> {
    let mut by_label = BTreeMap::new();
    for mapping in mappings {
        let plaintext = state.dek.open(&mapping.sealed_value).unwrap();
        let prior = by_label.insert(mapping.token.clone(), plaintext);
        assert!(prior.is_none(), "label {} stored twice", mapping.token);
    }
    by_label
}

#[tokio::test]
async fn parallel_requests_with_distinct_values_all_succeed_and_restore() {
    let store = Arc::new(GatedStore::new(false));
    let (state, router) = harness(store.clone(), true).await;

    let seeded = redact(router.clone(), "seed@example.com").await;
    assert_eq!(seeded.status, StatusCode::OK, "{}", seeded.body);
    let seeded_token = token_in(&seeded);

    store.arm();
    let emails: Vec<String> = (0..PARALLEL)
        .map(|i| format!("user{i}@example.com"))
        .collect();
    let mut tasks = Vec::new();
    for email in emails.clone() {
        let router = router.clone();
        tasks.push(tokio::spawn(async move {
            let response = redact(router, &email).await;
            (email, response)
        }));
    }

    let mut label_for_email = BTreeMap::new();
    for task in tasks {
        let (email, response) = task.await.unwrap();
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        label_for_email.insert(email, token_in(&response));
    }

    let labels: BTreeSet<_> = label_for_email.values().cloned().collect();
    assert_eq!(
        labels.len(),
        PARALLEL,
        "labels must be unique: {label_for_email:?}"
    );
    assert!(
        !labels.contains(&seeded_token),
        "seed label must not be reissued"
    );

    let stored = stored_plaintexts(&state, &store.inner.get("default", SESSION).await.unwrap());
    assert_eq!(stored.len(), PARALLEL + 1);
    assert_eq!(stored[&seeded_token], "seed@example.com");
    for (email, label) in &label_for_email {
        assert_eq!(&stored[label], email, "label must restore to its own value");
    }
}

#[tokio::test]
async fn parallel_requests_with_the_same_value_converge_on_one_label() {
    let store = Arc::new(GatedStore::new(false));
    let (state, router) = harness(store.clone(), true).await;

    store.arm();
    let mut tasks = Vec::new();
    for _ in 0..PARALLEL {
        let router = router.clone();
        tasks.push(tokio::spawn(async move {
            redact(router, "shared@example.com").await
        }));
    }

    let mut labels = BTreeSet::new();
    for task in tasks {
        let response = task.await.unwrap();
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        labels.insert(token_in(&response));
    }
    assert_eq!(labels.len(), 1, "one value must keep one label: {labels:?}");

    let stored = stored_plaintexts(&state, &store.inner.get("default", SESSION).await.unwrap());
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[labels.iter().next().unwrap()], "shared@example.com");
}

/// `MAX_MINT_ATTEMPTS` in `routes.rs`.
const EXPECTED_MINT_ATTEMPTS: usize = 8;

/// Collects formatted tracing output so a test can assert on log content.
#[derive(Clone, Default)]
struct LogBuffer(Arc<std::sync::Mutex<Vec<u8>>>);

impl LogBuffer {
    fn contents(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
    }
}

impl std::io::Write for LogBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogBuffer {
    type Writer = LogBuffer;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn persistent_merge_conflict_fails_closed_after_exactly_max_attempts() {
    // A merge conflict is an integrity failure, so it must fail closed whether
    // or not the profile lets ordinary backend errors fail open.
    for fail_closed in [true, false] {
        let logs = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::WARN)
            .finish();
        let _logging = tracing::subscriber::set_default(subscriber);

        let store = Arc::new(GatedStore::new(true));
        let (_state, router) = harness(store.clone(), fail_closed).await;

        let response = redact(router, "alice@example.com").await;

        assert_eq!(
            response.status,
            StatusCode::SERVICE_UNAVAILABLE,
            "fail_closed={fail_closed}: {}",
            response.body
        );
        assert!(
            response.body.contains("token map write failed"),
            "fail_closed={fail_closed}: {}",
            response.body
        );
        assert_eq!(
            store.put_calls.load(Ordering::SeqCst),
            EXPECTED_MINT_ATTEMPTS,
            "fail_closed={fail_closed}: one put per attempt, no more"
        );
        assert!(
            store
                .inner
                .get("default", SESSION)
                .await
                .unwrap()
                .is_empty(),
            "fail_closed={fail_closed}: nothing may be persisted"
        );

        let logged = logs.contents();
        assert!(
            logged.contains("WARN") && logged.contains("failing closed"),
            "fail_closed={fail_closed}: expected an exhaustion warning, got {logged:?}"
        );
        assert!(
            !logged.contains("EMAIL_ADDRESS") && !logged.contains("alice"),
            "fail_closed={fail_closed}: exhaustion log must not carry tokens or values: {logged:?}"
        );
    }
}

#[cfg(feature = "vault")]
mod kv2 {
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;

    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::response::IntoResponse;
    use axum::routing::get;
    use axum::Json;
    use redact_gateway::config::{AuthMode, VaultBackend};
    use redact_gateway::redact::token::Dek;
    use serde_json::{json, Value};
    use tokio::sync::Mutex;

    #[derive(Clone, Default)]
    struct MockKv2 {
        /// path -> (payload, version)
        secrets: Arc<Mutex<HashMap<String, (Value, u64)>>>,
        /// Payload of a competing writer that lands during the next write,
        /// beating it on check-and-set.
        winner_on_next_write: Arc<Mutex<Option<Value>>>,
        /// Check-and-set values seen on write attempts, in order.
        write_cas: Arc<Mutex<Vec<u64>>>,
        reads: Arc<Mutex<u32>>,
    }

    fn cas_rejected() -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": ["check-and-set parameter did not match the current version"]
            })),
        )
            .into_response()
    }

    async fn read(
        State(state): State<MockKv2>,
        Path((mount, path)): Path<(String, String)>,
    ) -> axum::response::Response {
        *state.reads.lock().await += 1;
        match state.secrets.lock().await.get(&format!("{mount}/{path}")) {
            Some((data, version)) => Json(json!({
                "request_id": "mock",
                "lease_id": "",
                "renewable": false,
                "lease_duration": 0,
                "data": {
                    "data": data,
                    "metadata": {
                        "created_time": "2024-01-01T00:00:00Z",
                        "deletion_time": "",
                        "destroyed": false,
                        "version": version,
                        "custom_metadata": null
                    }
                }
            }))
            .into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({"errors": []}))).into_response(),
        }
    }

    async fn write(
        State(state): State<MockKv2>,
        Path((mount, path)): Path<(String, String)>,
        body: Bytes,
    ) -> axum::response::Response {
        let body: Value = serde_json::from_slice(&body).unwrap();
        let key = format!("{mount}/{path}");
        let cas = body.pointer("/options/cas").and_then(Value::as_u64);
        state.write_cas.lock().await.push(cas.unwrap_or(u64::MAX));

        let mut secrets = state.secrets.lock().await;
        let current = secrets.get(&key).map(|(_, v)| *v).unwrap_or(0);
        if let Some(winner) = state.winner_on_next_write.lock().await.take() {
            secrets.insert(key, (winner, current + 1));
            return cas_rejected();
        }
        if cas.is_some_and(|c| c != current) {
            return cas_rejected();
        }
        secrets.insert(key, (body["data"].clone(), current + 1));
        Json(json!({
            "request_id": "mock",
            "lease_id": "",
            "renewable": false,
            "lease_duration": 0,
            "data": {
                "created_time": "2024-01-01T00:00:00Z",
                "deletion_time": "",
                "destroyed": false,
                "version": current + 1,
                "custom_metadata": null
            }
        }))
        .into_response()
    }

    async fn start() -> (SocketAddr, MockKv2) {
        let state = MockKv2::default();
        let app = axum::Router::new()
            .route(
                "/v1/sys/health",
                get(|| async { Json(json!({"initialized": true, "sealed": false})) }),
            )
            .route("/v1/{mount}/data/{*path}", get(read).post(write))
            .with_state(state.clone());
        (spawn(app).await, state)
    }

    fn sealed_session(dek: &Dek, entries: &[(&str, &str)]) -> Value {
        let mappings: Vec<Value> = entries
            .iter()
            .map(|(token, plaintext)| {
                json!({
                    "token": token,
                    "entity_type": "EMAIL_ADDRESS",
                    "sealed_value": dek.seal(plaintext).unwrap(),
                    "created_at": chrono::Utc::now(),
                })
            })
            .collect();
        json!({
            "mappings": mappings,
            "expires_at": (chrono::Utc::now() + chrono::Duration::hours(1)).to_rfc3339(),
        })
    }

    /// A CAS rejection exposes a competing writer's mapping that reuses the
    /// label this request just minted. The store's retry then sees a merge
    /// conflict, and the handler must re-read, re-mint a fresh label and still
    /// return a response that restores to the right value.
    #[tokio::test]
    async fn cas_rejection_that_reveals_a_colliding_label_re_mints_and_restores() {
        let (addr, mock) = start().await;
        let upstream = mock_json_upstream(chat_response("ok")).await;
        let mut config = config_for(&upstream);
        config.vault.backend = VaultBackend::VaultKv2;
        config.vault.address = Some(format!("http://{addr}"));
        config.vault.token = Some("test-token".to_string());
        config.policy = Arc::new(policy_with(tokenize_profile(true)));
        config.auth.mode = AuthMode::ApiKey;
        config.auth.api_keys = vec!["caller-a".to_string()];
        let (state, router) = state_and_router(config).await;

        *mock.winner_on_next_write.lock().await = Some(sealed_session(
            &state.dek,
            &[("[EMAIL_ADDRESS_1]", "winner@example.com")],
        ));

        let auth = [("authorization", "Bearer caller-a")];
        let redacted = post_json_with_headers(
            router.clone(),
            "/v1/redact",
            json!({"text": "mail loser@example.com", "session_id": SESSION}),
            &auth,
        )
        .await;
        assert_eq!(redacted.status, StatusCode::OK, "{}", redacted.body);
        let redacted_text = redacted.json()["text"].as_str().unwrap().to_string();
        assert_eq!(
            redacted_text, "mail [EMAIL_ADDRESS_2]",
            "the winner owns label 1, so this request must re-mint label 2"
        );

        // Write 1 (cas=0) lost to the winner. The merge conflict is detected on
        // the store's re-read, so nothing is sent until the handler's second
        // attempt writes against the winner's version.
        assert_eq!(*mock.write_cas.lock().await, vec![0, 1]);

        let restored = post_json_with_headers(
            router.clone(),
            "/v1/restore",
            json!({"text": redacted_text, "session_id": SESSION}),
            &auth,
        )
        .await;
        assert_eq!(restored.status, StatusCode::OK, "{}", restored.body);
        assert_eq!(restored.json()["text"], "mail loser@example.com");

        let winner_label = post_json_with_headers(
            router,
            "/v1/restore",
            json!({"text": "[EMAIL_ADDRESS_1]", "session_id": SESSION}),
            &auth,
        )
        .await;
        assert_eq!(winner_label.json()["text"], "winner@example.com");

        let secrets = mock.secrets.lock().await;
        assert_eq!(secrets.len(), 1);
        let (stored, version) = secrets.values().next().unwrap();
        assert_eq!(*version, 2);
        let mut by_label = BTreeMap::new();
        for mapping in stored["mappings"].as_array().unwrap() {
            let plaintext = state
                .dek
                .open(mapping["sealed_value"].as_str().unwrap())
                .unwrap();
            let prior = by_label.insert(mapping["token"].as_str().unwrap().to_string(), plaintext);
            assert!(prior.is_none(), "label stored twice");
        }
        assert_eq!(by_label.len(), 2);
        assert_eq!(by_label["[EMAIL_ADDRESS_1]"], "winner@example.com");
        assert_eq!(by_label["[EMAIL_ADDRESS_2]"], "loser@example.com");
    }
}
