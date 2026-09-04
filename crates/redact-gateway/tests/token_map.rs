// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Token map store backends: memory, disabled, and KV v2 against a mock Vault.

use chrono::{Duration, Utc};
use redact_gateway::config::{VaultAuthMethod, VaultBackend, VaultSettings};
use redact_gateway::redact::token::{Dek, TokenMapping};
use redact_gateway::vault::{
    build_store, session_path, DisabledStore, MemoryStore, TokenMapError, TokenMapStore,
};

fn mapping(token: &str, sealed: &str) -> TokenMapping {
    TokenMapping {
        token: token.to_string(),
        entity_type: "EMAIL_ADDRESS".to_string(),
        sealed_value: sealed.to_string(),
        created_at: Utc::now(),
    }
}

fn sealed_email(plaintext: &str) -> (Dek, String) {
    let dek = Dek::generate().unwrap();
    let sealed = dek.seal(plaintext).unwrap();
    (dek, sealed)
}

#[tokio::test]
async fn memory_put_get_round_trip() {
    let store = MemoryStore::new(3600);
    let (_dek, sealed) = sealed_email("alice@example.com");
    let mappings = vec![mapping("[EMAIL_ADDRESS_1]", &sealed)];

    store.put("acme", "sess-1", &mappings).await.unwrap();
    let loaded = store.get("acme", "sess-1").await.unwrap();
    assert_eq!(loaded.len(), 1);
    assert_eq!(loaded[0].token, "[EMAIL_ADDRESS_1]");
    assert_eq!(loaded[0].sealed_value, sealed);
    assert!(!loaded[0].sealed_value.contains("alice"));
}

#[tokio::test]
async fn memory_merges_mappings_for_the_same_session() {
    let store = MemoryStore::new(3600);
    let (_dek, sealed_a) = sealed_email("a@example.com");
    let (_dek, sealed_b) = sealed_email("b@example.com");

    store
        .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed_a)])
        .await
        .unwrap();
    store
        .put("t", "s", &[mapping("[EMAIL_ADDRESS_2]", &sealed_b)])
        .await
        .unwrap();

    let loaded = store.get("t", "s").await.unwrap();
    assert_eq!(loaded.len(), 2);
}

#[tokio::test]
async fn memory_isolates_sessions_and_tenants() {
    let store = MemoryStore::new(3600);
    let (_dek, sealed) = sealed_email("alice@example.com");
    let mappings = vec![mapping("[EMAIL_ADDRESS_1]", &sealed)];

    store.put("tenant-a", "sess-1", &mappings).await.unwrap();
    store.put("tenant-a", "sess-2", &[]).await.unwrap();
    store.put("tenant-b", "sess-1", &[]).await.unwrap();

    assert_eq!(store.get("tenant-a", "sess-1").await.unwrap().len(), 1);
    assert!(store.get("tenant-a", "sess-2").await.unwrap().is_empty());
    assert!(store.get("tenant-b", "sess-1").await.unwrap().is_empty());
}

#[tokio::test]
async fn memory_delete_forgets_a_session() {
    let store = MemoryStore::new(3600);
    let (_dek, sealed) = sealed_email("alice@example.com");
    store
        .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed)])
        .await
        .unwrap();
    store.delete("t", "s").await.unwrap();
    assert!(store.get("t", "s").await.unwrap().is_empty());
}

#[tokio::test]
async fn memory_ttl_expiry_without_long_sleep() {
    let store = MemoryStore::with_ttl(std::time::Duration::from_secs(60));
    let start = Utc::now();
    store.set_now_for_test(start).await;

    let (_dek, sealed) = sealed_email("alice@example.com");
    store
        .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed)])
        .await
        .unwrap();
    assert_eq!(store.get("t", "s").await.unwrap().len(), 1);

    store.set_now_for_test(start + Duration::seconds(61)).await;
    assert!(store.get("t", "s").await.unwrap().is_empty());
}

#[tokio::test]
async fn disabled_backend_returns_disabled() {
    let store = DisabledStore;
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

    let settings = VaultSettings {
        backend: VaultBackend::Off,
        ..VaultSettings::default()
    };
    let built = build_store(&settings).await.unwrap();
    assert_eq!(built.backend_name(), "off");
    assert!(matches!(
        built.get("t", "s").await,
        Err(TokenMapError::Disabled)
    ));
}

#[tokio::test]
async fn path_traversal_cannot_read_another_tenant() {
    let store = MemoryStore::new(3600);
    let (_dek, sealed) = sealed_email("secret@example.com");
    store
        .put("victim", "sess", &[mapping("[EMAIL_ADDRESS_1]", &sealed)])
        .await
        .unwrap();

    // Traversal-shaped tenant/session ids are sanitized to distinct keys.
    assert!(store.get("../victim", "sess").await.unwrap().is_empty());
    assert!(store.get("victim", "../sess").await.unwrap().is_empty());
    assert!(store.get("vic/tim", "sess").await.unwrap().is_empty());
    assert!(store.get("victim", "other/sess").await.unwrap().is_empty());

    // Writing under a traversal-shaped id must not overwrite the victim.
    store
        .put(
            "../victim",
            "sess",
            &[mapping("[EMAIL_ADDRESS_9]", "cipher")],
        )
        .await
        .unwrap();
    let victim = store.get("victim", "sess").await.unwrap();
    assert_eq!(victim.len(), 1);
    assert_eq!(victim[0].token, "[EMAIL_ADDRESS_1]");

    assert_ne!(
        session_path("p", "../victim", "sess"),
        session_path("p", "victim", "sess")
    );
    assert_ne!(session_path("p", "t", "a/b"), session_path("p", "t", "a"));
}

#[tokio::test]
#[cfg(not(feature = "vault"))]
async fn build_store_vault_kv2_without_feature_is_unavailable() {
    let settings = VaultSettings {
        backend: VaultBackend::VaultKv2,
        address: Some("http://127.0.0.1:8200".to_string()),
        token: Some("t".to_string()),
        ..VaultSettings::default()
    };
    let err = build_store(&settings).await.unwrap_err();
    match err {
        TokenMapError::Unavailable(msg) => {
            assert!(
                msg.contains("vault"),
                "expected missing-feature message, got {msg}"
            );
        }
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

// --- Mock Vault KV v2 -------------------------------------------------------

#[cfg(feature = "vault")]
mod kv2_mock {
    use super::*;
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use axum::body::Bytes;
    use axum::extract::{Path, State};
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use redact_gateway::vault::Kv2Store;
    use serde_json::{json, Value};
    use tokio::sync::Mutex;

    #[derive(Clone)]
    struct SecretEntry {
        data: Value,
        version: u64,
    }

    #[derive(Clone, Default)]
    struct MockVaultState {
        secrets: Arc<Mutex<HashMap<String, SecretEntry>>>,
        /// Last JSON body received by a POST to `/v1/{mount}/data/{*path}`.
        last_write: Arc<Mutex<Option<Value>>>,
        /// Remaining times a would-be-successful CAS write is rejected to
        /// simulate a concurrent writer winning the race.
        cas_fail_remaining: Arc<Mutex<u32>>,
        /// When a forced CAS failure fires, optionally apply this payload as
        /// the concurrent writer's successful write (version bump included).
        concurrent_data_on_cas_fail: Arc<Mutex<Option<Value>>>,
        /// Counts POST attempts that reached the CAS check (for assertions).
        write_attempts: Arc<Mutex<u32>>,
        /// Kubernetes auth logins recorded (role + jwt).
        logins: Arc<Mutex<Vec<(String, String)>>>,
    }

    impl MockVaultState {
        async fn arm_cas_fail(&self, times: u32, concurrent_data: Option<Value>) {
            *self.cas_fail_remaining.lock().await = times;
            *self.concurrent_data_on_cas_fail.lock().await = concurrent_data;
        }
    }

    fn cas_conflict_response() -> axum::response::Response {
        (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "errors": [
                    "check-and-set parameter did not match the current version"
                ]
            })),
        )
            .into_response()
    }

    async fn mock_k8s_login(State(state): State<MockVaultState>, body: Bytes) -> impl IntoResponse {
        let body: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "errors": [err.to_string()] })),
                )
                    .into_response();
            }
        };
        let role = body
            .get("role")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let jwt = body
            .get("jwt")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        state.logins.lock().await.push((role, jwt));
        (
            StatusCode::OK,
            Json(json!({
                "auth": {
                    "client_token": "k8s-issued-token",
                    "lease_duration": 3600,
                    "renewable": true
                }
            })),
        )
            .into_response()
    }

    async fn mock_health() -> impl IntoResponse {
        Json(json!({
            "initialized": true,
            "sealed": false,
            "standby": false,
            "performance_standby": false,
            "replication_performance_mode": "disabled",
            "replication_dr_mode": "disabled",
            "server_time_utc": 1_700_000_000_i64,
            "version": "1.15.0",
            "cluster_name": "mock",
            "cluster_id": "00000000-0000-0000-0000-000000000000"
        }))
    }

    async fn mock_read_secret(
        State(state): State<MockVaultState>,
        Path((mount, path)): Path<(String, String)>,
    ) -> impl IntoResponse {
        let key = format!("{mount}/data/{path}");
        let secrets = state.secrets.lock().await;
        match secrets.get(&key) {
            Some(entry) => (
                StatusCode::OK,
                Json(json!({
                    "request_id": "mock",
                    "lease_id": "",
                    "renewable": false,
                    "lease_duration": 0,
                    "data": {
                        "data": entry.data,
                        "metadata": {
                            "created_time": "2024-01-01T00:00:00Z",
                            "deletion_time": "",
                            "destroyed": false,
                            "version": entry.version,
                            "custom_metadata": null
                        }
                    }
                })),
            )
                .into_response(),
            None => (StatusCode::NOT_FOUND, Json(json!({ "errors": [] }))).into_response(),
        }
    }

    async fn mock_write_secret(
        State(state): State<MockVaultState>,
        Path((mount, path)): Path<(String, String)>,
        body: Bytes,
    ) -> impl IntoResponse {
        // vaultrs does not always set Content-Type, so parse JSON from raw bytes.
        let body: Value = match serde_json::from_slice(&body) {
            Ok(v) => v,
            Err(err) => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "errors": [err.to_string()] })),
                )
                    .into_response();
            }
        };
        let key = format!("{mount}/data/{path}");
        *state.last_write.lock().await = Some(body.clone());
        *state.write_attempts.lock().await += 1;

        let data = body
            .get("data")
            .cloned()
            .unwrap_or(Value::Object(Default::default()));
        let cas = body
            .pointer("/options/cas")
            .and_then(|v| v.as_u64().or_else(|| v.as_i64().map(|n| n as u64)));

        let mut secrets = state.secrets.lock().await;
        let current_version = secrets.get(&key).map(|e| e.version).unwrap_or(0);

        if let Some(cas) = cas {
            if cas != current_version {
                return cas_conflict_response();
            }
        }

        // Simulate a concurrent writer: reject this CAS and advance the key.
        let mut fail_remaining = state.cas_fail_remaining.lock().await;
        if *fail_remaining > 0 {
            *fail_remaining -= 1;
            let concurrent = state.concurrent_data_on_cas_fail.lock().await.clone();
            let new_version = current_version + 1;
            if let Some(concurrent_data) = concurrent {
                secrets.insert(
                    key,
                    SecretEntry {
                        data: concurrent_data,
                        version: new_version,
                    },
                );
            } else if let Some(entry) = secrets.get_mut(&key) {
                entry.version = new_version;
            } else {
                // cas=0 create race: leave a readable empty session at v1.
                secrets.insert(
                    key,
                    SecretEntry {
                        data: json!({
                            "mappings": [],
                            "expires_at": "2099-01-01T00:00:00Z",
                        }),
                        version: new_version,
                    },
                );
            }
            return cas_conflict_response();
        }
        drop(fail_remaining);

        let new_version = current_version + 1;
        secrets.insert(
            key,
            SecretEntry {
                data,
                version: new_version,
            },
        );
        (
            StatusCode::OK,
            Json(json!({
                "request_id": "mock",
                "lease_id": "",
                "renewable": false,
                "lease_duration": 0,
                "data": {
                    "created_time": "2024-01-01T00:00:00Z",
                    "deletion_time": "",
                    "destroyed": false,
                    "version": new_version,
                    "custom_metadata": null
                }
            })),
        )
            .into_response()
    }

    async fn mock_delete_secret(
        State(state): State<MockVaultState>,
        Path((mount, path)): Path<(String, String)>,
    ) -> impl IntoResponse {
        let key = format!("{mount}/data/{path}");
        state.secrets.lock().await.remove(&key);
        StatusCode::NO_CONTENT
    }

    async fn start_mock_vault() -> (SocketAddr, MockVaultState) {
        let state = MockVaultState::default();
        let app = Router::new()
            .route("/v1/sys/health", get(mock_health))
            .route("/v1/auth/{mount}/login", post(mock_k8s_login))
            .route(
                "/v1/{mount}/data/{*path}",
                get(mock_read_secret)
                    .post(mock_write_secret)
                    .delete(mock_delete_secret),
            )
            .with_state(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        // Give the accept loop a tick so the first client connect succeeds.
        tokio::task::yield_now().await;
        (addr, state)
    }

    fn kv2_settings(addr: SocketAddr) -> VaultSettings {
        VaultSettings {
            backend: VaultBackend::VaultKv2,
            address: Some(format!("http://{addr}")),
            token: Some("test-token".to_string()),
            ..VaultSettings::default()
        }
    }

    fn stored_session_json(mappings: &[TokenMapping]) -> Value {
        json!({
            "mappings": mappings,
            "expires_at": (Utc::now() + Duration::hours(1)).to_rfc3339(),
        })
    }

    #[tokio::test]
    async fn kv2_put_get_delete_round_trip_against_mock() {
        let (addr, state) = start_mock_vault().await;
        let store = Kv2Store::from_settings(&kv2_settings(addr)).unwrap();
        assert_eq!(store.backend_name(), "vault_kv2");

        store.health().await.expect("mock health should pass");

        let plaintext = "alice@example.com";
        let (_dek, sealed) = sealed_email(plaintext);
        assert!(!sealed.contains("alice"));

        let mappings = vec![mapping("[EMAIL_ADDRESS_1]", &sealed)];
        store.put("acme", "chat-1", &mappings).await.unwrap();

        // Stored payload must contain only ciphertext.
        let written = state
            .last_write
            .lock()
            .await
            .clone()
            .expect("mock should have recorded a write");
        let rendered = written.to_string();
        assert!(
            !rendered.contains(plaintext),
            "plaintext leaked into vault payload: {rendered}"
        );
        assert!(
            rendered.contains(&sealed),
            "sealed value missing from vault payload: {rendered}"
        );
        assert!(
            written.pointer("/options/cas").is_some(),
            "CAS option missing from vault write: {rendered}"
        );

        let loaded = store.get("acme", "chat-1").await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].sealed_value, sealed);

        // Missing session is empty, not an error.
        assert!(store.get("acme", "missing").await.unwrap().is_empty());

        store.delete("acme", "chat-1").await.unwrap();
        assert!(store.get("acme", "chat-1").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn kv2_first_write_to_new_session_succeeds() {
        let (addr, state) = start_mock_vault().await;
        let store = Kv2Store::from_settings(&kv2_settings(addr)).unwrap();
        let (_dek, sealed) = sealed_email("first@example.com");

        store
            .put("t", "new-sess", &[mapping("[EMAIL_ADDRESS_1]", &sealed)])
            .await
            .unwrap();

        let written = state.last_write.lock().await.clone().unwrap();
        assert_eq!(
            written.pointer("/options/cas").and_then(|v| v.as_u64()),
            Some(0)
        );
        assert_eq!(store.get("t", "new-sess").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn kv2_sequential_writes_both_survive() {
        let (addr, _) = start_mock_vault().await;
        let store = Kv2Store::from_settings(&kv2_settings(addr)).unwrap();
        let (_dek, sealed_a) = sealed_email("a@example.com");
        let (_dek, sealed_b) = sealed_email("b@example.com");

        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed_a)])
            .await
            .unwrap();
        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_2]", &sealed_b)])
            .await
            .unwrap();

        let loaded = store.get("t", "s").await.unwrap();
        let tokens: Vec<_> = loaded.iter().map(|m| m.token.as_str()).collect();
        assert_eq!(loaded.len(), 2);
        assert!(tokens.contains(&"[EMAIL_ADDRESS_1]"));
        assert!(tokens.contains(&"[EMAIL_ADDRESS_2]"));
    }

    #[tokio::test]
    async fn kv2_build_store_and_merge_against_mock() {
        let (addr, _) = start_mock_vault().await;
        let settings = kv2_settings(addr);
        let store = build_store(&settings).await.unwrap();
        assert_eq!(store.backend_name(), "vault_kv2");

        let (_dek, sealed_a) = sealed_email("a@example.com");
        let (_dek, sealed_b) = sealed_email("b@example.com");
        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed_a)])
            .await
            .unwrap();
        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_2]", &sealed_b)])
            .await
            .unwrap();
        assert_eq!(store.get("t", "s").await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn kv2_stale_cas_retries_and_keeps_both_writers() {
        let (addr, state) = start_mock_vault().await;
        let store = Kv2Store::from_settings(&kv2_settings(addr)).unwrap();

        let (_dek, sealed_a) = sealed_email("a@example.com");
        let (_dek, sealed_b) = sealed_email("b@example.com");
        let (_dek, sealed_c) = sealed_email("c@example.com");

        // Seed version 1 with writer A's mapping.
        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed_a)])
            .await
            .unwrap();

        // Next write (writer B) will see a stale CAS: the mock applies writer C's
        // merged result (A+C) concurrently, bumps the version, and returns a
        // check-and-set error. B must re-read, merge, and retry so A+B+C survive.
        let concurrent_c = stored_session_json(&[
            mapping("[EMAIL_ADDRESS_1]", &sealed_a),
            mapping("[EMAIL_ADDRESS_3]", &sealed_c),
        ]);
        state.arm_cas_fail(1, Some(concurrent_c)).await;

        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_2]", &sealed_b)])
            .await
            .unwrap();

        assert!(
            *state.write_attempts.lock().await >= 3,
            "expected seed write + failed CAS + successful retry"
        );

        let loaded = store.get("t", "s").await.unwrap();
        let tokens: Vec<_> = loaded.iter().map(|m| m.token.as_str()).collect();
        assert_eq!(
            loaded.len(),
            3,
            "expected both writers plus seed: {tokens:?}"
        );
        assert!(tokens.contains(&"[EMAIL_ADDRESS_1]"));
        assert!(tokens.contains(&"[EMAIL_ADDRESS_2]"));
        assert!(tokens.contains(&"[EMAIL_ADDRESS_3]"));
    }

    #[tokio::test]
    async fn kv2_exhausted_cas_retries_return_backend_error() {
        let (addr, state) = start_mock_vault().await;
        let store = Kv2Store::from_settings(&kv2_settings(addr)).unwrap();
        let (_dek, sealed_a) = sealed_email("a@example.com");
        let (_dek, sealed_b) = sealed_email("b@example.com");

        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed_a)])
            .await
            .unwrap();

        // More forced failures than the client's retry budget.
        state.arm_cas_fail(10, None).await;

        let err = store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_2]", &sealed_b)])
            .await
            .unwrap_err();
        match err {
            TokenMapError::Backend(msg) => {
                assert!(
                    msg.to_ascii_lowercase().contains("compare-and-set")
                        || msg.to_ascii_lowercase().contains("check-and-set"),
                    "expected CAS conflict message, got {msg}"
                );
            }
            other => panic!("expected Backend error, got {other:?}"),
        }

        // Seed mapping A must still be present — exhausted retries must not
        // clobber existing data with a lossy unconditional write.
        let loaded = store.get("t", "s").await.unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].token, "[EMAIL_ADDRESS_1]");
    }

    #[tokio::test]
    async fn kv2_tenant_isolation_against_mock() {
        let (addr, _) = start_mock_vault().await;
        let store = Kv2Store::from_settings(&kv2_settings(addr)).unwrap();
        let (_dek, sealed) = sealed_email("secret@example.com");
        store
            .put("victim", "sess", &[mapping("[EMAIL_ADDRESS_1]", &sealed)])
            .await
            .unwrap();

        assert!(store.get("../victim", "sess").await.unwrap().is_empty());
        assert_eq!(store.get("victim", "sess").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn kv2_skips_put_when_mappings_are_empty() {
        let (addr, state) = start_mock_vault().await;
        let store = Kv2Store::from_settings(&kv2_settings(addr)).unwrap();
        store.put("t", "s", &[]).await.unwrap();
        assert_eq!(*state.write_attempts.lock().await, 0);
        assert!(state.last_write.lock().await.is_none());
    }

    #[tokio::test]
    async fn kv2_kubernetes_auth_logins_and_caches_the_token() {
        let (addr, state) = start_mock_vault().await;
        let jwt_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(jwt_file.path(), "projected-sa-jwt").unwrap();

        let settings = VaultSettings {
            backend: VaultBackend::VaultKv2,
            address: Some(format!("http://{addr}")),
            auth: VaultAuthMethod::Kubernetes,
            kubernetes_role: Some("redact-gateway".into()),
            jwt_path: jwt_file.path().to_path_buf(),
            token: None,
            ..VaultSettings::default()
        };
        let store = Kv2Store::from_settings(&settings).unwrap();
        let (_dek, sealed) = sealed_email("k8s@example.com");
        store
            .put("t", "s", &[mapping("[EMAIL_ADDRESS_1]", &sealed)])
            .await
            .unwrap();
        store.get("t", "s").await.unwrap();

        let logins = state.logins.lock().await.clone();
        assert_eq!(logins.len(), 1, "login should be cached across put+get");
        assert_eq!(logins[0].0, "redact-gateway");
        assert_eq!(logins[0].1, "projected-sa-jwt");
        assert_eq!(store.get("t", "s").await.unwrap().len(), 1);
    }
}
