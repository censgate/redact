//! Real-backend migration, peer-replica HTTP operations and privacy boundaries.
#![cfg(feature = "vault")]
mod support;
use axum::http::StatusCode;
use redact_gateway::{config::AuthMode, routes::create_router, vault::indexed::IndexedStore};
use redact_token_store::{postgres::Postgres, TokenStore};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use support::*;

async fn exercise(target: Arc<dyn TokenStore>) {
    completed_peer_import_contract(target.clone()).await;
    erasure_contract(target.clone()).await;
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.vault.backend = redact_gateway::config::VaultBackend::Memory;
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = vec!["synthetic-owner-a".into(), "synthetic-owner-b".into()];
    config.policy = Arc::new(policy_with(tokenize_profile(false)));
    let mut state = state_for(config).await;
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let settings = redact_gateway::config::VaultSettings {
        backend: redact_gateway::config::VaultBackend::VaultKv2,
        address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
        token: Some(credential.trim().into()),
        path_prefix: format!("source-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let source: Arc<dyn redact_gateway::vault::TokenMapStore> =
        Arc::new(redact_gateway::vault::Kv2Store::from_settings(&settings).unwrap());
    state.tokens = source.clone();
    let original = create_router(state.clone());
    let context = uuid::Uuid::new_v4().to_string();
    let headers = [("authorization", "Bearer synthetic-owner-a")];
    let old = post_json_with_headers(
        original.clone(),
        "/v1/redact",
        json!({"text":"mail fixture@example.invalid","vault":{"context_id":context}}),
        &headers,
    )
    .await;
    assert_eq!(old.status, StatusCode::OK, "{}", old.body);
    let old_text = old.json()["text"].as_str().unwrap().to_string();
    assert!(old_text.contains("[EMAIL_ADDRESS_1]"));
    let second = post_json_with_headers(
        original.clone(),
        "/v1/redact",
        json!({"text":"second@example.invalid","session_id":context}),
        &headers,
    )
    .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    state.tokens = Arc::new(
        IndexedStore::new(
            target.clone(),
            source.clone(),
            state.dek.clone(),
            Duration::from_secs(3600),
        )
        .unwrap(),
    );
    let router = create_router(state.clone());
    let ready = get_path(router.clone(), "/readyz").await;
    assert_eq!(ready.status, StatusCode::OK);
    assert_eq!(
        ready.json()["token_map"]["backend"],
        state.tokens.backend_name()
    );
    let imported = post_json_with_headers(
        router.clone(),
        "/v1/restore",
        json!({"text":old_text,"vault":{"context_id":context}}),
        &headers,
    )
    .await;
    assert_eq!(imported.status, StatusCode::OK, "{}", imported.body);
    assert_eq!(imported.json()["text"], "mail fixture@example.invalid");
    // The compatible legacy binary still cannot write a migrated context. A
    // digest rollback must never reopen the source or allocate a new identity.
    let rollback_write = post_json_with_headers(
        original.clone(),
        "/v1/redact",
        json!({"text":"rollback@example.invalid","session_id":context}),
        &headers,
    )
    .await;
    assert!(!rollback_write.status.is_success());
    assert!(!rollback_write.body.contains("rollback@example.invalid"));
    // A separately constructed replica has no request-local migration state.
    let mut peer = state.clone();
    peer.tokens = Arc::new(
        IndexedStore::new(target, source, state.dek.clone(), Duration::from_secs(3600)).unwrap(),
    );
    let peer_router = create_router(peer);
    let reused = post_json_with_headers(
        peer_router.clone(),
        "/v1/redact",
        json!({"text":"mail fixture@example.invalid","session_id":context}),
        &headers,
    )
    .await;
    assert_eq!(reused.status, StatusCode::OK, "{}", reused.body);
    assert_eq!(reused.json()["text"], old_text);
    let mut workers = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let router = peer_router.clone();
        let context = context.clone();
        workers.spawn(async move {
            post_json_with_headers(
                router,
                "/v1/redact",
                json!({"text":"other@example.invalid","session_id":context}),
                &[("authorization", "Bearer synthetic-owner-a")],
            )
            .await
        });
    }
    let mut canonical = None;
    while let Some(result) = workers.join_next().await {
        let response = result.unwrap();
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        let text = response.json()["text"].as_str().unwrap().to_string();
        if let Some(expected) = &canonical {
            assert_eq!(&text, expected);
        } else {
            canonical = Some(text);
        }
    }
    let foreign = post_json_with_headers(
        peer_router.clone(),
        "/v1/restore",
        json!({"text":old_text,"session_id":context}),
        &[("authorization", "Bearer synthetic-owner-b")],
    )
    .await;
    assert_eq!(foreign.status, StatusCode::OK);
    assert_eq!(foreign.json()["text"], old_text);
    let proxy=post_json_with_headers(router.clone(),"/v1/chat/completions",json!({"model":"fixture","messages":[{"role":"user","content":"mail fixture@example.invalid"}]}),&[("authorization","Bearer synthetic-owner-a"),("x-censgate-session-id",&context)]).await;
    assert_eq!(proxy.status, StatusCode::OK, "{}", proxy.body);
    assert!(!upstream
        .last_request()
        .to_string()
        .contains("fixture@example.invalid"));
    let too_many = (1..=257)
        .map(|n| format!("[EMAIL_ADDRESS_{n}]"))
        .collect::<Vec<_>>()
        .join(" ");
    let capacity = post_json_with_headers(
        router.clone(),
        "/v1/restore",
        json!({"text":too_many,"session_id":context}),
        &headers,
    )
    .await;
    assert_eq!(capacity.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(capacity.json()["error"]["type"], "token_store_capacity");
    let too_many_values = (1..=600)
        .map(|n| format!("fixture{n}@example.invalid"))
        .collect::<Vec<_>>()
        .join(" ");
    let capacity = post_json_with_headers(
        router.clone(),
        "/v1/redact",
        json!({"text":too_many_values,"session_id":context}),
        &headers,
    )
    .await;
    assert_eq!(capacity.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert!(!capacity.body.contains("@example.invalid"));
    platform_client_contract(original, router.clone()).await;
    let erased = delete_json_with_headers(
        router.clone(),
        "/v1/vault/context",
        json!({"vault":{"context_id":context}}),
        &headers,
    )
    .await;
    assert_eq!(erased.status, StatusCode::OK, "{}", erased.body);
    let after = post_json_with_headers(
        router.clone(),
        "/v1/restore",
        json!({"text":old_text,"session_id":context}),
        &headers,
    )
    .await;
    assert_eq!(after.status, StatusCode::OK);
    assert_eq!(after.json()["text"], old_text);
    // Even an explicitly fail-open profile cannot release an uncommitted token.
    let rebound = post_json_with_headers(
        router,
        "/v1/redact",
        json!({"text":"fixture@example.invalid","session_id":context}),
        &headers,
    )
    .await;
    assert_eq!(rebound.status, StatusCode::GONE);
    assert_eq!(rebound.json()["error"]["type"], "token_store_retired");
}

#[derive(Debug)]
struct InterruptErasure {
    inner: Arc<redact_gateway::vault::Kv2Store>,
    stage: std::sync::atomic::AtomicU8,
    freeze_pause: Option<Arc<FreezePause>>,
}
#[derive(Debug)]
struct FreezePause {
    entered: tokio::sync::Notify,
    resume: tokio::sync::Notify,
    integrity: bool,
}
#[async_trait::async_trait]
impl redact_gateway::vault::TokenMapStore for InterruptErasure {
    fn backend_name(&self) -> &'static str {
        "vault_kv2"
    }
    async fn put(
        &self,
        t: &str,
        c: &str,
        m: &[redact_gateway::redact::token::TokenMapping],
    ) -> Result<(), redact_gateway::vault::TokenMapError> {
        self.inner.put(t, c, m).await
    }
    async fn get(
        &self,
        t: &str,
        c: &str,
    ) -> Result<
        Vec<redact_gateway::redact::token::TokenMapping>,
        redact_gateway::vault::TokenMapError,
    > {
        self.inner.get(t, c).await
    }
    async fn delete(&self, t: &str, c: &str) -> Result<(), redact_gateway::vault::TokenMapError> {
        self.inner.delete(t, c).await
    }
    async fn exists(&self, t: &str, c: &str) -> Result<bool, redact_gateway::vault::TokenMapError> {
        self.inner.exists(t, c).await
    }
    async fn get_lineage(
        &self,
        t: &str,
        c: &str,
    ) -> Result<redact_gateway::vault::CredentialLineage, redact_gateway::vault::TokenMapError>
    {
        self.inner.get_lineage(t, c).await
    }
    async fn put_lineage(
        &self,
        t: &str,
        c: &str,
        lineage: &redact_gateway::vault::CredentialLineage,
    ) -> Result<(), redact_gateway::vault::TokenMapError> {
        self.inner.put_lineage(t, c, lineage).await
    }
    async fn health(&self) -> Result<(), redact_gateway::vault::TokenMapError> {
        self.inner.health().await
    }
    async fn freeze(
        &self,
        t: &str,
        c: &str,
    ) -> Result<redact_gateway::vault::FrozenSnapshot, redact_gateway::vault::TokenMapError> {
        if let Some(pause) = &self.freeze_pause {
            pause.entered.notify_one();
            pause.resume.notified().await;
            if pause.integrity {
                return Err(redact_token_store::Error::Integrity.into());
            }
        }
        self.inner.freeze(t, c).await
    }
    async fn fence_for_erasure(
        &self,
        t: &str,
        c: &str,
    ) -> Result<(), redact_gateway::vault::TokenMapError> {
        let stage = self.stage.swap(0, std::sync::atomic::Ordering::SeqCst);
        if stage == 1 {
            return Err(redact_token_store::Error::Unavailable.into());
        }
        self.inner.fence_for_erasure(t, c).await?;
        if stage == 2 {
            return Err(redact_token_store::Error::Unavailable.into());
        }
        Ok(())
    }
    async fn clear_frozen(
        &self,
        t: &str,
        c: &str,
    ) -> Result<(), redact_gateway::vault::TokenMapError> {
        self.inner.clear_frozen(t, c).await
    }
}

async fn completed_peer_import_contract(target: Arc<dyn TokenStore>) {
    use redact_gateway::{
        redact::token::{Dek, TokenMapping},
        vault::{Kv2Store, TokenMapStore},
    };
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let source = Arc::new(
        Kv2Store::from_settings(&redact_gateway::config::VaultSettings {
            backend: redact_gateway::config::VaultBackend::VaultKv2,
            address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
            token: Some(credential.trim().into()),
            path_prefix: format!("peer-import-{}", uuid::Uuid::new_v4()),
            ..Default::default()
        })
        .unwrap(),
    );
    let key = Arc::new(Dek::from_bytes([7; 32]));
    for integrity in [false, true] {
        let context = uuid::Uuid::new_v4().to_string();
        let value = TokenMapping {
            token: "[PERSON_1]".into(),
            entity_type: "PERSON".into(),
            sealed_value: key.seal("Synthetic Original").unwrap(),
            created_at: chrono::Utc::now(),
        };
        source
            .put("synthetic-tenant", &context, &[value])
            .await
            .unwrap();
        let pause = Arc::new(FreezePause {
            entered: tokio::sync::Notify::new(),
            resume: tokio::sync::Notify::new(),
            integrity,
        });
        let slow = Arc::new(
            IndexedStore::new(
                target.clone(),
                Arc::new(InterruptErasure {
                    inner: source.clone(),
                    stage: std::sync::atomic::AtomicU8::new(0),
                    freeze_pause: Some(pause.clone()),
                }),
                key.clone(),
                Duration::from_secs(3600),
            )
            .unwrap(),
        );
        let pending = tokio::spawn({
            let context = context.clone();
            async move {
                slow.lookup("synthetic-tenant", &context, "[PERSON_1]")
                    .await
            }
        });
        tokio::time::timeout(Duration::from_secs(3), pause.entered.notified())
            .await
            .unwrap();
        let peer = IndexedStore::new(
            target.clone(),
            source.clone(),
            key.clone(),
            Duration::from_secs(3600),
        )
        .unwrap();
        let expected = peer
            .lookup("synthetic-tenant", &context, "[PERSON_1]")
            .await
            .unwrap();
        assert_eq!(
            expected.get("[PERSON_1]").map(String::as_str),
            Some("Synthetic Original")
        );
        assert!(source
            .freeze("synthetic-tenant", &context)
            .await
            .unwrap()
            .mappings
            .is_empty());
        pause.resume.notify_one();
        let actual = tokio::time::timeout(Duration::from_secs(3), pending)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(
            actual, expected,
            "completed peer import must win over a stale source read"
        );
    }
    // An integrity failure without a committed peer import remains terminal.
    let pause = Arc::new(FreezePause {
        entered: tokio::sync::Notify::new(),
        resume: tokio::sync::Notify::new(),
        integrity: true,
    });
    pause.resume.notify_one();
    let broken = IndexedStore::new(
        target,
        Arc::new(InterruptErasure {
            inner: source,
            stage: std::sync::atomic::AtomicU8::new(0),
            freeze_pause: Some(pause),
        }),
        key,
        Duration::from_secs(3600),
    )
    .unwrap();
    assert!(matches!(
        broken
            .lookup(
                "synthetic-tenant",
                &uuid::Uuid::new_v4().to_string(),
                "[PERSON_1]"
            )
            .await,
        Err(redact_gateway::vault::TokenMapError::Indexed(
            redact_token_store::Error::Integrity
        ))
    ));
}

async fn erasure_contract(target: Arc<dyn TokenStore>) {
    use redact_gateway::{
        redact::token::{subject_bound_session_key, TokenMapping},
        vault::{session_path, Kv2Store, TokenMapStore},
    };
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = vec!["synthetic-owner-a".into()];
    config.policy = Arc::new(policy_with(tokenize_profile(false)));
    let mut state = state_for(config).await;
    let mut auth_headers = axum::http::HeaderMap::new();
    auth_headers.insert("authorization", "Bearer synthetic-owner-a".parse().unwrap());
    let auth = state.auth.authenticate(&auth_headers).await.unwrap();
    let headers = [("authorization", "Bearer synthetic-owner-a")];
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let settings = redact_gateway::config::VaultSettings {
        backend: redact_gateway::config::VaultBackend::VaultKv2,
        address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
        token: Some(credential.trim().into()),
        path_prefix: format!("erase-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let source = Arc::new(Kv2Store::from_settings(&settings).unwrap());
    state.tokens = Arc::new(
        IndexedStore::new(
            target.clone(),
            source.clone(),
            state.dek.clone(),
            Duration::from_secs(3600),
        )
        .unwrap(),
    );
    let router = create_router(state.clone());
    let empty = uuid::Uuid::new_v4().to_string();
    let empty_key = subject_bound_session_key(&empty, auth.subject.as_deref().unwrap());
    let absent = post_json_with_headers(
        router.clone(),
        "/v1/vault/context/verify",
        json!({"vault":{"context_id":empty}}),
        &headers,
    )
    .await;
    assert_eq!(absent.status, StatusCode::OK);
    assert_eq!(absent.json()["state"], "absent");
    assert!(
        !source.exists(&auth.tenant, &empty_key).await.unwrap(),
        "verification must not create a source fence"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    for (case, stage) in [
        ("pruned", 0),
        ("rebound", 1),
        ("destroyed", 2),
        ("deleted_latest", 0),
        ("malformed", 2),
    ] {
        let context = uuid::Uuid::new_v4().to_string();
        let key = subject_bound_session_key(&context, auth.subject.as_deref().unwrap());
        let path = session_path(&settings.path_prefix, &auth.tenant, &key);
        let url = |operation: &str| {
            format!(
                "{}/v1/secret/{operation}/{path}",
                settings.address.as_ref().unwrap()
            )
        };
        if case == "pruned" {
            client
                .post(url("metadata"))
                .header("X-Vault-Token", credential.trim())
                .json(&json!({"max_versions":1}))
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }
        let mapping = TokenMapping {
            token: "[PERSON_1]".into(),
            entity_type: "PERSON".into(),
            sealed_value: state.dek.seal("Synthetic original").unwrap(),
            created_at: chrono::Utc::now(),
        };
        for n in 1..=3 {
            let mut row = mapping.clone();
            if case == "rebound" && n == 3 {
                row.sealed_value = state.dek.seal("Synthetic rebound").unwrap();
            }
            client.post(url("data")).header("X-Vault-Token",credential.trim()).json(&json!({"data":{"mappings":[row],"expires_at":chrono::Utc::now()+chrono::Duration::hours(1)}})).send().await.unwrap().error_for_status().unwrap();
        }
        match case {
            "destroyed" => {
                client
                    .post(url("destroy"))
                    .header("X-Vault-Token", credential.trim())
                    .json(&json!({"versions":[1]}))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
            }
            "deleted_latest" => {
                client
                    .delete(url("data"))
                    .header("X-Vault-Token", credential.trim())
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
            }
            "malformed" => {
                client
                    .post(url("data"))
                    .header("X-Vault-Token", credential.trim())
                    .json(&json!({"data":{"unexpected":true}}))
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap();
            }
            _ => {}
        }
        assert!(
            source.freeze(&auth.tenant, &key).await.is_err(),
            "{case} must remain ineligible for identity import"
        );
        let present = post_json_with_headers(
            router.clone(),
            "/v1/vault/context/verify",
            json!({"vault":{"context_id":context}}),
            &headers,
        )
        .await;
        assert_eq!(present.status, StatusCode::OK);
        assert_eq!(present.json()["state"], "present");
        let mut interrupted = state.clone();
        interrupted.tokens = Arc::new(
            IndexedStore::new(
                target.clone(),
                Arc::new(InterruptErasure {
                    inner: source.clone(),
                    stage: std::sync::atomic::AtomicU8::new(stage),
                    freeze_pause: None,
                }),
                state.dek.clone(),
                Duration::from_secs(3600),
            )
            .unwrap(),
        );
        let erased = delete_json_with_headers(
            create_router(interrupted),
            "/v1/vault/context",
            json!({"vault":{"context_id":context}}),
            &headers,
        )
        .await;
        assert_eq!(
            erased.status,
            if stage == 0 {
                StatusCode::OK
            } else {
                StatusCode::SERVICE_UNAVAILABLE
            },
            "{case}"
        );
        // Restarted verification must finish a source fence/cleanup even when
        // the earlier DELETE committed target retirement but lost its reply.
        let peer = Arc::new(Kv2Store::from_settings(&settings).unwrap());
        let mut recovered = state.clone();
        recovered.tokens = Arc::new(
            IndexedStore::new(
                target.clone(),
                peer.clone(),
                state.dek.clone(),
                Duration::from_secs(3600),
            )
            .unwrap(),
        );
        let verified = post_json_with_headers(
            create_router(recovered),
            "/v1/vault/context/verify",
            json!({"vault":{"context_id":context}}),
            &headers,
        )
        .await;
        assert_eq!(verified.status, StatusCode::OK, "{case}: {}", verified.body);
        assert_eq!(verified.json()["state"], "absent");
        assert!(
            peer.put(&auth.tenant, &key, &[mapping]).await.is_err(),
            "erasure fence lost"
        );
        let latest: serde_json::Value = client
            .get(url("data"))
            .header("X-Vault-Token", credential.trim())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        let data = &latest["data"]["data"];
        assert_eq!(data["frozen"], true);
        assert_eq!(data["mappings"], json!([]));
        let through = data["cleanup_through"].as_u64().unwrap();
        assert_eq!(data["destroyed_through"].as_u64(), Some(through));
        let metadata: serde_json::Value = client
            .get(url("metadata"))
            .header("X-Vault-Token", credential.trim())
            .send()
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json()
            .await
            .unwrap();
        for (version, details) in metadata["data"]["versions"].as_object().unwrap() {
            if version.parse::<u64>().unwrap() <= through {
                assert_eq!(
                    details["destroyed"], true,
                    "{case} retained ciphertext history"
                );
            }
        }
    }
}

// Optional cross-repository check uses a consuming application's client against
// both real HTTP surfaces. Ordinary CI still exercises every backend/migration
// test; the extra checkout is supplied explicitly by the caller.
async fn platform_client_contract(legacy: axum::Router, indexed: axum::Router) {
    let Ok(directory) = std::env::var("TOKEN_STORE_PLATFORM_TEST_DIR") else {
        return;
    };
    let legacy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let indexed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let legacy_url = format!("http://{}", legacy_listener.local_addr().unwrap());
    let indexed_url = format!("http://{}", indexed_listener.local_addr().unwrap());
    let legacy_server = tokio::spawn(async { axum::serve(legacy_listener, legacy).await.unwrap() });
    let indexed_server =
        tokio::spawn(async { axum::serve(indexed_listener, indexed).await.unwrap() });
    let mut command = tokio::process::Command::new("go");
    command
        .args([
            "test",
            "./internal/privacy",
            "-run",
            "^TestLiveIndexedShardMigration$",
            "-count=1",
            "-v",
        ])
        .current_dir(directory)
        .env("PLATFORM_TEST_LEGACY_GATEWAY_URL", legacy_url)
        .env("PLATFORM_TEST_INDEXED_GATEWAY_URL", indexed_url)
        .kill_on_drop(true);
    let result = tokio::time::timeout(Duration::from_secs(120), command.output()).await;
    legacy_server.abort();
    indexed_server.abort();
    let output = result
        .expect("optional client contract deadline")
        .expect("run optional consuming-application client");
    assert!(
        output.status.success(),
        "optional client contract failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("optional mixed-shard client contract passed");
}

#[tokio::test]
#[ignore = "requires isolated token-store PostgreSQL"]
async fn postgres_gateway_migration() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect(&std::env::var("TOKEN_STORE_PG_URL").unwrap())
        .await
        .unwrap();
    exercise(Arc::new(Postgres::new(pool).await.unwrap())).await;
}

#[tokio::test]
#[ignore = "requires isolated token-store OpenBao"]
async fn openbao_gateway_migration() {
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let store = redact_token_store::openbao::OpenBao::new(
        &std::env::var("TOKEN_STORE_BAO_ADDR").unwrap(),
        "secret",
        "gateway-contract",
        credential.trim().into(),
        Duration::from_secs(5),
    )
    .unwrap();
    exercise(Arc::new(store)).await;
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn erasure_resumes_beyond_migration_history_limit() {
    use redact_gateway::vault::{session_path, Kv2Store, TokenMapError, TokenMapStore};
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let settings = redact_gateway::config::VaultSettings {
        backend: redact_gateway::config::VaultBackend::VaultKv2,
        address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
        token: Some(credential.trim().into()),
        path_prefix: format!("long-erasure-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let tenant = "synthetic-tenant";
    let context = "synthetic-context";
    let path = session_path(&settings.path_prefix, tenant, context);
    let url = |operation: &str| {
        format!(
            "{}/v1/secret/{operation}/{path}",
            settings.address.as_ref().unwrap()
        )
    };
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    client
        .post(url("metadata"))
        .header("X-Vault-Token", credential.trim())
        .json(&json!({"max_versions":2500}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    // Larger than both strict migration's 2,048 versions and one cleanup call.
    for _ in 0..2090 {
        client.post(url("data")).header("X-Vault-Token",credential.trim())
            .json(&json!({"data":{"mappings":[],"expires_at":chrono::Utc::now()+chrono::Duration::hours(1),"legacy_ciphertext":"synthetic-encrypted-placeholder"}}))
            .send().await.unwrap().error_for_status().unwrap();
    }
    let source = Kv2Store::from_settings(&settings).unwrap();
    assert!(source.freeze(tenant, context).await.is_err());
    source.fence_for_erasure(tenant, context).await.unwrap();
    assert!(matches!(
        source.clear_frozen(tenant, context).await,
        Err(TokenMapError::Indexed(redact_token_store::Error::Busy))
    ));
    let checkpoint: serde_json::Value = client
        .get(url("data"))
        .header("X-Vault-Token", credential.trim())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let data = &checkpoint["data"]["data"];
    assert_eq!(data["cleanup_through"], 2090);
    assert_eq!(data["destroyed_through"], 2048);
    let peer = Kv2Store::from_settings(&settings).unwrap();
    peer.fence_for_erasure(tenant, context).await.unwrap();
    let resumed: serde_json::Value = client
        .get(url("data"))
        .header("X-Vault-Token", credential.trim())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        checkpoint["data"], resumed["data"],
        "restart reset the cleanup checkpoint"
    );
    peer.clear_frozen(tenant, context).await.unwrap();
    let metadata: serde_json::Value = client
        .get(url("metadata"))
        .header("X-Vault-Token", credential.trim())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    for (version, details) in metadata["data"]["versions"].as_object().unwrap() {
        if version.parse::<u64>().unwrap() <= 2090 {
            assert_eq!(
                details["destroyed"], true,
                "legacy version survived erasure"
            );
        }
    }
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn legacy_fence_survives_cleanup_and_rebinding_is_rejected() {
    use redact_gateway::redact::token::{Dek, TokenMapping};
    use redact_gateway::vault::TokenMapStore;
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let mut settings = redact_gateway::config::VaultSettings {
        backend: redact_gateway::config::VaultBackend::VaultKv2,
        address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
        token: Some(credential.trim().into()),
        path_prefix: format!("fence-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let key = Dek::from_bytes([7; 32]);
    let first = TokenMapping {
        token: "[PERSON_1]".into(),
        entity_type: "PERSON".into(),
        sealed_value: key.seal("Synthetic First").unwrap(),
        created_at: chrono::Utc::now(),
    };
    let source = redact_gateway::vault::Kv2Store::from_settings(&settings).unwrap();
    source
        .put(
            "synthetic-tenant",
            "synthetic-context",
            std::slice::from_ref(&first),
        )
        .await
        .unwrap();
    let frozen = source
        .freeze("synthetic-tenant", "synthetic-context")
        .await
        .unwrap();
    assert_eq!(frozen.mappings.len(), 1);
    assert!(source
        .put(
            "synthetic-tenant",
            "synthetic-context",
            std::slice::from_ref(&first)
        )
        .await
        .is_err());
    assert!(source
        .purge("synthetic-tenant", "synthetic-context")
        .await
        .is_err());
    source
        .clear_frozen("synthetic-tenant", "synthetic-context")
        .await
        .unwrap();
    let peer = redact_gateway::vault::Kv2Store::from_settings(&settings).unwrap();
    peer.clear_frozen("synthetic-tenant", "synthetic-context")
        .await
        .unwrap();
    assert!(peer
        .freeze("synthetic-tenant", "synthetic-context")
        .await
        .unwrap()
        .mappings
        .is_empty());
    assert!(peer
        .put(
            "synthetic-tenant",
            "synthetic-context",
            std::slice::from_ref(&first)
        )
        .await
        .is_err());
    settings.ttl_secs = 0;
    settings.path_prefix = format!("rebound-{}", uuid::Uuid::new_v4());
    let expired = redact_gateway::vault::Kv2Store::from_settings(&settings).unwrap();
    expired
        .put(
            "synthetic-tenant",
            "synthetic-context",
            std::slice::from_ref(&first),
        )
        .await
        .unwrap();
    let mut rebound = first;
    rebound.sealed_value = key.seal("Synthetic Other").unwrap();
    expired
        .put("synthetic-tenant", "synthetic-context", &[rebound])
        .await
        .unwrap();
    assert!(expired
        .freeze("synthetic-tenant", "synthetic-context")
        .await
        .is_err());
}

#[tokio::test]
#[ignore = "requires isolated token-store PostgreSQL and OpenBao source"]
async fn expiry_maintenance_clears_only_expired_imported_ciphertext() {
    use redact_gateway::{
        redact::token::{Dek, TokenMapping},
        vault::{
            indexed::MaintenanceState,
            maintenance::{
                CheckpointStore, Inventory, Limits, MaintenanceMetrics, StopReason, Worker,
            },
            Kv2Store, TokenMapStore,
        },
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("TOKEN_STORE_PG_URL").unwrap())
        .await
        .unwrap();
    let target: Arc<dyn TokenStore> = Arc::new(Postgres::new(pool).await.unwrap());
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let source = Arc::new(
        Kv2Store::from_settings(&redact_gateway::config::VaultSettings {
            backend: redact_gateway::config::VaultBackend::VaultKv2,
            address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
            token: Some(credential.trim().into()),
            path_prefix: format!("maintenance-{}", uuid::Uuid::new_v4()),
            ..Default::default()
        })
        .unwrap(),
    );
    let key = Arc::new(Dek::from_bytes([11; 32]));
    let mapping = |token: &str, original: &str| TokenMapping {
        token: token.into(),
        entity_type: "EMAIL_ADDRESS".into(),
        sealed_value: key.seal(original).unwrap(),
        created_at: chrono::Utc::now(),
    };
    let tenant = format!("synthetic-maint-tenant-{}", uuid::Uuid::new_v4());
    let live = uuid::Uuid::new_v4().to_string();
    let untouched = uuid::Uuid::new_v4().to_string();
    let retired = uuid::Uuid::new_v4().to_string();
    for context in [&live, &untouched, &retired] {
        source
            .put(
                &tenant,
                context,
                &[mapping("[EMAIL_ADDRESS_1]", "legacy@example.invalid")],
            )
            .await
            .unwrap();
    }
    // One-second retention for values interned after import.
    let store =
        IndexedStore::new(target, source.clone(), key.clone(), Duration::from_secs(1)).unwrap();
    let assigned = store
        .commit(
            &tenant,
            &live,
            &[mapping("[EMAIL_ADDRESS_2]", "short-lived@example.invalid")],
        )
        .await
        .unwrap();
    let durable = assigned["[EMAIL_ADDRESS_2]"].clone();
    store
        .commit(
            &tenant,
            &retired,
            &[mapping("[EMAIL_ADDRESS_2]", "erased@example.invalid")],
        )
        .await
        .unwrap();
    TokenMapStore::purge(&store, &tenant, &retired)
        .await
        .unwrap();
    let before = store
        .lookup(&tenant, &live, &format!("{durable} [EMAIL_ADDRESS_1]"))
        .await
        .unwrap();
    assert_eq!(before[&durable], "short-lived@example.invalid");
    assert_eq!(
        store.maintenance_state(&tenant, &untouched).await.unwrap(),
        MaintenanceState::NotImported
    );
    // The direct entry point refuses to start a migration.
    assert!(store.purge_expired(&tenant, &untouched, 1).await.is_err());
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let lines = [&live, &untouched, &retired]
        .iter()
        .map(|c| json!({"tenant":tenant,"context":c}).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let inventory = Inventory::parse(lines.as_bytes()).unwrap();
    let checkpoint =
        std::env::temp_dir().join(format!("maintenance-{}.json", uuid::Uuid::new_v4()));
    let checkpoints = CheckpointStore::new(&checkpoint);
    let worker = Worker::new(&store, Limits::default(), MaintenanceMetrics::noop()).unwrap();
    let summary = worker.run(&inventory, &checkpoints, false).await.unwrap();
    assert_eq!(summary.stop_reason, Some(StopReason::PassComplete));
    assert_eq!(
        (
            summary.drained,
            summary.retired,
            summary.not_imported,
            summary.cleared
        ),
        (1, 1, 1, 1),
        "{summary:?}"
    );
    // Expired ciphertext is gone; the unexpired imported identity still restores.
    let after = store
        .lookup(&tenant, &live, &format!("{durable} [EMAIL_ADDRESS_1]"))
        .await
        .unwrap();
    assert!(!after.contains_key(&durable), "expired value restored");
    assert_eq!(after["[EMAIL_ADDRESS_1]"], "legacy@example.invalid");
    // The expired identity stays reserved: reuse never binds a new token.
    if let Ok(again) = store
        .commit(
            &tenant,
            &live,
            &[mapping("[EMAIL_ADDRESS_3]", "short-lived@example.invalid")],
        )
        .await
    {
        assert_eq!(
            again["[EMAIL_ADDRESS_3]"], durable,
            "expired identity rebound"
        );
    }
    // Maintenance did not migrate the never-imported context.
    assert_eq!(
        store.maintenance_state(&tenant, &untouched).await.unwrap(),
        MaintenanceState::NotImported
    );
    assert!(source.exists(&tenant, &untouched).await.unwrap());
    // Idempotent: the next pass finds nothing further to clear.
    let next = worker.run(&inventory, &checkpoints, false).await.unwrap();
    assert_eq!((next.pass, next.cleared), (2, 0));
    let raw = std::fs::read_to_string(&checkpoint).unwrap();
    assert!(!raw.contains(&tenant) && !raw.contains(&live));
}

/// Fault injection in front of a real token store. `Down` fails before the
/// backend is reached; `LoseReply` commits and then reports `Unavailable`, the
/// case the store contract calls "a failed commit may have succeeded".
const FAULT_NONE: u8 = 0;
const FAULT_DOWN: u8 = 1;
const FAULT_LOSE_REPLY: u8 = 2;

struct FaultyStore {
    inner: Arc<dyn TokenStore>,
    fault: std::sync::atomic::AtomicU8,
}
impl FaultyStore {
    fn set(&self, fault: u8) {
        self.fault.store(fault, std::sync::atomic::Ordering::SeqCst);
    }
    fn mode(&self) -> u8 {
        self.fault.load(std::sync::atomic::Ordering::SeqCst)
    }
    fn before(&self) -> Result<(), redact_token_store::Error> {
        if self.mode() == FAULT_DOWN {
            return Err(redact_token_store::Error::Unavailable);
        }
        Ok(())
    }
    fn after<T>(&self, value: T) -> Result<T, redact_token_store::Error> {
        if self.mode() == FAULT_LOSE_REPLY {
            return Err(redact_token_store::Error::Unavailable);
        }
        Ok(value)
    }
}
#[async_trait::async_trait]
impl TokenStore for FaultyStore {
    fn backend(&self) -> &'static str {
        "fault_injection"
    }
    async fn health(&self) -> Result<(), redact_token_store::Error> {
        self.before()?;
        self.inner.health().await
    }
    async fn intern(
        &self,
        scope: &redact_token_store::Scope,
        candidates: &[redact_token_store::Entry],
    ) -> Result<Vec<redact_token_store::Entry>, redact_token_store::Error> {
        self.before()?;
        let out = self.inner.intern(scope, candidates).await?;
        self.after(out)
    }
    async fn intern_with_aliases(
        &self,
        scope: &redact_token_store::Scope,
        candidates: &[redact_token_store::Entry],
        aliases: &[Vec<String>],
    ) -> Result<Vec<redact_token_store::Entry>, redact_token_store::Error> {
        self.before()?;
        let out = self
            .inner
            .intern_with_aliases(scope, candidates, aliases)
            .await?;
        self.after(out)
    }
    async fn resolve(
        &self,
        scope: &redact_token_store::Scope,
        tokens: &[String],
    ) -> Result<Vec<Option<redact_token_store::Entry>>, redact_token_store::Error> {
        self.before()?;
        self.inner.resolve(scope, tokens).await
    }
    async fn retire(
        &self,
        scope: &redact_token_store::Scope,
    ) -> Result<(), redact_token_store::Error> {
        self.before()?;
        self.inner.retire(scope).await
    }
    async fn purge_expired(
        &self,
        scope: &redact_token_store::Scope,
        limit: usize,
    ) -> Result<usize, redact_token_store::Error> {
        self.before()?;
        self.inner.purge_expired(scope, limit).await
    }
    async fn context_state(
        &self,
        scope: &redact_token_store::Scope,
    ) -> Result<redact_token_store::ContextState, redact_token_store::Error> {
        self.before()?;
        self.inner.context_state(scope).await
    }
    async fn import_legacy(
        &self,
        scope: &redact_token_store::Scope,
        snapshot: &redact_token_store::LegacyImport,
    ) -> Result<(), redact_token_store::Error> {
        self.before()?;
        self.inner.import_legacy(scope, snapshot).await
    }
    async fn complete_legacy_cleanup(
        &self,
        scope: &redact_token_store::Scope,
        source: &str,
    ) -> Result<(), redact_token_store::Error> {
        self.before()?;
        self.inner.complete_legacy_cleanup(scope, source).await
    }
}

/// The indexed store, through its real HTTP surface, must be correct
/// (stable identity per scope, isolation between contexts and subjects),
/// terminal when a context is retired (typed 410, nothing resurrected, the
/// fence survives) and resilient (an unavailable or reply-losing backend fails
/// closed with a typed 503 and the same request converges on one identity when
/// the backend returns). Synthetic data only.
#[tokio::test]
#[ignore = "requires isolated token-store PostgreSQL and OpenBao source"]
async fn retire_is_terminal_isolated_and_resilient_over_http() {
    use redact_gateway::{
        redact::token::{subject_bound_session_key, TokenMapping},
        vault::{Kv2Store, TokenMapStore},
    };
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect(&std::env::var("TOKEN_STORE_PG_URL").unwrap())
        .await
        .unwrap();
    let faulty = Arc::new(FaultyStore {
        inner: Arc::new(Postgres::new(pool).await.unwrap()),
        fault: std::sync::atomic::AtomicU8::new(FAULT_NONE),
    });
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.vault.backend = redact_gateway::config::VaultBackend::Memory;
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = vec!["synthetic-owner-a".into(), "synthetic-owner-b".into()];
    config.policy = Arc::new(policy_with(tokenize_profile(false)));
    let mut state = state_for(config).await;
    let credential =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let source = Arc::new(
        Kv2Store::from_settings(&redact_gateway::config::VaultSettings {
            backend: redact_gateway::config::VaultBackend::VaultKv2,
            address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
            token: Some(credential.trim().into()),
            path_prefix: format!("retire-{}", uuid::Uuid::new_v4()),
            ..Default::default()
        })
        .unwrap(),
    );
    state.tokens = Arc::new(
        IndexedStore::new(
            faulty.clone(),
            source.clone(),
            state.dek.clone(),
            Duration::from_secs(3600),
        )
        .unwrap(),
    );
    let router = create_router(state.clone());
    let a = [("authorization", "Bearer synthetic-owner-a")];
    let b = [("authorization", "Bearer synthetic-owner-b")];
    let mut a_auth = axum::http::HeaderMap::new();
    a_auth.insert("authorization", "Bearer synthetic-owner-a".parse().unwrap());
    let a_auth = state.auth.authenticate(&a_auth).await.unwrap();

    let doomed = uuid::Uuid::new_v4().to_string();
    let neighbour = uuid::Uuid::new_v4().to_string();
    let redact = |headers: &'static [(&'static str, &'static str)], context: &str, text: &str| {
        let router = router.clone();
        let body = json!({"text": text, "session_id": context});
        async move { post_json_with_headers(router, "/v1/redact", body, headers).await }
    };
    let restore = |headers: &'static [(&'static str, &'static str)], context: &str, text: &str| {
        let router = router.clone();
        let body = json!({"text": text, "session_id": context});
        async move { post_json_with_headers(router, "/v1/restore", body, headers).await }
    };
    let a: &'static [(&str, &str)] = Box::leak(Box::new(a));
    let b: &'static [(&str, &str)] = Box::leak(Box::new(b));

    // Correctness: one stable identity per scope, restorable by its owner only.
    let first = redact(a, &doomed, "mail alpha@example.invalid").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let doomed_text = first.json()["text"].as_str().unwrap().to_string();
    assert!(!doomed_text.contains("alpha@example.invalid"));
    let again = redact(a, &doomed, "mail alpha@example.invalid").await;
    assert_eq!(again.json()["text"], doomed_text, "identity must be stable");
    let near = redact(a, &neighbour, "mail beta@example.invalid").await;
    assert_eq!(near.status, StatusCode::OK, "{}", near.body);
    let near_text = near.json()["text"].as_str().unwrap().to_string();
    let other = redact(b, &doomed, "mail gamma@example.invalid").await;
    assert_eq!(other.status, StatusCode::OK, "{}", other.body);
    let other_text = other.json()["text"].as_str().unwrap().to_string();
    for (headers, context, text, original) in [
        (a, &doomed, &doomed_text, "mail alpha@example.invalid"),
        (a, &neighbour, &near_text, "mail beta@example.invalid"),
        (b, &doomed, &other_text, "mail gamma@example.invalid"),
    ] {
        let restored = restore(headers, context, text).await;
        assert_eq!(restored.status, StatusCode::OK, "{}", restored.body);
        assert_eq!(restored.json()["text"], original);
    }

    // Resilience: an unavailable backend fails closed with a typed 503, never a
    // raw value, and the readiness probe reports it.
    faulty.set(FAULT_DOWN);
    let down = redact(a, &neighbour, "mail delta@example.invalid").await;
    assert_eq!(
        down.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        down.body
    );
    assert_eq!(down.json()["error"]["type"], "token_store_unavailable");
    assert!(!down.body.contains("delta@example.invalid"));
    let down_restore = restore(a, &neighbour, &near_text).await;
    assert_eq!(down_restore.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(!down_restore.body.contains("beta@example.invalid"));
    assert!(!get_path(router.clone(), "/readyz")
        .await
        .status
        .is_success());

    // A reply lost after the backend committed: the caller sees 503, and the
    // identical retry converges on one identity (no rebinding, no second label).
    faulty.set(FAULT_LOSE_REPLY);
    let lost = redact(a, &neighbour, "mail delta@example.invalid").await;
    assert_eq!(
        lost.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "{}",
        lost.body
    );
    faulty.set(FAULT_NONE);
    assert!(get_path(router.clone(), "/readyz")
        .await
        .status
        .is_success());
    let retry = redact(a, &neighbour, "mail delta@example.invalid").await;
    assert_eq!(retry.status, StatusCode::OK, "{}", retry.body);
    let retry_text = retry.json()["text"].as_str().unwrap().to_string();
    let retry_again = redact(a, &neighbour, "mail delta@example.invalid").await;
    assert_eq!(retry_again.json()["text"], retry_text);
    let restored = restore(a, &neighbour, &retry_text).await;
    assert_eq!(restored.json()["text"], "mail delta@example.invalid");

    // Terminal retirement through the real HTTP handler, idempotent.
    for _ in 0..2 {
        let erased = delete_json_with_headers(
            router.clone(),
            "/v1/vault/context",
            json!({"vault":{"context_id":doomed}}),
            &a,
        )
        .await;
        assert_eq!(erased.status, StatusCode::OK, "{}", erased.body);
        assert_eq!(erased.json()["state"], "absent");
    }
    let verified = post_json_with_headers(
        router.clone(),
        "/v1/vault/context/verify",
        json!({"vault":{"context_id":doomed}}),
        &a,
    )
    .await;
    assert_eq!(verified.json()["state"], "absent");
    assert_eq!(verified.json()["verified"], true);

    // The retired context is typed 410 for every new write, repeatedly, and its
    // identities are never released again or reallocated.
    for text in ["mail alpha@example.invalid", "mail epsilon@example.invalid"] {
        for _ in 0..2 {
            let gone = redact(a, &doomed, text).await;
            assert_eq!(gone.status, StatusCode::GONE, "{}", gone.body);
            assert_eq!(gone.json()["error"]["type"], "token_store_retired");
            assert!(!gone.body.contains("example.invalid"));
        }
    }
    let withheld = restore(a, &doomed, &doomed_text).await;
    assert_eq!(withheld.status, StatusCode::OK);
    assert_eq!(
        withheld.json()["text"],
        doomed_text,
        "retired identity restored"
    );
    assert!(!withheld.body.contains("alpha@example.invalid"));
    let key = subject_bound_session_key(&doomed, a_auth.subject.as_deref().unwrap());
    let probe = TokenMapping {
        token: "[EMAIL_ADDRESS_1]".into(),
        entity_type: "EMAIL_ADDRESS".into(),
        sealed_value: state.dek.seal("late@example.invalid").unwrap(),
        created_at: chrono::Utc::now(),
    };
    assert!(
        source.put(&a_auth.tenant, &key, &[probe]).await.is_err(),
        "the retirement fence must outlive the erase"
    );

    // Isolation: the neighbour context, the same context id under another
    // subject, and a brand-new context are unaffected and still writable.
    let neighbour_restored = restore(a, &neighbour, &retry_text).await;
    assert_eq!(
        neighbour_restored.json()["text"],
        "mail delta@example.invalid"
    );
    let other_restored = restore(b, &doomed, &other_text).await;
    assert_eq!(other_restored.json()["text"], "mail gamma@example.invalid");
    let other_write = redact(b, &doomed, "mail zeta@example.invalid").await;
    assert_eq!(other_write.status, StatusCode::OK, "{}", other_write.body);
    let neighbour_write = redact(a, &neighbour, "mail eta@example.invalid").await;
    assert_eq!(
        neighbour_write.status,
        StatusCode::OK,
        "{}",
        neighbour_write.body
    );
    let fresh = uuid::Uuid::new_v4().to_string();
    let fresh_write = redact(a, &fresh, "mail theta@example.invalid").await;
    assert_eq!(fresh_write.status, StatusCode::OK, "{}", fresh_write.body);
}
