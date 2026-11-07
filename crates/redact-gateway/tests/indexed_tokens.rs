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
    let imported = post_json_with_headers(
        router.clone(),
        "/v1/restore",
        json!({"text":old_text,"vault":{"context_id":context}}),
        &headers,
    )
    .await;
    assert_eq!(imported.status, StatusCode::OK, "{}", imported.body);
    assert_eq!(imported.json()["text"], "mail fixture@example.invalid");
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

// Optional cross-repository check uses Platform's real Go client against both
// real HTTP surfaces. Ordinary CI still exercises every backend/migration test;
// the private Platform checkout is supplied explicitly by the caller.
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
        .expect("Platform client contract deadline")
        .expect("run Platform Go client");
    assert!(
        output.status.success(),
        "Platform client contract failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("Platform live mixed-shard client contract passed");
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
