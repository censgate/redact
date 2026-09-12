// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Vault context alias, erase/verify, and credential predecessor registration.

mod support;

use axum::http::StatusCode;
use redact_gateway::config::AuthMode;
use serde_json::json;
use support::*;

fn memory_tokenize_callers(
    upstream: &MockUpstream,
    keys: &[&str],
) -> redact_gateway::config::ResolvedConfig {
    let mut config = config_for(upstream);
    config.vault.backend = redact_gateway::config::VaultBackend::Memory;
    config.policy = std::sync::Arc::new(policy_with(tokenize_profile(true)));
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = keys.iter().map(|k| (*k).to_string()).collect();
    config
}

async fn post_auth(
    router: axum::Router,
    uri: &str,
    body: serde_json::Value,
    key: &str,
) -> TestResponse {
    let auth = format!("Bearer {key}");
    post_json_with_headers(router, uri, body, &[("authorization", &auth)]).await
}

async fn delete_auth(
    router: axum::Router,
    uri: &str,
    body: serde_json::Value,
    key: &str,
) -> TestResponse {
    let auth = format!("Bearer {key}");
    delete_json_with_headers(router, uri, body, &[("authorization", &auth)]).await
}

fn context_body(context_id: &str) -> serde_json::Value {
    json!({"vault": {"context_id": context_id}})
}

#[tokio::test]
async fn context_id_aliases_session_id_on_redact_and_restore() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(&upstream, &["caller-a"])).await;

    let redacted = post_auth(
        router.clone(),
        "/v1/redact",
        json!({
            "text": "mail alice@example.com",
            "vault": {"context_id": "context-1"}
        }),
        "caller-a",
    )
    .await;
    assert_eq!(redacted.status, StatusCode::OK);
    assert_eq!(redacted.json()["session_id"], "context-1");
    let token_text = redacted.json()["text"].as_str().unwrap().to_string();
    assert!(token_text.contains("[EMAIL_ADDRESS_"));

    let restored = post_auth(
        router.clone(),
        "/v1/restore",
        json!({
            "text": token_text,
            "session_id": "context-1"
        }),
        "caller-a",
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(restored.json()["session_id"], "context-1");
    assert!(restored.json()["text"]
        .as_str()
        .unwrap()
        .contains("alice@example.com"));

    let restored_alias = post_auth(
        router,
        "/v1/restore",
        json!({
            "text": "[EMAIL_ADDRESS_1]",
            "vault": {"context_id": "context-1"}
        }),
        "caller-a",
    )
    .await;
    assert_eq!(restored_alias.status, StatusCode::OK);
    assert_eq!(restored_alias.json()["session_id"], "context-1");
    assert_eq!(restored_alias.json()["restored"], 1);
}

#[tokio::test]
async fn conflicting_session_id_and_context_id_is_rejected() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(&upstream, &["caller-a"])).await;

    let response = post_auth(
        router,
        "/v1/redact",
        json!({
            "text": "mail alice@example.com",
            "session_id": "context-1",
            "vault": {"context_id": "context-2"}
        }),
        "caller-a",
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.json()["error"]["type"], "invalid_request_error");
}

#[tokio::test]
async fn existing_session_id_body_still_round_trips() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(&upstream, &["caller-a"])).await;

    let redacted = post_auth(
        router.clone(),
        "/v1/redact",
        json!({
            "text": "mail alice@example.com",
            "session_id": "context-1"
        }),
        "caller-a",
    )
    .await;
    assert_eq!(redacted.status, StatusCode::OK);
    assert_eq!(redacted.json()["session_id"], "context-1");

    let restored = post_auth(
        router,
        "/v1/restore",
        json!({
            "text": "[EMAIL_ADDRESS_1]",
            "session_id": "context-1"
        }),
        "caller-a",
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(restored.json()["restored"], 1);
    assert_eq!(restored.json()["text"], "alice@example.com");
}

#[tokio::test]
async fn erase_and_verify_are_idempotent_and_restore_misses_after_purge() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(&upstream, &["caller-a"])).await;

    let minted = post_auth(
        router.clone(),
        "/v1/redact",
        json!({
            "text": "mail alice@example.com",
            "vault": {"context_id": "context-1"}
        }),
        "caller-a",
    )
    .await;
    assert_eq!(minted.status, StatusCode::OK);

    let present = post_auth(
        router.clone(),
        "/v1/vault/context/verify",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(present.status, StatusCode::OK);
    assert_eq!(present.json()["state"], "present");
    assert_eq!(present.json()["verified"], false);
    assert_eq!(present.json()["predecessor_count"], 0);

    let erased = delete_auth(
        router.clone(),
        "/v1/vault/context",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(erased.status, StatusCode::OK);
    assert_eq!(erased.json()["state"], "absent");
    assert_eq!(erased.json()["verified"], true);

    let erased_again = delete_auth(
        router.clone(),
        "/v1/vault/context",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(erased_again.status, StatusCode::OK);
    assert_eq!(erased_again.json()["state"], "absent");
    assert_eq!(erased_again.json()["verified"], true);

    let verified = post_auth(
        router.clone(),
        "/v1/vault/context/verify",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(verified.status, StatusCode::OK);
    assert_eq!(verified.json()["state"], "absent");
    assert_eq!(verified.json()["verified"], true);

    let restored = post_auth(
        router,
        "/v1/restore",
        json!({
            "text": "[EMAIL_ADDRESS_1]",
            "session_id": "context-1"
        }),
        "caller-a",
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(restored.json()["restored"], 0);
    assert_eq!(restored.json()["missing"], 1);
    assert_eq!(restored.json()["text"], "[EMAIL_ADDRESS_1]");
}

#[tokio::test]
async fn erase_and_verify_fail_when_token_map_is_off() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = vec!["caller-a".to_string()];
    let router = router_for(config).await;

    let erased = delete_auth(
        router.clone(),
        "/v1/vault/context",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(erased.status, StatusCode::SERVICE_UNAVAILABLE);

    let verified = post_auth(
        router,
        "/v1/vault/context/verify",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(verified.status, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn predecessor_register_requires_proof_and_rejects_subjects_in_body() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(
        &upstream,
        &["caller-a", "caller-b"],
    ))
    .await;

    let missing = post_auth(
        router.clone(),
        "/v1/credentials/predecessors",
        json!({}),
        "caller-a",
    )
    .await;
    assert_eq!(missing.status, StatusCode::UNAUTHORIZED);

    let with_subject = post_json_with_headers(
        router.clone(),
        "/v1/credentials/predecessors",
        json!({"subject": "caller-b"}),
        &[
            ("authorization", "Bearer caller-a"),
            ("x-predecessor-authorization", "Bearer caller-b"),
        ],
    )
    .await;
    assert_eq!(with_subject.status, StatusCode::BAD_REQUEST);

    let registered = post_json_with_headers(
        router,
        "/v1/credentials/predecessors",
        json!({}),
        &[
            ("authorization", "Bearer caller-a"),
            ("x-predecessor-authorization", "Bearer caller-b"),
        ],
    )
    .await;
    assert_eq!(registered.status, StatusCode::OK);
    assert_eq!(registered.json()["predecessor_count"], 1);
    assert_eq!(registered.json()["lineage_revision"], 1);
}

#[tokio::test]
async fn predecessor_self_link_and_cycle_are_rejected() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(
        &upstream,
        &["caller-a", "caller-b"],
    ))
    .await;

    let self_link = post_json_with_headers(
        router.clone(),
        "/v1/credentials/predecessors",
        json!({}),
        &[
            ("authorization", "Bearer caller-a"),
            ("x-predecessor-authorization", "Bearer caller-a"),
        ],
    )
    .await;
    assert_eq!(self_link.status, StatusCode::BAD_REQUEST);

    let first = post_json_with_headers(
        router.clone(),
        "/v1/credentials/predecessors",
        json!({}),
        &[
            ("authorization", "Bearer caller-a"),
            ("x-predecessor-authorization", "Bearer caller-b"),
        ],
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);

    let cycle = post_json_with_headers(
        router,
        "/v1/credentials/predecessors",
        json!({}),
        &[
            ("authorization", "Bearer caller-b"),
            ("x-predecessor-authorization", "Bearer caller-a"),
        ],
    )
    .await;
    assert_eq!(cycle.status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn predecessor_register_then_transitive_forget_after_rotation() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(
        &upstream,
        &["caller-a", "caller-b", "caller-c"],
    ))
    .await;

    // caller-b proves caller-c, then caller-a proves caller-b → transitive [b, c].
    let mid = post_json_with_headers(
        router.clone(),
        "/v1/credentials/predecessors",
        json!({}),
        &[
            ("authorization", "Bearer caller-b"),
            ("x-predecessor-authorization", "Bearer caller-c"),
        ],
    )
    .await;
    assert_eq!(mid.status, StatusCode::OK);
    assert_eq!(mid.json()["predecessor_count"], 1);

    let rotated = post_json_with_headers(
        router.clone(),
        "/v1/credentials/predecessors",
        json!({}),
        &[
            ("authorization", "Bearer caller-a"),
            ("x-predecessor-authorization", "Bearer caller-b"),
        ],
    )
    .await;
    assert_eq!(rotated.status, StatusCode::OK);
    assert_eq!(rotated.json()["predecessor_count"], 2);
    assert_eq!(rotated.json()["lineage_revision"], 1);

    for key in ["caller-a", "caller-b", "caller-c"] {
        let minted = post_auth(
            router.clone(),
            "/v1/redact",
            json!({
                "text": "mail alice@example.com",
                "vault": {"context_id": "context-1"}
            }),
            key,
        )
        .await;
        assert_eq!(minted.status, StatusCode::OK, "mint as {key}");
    }

    let erased = delete_auth(
        router.clone(),
        "/v1/vault/context",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(erased.status, StatusCode::OK);
    assert_eq!(erased.json()["state"], "absent");
    assert_eq!(erased.json()["verified"], true);
    assert_eq!(erased.json()["predecessor_count"], 2);

    for key in ["caller-a", "caller-b", "caller-c"] {
        let restored = post_auth(
            router.clone(),
            "/v1/restore",
            json!({
                "text": "[EMAIL_ADDRESS_1]",
                "vault": {"context_id": "context-1"}
            }),
            key,
        )
        .await;
        assert_eq!(restored.status, StatusCode::OK, "restore as {key}");
        assert_eq!(
            restored.json()["restored"],
            0,
            "maps for {key} must be gone"
        );
        assert_eq!(restored.json()["text"], "[EMAIL_ADDRESS_1]");
    }
}

#[tokio::test]
async fn lineage_mismatch_does_not_purge_unlinked_subject() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(
        &upstream,
        &["caller-a", "caller-b"],
    ))
    .await;

    let minted_b = post_auth(
        router.clone(),
        "/v1/redact",
        json!({
            "text": "mail bob@example.com",
            "vault": {"context_id": "context-1"}
        }),
        "caller-b",
    )
    .await;
    assert_eq!(minted_b.status, StatusCode::OK);

    let erased = delete_auth(
        router.clone(),
        "/v1/vault/context",
        context_body("context-1"),
        "caller-a",
    )
    .await;
    assert_eq!(erased.status, StatusCode::OK);
    assert_eq!(erased.json()["predecessor_count"], 0);

    let restored = post_auth(
        router,
        "/v1/restore",
        json!({
            "text": "[EMAIL_ADDRESS_1]",
            "vault": {"context_id": "context-1"}
        }),
        "caller-b",
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(restored.json()["restored"], 1);
    assert_eq!(restored.json()["text"], "bob@example.com");
}

#[tokio::test]
async fn proof_header_is_not_echoed_on_failure() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(&upstream, &["caller-a"])).await;

    let response = post_json_with_headers(
        router,
        "/v1/credentials/predecessors",
        json!({}),
        &[
            ("authorization", "Bearer caller-a"),
            (
                "x-predecessor-authorization",
                "Bearer secret-previous-token",
            ),
        ],
    )
    .await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert!(
        !response.body.contains("secret-previous-token"),
        "predecessor proof must not appear in the response: {}",
        response.body
    );
}

#[tokio::test]
async fn erase_verify_and_predecessor_reject_unknown_fields() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_callers(
        &upstream,
        &["caller-a", "caller-b"],
    ))
    .await;

    let erase = delete_auth(
        router.clone(),
        "/v1/vault/context",
        json!({"vault":{"context_id":"context-1"},"subject_id":"foreign"}),
        "caller-a",
    )
    .await;
    assert_eq!(erase.status, StatusCode::BAD_REQUEST);

    let verify = post_auth(
        router.clone(),
        "/v1/vault/context/verify",
        json!({"vault":{"context_id":"context-1","tenant":"other"}}),
        "caller-a",
    )
    .await;
    assert_eq!(verify.status, StatusCode::BAD_REQUEST);

    let register = post_json_with_headers(
        router,
        "/v1/credentials/predecessors",
        json!({"subject_id":"foreign"}),
        &[
            ("authorization", "Bearer caller-a"),
            ("x-predecessor-authorization", "Bearer caller-b"),
        ],
    )
    .await;
    assert_eq!(register.status, StatusCode::BAD_REQUEST);
}
