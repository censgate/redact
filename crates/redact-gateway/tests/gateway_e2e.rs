// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! End-to-end integration tests that drive the real gateway router and assert
//! observable HTTP behavior (status codes, forwarded bodies, audit files,
//! metrics text).

mod support;

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use redact_gateway::config::{AuditExport, AuthMode, StreamMode, VaultBackend};
use redact_gateway::policy::{EntityAction, Profile};
use serde_json::{json, Value};
use support::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

fn api_key_config(upstream: &MockUpstream, key: &str) -> redact_gateway::config::ResolvedConfig {
    let mut config = config_for(upstream);
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = vec![key.to_string()];
    config
}

#[tokio::test]
async fn missing_credentials_are_rejected_and_never_forwarded() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(api_key_config(&upstream, "secret-key")).await;

    let response = post_json(router, "/v1/chat/completions", chat_request("hello")).await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.json()["error"]["type"], "authentication_error");
    assert!(response.json()["error"]["message"].as_str().is_some());
    assert!(
        upstream.received_nothing(),
        "unauthenticated traffic must never reach the provider"
    );
}

#[tokio::test]
async fn a_valid_bearer_api_key_is_accepted() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(api_key_config(&upstream, "secret-key")).await;

    let response = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("hello"),
        &[("authorization", "Bearer secret-key")],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(!upstream.received_nothing());
}

#[tokio::test]
async fn a_valid_x_api_key_header_is_accepted() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(api_key_config(&upstream, "secret-key")).await;

    let response = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("hello"),
        &[("x-api-key", "secret-key")],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(!upstream.received_nothing());
}

#[tokio::test]
async fn a_wrong_api_key_is_rejected() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(api_key_config(&upstream, "secret-key")).await;

    let response = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("hello"),
        &[("authorization", "Bearer wrong-key")],
    )
    .await;

    assert_eq!(response.status, StatusCode::UNAUTHORIZED);
    assert_eq!(response.json()["error"]["type"], "authentication_error");
    assert!(upstream.received_nothing());
}

#[tokio::test]
async fn health_liveness_readiness_and_metrics_remain_public_when_auth_is_enabled() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(api_key_config(&upstream, "secret-key")).await;

    for path in ["/health", "/livez", "/readyz", "/metrics"] {
        let response = get_path(router.clone(), path).await;
        assert_ne!(
            response.status,
            StatusCode::UNAUTHORIZED,
            "{path} must stay reachable without credentials"
        );
        assert!(
            response.status == StatusCode::OK || response.status == StatusCode::NOT_FOUND,
            "{path} unexpected status {}",
            response.status
        );
    }
}

// ---------------------------------------------------------------------------
// Token persistence across requests
// ---------------------------------------------------------------------------

fn memory_tokenize_config(upstream: &MockUpstream) -> redact_gateway::config::ResolvedConfig {
    let mut config = config_for(upstream);
    config.vault.backend = VaultBackend::Memory;
    config.policy = Arc::new(policy_with(tokenize_profile(true)));
    config
}

#[tokio::test]
async fn the_same_session_reuses_tokens_and_restores_them_on_later_responses() {
    let upstream = mock_json_upstream_sequence(vec![
        chat_response("ack"),
        chat_response("I still have [EMAIL_ADDRESS_1]"),
    ])
    .await;
    let router = router_for(memory_tokenize_config(&upstream)).await;
    let session = [("x-censgate-session-id", "s1")];

    let first = post_json_with_headers(
        router.clone(),
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
        &session,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK);
    assert_eq!(
        upstream.last_request()["messages"][0]["content"],
        "mail [EMAIL_ADDRESS_1]",
        "provider should see the placeholder on the first request"
    );

    let second = post_json_with_headers(
        router.clone(),
        "/v1/chat/completions",
        chat_request("mail alice@example.com again"),
        &session,
    )
    .await;
    assert_eq!(second.status, StatusCode::OK);
    assert_eq!(
        upstream.last_request()["messages"][0]["content"],
        "mail [EMAIL_ADDRESS_1] again",
        "same session must reuse the same token for the same value"
    );
    assert_eq!(
        second.json()["choices"][0]["message"]["content"],
        "I still have alice@example.com",
        "a later response that echoes the earlier token must be restored"
    );
}

#[tokio::test]
async fn a_different_session_gets_an_isolated_token_namespace() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_config(&upstream)).await;

    let s1 = post_json_with_headers(
        router.clone(),
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
        &[("x-censgate-session-id", "s1")],
    )
    .await;
    assert_eq!(s1.status, StatusCode::OK);

    let s2 = post_json_with_headers(
        router.clone(),
        "/v1/chat/completions",
        chat_request("mail bob@example.com"),
        &[("x-censgate-session-id", "s2")],
    )
    .await;
    assert_eq!(s2.status, StatusCode::OK);
    // Each session starts its own counter; both mint `_1`, proving isolation
    // rather than continuing s1's namespace.
    assert_eq!(
        upstream.last_request()["messages"][0]["content"],
        "mail [EMAIL_ADDRESS_1]"
    );

    let restore_s1 = post_json(
        router.clone(),
        "/v1/restore",
        json!({"text": "to [EMAIL_ADDRESS_1]", "session_id": "s1"}),
    )
    .await;
    assert_eq!(restore_s1.status, StatusCode::OK);
    assert_eq!(restore_s1.json()["text"], "to alice@example.com");

    let restore_s2 = post_json(
        router,
        "/v1/restore",
        json!({"text": "to [EMAIL_ADDRESS_1]", "session_id": "s2"}),
    )
    .await;
    assert_eq!(restore_s2.status, StatusCode::OK);
    assert_eq!(restore_s2.json()["text"], "to bob@example.com");
}

#[tokio::test]
async fn restore_endpoint_rewrites_tokens_for_a_session() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(memory_tokenize_config(&upstream)).await;

    let minted = post_json_with_headers(
        router.clone(),
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
        &[("x-censgate-session-id", "restore-me")],
    )
    .await;
    assert_eq!(minted.status, StatusCode::OK);

    let restored = post_json(
        router,
        "/v1/restore",
        json!({
            "text": "please write to [EMAIL_ADDRESS_1] soon",
            "session_id": "restore-me"
        }),
    )
    .await;
    assert_eq!(restored.status, StatusCode::OK);
    assert_eq!(
        restored.json()["text"],
        "please write to alice@example.com soon"
    );
    assert_eq!(restored.json()["restored"], 1);
}

#[tokio::test]
async fn restore_endpoint_is_unavailable_when_the_token_map_is_off() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.vault.backend = VaultBackend::Off;
    let router = router_for(config).await;

    let response = post_json(
        router,
        "/v1/restore",
        json!({"text": "[EMAIL_ADDRESS_1]", "session_id": "s"}),
    )
    .await;

    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.json()["error"]["type"], "dependency_unavailable");
}

// ---------------------------------------------------------------------------
// Fail-closed behavior
// ---------------------------------------------------------------------------

fn unreachable_vault_config(
    upstream: &MockUpstream,
    fail_closed: bool,
) -> redact_gateway::config::ResolvedConfig {
    let mut config = config_for(upstream);
    config.vault.backend = VaultBackend::VaultKv2;
    config.vault.address = Some("http://127.0.0.1:1".to_string());
    config.vault.token = Some("test-token".to_string());
    config.policy = Arc::new(policy_with(tokenize_profile(fail_closed)));
    config
}

#[tokio::test]
async fn fail_closed_refuses_when_the_token_map_cannot_persist() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(unreachable_vault_config(&upstream, true)).await;

    let response = post_json(
        router,
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
    )
    .await;

    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.json()["error"]["type"], "dependency_unavailable");
    assert!(
        upstream.received_nothing(),
        "fail-closed must keep the provider from ever seeing the prompt"
    );
}

#[tokio::test]
async fn a_non_fail_closed_profile_still_serves_when_the_token_map_is_down() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(unreachable_vault_config(&upstream, false)).await;

    let response = post_json(
        router,
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let forwarded = upstream.last_request();
    let content = forwarded["messages"][0]["content"].as_str().unwrap();
    assert!(
        !content.contains("alice@example.com"),
        "prompt must still be redacted even when persistence fails: {content}"
    );
}

// ---------------------------------------------------------------------------
// Incremental streaming
// ---------------------------------------------------------------------------

fn split_email_sse() -> String {
    [
        r#"data: {"id":"chatcmpl-s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#,
        r#"data: {"id":"chatcmpl-s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Call "},"finish_reason":null}]}"#,
        r#"data: {"id":"chatcmpl-s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"leak@exa"},"finish_reason":null}]}"#,
        r#"data: {"id":"chatcmpl-s","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"mple.com"},"finish_reason":null}]}"#,
        r#"data: {"id":"chatcmpl-s","object":"chat.completion.chunk","created":99,"model":"test-model","choices":[{"index":0,"delta":{},"finish_reason":"length"}]}"#,
        "data: [DONE]",
    ]
    .join("\n\n")
        + "\n\n"
}

fn long_word_sse(deltas: usize) -> String {
    let mut frames = vec![
        r#"data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#
            .to_string(),
    ];
    for i in 0..deltas {
        frames.push(format!(
            r#"data: {{"id":"c","object":"chat.completion.chunk","choices":[{{"index":0,"delta":{{"content":"word{i} "}},"finish_reason":null}}]}}"#
        ));
    }
    frames.push(
        r#"data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#
            .to_string(),
    );
    frames.push("data: [DONE]".to_string());
    frames.join("\n\n") + "\n\n"
}

fn sse_chunks(body: &str) -> Vec<Value> {
    body.split("\n\n")
        .filter_map(|block| block.strip_prefix("data: "))
        .filter(|data| *data != "[DONE]")
        .filter_map(|data| serde_json::from_str(data).ok())
        .collect()
}

fn streamed_content(body: &str) -> String {
    sse_chunks(body)
        .iter()
        .filter_map(|chunk| {
            chunk
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect()
}

fn content_frame_count(body: &str) -> usize {
    sse_chunks(body)
        .iter()
        .filter(|chunk| {
            chunk
                .pointer("/choices/0/delta/content")
                .and_then(Value::as_str)
                .is_some_and(|c| !c.is_empty())
        })
        .count()
}

#[tokio::test]
async fn incremental_mode_redacts_an_email_split_across_deltas() {
    let upstream = mock_sse_upstream(split_email_sse()).await;
    let mut config = config_for(&upstream);
    config.redaction.stream_mode = StreamMode::Incremental;
    config.redaction.stream_holdback_bytes = 16;
    let router = router_for(config).await;

    let mut request = chat_request("say the address");
    request["stream"] = json!(true);
    let response = post_json(router, "/v1/chat/completions", request).await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(!response.body.contains("leak@example.com"));
    assert!(streamed_content(&response.body).contains("[EMAIL_ADDRESS]"));
    assert!(
        response.body.contains("data: [DONE]"),
        "stream must terminate with [DONE]"
    );
}

#[tokio::test]
async fn incremental_mode_restores_tokens_in_the_emitted_stream() {
    let sse = [
        r#"data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}"#,
        r#"data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"sent to [EMAIL_ADDRESS_1]"},"finish_reason":null}]}"#,
        r#"data: {"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}"#,
        "data: [DONE]",
    ]
    .join("\n\n")
        + "\n\n";

    let upstream = mock_sse_upstream(sse).await;
    let mut config = config_for(&upstream);
    config.redaction.stream_mode = StreamMode::Incremental;
    // Keep the whole completion inside the holdback window so the token is
    // restored in one emit (tokens split by the holdback are a separate bug).
    config.redaction.stream_holdback_bytes = 256;
    config.vault.backend = VaultBackend::Memory;
    config.policy = Arc::new(policy_with(tokenize_profile(true)));
    let router = router_for(config).await;

    let mut request = chat_request("mail alice@example.com");
    request["stream"] = json!(true);
    let response = post_json(router, "/v1/chat/completions", request).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        streamed_content(&response.body),
        "sent to alice@example.com"
    );
    assert!(!response.body.contains("[EMAIL_ADDRESS_1]"));
}

#[tokio::test]
async fn incremental_and_buffered_modes_both_hide_split_entity_values() {
    for mode in [StreamMode::Buffered, StreamMode::Incremental] {
        let upstream = mock_sse_upstream(split_email_sse()).await;
        let mut config = config_for(&upstream);
        config.redaction.stream_mode = mode;
        config.redaction.stream_holdback_bytes = 16;
        let router = router_for(config).await;

        let mut request = chat_request("say the address");
        request["stream"] = json!(true);
        let response = post_json(router, "/v1/chat/completions", request).await;

        assert_eq!(response.status, StatusCode::OK, "mode {:?}", mode);
        assert!(
            !response.body.contains("leak@example.com"),
            "mode {:?} leaked raw email",
            mode
        );
        assert!(
            streamed_content(&response.body).contains("[EMAIL_ADDRESS]"),
            "mode {:?} missing replacement",
            mode
        );
    }
}

#[tokio::test]
async fn incremental_mode_releases_content_progressively() {
    let upstream = mock_sse_upstream(long_word_sse(50)).await;
    let mut config = config_for(&upstream);
    config.redaction.stream_mode = StreamMode::Incremental;
    // Small holdback so text is released across many frames rather than once.
    config.redaction.stream_holdback_bytes = 16;
    let router = router_for(config).await;

    let mut request = chat_request("count");
    request["stream"] = json!(true);
    let response = post_json(router, "/v1/chat/completions", request).await;

    assert_eq!(response.status, StatusCode::OK);
    assert!(
        content_frame_count(&response.body) > 1,
        "incremental mode must emit more than one content frame; got {}",
        content_frame_count(&response.body)
    );
    assert!(response.body.contains("data: [DONE]"));
}

// ---------------------------------------------------------------------------
// Audit records
// ---------------------------------------------------------------------------

fn audit_file_config(
    upstream: &MockUpstream,
    path: PathBuf,
) -> redact_gateway::config::ResolvedConfig {
    let mut config = config_for(upstream);
    config.audit.export = AuditExport::File;
    config.audit.file_path = Some(path);
    config
}

#[tokio::test]
async fn a_successful_chat_writes_audit_lines_without_prompt_or_entity_values() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let (state, router) = state_and_router(audit_file_config(&upstream, path.clone())).await;

    let response = post_json(
        router,
        "/v1/chat/completions",
        chat_request("Contact alice@example.com please"),
    )
    .await;
    assert_eq!(response.status, StatusCode::OK);

    state.audit.flush().await.expect("flush audit");
    let contents = wait_for_audit_containing(&path, "redact.gateway.request").await;
    let _ = wait_for_audit_containing(&path, "redact.gateway.response").await;

    assert!(
        !contents.contains("alice@example.com"),
        "raw entity value leaked into audit file"
    );
    assert!(
        !contents.contains("Contact alice"),
        "raw prompt text leaked into audit file"
    );
    assert!(contents.contains("redact.gateway.request"));
    assert!(contents.contains("redact.gateway.response"));
}

#[tokio::test]
async fn a_policy_block_writes_an_audit_block_record() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let (state, router) = state_and_router(audit_file_config(&upstream, path.clone())).await;

    let response = post_json(
        router,
        "/v1/chat/completions",
        chat_request("my key is AKIAIOSFODNN7EXAMPLE"),
    )
    .await;
    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);

    state.audit.flush().await.expect("flush audit");
    let contents = wait_for_audit_containing(&path, "redact.gateway.policy_block").await;
    assert!(contents.contains("\"outcome\":\"blocked\"") || contents.contains("blocked"));
    assert!(!contents.contains("AKIAIOSFODNN7EXAMPLE"));
}

#[tokio::test]
async fn an_auth_denial_writes_an_audit_denial_record() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("audit.jsonl");
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = audit_file_config(&upstream, path.clone());
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = vec!["only-this-key".to_string()];
    let (state, router) = state_and_router(config).await;

    let response = post_json(router, "/v1/chat/completions", chat_request("hello")).await;
    assert_eq!(response.status, StatusCode::UNAUTHORIZED);

    state.audit.flush().await.expect("flush audit");
    let contents = wait_for_audit_containing(&path, "redact.gateway.auth_denied").await;
    assert!(contents.contains("denied") || contents.contains("auth_denied"));
}

// ---------------------------------------------------------------------------
// Metrics and status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn metrics_exposes_gateway_instruments_after_traffic() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let chat = post_json(
        router.clone(),
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
    )
    .await;
    assert_eq!(chat.status, StatusCode::OK);

    let metrics = get_path(router, "/metrics").await;
    assert_eq!(metrics.status, StatusCode::OK);
    assert!(
        metrics.body.contains("redact_gateway_redactions")
            || metrics.body.contains("redact_gateway_policy"),
        "expected translated gateway metric names, got:\n{}",
        metrics.body
    );
}

#[tokio::test]
async fn metrics_returns_404_when_the_endpoint_is_disabled() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.server.metrics_endpoint = false;
    let router = router_for(config).await;

    let metrics = get_path(router, "/metrics").await;
    assert_eq!(metrics.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn compliance_status_reports_profiles_token_map_auth_and_audit() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.vault.backend = VaultBackend::Memory;
    config.auth.mode = AuthMode::ApiKey;
    config.auth.api_keys = vec!["k".to_string()];
    config.audit.export = AuditExport::Stdout;
    let router = router_for(config).await;

    let status = get_path_with_headers(
        router,
        "/v1/compliance/status",
        &[("authorization", "Bearer k")],
    )
    .await;

    assert_eq!(status.status, StatusCode::OK);
    let body = status.json();
    assert!(!body["profiles"].as_array().unwrap().is_empty());
    assert_eq!(body["token_map_backend"], "memory");
    assert_eq!(body["auth_mode"], "api_key");
    assert_eq!(body["audit_export"], "stdout");
}

#[tokio::test]
async fn readyz_degrades_when_the_token_map_backend_is_unhealthy() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.vault.backend = VaultBackend::VaultKv2;
    config.vault.address = Some("http://127.0.0.1:1".to_string());
    config.vault.token = Some("t".to_string());
    // Avoid fail-closed chat path; we only care about readiness here.
    config.policy = Arc::new(policy_with(Profile {
        name: "default".to_string(),
        default_action: EntityAction::Replace,
        fail_closed: false,
        ..Profile::default()
    }));
    let router = router_for(config).await;

    let ready = get_path(router, "/readyz").await;
    assert_eq!(ready.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(ready.json()["status"], "degraded");
    assert_eq!(ready.json()["token_map"]["ready"], false);
}

// ---------------------------------------------------------------------------
// Payload coverage through the real router
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tool_call_arguments_are_redacted_before_forwarding() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let request = json!({
        "model": "test-model",
        "messages": [{
            "role": "assistant",
            "content": null,
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "send_email",
                    "arguments": "{\"to\":\"alice@example.com\"}"
                }
            }]
        }]
    });

    let response = post_json(router, "/v1/chat/completions", request).await;
    assert_eq!(response.status, StatusCode::OK);

    let forwarded = upstream.last_request();
    let args = forwarded["messages"][0]["tool_calls"][0]["function"]["arguments"]
        .as_str()
        .unwrap();
    assert!(!args.contains("alice@example.com"), "leaked: {args}");
    assert!(args.contains("[EMAIL_ADDRESS]"), "got: {args}");
}

#[tokio::test]
async fn every_choice_is_redacted_when_n_is_greater_than_one() {
    let upstream = mock_json_upstream(json!({
        "id": "chatcmpl-multi",
        "object": "chat.completion",
        "created": 1,
        "model": "test-model",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "first alice@example.com"},
                "finish_reason": "stop"
            },
            {
                "index": 1,
                "message": {"role": "assistant", "content": "second bob@example.com"},
                "finish_reason": "stop"
            }
        ]
    }))
    .await;
    let router = router_for(config_for(&upstream)).await;

    let mut request = chat_request("hello");
    request["n"] = json!(2);
    let response = post_json(router, "/v1/chat/completions", request).await;

    assert_eq!(response.status, StatusCode::OK);
    let body = response.json();
    let choices = body["choices"].as_array().unwrap();
    assert_eq!(choices.len(), 2);
    assert_eq!(choices[0]["message"]["content"], "first [EMAIL_ADDRESS]");
    assert_eq!(choices[1]["message"]["content"], "second [EMAIL_ADDRESS]");
}

#[tokio::test]
async fn unknown_provider_extension_fields_survive_the_round_trip() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let request = json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": "hello"}],
        "temperature": 0.2,
        "provider_specific": {"beta": true, "trace_id": "ext-1"}
    });

    let response = post_json(router, "/v1/chat/completions", request).await;
    assert_eq!(response.status, StatusCode::OK);

    let forwarded = upstream.last_request();
    assert_eq!(forwarded["temperature"], 0.2);
    assert_eq!(forwarded["provider_specific"]["beta"], true);
    assert_eq!(forwarded["provider_specific"]["trace_id"], "ext-1");
}

#[tokio::test]
async fn well_formed_and_malformed_traceparent_headers_both_succeed() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let well_formed = post_json_with_headers(
        router.clone(),
        "/v1/chat/completions",
        chat_request("hello"),
        &[(
            "traceparent",
            "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
        )],
    )
    .await;
    assert_eq!(well_formed.status, StatusCode::OK);

    let malformed = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("hello"),
        &[("traceparent", "not-a-valid-traceparent")],
    )
    .await;
    assert_eq!(malformed.status, StatusCode::OK);
}
