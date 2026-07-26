// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! End-to-end behavior of the non-streaming OpenAI-compatible surfaces.

mod support;

use axum::http::StatusCode;
use redact_gateway::policy::{EntityAction, PolicySet, Profile};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::Arc;
use support::*;

fn policy_with(profile: Profile) -> PolicySet {
    let mut profiles = BTreeMap::new();
    profiles.insert("default".to_string(), Arc::new(profile));
    let mut set = PolicySet {
        default_profile: "default".to_string(),
        profiles,
    };
    set.normalize().unwrap();
    set
}

#[tokio::test]
async fn prompts_are_redacted_before_they_reach_the_provider() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(
        router,
        "/v1/chat/completions",
        chat_request("Contact alice@example.com"),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("x-censgate-redactions-applied"), Some("1"));
    assert_eq!(
        response.header("x-censgate-redaction-types"),
        Some("EMAIL_ADDRESS")
    );

    let forwarded = upstream.last_request();
    let content = forwarded["messages"][0]["content"].as_str().unwrap();
    assert!(!content.contains("alice@example.com"), "leaked: {content}");
    assert!(content.contains("[EMAIL_ADDRESS]"), "got: {content}");
}

#[tokio::test]
async fn model_answers_are_redacted_before_they_reach_the_caller() {
    let upstream = mock_json_upstream(chat_response("reply to bob@example.com")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(router, "/v1/chat/completions", chat_request("hello")).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.json()["choices"][0]["message"]["content"],
        "reply to [EMAIL_ADDRESS]"
    );
    assert_eq!(response.header("x-censgate-response-redactions"), Some("1"));
}

#[tokio::test]
async fn blocked_entities_in_model_answers_are_refused() {
    // Response-side block must not return the credential to the caller.
    let upstream = mock_json_upstream(chat_response("here is AKIAIOSFODNN7EXAMPLE for you")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(router, "/v1/chat/completions", chat_request("hello")).await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.json()["error"]["type"], "policy_violation");
    let body = response.body;
    assert!(
        !body.contains("AKIAIOSFODNN7EXAMPLE"),
        "blocked secret leaked in error body: {body}"
    );
}

#[tokio::test]
async fn blocked_entities_in_provider_error_messages_are_refused() {
    let upstream = mock_json_upstream_status(
        500,
        json!({
            "error": {
                "message": "upstream saw AKIAIOSFODNN7EXAMPLE",
                "type": "server_error"
            }
        }),
    )
    .await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(router, "/v1/chat/completions", chat_request("hello")).await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.json()["error"]["type"], "policy_violation");
    assert!(
        !response.body.contains("AKIAIOSFODNN7EXAMPLE"),
        "blocked secret leaked: {}",
        response.body
    );
}

#[tokio::test]
async fn blocked_entities_are_refused_and_never_forwarded() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(
        router,
        "/v1/chat/completions",
        chat_request("my key is AKIAIOSFODNN7EXAMPLE"),
    )
    .await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(response.json()["error"]["type"], "policy_violation");
    assert!(response.json()["error"]["message"]
        .as_str()
        .unwrap()
        .contains("AWS_ACCESS_KEY"));
    assert!(
        upstream.captured.lock().unwrap().is_none(),
        "a blocked request must never reach the provider"
    );
}

#[tokio::test]
async fn tokenized_values_are_restored_in_the_answer() {
    let upstream = mock_json_upstream(chat_response("I mailed [EMAIL_ADDRESS_1]")).await;
    let mut config = config_for(&upstream);
    config.policy = Arc::new(policy_with(Profile {
        default_action: EntityAction::Tokenize,
        min_confidence: 0.4,
        restore_responses: true,
        ..Profile::default()
    }));
    let router = router_for(config).await;

    let response = post_json(
        router,
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    let forwarded = upstream.last_request();
    assert_eq!(
        forwarded["messages"][0]["content"], "mail [EMAIL_ADDRESS_1]",
        "the provider only sees the placeholder"
    );
    assert_eq!(
        response.json()["choices"][0]["message"]["content"],
        "I mailed alice@example.com",
        "the caller sees the original value"
    );
    assert_eq!(response.header("x-censgate-tokens-issued"), Some("1"));
    assert_eq!(response.header("x-censgate-tokens-restored"), Some("1"));
}

#[tokio::test]
async fn the_profile_header_is_ignored_by_default() {
    // An unauthenticated caller must not be able to pick a weaker profile.
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let config = config_for(&upstream);
    assert!(
        !config.redaction.allow_profile_header,
        "must default to off"
    );
    let router = router_for(config).await;

    let response = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
        &[("x-censgate-profile", "permissive")],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("x-censgate-redactions-applied"), Some("1"));
    assert_eq!(
        upstream.last_request()["messages"][0]["content"],
        "mail [EMAIL_ADDRESS]",
        "the configured profile applies despite the header"
    );
}

#[tokio::test]
async fn an_unknown_profile_header_is_ignored_by_default() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("hello"),
        &[("x-censgate-profile", "does-not-exist")],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
}

#[tokio::test]
async fn a_profile_can_be_selected_when_the_header_is_enabled() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.redaction.allow_profile_header = true;
    let router = router_for(config).await;

    let response = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("mail alice@example.com"),
        &[("x-censgate-profile", "permissive")],
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.header("x-censgate-redactions-applied"), Some("0"));
    assert_eq!(
        upstream.last_request()["messages"][0]["content"],
        "mail alice@example.com",
        "the permissive profile observes without rewriting"
    );
}

#[tokio::test]
async fn an_unknown_profile_is_rejected_rather_than_downgraded() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.redaction.allow_profile_header = true;
    let router = router_for(config).await;

    let response = post_json_with_headers(
        router,
        "/v1/chat/completions",
        chat_request("hello"),
        &[("x-censgate-profile", "does-not-exist")],
    )
    .await;

    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.json()["error"]["type"], "invalid_request_error");
}

#[tokio::test]
async fn embeddings_input_is_redacted() {
    let upstream = mock_json_upstream(json!({"object": "list", "data": []})).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(
        router,
        "/v1/embeddings",
        json!({"model": "embed", "input": ["mail alice@example.com"]}),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(upstream.last_request()["input"][0], "mail [EMAIL_ADDRESS]");
}

#[tokio::test]
async fn models_are_proxied_untouched() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = get_path(router, "/v1/models").await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["object"], "list");
}

#[tokio::test]
async fn an_unreachable_provider_is_reported_as_a_gateway_error() {
    let mut config = config_for(&mock_json_upstream(chat_response("ok")).await);
    config.provider.base_url = "http://127.0.0.1:1".to_string();
    let router = router_for(config).await;

    let response = post_json(router, "/v1/chat/completions", chat_request("hello")).await;

    assert_eq!(response.status, StatusCode::BAD_GATEWAY);
    assert_eq!(response.json()["error"]["type"], "provider_error");
}

#[tokio::test]
async fn health_and_status_describe_the_active_policy() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let config = config_for(&upstream);
    let router = router_for(config).await;

    let health = get_path(router.clone(), "/health").await;
    assert_eq!(health.status, StatusCode::OK);
    assert_eq!(health.json()["status"], "ok");
    assert_eq!(health.json()["default_profile"], "default");

    let status = get_path(router, "/v1/compliance/status").await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.json()["token_map_backend"], "off");
    assert!(status.json()["profiles"].as_array().unwrap().len() >= 5);
}

#[tokio::test]
async fn the_redact_endpoint_applies_policy_without_an_upstream_call() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(
        router,
        "/v1/redact",
        json!({"text": "mail alice@example.com", "profile": "default"}),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["text"], "mail [EMAIL_ADDRESS]");
    assert_eq!(response.json()["blocked"], false);
    assert!(upstream.captured.lock().unwrap().is_none());
}

#[tokio::test]
async fn the_compliance_check_endpoint_reports_a_block_without_rewriting() {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let router = router_for(config_for(&upstream)).await;

    let response = post_json(
        router,
        "/v1/compliance/check",
        json!({"text": "key AKIAIOSFODNN7EXAMPLE"}),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["allowed"], false);
    assert_eq!(response.json()["blocked_entities"][0], "AWS_ACCESS_KEY");
}
