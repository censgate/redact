// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Streaming behavior of `/v1/chat/completions`.

mod support;

use axum::http::StatusCode;
use redact_gateway::policy::{EntityAction, PolicySet, Profile};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use support::*;

/// An upstream stream that splits an email address across three deltas.
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

#[tokio::test]
async fn entities_split_across_deltas_are_still_redacted() {
    let upstream = mock_sse_upstream(split_email_sse()).await;
    let router = router_for(config_for(&upstream)).await;

    let mut request = chat_request("say the address");
    request["stream"] = json!(true);
    let response = post_json(router, "/v1/chat/completions", request).await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(
        response.header("content-type"),
        Some("text/event-stream; charset=utf-8")
    );
    assert!(!response.body.contains("leak@example.com"));
    assert_eq!(streamed_content(&response.body), "Call [EMAIL_ADDRESS]");
    assert!(response.body.ends_with("data: [DONE]\n\n"));
}

#[tokio::test]
async fn prompts_are_redacted_on_the_streaming_path_too() {
    let upstream = mock_sse_upstream(split_email_sse()).await;
    let router = router_for(config_for(&upstream)).await;

    let mut request = chat_request("mail alice@example.com");
    request["stream"] = json!(true);
    post_json(router, "/v1/chat/completions", request).await;

    let forwarded = upstream.last_request();
    assert_eq!(forwarded["messages"][0]["content"], "mail [EMAIL_ADDRESS]");
    assert_eq!(forwarded["stream"], true);
}

#[tokio::test]
async fn upstream_metadata_is_preserved_on_the_rebuilt_stream() {
    let upstream = mock_sse_upstream(split_email_sse()).await;
    let router = router_for(config_for(&upstream)).await;

    let mut request = chat_request("hello");
    request["stream"] = json!(true);
    let response = post_json(router, "/v1/chat/completions", request).await;

    let chunks = sse_chunks(&response.body);
    let last = chunks.last().unwrap();
    assert_eq!(last["choices"][0]["finish_reason"], "length");
    assert_eq!(last["created"], 99);
    assert_eq!(last["model"], "test-model");
}

#[tokio::test]
async fn tokens_are_restored_in_streamed_answers() {
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
    let mut profiles = BTreeMap::new();
    profiles.insert(
        "default".to_string(),
        Arc::new(Profile {
            default_action: EntityAction::Tokenize,
            min_confidence: 0.4,
            ..Profile::default()
        }),
    );
    let mut policy = PolicySet {
        default_profile: "default".to_string(),
        profiles,
    };
    policy.normalize().unwrap();
    config.policy = Arc::new(policy);
    let router = router_for(config).await;

    let mut request = chat_request("mail alice@example.com");
    request["stream"] = json!(true);
    let response = post_json(router, "/v1/chat/completions", request).await;

    assert_eq!(
        upstream.last_request()["messages"][0]["content"],
        "mail [EMAIL_ADDRESS_1]"
    );
    assert_eq!(
        streamed_content(&response.body),
        "sent to alice@example.com"
    );
}

#[tokio::test]
async fn a_blocked_prompt_never_opens_a_stream() {
    let upstream = mock_sse_upstream(split_email_sse()).await;
    let router = router_for(config_for(&upstream)).await;

    let mut request = chat_request("key AKIAIOSFODNN7EXAMPLE");
    request["stream"] = json!(true);
    let response = post_json(router, "/v1/chat/completions", request).await;

    assert_eq!(response.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(upstream.captured.lock().unwrap().is_none());
}
