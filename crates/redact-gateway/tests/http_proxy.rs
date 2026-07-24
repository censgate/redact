// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use axum::body::Body;
use axum::extract::Json;
use axum::http::{Request, StatusCode};
use axum::routing::post;
use axum::Router;
use http_body_util::BodyExt;
use redact_core::{AnalyzerEngine, AnonymizationStrategy, AnonymizerConfig};
use redact_gateway::proxy::HttpChatUpstream;
use redact_gateway::routes::{create_router, AppState};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

#[tokio::test]
async fn chat_completions_forwards_redacted_prompt_to_upstream() {
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();

    let mock = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let captured_clone = captured_clone.clone();
            async move {
                *captured_clone.lock().unwrap() = Some(body);
                Json(json!({
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "ok"},
                        "finish_reason": "stop"
                    }]
                }))
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });

    let state = AppState {
        engine: Arc::new(AnalyzerEngine::new()),
        anonymizer: AnonymizerConfig {
            strategy: AnonymizationStrategy::Replace,
            ..Default::default()
        },
        upstream: HttpChatUpstream::new(format!("http://{addr}"), None).unwrap(),
    };
    let app = create_router(state);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/chat/completions")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({
                        "model": "test-model",
                        "messages": [{
                            "role": "user",
                            "content": "Contact alice@example.com"
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("x-censgate-redactions-applied")
            .and_then(|v| v.to_str().ok()),
        Some("1")
    );

    let forwarded = captured
        .lock()
        .unwrap()
        .clone()
        .expect("upstream should receive a body");
    let content = forwarded["messages"][0]["content"].as_str().unwrap();
    assert!(
        !content.contains("alice@example.com"),
        "upstream must not see raw email: {content}"
    );
    assert!(
        content.contains("[EMAIL_ADDRESS]"),
        "expected redacted placeholder: {content}"
    );

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["choices"][0]["message"]["content"], "ok");
}
