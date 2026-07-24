// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use axum::body::Body;
use axum::extract::Json;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
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
async fn streaming_chat_completions_redacts_request_and_response() {
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let captured_clone = captured.clone();

    let mock = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let captured_clone = captured_clone.clone();
            async move {
                *captured_clone.lock().unwrap() = Some(body);
                let sse = concat!(
                    "data: {\"id\":\"chatcmpl-s\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"},\"finish_reason\":null}]}\n\n",
                    "data: {\"id\":\"chatcmpl-s\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Call \"},\"finish_reason\":null}]}\n\n",
                    "data: {\"id\":\"chatcmpl-s\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"leak@example.com\"},\"finish_reason\":null}]}\n\n",
                    "data: {\"id\":\"chatcmpl-s\",\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" now\"},\"finish_reason\":null}]}\n\n",
                    "data: {\"id\":\"chatcmpl-s\",\"object\":\"chat.completion.chunk\",\"created\":99,\"model\":\"test-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"length\"}]}\n\n",
                    "data: [DONE]\n\n",
                );
                (
                    StatusCode::OK,
                    [("content-type", "text/event-stream")],
                    sse.to_string(),
                )
                    .into_response()
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
                        "stream": true,
                        "messages": [{
                            "role": "user",
                            "content": "My email is alice@example.com"
                        }]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        content_type.contains("text/event-stream"),
        "expected SSE content-type, got {content_type}"
    );

    let forwarded = captured.lock().unwrap().clone().expect("upstream body");
    assert_eq!(forwarded["stream"], true);
    let req_content = forwarded["messages"][0]["content"].as_str().unwrap();
    assert!(
        !req_content.contains("alice@example.com"),
        "upstream must not see request email: {req_content}"
    );

    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let sse = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        !sse.contains("leak@example.com"),
        "stream must not leak response email: {sse}"
    );
    assert!(
        sse.contains("[EMAIL_ADDRESS]"),
        "expected redacted placeholder in stream: {sse}"
    );
    assert!(sse.contains("data: [DONE]"), "expected stream terminator");
    assert!(
        sse.contains("\"finish_reason\":\"length\""),
        "expected upstream finish_reason preserved: {sse}"
    );
    assert!(
        sse.contains("\"created\":99"),
        "expected upstream created preserved: {sse}"
    );
}

#[tokio::test]
async fn non_streaming_chat_completions_redacts_assistant_response() {
    let mock = Router::new().route(
        "/v1/chat/completions",
        post(|Json(_body): Json<Value>| async move {
            Json(json!({
                "id": "chatcmpl-n",
                "object": "chat.completion",
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": "Email leak@example.com please"
                    },
                    "finish_reason": "stop"
                }]
            }))
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
                        "messages": [{"role":"user","content":"hello"}]
                    })
                    .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    let content = body["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(!content.contains("leak@example.com"));
    assert!(content.contains("[EMAIL_ADDRESS]"));
}
