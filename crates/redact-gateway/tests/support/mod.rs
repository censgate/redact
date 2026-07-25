// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Shared harness for gateway integration tests: a mock upstream provider and
//! helpers for driving the router without binding a real port.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::Body;
use axum::extract::Json;
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use http_body_util::BodyExt;
use redact_core::AnalyzerEngine;
use redact_gateway::config::{ConfigHandle, ResolvedConfig};
use redact_gateway::policy::{EntityAction, PolicySet, Profile};
use redact_gateway::proxy::ProviderClient;
use redact_gateway::redact::token::Dek;
use redact_gateway::routes::{create_router, AppState};
use serde_json::{json, Value};
use tower::ServiceExt;

/// A running mock upstream provider.
pub struct MockUpstream {
    /// Address the mock is listening on.
    pub addr: SocketAddr,
    /// Last request body the mock received.
    pub captured: Arc<Mutex<Option<Value>>>,
}

impl MockUpstream {
    /// The JSON body most recently received by the mock.
    pub fn last_request(&self) -> Value {
        self.captured
            .lock()
            .unwrap()
            .clone()
            .expect("upstream should have received a request")
    }

    /// Whether the mock has not received any request yet.
    pub fn received_nothing(&self) -> bool {
        self.captured.lock().unwrap().is_none()
    }

    /// Base URL of the mock.
    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

/// Serve a router on an ephemeral port.
pub async fn spawn(router: Router) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });
    addr
}

/// Mock upstream that captures the request and answers with `response`.
pub async fn mock_json_upstream(response: Value) -> MockUpstream {
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let sink = captured.clone();

    let router = Router::new()
        .route(
            "/v1/chat/completions",
            post({
                let sink = sink.clone();
                let response = response.clone();
                move |Json(body): Json<Value>| {
                    let sink = sink.clone();
                    let response = response.clone();
                    async move {
                        *sink.lock().unwrap() = Some(body);
                        Json(response)
                    }
                }
            }),
        )
        .route(
            "/v1/completions",
            post({
                let sink = sink.clone();
                let response = response.clone();
                move |Json(body): Json<Value>| {
                    let sink = sink.clone();
                    let response = response.clone();
                    async move {
                        *sink.lock().unwrap() = Some(body);
                        Json(response)
                    }
                }
            }),
        )
        .route(
            "/v1/embeddings",
            post({
                let sink = sink.clone();
                let response = response.clone();
                move |Json(body): Json<Value>| {
                    let sink = sink.clone();
                    let response = response.clone();
                    async move {
                        *sink.lock().unwrap() = Some(body);
                        Json(response)
                    }
                }
            }),
        )
        .route(
            "/v1/models",
            get(|| async { Json(json!({"object": "list", "data": []})) }),
        );

    let addr = spawn(router).await;
    MockUpstream { addr, captured }
}

/// Mock upstream that returns a different JSON body for each successive request.
pub async fn mock_json_upstream_sequence(responses: Vec<Value>) -> MockUpstream {
    assert!(
        !responses.is_empty(),
        "mock_json_upstream_sequence requires at least one response"
    );
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let sink = captured.clone();
    let fallback = responses.last().cloned().unwrap();
    let queue: Arc<Mutex<VecDeque<Value>>> = Arc::new(Mutex::new(responses.into()));

    let router = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let sink = sink.clone();
            let queue = queue.clone();
            let fallback = fallback.clone();
            async move {
                *sink.lock().unwrap() = Some(body);
                let response = queue.lock().unwrap().pop_front().unwrap_or(fallback);
                Json(response)
            }
        }),
    );

    let addr = spawn(router).await;
    MockUpstream { addr, captured }
}

/// Mock upstream that answers with a raw `text/event-stream` body.
pub async fn mock_sse_upstream(sse: impl Into<String>) -> MockUpstream {
    let captured: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));
    let sink = captured.clone();
    let sse = sse.into();

    let router = Router::new().route(
        "/v1/chat/completions",
        post(move |Json(body): Json<Value>| {
            let sink = sink.clone();
            let sse = sse.clone();
            async move {
                *sink.lock().unwrap() = Some(body);
                (StatusCode::OK, [("content-type", "text/event-stream")], sse).into_response()
            }
        }),
    );

    let addr = spawn(router).await;
    MockUpstream { addr, captured }
}

/// A default configuration pointed at `upstream`.
pub fn config_for(upstream: &MockUpstream) -> ResolvedConfig {
    ResolvedConfig {
        provider: redact_gateway::config::ProviderSettings {
            base_url: upstream.base_url(),
            ..Default::default()
        },
        ..ResolvedConfig::default()
    }
}

/// Build handler state for a configuration.
pub async fn state_for(config: ResolvedConfig) -> AppState {
    let provider = ProviderClient::from_settings(&config.provider).unwrap();
    let telemetry =
        Arc::new(redact_gateway::telemetry::init(&config.telemetry).expect("telemetry"));
    let audit = Arc::new(
        redact_gateway::audit::build_dispatcher(&config.audit, telemetry.logger_provider())
            .expect("audit"),
    );
    let tokens = redact_gateway::vault::build_store(&config.vault)
        .await
        .expect("token map");
    let auth = redact_gateway::auth::build_authenticator(&config.auth)
        .await
        .expect("authenticator");

    AppState {
        config: ConfigHandle::new(config),
        engine: Arc::new(AnalyzerEngine::new()),
        provider,
        dek: Arc::new(Dek::generate().unwrap()),
        tokens,
        auth,
        audit,
        telemetry,
    }
}

/// Build a router for a configuration.
pub async fn router_for(config: ResolvedConfig) -> Router {
    create_router(state_for(config).await)
}

/// Build state and a router that share it (needed when tests flush audit or
/// inspect readiness against the same backends the router uses).
pub async fn state_and_router(config: ResolvedConfig) -> (AppState, Router) {
    let state = state_for(config).await;
    let router = create_router(state.clone());
    (state, router)
}

/// A [`PolicySet`] with a single named profile used as the default.
pub fn policy_with(profile: Profile) -> PolicySet {
    let mut profiles = std::collections::BTreeMap::new();
    let name = if profile.name.is_empty() {
        "default".to_string()
    } else {
        profile.name.clone()
    };
    profiles.insert(name.clone(), Arc::new(profile));
    let mut set = PolicySet {
        default_profile: name,
        profiles,
    };
    set.normalize().unwrap();
    set
}

/// Tokenize-everything profile suitable for token-map persistence tests.
pub fn tokenize_profile(fail_closed: bool) -> Profile {
    Profile {
        name: "default".to_string(),
        default_action: EntityAction::Tokenize,
        min_confidence: 0.4,
        restore_responses: true,
        fail_closed,
        ..Profile::default()
    }
}

/// Poll an audit file until it contains `needle` or the retry budget is spent.
pub async fn wait_for_audit_containing(path: &Path, needle: &str) -> String {
    for _ in 0..50 {
        if let Ok(contents) = std::fs::read_to_string(path) {
            if contents.contains(needle) {
                return contents;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let contents = std::fs::read_to_string(path).unwrap_or_default();
    panic!("audit file never contained `{needle}` within retry budget; got:\n{contents}");
}

/// Result of driving the router once.
pub struct TestResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Response headers.
    pub headers: HeaderMap,
    /// Raw body.
    pub body: String,
}

impl TestResponse {
    /// Parse the body as JSON.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).expect("response body should be JSON")
    }

    /// Read a response header as a string.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }
}

/// POST a JSON body to the router.
pub async fn post_json(router: Router, uri: &str, body: Value) -> TestResponse {
    request(router, "POST", uri, Some(body), &[]).await
}

/// POST a JSON body with extra request headers.
pub async fn post_json_with_headers(
    router: Router,
    uri: &str,
    body: Value,
    headers: &[(&str, &str)],
) -> TestResponse {
    request(router, "POST", uri, Some(body), headers).await
}

/// GET a path from the router.
pub async fn get_path(router: Router, uri: &str) -> TestResponse {
    request(router, "GET", uri, None, &[]).await
}

/// GET a path with extra request headers.
pub async fn get_path_with_headers(
    router: Router,
    uri: &str,
    headers: &[(&str, &str)],
) -> TestResponse {
    request(router, "GET", uri, None, headers).await
}

async fn request(
    router: Router,
    method: &str,
    uri: &str,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> TestResponse {
    let mut builder = Request::builder().method(method).uri(uri);
    if body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let request = builder
        .body(
            body.map(|b| Body::from(b.to_string()))
                .unwrap_or(Body::empty()),
        )
        .unwrap();

    let response = router.oneshot(request).await.unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    TestResponse {
        status,
        headers,
        body: String::from_utf8_lossy(&bytes).to_string(),
    }
}

/// A minimal successful chat completion payload.
pub fn chat_response(content: &str) -> Value {
    json!({
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1_700_000_000,
        "model": "test-model",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": content},
            "finish_reason": "stop"
        }],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
    })
}

/// A minimal chat completion request payload.
pub fn chat_request(content: &str) -> Value {
    json!({
        "model": "test-model",
        "messages": [{"role": "user", "content": content}]
    })
}
