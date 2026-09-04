// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Standalone `/v1/redact` must emit detect/policy/pattern child spans
//! without changing the redacted bytes.

mod support;

use axum::http::StatusCode;
use redact_gateway::config::TraceLevel;
use redact_gateway::routes::create_router;
use redact_gateway::telemetry::semconv;
use redact_gateway::telemetry::testing::{init_test, test_settings};
use redact_gateway::GatewayServer;
use serde_json::json;
use std::sync::{Arc, Mutex, OnceLock};
use support::*;

fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[tokio::test]
async fn standalone_redact_emits_detect_policy_and_patterns_without_changing_bytes() {
    let _guard = env_lock();
    let redact_gateway::telemetry::testing::TestTelemetry {
        telemetry,
        handles,
        _guard,
    } = init_test(&test_settings(TraceLevel::Basic)).expect("init");
    let telemetry = Arc::new(telemetry);
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let config = config_for(&upstream);
    let server = GatewayServer::with_telemetry(config, telemetry.clone())
        .await
        .expect("server");
    let router = create_router(server.state());

    let response = post_json(
        router,
        "/v1/redact",
        json!({"text": "mail alice@example.com", "profile": "default"}),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["text"], "mail [EMAIL_ADDRESS]");
    assert!(upstream.captured.lock().unwrap().is_none());

    if let Some(p) = telemetry.tracer_provider() {
        let _ = p.force_flush();
    }
    let finished = handles.spans.finished();
    let names: Vec<String> = finished.iter().map(|s| s.name.to_string()).collect();
    for want in [
        semconv::span_name::DETECT,
        semconv::span_name::POLICY_EVALUATE,
        semconv::span_name::DETECT_PATTERNS,
    ] {
        assert!(
            names.iter().any(|n| n == want),
            "missing span {want} in {names:?}"
        );
    }
    for span in &finished {
        for kv in &span.attributes {
            let v = format!("{}", kv.value);
            assert!(
                !v.contains("alice@example.com"),
                "PII leaked onto span {}",
                span.name
            );
        }
    }
}

#[tokio::test]
async fn standalone_redact_omits_stage_spans_when_operations_off() {
    let _guard = env_lock();
    let redact_gateway::telemetry::testing::TestTelemetry {
        telemetry,
        handles,
        _guard,
    } = init_test(&test_settings(TraceLevel::Off)).expect("init");
    let telemetry = Arc::new(telemetry);
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.telemetry.operations = TraceLevel::Off;
    let server = GatewayServer::with_telemetry(config, telemetry.clone())
        .await
        .expect("server");
    let router = create_router(server.state());

    let response = post_json(
        router,
        "/v1/redact",
        json!({"text": "mail alice@example.com", "profile": "default"}),
    )
    .await;

    assert_eq!(response.status, StatusCode::OK);
    assert_eq!(response.json()["text"], "mail [EMAIL_ADDRESS]");

    if let Some(p) = telemetry.tracer_provider() {
        let _ = p.force_flush();
    }
    let finished = handles.spans.finished();
    let names: Vec<String> = finished.iter().map(|s| s.name.to_string()).collect();
    for forbid in [
        semconv::span_name::DETECT,
        semconv::span_name::POLICY_EVALUATE,
        semconv::span_name::DETECT_PATTERNS,
        semconv::span_name::DETECT_ONNX_LOCK_WAIT,
        semconv::span_name::DETECT_ONNX_EXEC,
        semconv::span_name::DETECT_TOKENIZER,
        semconv::span_name::DETECT_DECODE,
        semconv::span_name::DETECT_CONTEXTUAL,
    ] {
        assert!(
            names.iter().all(|n| n != forbid),
            "operations-off still emitted {forbid} in {names:?}"
        );
    }
}
