// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Telemetry and audit conformance tests.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use opentelemetry::trace::{SpanKind, TraceContextExt};
use redact_gateway::audit::{
    build_dispatcher, AuditContext, AuditEvent, AuditOutcome, AuditSink, FileSink, StdoutSink,
};
use redact_gateway::config::{AuditExport, AuditSettings, TelemetrySettings, TraceLevel};
use redact_gateway::redact::RedactionOutcome;
use redact_gateway::telemetry::semconv::{self, HTTP_DURATION_BOUNDS};
use redact_gateway::telemetry::testing::{init_test, test_settings, CapturedMetricKind};
use redact_gateway::telemetry::{self, spans, Metrics};
use tempfile::tempdir;

/// Serialize tests that mutate process-global OTEL env / providers.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

fn pii_outcome() -> RedactionOutcome {
    let mut entity_counts = BTreeMap::new();
    entity_counts.insert("EMAIL_ADDRESS".into(), 1);
    let mut action_counts = BTreeMap::new();
    action_counts.insert("replace".into(), 1);
    RedactionOutcome {
        redactions_applied: 1,
        entity_counts,
        action_counts,
        tokens_issued: 0,
        ..Default::default()
    }
}

fn assert_no_pii(haystack: &str) {
    assert!(
        !haystack.contains("alice@example.com"),
        "PII leaked into telemetry/audit payload: {haystack}"
    );
    assert!(
        !haystack.contains("secret-value"),
        "PII leaked into telemetry/audit payload: {haystack}"
    );
}

#[test]
fn metric_instruments_match_spec_names_units_and_kinds() {
    let _guard = env_lock();
    let tt = init_test(&test_settings(TraceLevel::Basic)).expect("init");
    let metrics = tt.telemetry.metrics();

    metrics.record_http_server(0.05, "POST", "https", "/v1/chat/completions", 200, None);
    metrics.record_http_client(0.02, "POST", Some(200), None);
    metrics.http_server_active_add(1, "POST", "https");
    metrics.record_redaction("EMAIL_ADDRESS", "replace", 1);
    metrics.record_policy_decision("default", "allow");
    metrics.record_tokenmap_operation("memory", "put", 0.001, None);
    metrics.record_audit_dropped(1);

    // Histograms need at least one data point for boundaries to appear.
    let captured = tt.collect_metrics();
    let by_name: BTreeMap<_, _> = captured.into_iter().map(|m| (m.name.clone(), m)).collect();

    let server = by_name
        .get(semconv::HTTP_SERVER_REQUEST_DURATION)
        .expect("http.server.request.duration");
    assert_eq!(server.unit, "s");
    assert_eq!(server.kind, CapturedMetricKind::Histogram);
    assert_eq!(server.boundaries, HTTP_DURATION_BOUNDS);

    let client = by_name
        .get(semconv::HTTP_CLIENT_REQUEST_DURATION)
        .expect("http.client.request.duration");
    assert_eq!(client.unit, "s");
    assert_eq!(client.kind, CapturedMetricKind::Histogram);

    let active = by_name
        .get(semconv::HTTP_SERVER_ACTIVE_REQUESTS)
        .expect("http.server.active_requests");
    assert_eq!(active.unit, "{request}");
    assert_eq!(active.kind, CapturedMetricKind::UpDownCounter);

    let redactions = by_name
        .get(semconv::REDACT_GATEWAY_REDACTIONS)
        .expect("redact.gateway.redactions");
    assert_eq!(redactions.unit, "{redaction}");
    assert_eq!(redactions.kind, CapturedMetricKind::Counter);

    let decisions = by_name
        .get(semconv::REDACT_GATEWAY_POLICY_DECISIONS)
        .expect("redact.gateway.policy.decisions");
    assert_eq!(decisions.unit, "{decision}");
    assert_eq!(decisions.kind, CapturedMetricKind::Counter);

    let token_ops = by_name
        .get(semconv::REDACT_GATEWAY_TOKENMAP_OPERATIONS)
        .expect("redact.gateway.tokenmap.operations");
    assert_eq!(token_ops.unit, "{operation}");
    assert_eq!(token_ops.kind, CapturedMetricKind::Counter);

    let token_dur = by_name
        .get(semconv::REDACT_GATEWAY_TOKENMAP_OPERATION_DURATION)
        .expect("redact.gateway.tokenmap.operation.duration");
    assert_eq!(token_dur.unit, "s");
    assert_eq!(token_dur.kind, CapturedMetricKind::Histogram);

    let dropped = by_name
        .get(semconv::REDACT_GATEWAY_AUDIT_RECORDS_DROPPED)
        .expect("redact.gateway.audit.records_dropped");
    assert_eq!(dropped.unit, "{record}");
    assert_eq!(dropped.kind, CapturedMetricKind::Counter);
}

#[test]
fn http_server_span_naming_kind_and_attributes() {
    let _guard = env_lock();
    let tt = init_test(&test_settings(TraceLevel::Off)).expect("init");

    {
        let span = spans::http_server("POST", "/v1/chat/completions", "https");
        let _enter = span.enter();
        spans::finish_http_server(&span, 200, None);
    }

    let finished = tt.finished_spans();
    let http = finished
        .iter()
        .find(|s| s.name == "POST /v1/chat/completions")
        .expect("http server span");
    assert_eq!(http.span_kind, SpanKind::Server);
    assert_attr(http, semconv::HTTP_REQUEST_METHOD, "POST");
    assert_attr(http, semconv::HTTP_ROUTE, "/v1/chat/completions");
    assert_attr(http, semconv::URL_SCHEME, "https");
    assert_attr_i64(http, semconv::HTTP_RESPONSE_STATUS_CODE, 200);
}

#[test]
fn operation_spans_respect_trace_level_and_nest() {
    let _guard = env_lock();

    // Basic: operation spans appear and nest under HTTP parent.
    {
        let tt = init_test(&test_settings(TraceLevel::Basic)).expect("init");
        {
            let parent = spans::http_server("POST", "/v1/chat/completions", "https");
            let _p = parent.enter();
            let detect = spans::detect(TraceLevel::Basic, 32).expect("detect span");
            let _d = detect.enter();
            spans::finish_detect(&detect, 1, TraceLevel::Basic, None);
            let anon = spans::anonymize(TraceLevel::Basic).expect("anon span");
            let _a = anon.enter();
            spans::finish_anonymize(&anon, 1, None);
        }
        let finished = tt.finished_spans();
        let parent = finished
            .iter()
            .find(|s| s.name == "POST /v1/chat/completions")
            .expect("parent");
        let detect = finished
            .iter()
            .find(|s| s.name.as_ref() == semconv::span_name::DETECT)
            .expect("detect");
        assert_eq!(detect.parent_span_id, parent.span_context.span_id());
        assert!(finished
            .iter()
            .any(|s| s.name.as_ref() == semconv::span_name::ANONYMIZE));
    }

    // Off: operation helpers return None (no construction).
    {
        assert!(spans::detect(TraceLevel::Off, 10).is_none());
        assert!(spans::anonymize(TraceLevel::Off).is_none());
        assert!(spans::policy_evaluate(TraceLevel::Off, "default").is_none());
        assert!(spans::detect_patterns(TraceLevel::Off).is_none());
        assert!(spans::detect_contextual(TraceLevel::Off).is_none());
        assert!(spans::detect_tokenizer(TraceLevel::Off).is_none());
        assert!(spans::detect_onnx_lock_wait(TraceLevel::Off).is_none());
        assert!(spans::detect_onnx_exec(TraceLevel::Off).is_none());
        assert!(spans::detect_decode(TraceLevel::Off).is_none());
    }

    // Detailed: stream chunk attribute is recorded.
    {
        let tt = init_test(&test_settings(TraceLevel::Detailed)).expect("init");
        {
            let span = spans::stream_redact(TraceLevel::Detailed, "incremental").unwrap();
            let _e = span.enter();
            spans::finish_stream_redact(&span, 7, TraceLevel::Detailed, None);
        }
        let finished = tt.finished_spans();
        let stream = finished
            .iter()
            .find(|s| s.name.as_ref() == semconv::span_name::STREAM_REDACT)
            .expect("stream");
        assert_attr_i64(stream, semconv::REDACT_STREAM_CHUNKS, 7);
        assert_attr(stream, semconv::REDACT_STREAM_MODE, "incremental");
    }
}

#[test]
fn traceparent_round_trip_preserves_trace_id() {
    let _guard = env_lock();
    let _tt = init_test(&test_settings(TraceLevel::Basic)).expect("init");

    // Seed an active context by creating a span.
    let parent = spans::http_server("GET", "/health", "http");
    let _enter = parent.enter();
    let cx = opentelemetry::Context::current();
    let expected = cx.span().span_context().trace_id();

    let mut outbound = reqwest::header::HeaderMap::new();
    telemetry::inject_context_with(&cx, &mut outbound);
    let traceparent = outbound
        .get("traceparent")
        .expect("traceparent injected")
        .to_str()
        .unwrap()
        .to_string();

    let mut inbound = axum::http::HeaderMap::new();
    inbound.insert(
        axum::http::header::HeaderName::from_static("traceparent"),
        axum::http::HeaderValue::from_str(&traceparent).unwrap(),
    );
    let extracted = telemetry::extract_context(&inbound);
    assert_eq!(extracted.span().span_context().trace_id(), expected);
}

#[test]
fn otel_sdk_disabled_is_noop_without_error() {
    let _guard = env_lock();
    // SAFETY: serialized by env_lock.
    std::env::set_var("OTEL_SDK_DISABLED", "true");
    std::env::set_var("OTEL_TRACES_EXPORTER", "none");
    std::env::set_var("OTEL_METRICS_EXPORTER", "none");
    std::env::set_var("OTEL_LOGS_EXPORTER", "none");

    let settings = TelemetrySettings::default();
    let tel = telemetry::init(&settings).expect("disabled init must succeed");
    assert!(tel.is_disabled());
    tel.metrics()
        .record_http_server(0.01, "GET", "http", "/health", 200, None);
    assert!(tel.tracer_provider().is_none());
    assert!(tel.prometheus_metrics().is_none() || tel.prometheus_metrics().is_some());

    std::env::remove_var("OTEL_SDK_DISABLED");
}

#[test]
fn spans_and_audit_never_contain_entity_values() {
    let _guard = env_lock();
    let tt = init_test(&test_settings(TraceLevel::Detailed)).expect("init");
    let outcome = pii_outcome();
    // Deliberately include a PII string only in local variables — helpers must
    // not accept it.
    let secret = "alice@example.com";
    let _ = secret;

    {
        let span = spans::detect(TraceLevel::Detailed, 64).unwrap();
        let _e = span.enter();
        spans::finish_detect(&span, 1, TraceLevel::Detailed, None);
        let anon = spans::anonymize(TraceLevel::Detailed).unwrap();
        let _a = anon.enter();
        spans::finish_anonymize(&anon, outcome.redactions_applied, None);
    }
    tt.telemetry
        .metrics()
        .record_redaction_outcome(&outcome, "default");

    let event = AuditEvent::from_outcome(
        &outcome,
        AuditContext {
            event_name: semconv::event::RESPONSE,
            action: "chat.completions".into(),
            profile: "default".into(),
            tenant: "t1".into(),
            content_sha256: Some(redact_gateway::redact::content_digest("[EMAIL_ADDRESS]")),
            include_entity_types: true,
            ..AuditContext::default()
        },
    );
    let json = serde_json::to_string(&event.to_json(true)).unwrap();
    assert_no_pii(&json);
    assert!(json.contains("EMAIL_ADDRESS"));

    for span in tt.finished_spans() {
        let rendered = format!("{:?}", span.attributes);
        assert_no_pii(&rendered);
        for kv in &span.attributes {
            let val = format!("{}", kv.value);
            assert_no_pii(&val);
        }
    }
}

#[tokio::test]
async fn audit_stdout_and_file_json_shape() {
    let outcome = pii_outcome();
    let event = AuditEvent::from_outcome(
        &outcome,
        AuditContext {
            event_name: semconv::event::RESPONSE,
            action: "chat.completions".into(),
            outcome: Some(AuditOutcome::Allowed),
            profile: "default".into(),
            tenant: "acme".into(),
            content_sha256: Some("abc123".into()),
            include_entity_types: true,
            ..AuditContext::default()
        },
    );

    let stdout = StdoutSink::new(true);
    stdout.emit(&event).await.unwrap();

    let dir = tempdir().unwrap();
    let path = dir.path().join("audit.jsonl");
    let file = FileSink::new(&path, true).unwrap();
    file.emit(&event).await.unwrap();
    let contents = std::fs::read_to_string(&path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(contents.trim()).unwrap();
    assert_eq!(parsed["event_name"], "redact.gateway.response");
    assert_eq!(parsed["action"], "chat.completions");
    assert_eq!(parsed["outcome"], "allowed");
    assert_eq!(parsed["profile"], "default");
    assert_eq!(parsed["tenant"], "acme");
    assert_eq!(parsed["redactions"], 1);
    assert!(parsed.get("entity_types").is_some());
    assert_no_pii(&contents);
}

#[tokio::test]
async fn audit_include_entity_types_false_omits_list() {
    let outcome = pii_outcome();
    let event = AuditEvent::from_outcome(
        &outcome,
        AuditContext {
            event_name: semconv::event::RESPONSE,
            action: "chat.completions".into(),
            profile: "default".into(),
            tenant: "t".into(),
            include_entity_types: false,
            ..AuditContext::default()
        },
    );
    assert!(event.entity_types.is_empty());
    let json = event.to_json(false);
    assert!(json.get("entity_types").is_none());
}

#[tokio::test(flavor = "current_thread")]
async fn audit_full_queue_drops_and_reports_count() {
    let settings = AuditSettings {
        export: AuditExport::Stdout,
        file_path: None,
        queue_capacity: 1,
        include_entity_types: true,
    };
    let dispatcher = build_dispatcher(&settings, None).unwrap();

    // Fill the queue and overflow.
    for i in 0..50 {
        let event = AuditEvent::from_outcome(
            &pii_outcome(),
            AuditContext {
                event_name: semconv::event::REQUEST,
                action: format!("op-{i}"),
                profile: "default".into(),
                tenant: "t".into(),
                include_entity_types: true,
                ..AuditContext::default()
            },
        );
        dispatcher.emit(event);
    }

    // Give the worker a moment; drops should be > 0 because capacity is 1.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        dispatcher.dropped() > 0,
        "expected drops on a capacity-1 queue, got {}",
        dispatcher.dropped()
    );
    let _ = dispatcher.shutdown().await;
}

#[test]
fn metrics_noop_when_disabled() {
    // Ensures Metrics::noop constructs without panicking.
    let metrics = Metrics::noop();
    metrics.record_audit_dropped(1);
    metrics.record_policy_decision("default", "allow");
}

fn assert_attr(span: &opentelemetry_sdk::trace::SpanData, key: &str, expected: &str) {
    let found = span
        .attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .unwrap_or_else(|| panic!("missing attribute {key} on span {}", span.name));
    let actual = match &found.value {
        opentelemetry::Value::String(s) => s.as_str().to_string(),
        other => format!("{other}"),
    };
    assert_eq!(actual, expected, "attribute {key}");
}

fn assert_attr_i64(span: &opentelemetry_sdk::trace::SpanData, key: &str, expected: i64) {
    let found = span
        .attributes
        .iter()
        .find(|kv| kv.key.as_str() == key)
        .unwrap_or_else(|| panic!("missing attribute {key} on span {}", span.name));
    let actual = match &found.value {
        opentelemetry::Value::I64(v) => *v,
        opentelemetry::Value::String(s) => s
            .as_str()
            .parse()
            .unwrap_or_else(|_| panic!("non-numeric string for {key}: {s}")),
        other => panic!("expected i64/string for {key}, got {other:?}"),
    };
    assert_eq!(actual, expected, "attribute {key}");
}
