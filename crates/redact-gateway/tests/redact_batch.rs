// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Batch redaction, admission and RED metrics.
//!
//! The timed cases are the load check for this change: one packed detection
//! versus one detection per leaf, and overload that fails before detection.

mod support;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::http::StatusCode;
use redact_core::recognizers::Recognizer;
use redact_core::{AnalyzerEngine, EntityType, RecognizerResult};
use redact_gateway::config::{ResolvedConfig, TraceLevel, VaultBackend};
use redact_gateway::telemetry::semconv;
use redact_gateway::telemetry::testing::{
    init_test, test_settings, CapturedMetric, MetricRecorder,
};
use redact_gateway::GatewayServer;
use serde_json::json;
use support::{policy_with, post_json, post_json_with_headers, tokenize_profile};

#[derive(Debug)]
struct Probe {
    sizes: std::sync::Mutex<Vec<usize>>,
    delay: Duration,
    entered: Arc<AtomicBool>,
}

impl Probe {
    fn new(delay: Duration) -> Arc<Self> {
        Arc::new(Self {
            sizes: std::sync::Mutex::new(Vec::new()),
            delay,
            entered: Arc::new(AtomicBool::new(false)),
        })
    }

    fn sizes(&self) -> Vec<usize> {
        self.sizes.lock().expect("probe").clone()
    }
}

impl Recognizer for Probe {
    fn name(&self) -> &str {
        "probe"
    }

    fn supported_entities(&self) -> &[EntityType] {
        &[EntityType::EmailAddress]
    }

    fn analyze(&self, text: &str, language: &str) -> anyhow::Result<Vec<RecognizerResult>> {
        let mut rows = self.analyze_batch(std::slice::from_ref(&text), language)?;
        Ok(rows.pop().unwrap_or_default())
    }

    fn analyze_batch(&self, texts: &[&str], _: &str) -> anyhow::Result<Vec<Vec<RecognizerResult>>> {
        self.sizes.lock().expect("probe").push(texts.len());
        self.entered.store(true, Ordering::Release);
        if !self.delay.is_zero() {
            std::thread::sleep(self.delay);
        }
        Ok(texts
            .iter()
            .map(|text| {
                if text.contains('@') {
                    vec![RecognizerResult::new(
                        EntityType::EmailAddress,
                        0,
                        text.len(),
                        0.99,
                        "probe",
                    )]
                } else {
                    Vec::new()
                }
            })
            .collect())
    }
}

struct Running {
    router: axum::Router,
    state: redact_gateway::routes::AppState,
    metrics: MetricRecorder,
    _guard: tracing::subscriber::DefaultGuard,
}

async fn open(config: ResolvedConfig, engine: Option<Arc<AnalyzerEngine>>) -> Running {
    let server = match engine {
        Some(engine) => GatewayServer::with_engine(config, engine)
            .await
            .expect("server"),
        None => GatewayServer::new(config).await.expect("server"),
    };
    let telemetry = init_test(&test_settings(TraceLevel::Off)).expect("telemetry");
    let metrics = telemetry.handles.metrics.clone();
    let guard = telemetry._guard.expect("subscriber guard");
    let mut state = server.state();
    state.telemetry = Arc::new(telemetry.telemetry);
    let router = redact_gateway::routes::create_router(state.clone());
    Running {
        router,
        state,
        metrics,
        _guard: guard,
    }
}

fn collect(running: &Running) -> Vec<CapturedMetric> {
    if let Some(provider) = running.state.telemetry.meter_provider() {
        let _ = provider.force_flush();
    }
    running.metrics.finished()
}

fn matches_outcome(
    point: &redact_gateway::telemetry::testing::CapturedPoint,
    outcome: &str,
) -> bool {
    point
        .attributes
        .iter()
        .any(|(key, value)| key == semconv::REDACT_OUTCOME && value.contains(outcome))
}

fn point_value(metrics: &[CapturedMetric], name: &str, outcome: &str) -> f64 {
    metrics
        .iter()
        .find(|metric| metric.name == name)
        .map(|metric| {
            metric
                .points
                .iter()
                .filter(|point| matches_outcome(point, outcome))
                .map(|point| point.value)
                .sum()
        })
        .unwrap_or(0.0)
}

fn duration_count(metrics: &[CapturedMetric], outcome: &str) -> u64 {
    metrics
        .iter()
        .find(|metric| metric.name == semconv::REDACT_GATEWAY_REDACT_DURATION)
        .map(|metric| {
            metric
                .points
                .iter()
                .filter(|point| matches_outcome(point, outcome))
                .map(|point| point.count)
                .sum()
        })
        .unwrap_or(0)
}

fn engine_with(probe: Arc<Probe>) -> Arc<AnalyzerEngine> {
    let mut registry = redact_core::recognizers::RecognizerRegistry::new();
    registry.add_recognizer(probe);
    Arc::new(
        AnalyzerEngine::builder()
            .with_recognizer_registry(registry)
            .build(),
    )
}

fn batch_config(inflight: u32, queue_ms: u64, depth: u32) -> ResolvedConfig {
    let mut config = ResolvedConfig::default();
    config.server.redact_batch_enabled = true;
    config.server.redact_batch_inflight = inflight;
    config.server.redact_batch_queue_ms = queue_ms;
    config.server.redact_batch_queue_depth = depth;
    config.vault.backend = VaultBackend::Memory;
    config.policy = Arc::new(policy_with(tokenize_profile(true)));
    config
}

#[tokio::test]
async fn texts_are_rejected_until_batching_is_enabled() {
    let running = open(ResolvedConfig::default(), None).await;
    let response = post_json(
        running.router.clone(),
        "/v1/redact",
        json!({"texts": ["ada@example.com"]}),
    )
    .await;
    assert_eq!(response.status, StatusCode::BAD_REQUEST);
    assert_eq!(response.json()["error"]["type"], "invalid_request_error");
    assert!(!response.body.contains("ada@example.com"));

    let status = support::get_path(running.router.clone(), "/v1/compliance/status").await;
    assert_eq!(status.status, StatusCode::OK);
    assert_eq!(status.json()["capabilities"]["redact_texts_v1"], false);
    assert_eq!(status.json()["capabilities"]["max_texts"], 800);

    let metrics = collect(&running);
    assert_eq!(
        point_value(&metrics, semconv::REDACT_GATEWAY_REDACT_REQUESTS, "error"),
        1.0
    );
    assert_eq!(
        point_value(&metrics, semconv::REDACT_GATEWAY_REDACT_ERRORS, "error"),
        1.0
    );
    assert_eq!(duration_count(&metrics, "error"), 1);
}

#[tokio::test]
async fn batch_preserves_order_and_reuses_one_session() {
    let mut config = batch_config(1, 0, 0);
    config.server.redact_batch_enabled = true;
    let running = open(config, None).await;

    let scalar = post_json(
        running.router.clone(),
        "/v1/redact",
        json!({"text": "ada@example.com", "session_id": "scalar"}),
    )
    .await;
    assert_eq!(scalar.status, StatusCode::OK, "{}", scalar.body);
    assert!(scalar.json()["text"]
        .as_str()
        .unwrap()
        .contains("EMAIL_ADDRESS"));

    let first = post_json(
        running.router.clone(),
        "/v1/redact",
        json!({"texts": ["ada@example.com", "plain"], "session_id": "batch"}),
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    let texts = first.json()["texts"].as_array().unwrap().clone();
    assert_eq!(texts.len(), 2);
    assert!(texts[0].as_str().unwrap().contains("EMAIL_ADDRESS_1"));
    assert_eq!(texts[1], "plain");
    assert!(first.json().get("text").is_none());

    let second = post_json(
        running.router.clone(),
        "/v1/redact",
        json!({"texts": ["bea@example.com", "ada@example.com"], "session_id": "batch"}),
    )
    .await;
    assert_eq!(second.status, StatusCode::OK, "{}", second.body);
    let again = second.json()["texts"].as_array().unwrap().clone();
    assert!(again[0].as_str().unwrap().contains("EMAIL_ADDRESS_2"));
    assert_eq!(again[1], texts[0]);

    let both = post_json(
        running.router.clone(),
        "/v1/redact",
        json!({"text": "ada@example.com", "texts": ["ada@example.com"]}),
    )
    .await;
    assert_eq!(both.status, StatusCode::BAD_REQUEST);

    let metrics = collect(&running);
    assert!(
        point_value(
            &metrics,
            semconv::REDACT_GATEWAY_REDACT_REQUESTS,
            "completed"
        ) >= 3.0
    );
    assert_eq!(
        point_value(&metrics, semconv::REDACT_GATEWAY_REDACT_ERRORS, "completed"),
        0.0
    );
}

#[tokio::test]
async fn invalid_batch_body_does_not_echo_its_contents() {
    let running = open(batch_config(1, 0, 0), None).await;
    let response = post_json(
        running.router.clone(),
        "/v1/redact",
        json!({"texts": "super-secret-leaf"}),
    )
    .await;
    assert!(response.status.is_client_error(), "{}", response.status);
    assert!(
        !response.body.contains("super-secret-leaf"),
        "{}",
        response.body
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn overload_fails_before_detection_and_records_red() {
    let probe = Probe::new(Duration::from_millis(200));
    let running = open(batch_config(1, 0, 0), Some(engine_with(Arc::clone(&probe)))).await;
    let started = Instant::now();
    let mut tasks = Vec::new();
    for index in 0..8 {
        let router = running.router.clone();
        tasks.push(tokio::spawn(async move {
            let began = Instant::now();
            let response = post_json(
                router,
                "/v1/redact",
                json!({"texts": [format!("user{index}@example.com")], "session_id": format!("s{index}")}),
            )
            .await;
            (response, began.elapsed())
        }));
    }
    let mut completed = 0u32;
    let mut overload = 0u32;
    let mut overload_max = Duration::ZERO;
    for task in tasks {
        let (response, elapsed) = task.await.expect("task");
        if response.status == StatusCode::OK {
            completed += 1;
        } else {
            assert_eq!(
                response.status,
                StatusCode::SERVICE_UNAVAILABLE,
                "{}",
                response.body
            );
            assert_eq!(response.json()["error"]["type"], "overload");
            overload += 1;
            overload_max = overload_max.max(elapsed);
        }
    }
    assert_eq!(completed, 1, "one permit");
    assert_eq!(overload, 7);
    // The detector call count is the admission proof. This bound only rejects
    // a multi-second queue wait. Coverage tracing can delay a fail-fast
    // reject without the request entering detection.
    assert!(
        overload_max < Duration::from_millis(750),
        "overload waited {overload_max:?}; admission should not hold for detection"
    );
    assert_eq!(probe.sizes(), vec![1], "rejected requests must not detect");
    let metrics = collect(&running);
    assert_eq!(
        point_value(
            &metrics,
            semconv::REDACT_GATEWAY_REDACT_REQUESTS,
            "completed"
        ),
        1.0
    );
    assert_eq!(
        point_value(
            &metrics,
            semconv::REDACT_GATEWAY_REDACT_REQUESTS,
            "overload"
        ),
        7.0
    );
    assert_eq!(
        point_value(&metrics, semconv::REDACT_GATEWAY_REDACT_ERRORS, "overload"),
        7.0
    );
    assert_eq!(
        point_value(&metrics, semconv::REDACT_GATEWAY_REDACT_ERRORS, "completed"),
        0.0
    );
    assert_eq!(duration_count(&metrics, "completed"), 1);
    assert_eq!(duration_count(&metrics, "overload"), 7);
    eprintln!(
        "redact_admission_bench offered=8 completed={completed} overload={overload} overload_max_ms={} wall_ms={}",
        overload_max.as_secs_f64() * 1_000.0,
        started.elapsed().as_secs_f64() * 1_000.0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn queued_deadline_does_not_detect_or_write() {
    let probe = Probe::new(Duration::from_millis(400));
    let running = open(
        batch_config(1, 5_000, 1),
        Some(engine_with(Arc::clone(&probe))),
    )
    .await;
    let holder = tokio::spawn({
        let router = running.router.clone();
        async move {
            post_json(
                router,
                "/v1/redact",
                json!({"texts": ["holder@example.com"], "session_id": "holder"}),
            )
            .await
        }
    });
    let entered = Arc::clone(&probe.entered);
    let wait_started = Instant::now();
    while !entered.load(Ordering::Acquire) {
        if wait_started.elapsed() > Duration::from_secs(2) {
            panic!("holder never started detection");
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let queued = post_json_with_headers(
        running.router.clone(),
        "/v1/redact",
        json!({"texts": ["queued@example.com"], "session_id": "queued"}),
        &[("x-censgate-redact-timeout-ms", "60")], // pragma: allowlist secret
    )
    .await;
    assert_eq!(
        queued.status,
        StatusCode::GATEWAY_TIMEOUT,
        "{}",
        queued.body
    );
    assert_eq!(queued.json()["error"]["type"], "deadline");
    assert_eq!(probe.sizes(), vec![1]);
    let stored = running
        .state
        .tokens
        .get("default", "queued")
        .await
        .expect("read");
    assert!(stored.is_empty(), "deadline must not write");
    let holder = holder.await.expect("holder");
    assert_eq!(holder.status, StatusCode::OK, "{}", holder.body);
    let metrics = collect(&running);
    assert_eq!(
        point_value(&metrics, semconv::REDACT_GATEWAY_REDACT_ERRORS, "deadline"),
        1.0
    );
    assert_eq!(duration_count(&metrics, "deadline"), 1);
    assert_eq!(
        point_value(
            &metrics,
            semconv::REDACT_GATEWAY_REDACT_REQUESTS,
            "completed"
        ),
        1.0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_batch_detects_in_fewer_rounds_than_serial_leaves() {
    let probe = Probe::new(Duration::from_millis(8));
    let running = open(batch_config(1, 0, 0), Some(engine_with(Arc::clone(&probe)))).await;
    let leaves = 16usize;
    let serial_started = Instant::now();
    for index in 0..leaves {
        let response = post_json(
            running.router.clone(),
            "/v1/redact",
            json!({"text": format!("user{index}@example.com"), "session_id": format!("serial-{index}")}),
        )
        .await;
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    }
    let serial = serial_started.elapsed();
    probe.sizes.lock().expect("probe").clear();

    let batch_started = Instant::now();
    let texts: Vec<String> = (0..leaves)
        .map(|index| format!("batch{index}@example.com"))
        .collect();
    let response = post_json(
        running.router.clone(),
        "/v1/redact",
        json!({"texts": texts, "session_id": "packed"}),
    )
    .await;
    let batched = batch_started.elapsed();
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    assert_eq!(response.json()["texts"].as_array().unwrap().len(), leaves);
    assert_eq!(
        probe.sizes(),
        vec![leaves],
        "one request should detect every leaf together"
    );
    assert!(
        serial > batched.saturating_mul(3),
        "serial {serial:?} should cost more than one packed batch {batched:?}"
    );
    let metrics = collect(&running);
    let completed = point_value(
        &metrics,
        semconv::REDACT_GATEWAY_REDACT_REQUESTS,
        "completed",
    );
    let errors = metrics
        .iter()
        .find(|metric| metric.name == semconv::REDACT_GATEWAY_REDACT_ERRORS)
        .map(|metric| metric.points.iter().map(|point| point.value).sum::<f64>())
        .unwrap_or(0.0);
    assert_eq!(completed, leaves as f64 + 1.0);
    assert_eq!(errors, 0.0);
    assert!(duration_count(&metrics, "completed") >= leaves as u64);
    eprintln!(
        "redact_batch_bench leaves={leaves} serial_ms={:.1} batch_ms={:.1} speedup={:.1} serial_rounds={leaves} batch_rounds=1",
        serial.as_secs_f64() * 1_000.0,
        batched.as_secs_f64() * 1_000.0,
        serial.as_secs_f64() / batched.as_secs_f64()
    );
}
