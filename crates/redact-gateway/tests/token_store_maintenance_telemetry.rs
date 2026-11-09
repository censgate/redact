//! Expiry-maintenance RED metrics and spans are exported without identifiers.
//! Kept in its own binary: the thread-local test subscriber must observe every
//! callsite, which parallel tests in a shared binary can pre-empt.
use std::sync::Mutex;
use std::time::Duration;

use redact_gateway::config::TraceLevel;
use redact_gateway::telemetry::testing::{init_test, test_settings};
use redact_gateway::vault::indexed::MaintenanceState;
use redact_gateway::vault::maintenance::{
    CheckpointStore, ExpiryTarget, Inventory, Limits, MaintenanceMetrics, StopReason, Worker,
    METRIC_BACKLOG, METRIC_BATCHES, METRIC_BATCH_DURATION, METRIC_CLEARED, METRIC_CONTEXTS,
    METRIC_PASS_AGE, METRIC_RETRIES, SPAN_BATCH, SPAN_RUN,
};
use redact_gateway::vault::TokenMapError;
use redact_token_store::Error;

struct Fake {
    expired: Mutex<usize>,
    fail_once: Mutex<bool>,
}

#[async_trait::async_trait]
impl ExpiryTarget for Fake {
    fn backend(&self) -> &'static str {
        "fake"
    }
    async fn state(&self, _: &str, context: &str) -> Result<MaintenanceState, TokenMapError> {
        Ok(if context.ends_with("-a") {
            MaintenanceState::Eligible
        } else {
            MaintenanceState::NotImported
        })
    }
    async fn purge(&self, _: &str, _: &str, limit: usize) -> Result<usize, TokenMapError> {
        if std::mem::take(&mut *self.fail_once.lock().unwrap()) {
            return Err(TokenMapError::Indexed(Error::Unavailable));
        }
        let mut expired = self.expired.lock().unwrap();
        let cleared = (*expired).min(limit);
        *expired -= cleared;
        Ok(cleared)
    }
}

#[tokio::test]
async fn red_metrics_and_spans_carry_no_identifiers() {
    let test = init_test(&test_settings(TraceLevel::Basic)).expect("telemetry");
    let meter = opentelemetry::metrics::MeterProvider::meter(
        test.telemetry.meter_provider().unwrap(),
        "redact-gateway",
    );
    let fake = Fake {
        expired: Mutex::new(3),
        fail_once: Mutex::new(true),
    };
    let lines = ["ctx-canary-a", "ctx-canary-b"]
        .iter()
        .map(|c| serde_json::json!({"tenant":"tenant-canary","context":c}).to_string())
        .collect::<Vec<_>>()
        .join("\n");
    let inventory = Inventory::parse(lines.as_bytes()).unwrap();
    let store = CheckpointStore::new(
        std::env::temp_dir().join(format!("maint-otel-{}.json", uuid::Uuid::new_v4())),
    );
    let limits = Limits {
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        ..Limits::default()
    };
    let summary = Worker::new(&fake, limits, MaintenanceMetrics::new(&meter))
        .unwrap()
        .run(&inventory, &store, false)
        .await
        .unwrap();
    assert_eq!(summary.stop_reason, Some(StopReason::PassComplete));
    assert_eq!((summary.cleared, summary.retries), (3, 1));
    test.flush();
    let metrics = test.collect_metrics();
    let names: Vec<_> = metrics.iter().map(|m| m.name.as_str()).collect();
    for expected in [
        METRIC_BATCHES,
        METRIC_BATCH_DURATION,
        METRIC_CLEARED,
        METRIC_CONTEXTS,
        METRIC_RETRIES,
        METRIC_BACKLOG,
        METRIC_PASS_AGE,
    ] {
        assert!(names.contains(&expected), "missing {expected}: {names:?}");
    }
    let duration = metrics
        .iter()
        .find(|m| m.name == METRIC_BATCH_DURATION)
        .unwrap();
    assert_eq!(duration.unit, "s");
    let batches = metrics.iter().find(|m| m.name == METRIC_BATCHES).unwrap();
    assert!(batches.data_debug.contains("token_store_unavailable"));
    for metric in &metrics {
        assert!(
            !metric.data_debug.contains("canary"),
            "{}",
            metric.data_debug
        );
    }
    let spans = test.finished_spans();
    let span_names: Vec<_> = spans.iter().map(|s| s.name.to_string()).collect();
    assert!(span_names.iter().any(|n| n == SPAN_RUN), "{span_names:?}");
    assert!(span_names.iter().any(|n| n == SPAN_BATCH), "{span_names:?}");
    for span in &spans {
        let rendered = format!("{span:?}");
        assert!(!rendered.contains("canary"), "{rendered}");
    }
}
