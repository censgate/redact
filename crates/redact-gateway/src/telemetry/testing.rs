// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! In-process exporters and bootstrap helpers for conformance tests.
//!
//! The SDK's `InMemory*Exporter` types require the `testing` feature on
//! `opentelemetry_sdk`, which this crate does not enable. These capturing
//! exporters mirror that API surface for gateway tests.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use opentelemetry::metrics::MeterProvider as _;
use opentelemetry::propagation::TextMapCompositePropagator;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::logs::{LogBatch, LogExporter, SdkLogRecord, SdkLoggerProvider};
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, MetricData, ResourceMetrics};
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{SdkMeterProvider, Temporality};
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use opentelemetry_sdk::trace::{SdkTracerProvider, SpanData, SpanExporter};
use opentelemetry_sdk::Resource;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

use crate::config::{TelemetrySettings, TraceLevel};

use super::metrics::Metrics;
use super::semconv;
use super::{Telemetry, TelemetryError};

/// Captured log fields for assertions.
#[derive(Debug, Clone)]
pub struct CapturedLog {
    /// `event.name` when set.
    pub event_name: Option<&'static str>,
    /// Attribute key/value pairs as strings.
    pub attributes: Vec<(String, String)>,
    /// Trace id hex, when correlated.
    pub trace_id: Option<String>,
    /// Span id hex, when correlated.
    pub span_id: Option<String>,
}

/// Summary of a metric instrument observed during collection.
#[derive(Debug, Clone)]
pub struct CapturedMetric {
    /// Instrument name.
    pub name: String,
    /// UCUM unit.
    pub unit: String,
    /// Coarse instrument kind inferred from aggregated data.
    pub kind: CapturedMetricKind,
    /// Explicit histogram boundaries when present.
    pub boundaries: Vec<f64>,
}

/// Instrument kind as observed after aggregation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedMetricKind {
    /// Monotonic sum (Counter).
    Counter,
    /// Non-monotonic sum (UpDownCounter).
    UpDownCounter,
    /// Histogram.
    Histogram,
    /// Gauge or other.
    Other,
}

/// Shared handle to spans collected by [`CapturingSpanExporter`].
#[derive(Clone, Default, Debug)]
pub struct SpanRecorder {
    inner: Arc<Mutex<Vec<SpanData>>>,
}

impl SpanRecorder {
    /// Finished spans since the last reset.
    pub fn finished(&self) -> Vec<SpanData> {
        self.inner.lock().expect("span recorder").clone()
    }

    /// Clear recorded spans.
    pub fn reset(&self) {
        self.inner.lock().expect("span recorder").clear();
    }
}

/// In-memory span exporter.
#[derive(Clone, Debug, Default)]
pub struct CapturingSpanExporter {
    recorder: SpanRecorder,
}

impl CapturingSpanExporter {
    /// Create an exporter and its shared recorder.
    pub fn new() -> (Self, SpanRecorder) {
        let recorder = SpanRecorder::default();
        (
            Self {
                recorder: recorder.clone(),
            },
            recorder,
        )
    }
}

impl SpanExporter for CapturingSpanExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        self.recorder
            .inner
            .lock()
            .map_err(|e| OTelSdkError::InternalFailure(e.to_string()))?
            .extend(batch);
        Ok(())
    }
}

/// Shared handle to logs collected by [`CapturingLogExporter`].
#[derive(Clone, Default, Debug)]
pub struct LogRecorder {
    inner: Arc<Mutex<Vec<CapturedLog>>>,
}

impl LogRecorder {
    /// Captured logs since the last reset.
    pub fn finished(&self) -> Vec<CapturedLog> {
        self.inner.lock().expect("log recorder").clone()
    }

    /// Clear recorded logs.
    pub fn reset(&self) {
        self.inner.lock().expect("log recorder").clear();
    }
}

/// In-memory log exporter.
#[derive(Clone, Debug, Default)]
pub struct CapturingLogExporter {
    recorder: LogRecorder,
}

impl CapturingLogExporter {
    /// Create an exporter and its shared recorder.
    pub fn new() -> (Self, LogRecorder) {
        let recorder = LogRecorder::default();
        (
            Self {
                recorder: recorder.clone(),
            },
            recorder,
        )
    }
}

impl LogExporter for CapturingLogExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        let mut guard = self
            .recorder
            .inner
            .lock()
            .map_err(|e| OTelSdkError::InternalFailure(e.to_string()))?;
        for (record, _scope) in batch.iter() {
            guard.push(capture_log(record));
        }
        Ok(())
    }
}

fn capture_log(record: &SdkLogRecord) -> CapturedLog {
    let attributes = record
        .attributes_iter()
        .map(|(k, v)| (k.to_string(), format!("{v:?}")))
        .collect();
    let (trace_id, span_id) = record
        .trace_context()
        .map(|tc| (Some(tc.trace_id.to_string()), Some(tc.span_id.to_string())))
        .unwrap_or((None, None));
    CapturedLog {
        event_name: record.event_name(),
        attributes,
        trace_id,
        span_id,
    }
}

/// Shared handle to metrics collected by [`CapturingMetricExporter`].
#[derive(Clone, Default, Debug)]
pub struct MetricRecorder {
    inner: Arc<Mutex<Vec<CapturedMetric>>>,
}

impl MetricRecorder {
    /// Latest captured metric summaries.
    pub fn finished(&self) -> Vec<CapturedMetric> {
        self.inner.lock().expect("metric recorder").clone()
    }

    /// Clear recorded metrics.
    pub fn reset(&self) {
        self.inner.lock().expect("metric recorder").clear();
    }
}

/// In-memory metric exporter that stores instrument summaries.
#[derive(Clone, Debug, Default)]
pub struct CapturingMetricExporter {
    recorder: MetricRecorder,
    temporality: Temporality,
}

impl CapturingMetricExporter {
    /// Create an exporter and its shared recorder.
    pub fn new() -> (Self, MetricRecorder) {
        let recorder = MetricRecorder::default();
        (
            Self {
                recorder: recorder.clone(),
                temporality: Temporality::Cumulative,
            },
            recorder,
        )
    }
}

impl PushMetricExporter for CapturingMetricExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        let mut captured = Vec::new();
        for scope in metrics.scope_metrics() {
            for metric in scope.metrics() {
                let (kind, boundaries) = classify(metric.data());
                captured.push(CapturedMetric {
                    name: metric.name().to_string(),
                    unit: metric.unit().to_string(),
                    kind,
                    boundaries,
                });
            }
        }
        *self
            .recorder
            .inner
            .lock()
            .map_err(|e| OTelSdkError::InternalFailure(e.to_string()))? = captured;
        Ok(())
    }

    fn force_flush(&self) -> OTelSdkResult {
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        Ok(())
    }

    fn temporality(&self) -> Temporality {
        self.temporality
    }
}

fn classify(data: &AggregatedMetrics) -> (CapturedMetricKind, Vec<f64>) {
    match data {
        AggregatedMetrics::F64(MetricData::Histogram(h)) => {
            let bounds = h
                .data_points()
                .next()
                .map(|dp| dp.bounds().collect())
                .unwrap_or_default();
            (CapturedMetricKind::Histogram, bounds)
        }
        AggregatedMetrics::U64(MetricData::Histogram(h)) => {
            let bounds = h
                .data_points()
                .next()
                .map(|dp| dp.bounds().collect())
                .unwrap_or_default();
            (CapturedMetricKind::Histogram, bounds)
        }
        AggregatedMetrics::I64(MetricData::Histogram(h)) => {
            let bounds = h
                .data_points()
                .next()
                .map(|dp| dp.bounds().collect())
                .unwrap_or_default();
            (CapturedMetricKind::Histogram, bounds)
        }
        AggregatedMetrics::U64(MetricData::Sum(s)) => {
            if s.is_monotonic() {
                (CapturedMetricKind::Counter, Vec::new())
            } else {
                (CapturedMetricKind::UpDownCounter, Vec::new())
            }
        }
        AggregatedMetrics::I64(MetricData::Sum(s)) => {
            if s.is_monotonic() {
                (CapturedMetricKind::Counter, Vec::new())
            } else {
                (CapturedMetricKind::UpDownCounter, Vec::new())
            }
        }
        AggregatedMetrics::F64(MetricData::Sum(s)) => {
            if s.is_monotonic() {
                (CapturedMetricKind::Counter, Vec::new())
            } else {
                (CapturedMetricKind::UpDownCounter, Vec::new())
            }
        }
        _ => (CapturedMetricKind::Other, Vec::new()),
    }
}

/// Handles returned by [`init_test`].
#[derive(Debug)]
pub struct TestHandles {
    /// Span recorder.
    pub spans: SpanRecorder,
    /// Metric recorder.
    pub metrics: MetricRecorder,
    /// Log recorder.
    pub logs: LogRecorder,
}

/// Telemetry plus test handles.
#[derive(Debug)]
pub struct TestTelemetry {
    /// Bootstrapped telemetry.
    pub telemetry: Telemetry,
    /// In-memory collectors.
    pub handles: TestHandles,
    _guard: Option<tracing::subscriber::DefaultGuard>,
}

impl TestTelemetry {
    /// Force-flush providers so exporters observe recent data.
    pub fn flush(&self) {
        if let Some(p) = self.telemetry.tracer_provider() {
            let _ = p.force_flush();
        }
        if let Some(p) = self.telemetry.meter_provider() {
            let _ = p.force_flush();
        }
        if let Some(p) = self.telemetry.logger_provider() {
            let _ = p.force_flush();
        }
    }

    /// Collect metrics snapshot (after flush).
    pub fn collect_metrics(&self) -> Vec<CapturedMetric> {
        self.flush();
        self.handles.metrics.finished()
    }

    /// Finished spans.
    pub fn finished_spans(&self) -> Vec<SpanData> {
        self.flush();
        self.handles.spans.finished()
    }

    /// Finished logs.
    pub fn finished_logs(&self) -> Vec<CapturedLog> {
        self.flush();
        self.handles.logs.finished()
    }
}

/// Bootstrap telemetry with in-memory exporters for conformance tests.
///
/// Installs a thread-local tracing subscriber with the OpenTelemetry layer so
/// operation spans created via [`super::spans`] are exported.
pub fn init_test(settings: &TelemetrySettings) -> Result<TestTelemetry, TelemetryError> {
    let resource = Resource::builder()
        .with_service_name("redact-gateway-test")
        .with_attribute(KeyValue::new(
            semconv::SERVICE_VERSION,
            env!("CARGO_PKG_VERSION"),
        ))
        .build();

    global::set_text_map_propagator(TextMapCompositePropagator::new(vec![
        Box::new(TraceContextPropagator::new()),
        Box::new(BaggagePropagator::new()),
    ]));

    let (span_exporter, span_recorder) = CapturingSpanExporter::new();
    let tracer_provider = SdkTracerProvider::builder()
        .with_resource(resource.clone())
        .with_simple_exporter(span_exporter)
        .build();

    let (metric_exporter, metric_recorder) = CapturingMetricExporter::new();
    let meter_provider = SdkMeterProvider::builder()
        .with_resource(resource.clone())
        .with_periodic_exporter(metric_exporter)
        .build();

    let (log_exporter, log_recorder) = CapturingLogExporter::new();
    let logger_provider = SdkLoggerProvider::builder()
        .with_resource(resource)
        .with_simple_exporter(log_exporter)
        .build();

    global::set_tracer_provider(tracer_provider.clone());
    global::set_meter_provider(meter_provider.clone());

    let meter = meter_provider.meter("redact-gateway");
    let metrics = Metrics::new(&meter);

    let tracer = tracer_provider.tracer("redact-gateway");
    let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
    let subscriber = Registry::default().with(otel_layer);
    let guard = tracing::subscriber::set_default(subscriber);

    let telemetry = Telemetry {
        tracer_provider: Some(tracer_provider),
        meter_provider: Some(meter_provider),
        logger_provider: Some(logger_provider),
        metrics,
        trace_level: settings.operations,
        genai_attributes: settings.genai_attributes,
        filter: settings.filter.clone(),
        disabled: false,
        summary: serde_json::json!({
            "disabled": false,
            "operations": settings.operations.as_str(),
            "traces_exporter": "memory",
            "metrics_exporter": "memory",
            "logs_exporter": "memory",
            "sampler": "always_on",
        }),
        #[cfg(feature = "prometheus")]
        prometheus_registry: None,
    };

    Ok(TestTelemetry {
        telemetry,
        handles: TestHandles {
            spans: span_recorder,
            metrics: metric_recorder,
            logs: log_recorder,
        },
        _guard: Some(guard),
    })
}

/// Convenience settings for tests.
pub fn test_settings(level: TraceLevel) -> TelemetrySettings {
    TelemetrySettings {
        operations: level,
        filter: None,
        genai_attributes: false,
    }
}
