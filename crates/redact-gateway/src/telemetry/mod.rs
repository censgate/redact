// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! OpenTelemetry SDK bootstrap for traces, metrics and logs.
//!
//! # Environment variables
//!
//! ## Handled by this module
//!
//! | Variable | Role |
//! |---|---|
//! | `OTEL_SDK_DISABLED` | When `true`, all signals become no-ops. |
//! | `OTEL_TRACES_EXPORTER` | Trace exporter selection: `otlp`, `console`, `none`. Default `otlp` (or `none` without the `otlp` feature). |
//! | `OTEL_METRICS_EXPORTER` | Metrics exporter selection: `otlp`, `console`, `none` (comma-separated). Default `otlp`. |
//! | `OTEL_LOGS_EXPORTER` | Logs exporter selection: `otlp`, `console`, `none`. Default `otlp`. |
//! | `OTEL_PROPAGATORS` | Comma-separated propagators. Default `tracecontext,baggage`. |
//!
//! ## Handled by the OpenTelemetry SDK / OTLP crate
//!
//! | Variable | Handler |
//! |---|---|
//! | `OTEL_SERVICE_NAME` | SDK resource detector (we default to `redact-gateway` when unset). |
//! | `OTEL_RESOURCE_ATTRIBUTES` | SDK `EnvResourceDetector`. |
//! | `OTEL_EXPORTER_OTLP_ENDPOINT` / per-signal overrides | `opentelemetry-otlp`. |
//! | `OTEL_EXPORTER_OTLP_PROTOCOL` / per-signal overrides | `opentelemetry-otlp` (`grpc`, `http/protobuf`). |
//! | `OTEL_EXPORTER_OTLP_HEADERS` / per-signal overrides | `opentelemetry-otlp`. |
//! | `OTEL_TRACES_SAMPLER` / `OTEL_TRACES_SAMPLER_ARG` | SDK `Config::default()`. |
//! | `OTEL_BSP_*` | SDK `BatchSpanProcessor` / `BatchConfig`. |
//! | `OTEL_METRIC_EXPORT_INTERVAL` | SDK `PeriodicReader`. |

pub mod metrics;
pub mod semconv;
pub mod spans;

mod console;
pub mod testing;

use opentelemetry::propagation::{
    Extractor, Injector, TextMapCompositePropagator, TextMapPropagator,
};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::{global, KeyValue};
use opentelemetry_sdk::logs::{SdkLogger, SdkLoggerProvider};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::{BaggagePropagator, TraceContextPropagator};
use opentelemetry_sdk::trace::SdkTracerProvider;
use opentelemetry_sdk::Resource;
use thiserror::Error;
use tracing_subscriber::{EnvFilter, Registry};

use crate::config::{TelemetrySettings, TraceLevel};

pub use metrics::Metrics;
pub use testing::{TestHandles, TestTelemetry};

/// Failures while bootstrapping telemetry.
#[derive(Debug, Error)]
pub enum TelemetryError {
    /// An exporter could not be constructed.
    #[error("telemetry exporter error: {0}")]
    Exporter(String),
    /// Invalid configuration.
    #[error("telemetry configuration error: {0}")]
    Config(String),
}

/// Live OpenTelemetry providers and gateway instruments.
pub struct Telemetry {
    tracer_provider: Option<SdkTracerProvider>,
    meter_provider: Option<SdkMeterProvider>,
    logger_provider: Option<SdkLoggerProvider>,
    metrics: Metrics,
    trace_level: TraceLevel,
    genai_attributes: bool,
    filter: Option<String>,
    disabled: bool,
    summary: serde_json::Value,
    #[cfg(feature = "prometheus")]
    prometheus_registry: Option<prometheus::Registry>,
}

impl std::fmt::Debug for Telemetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Telemetry")
            .field("trace_level", &self.trace_level)
            .field("disabled", &self.disabled)
            .field("genai_attributes", &self.genai_attributes)
            .finish_non_exhaustive()
    }
}

/// RAII guard that shuts providers down on drop.
#[derive(Debug)]
pub struct TelemetryGuard {
    telemetry: Telemetry,
    shutdown: bool,
}

impl TelemetryGuard {
    /// Explicit shutdown (also called on drop).
    pub fn shutdown(&mut self) {
        if !self.shutdown {
            self.telemetry.shutdown();
            self.shutdown = true;
        }
    }

    /// Borrow the inner telemetry handle.
    pub fn telemetry(&self) -> &Telemetry {
        &self.telemetry
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

impl Telemetry {
    /// Access gateway metrics instruments.
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Configured operation trace level.
    pub fn trace_level(&self) -> TraceLevel {
        self.trace_level
    }

    /// Whether Development-stage `gen_ai.*` attributes should be emitted.
    pub fn genai_attributes(&self) -> bool {
        self.genai_attributes
    }

    /// Whether the SDK was disabled via `OTEL_SDK_DISABLED`.
    pub fn is_disabled(&self) -> bool {
        self.disabled
    }

    /// Tracer provider, when installed.
    pub fn tracer_provider(&self) -> Option<&SdkTracerProvider> {
        self.tracer_provider.as_ref()
    }

    /// Meter provider, when installed.
    pub fn meter_provider(&self) -> Option<&SdkMeterProvider> {
        self.meter_provider.as_ref()
    }

    /// Logger provider, when installed.
    pub fn logger_provider(&self) -> Option<&SdkLoggerProvider> {
        self.logger_provider.as_ref()
    }

    /// Resolved exporter / endpoint / protocol / sampler / operation level.
    pub fn summary(&self) -> serde_json::Value {
        self.summary.clone()
    }

    /// Render Prometheus exposition text from the shared meter provider.
    #[cfg(feature = "prometheus")]
    pub fn prometheus_metrics(&self) -> Option<String> {
        let registry = self.prometheus_registry.as_ref()?;
        let encoder = prometheus::TextEncoder::new();
        let families = registry.gather();
        let mut buffer = String::new();
        encoder.encode_utf8(&families, &mut buffer).ok()?;
        Some(buffer)
    }

    /// Prometheus endpoint is unavailable without the `prometheus` feature.
    #[cfg(not(feature = "prometheus"))]
    pub fn prometheus_metrics(&self) -> Option<String> {
        let _ = self;
        None
    }

    /// Build `tracing-subscriber` layers for the binary to install.
    ///
    /// Returns an OpenTelemetry trace layer (when enabled), an optional logs
    /// bridge, and an optional scoped `EnvFilter` from settings.
    pub fn tracing_layers<S>(&self) -> TracingLayers<S>
    where
        S: tracing::Subscriber + for<'span> tracing_subscriber::registry::LookupSpan<'span>,
    {
        let mut layers = TracingLayers {
            otel_trace: None,
            otel_logs: None,
            filter: None,
            _marker: std::marker::PhantomData,
        };

        if let Some(provider) = &self.tracer_provider {
            let tracer = provider.tracer("redact-gateway");
            layers.otel_trace = Some(tracing_opentelemetry::layer().with_tracer(tracer));
        }

        if let Some(provider) = &self.logger_provider {
            layers.otel_logs = Some(
                opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(provider),
            );
        }

        if let Some(directive) = &self.filter {
            if let Ok(filter) = EnvFilter::try_new(directive) {
                layers.filter = Some(filter);
            }
        }

        layers
    }

    /// Install a default subscriber composed of the OpenTelemetry layers plus
    /// an env-filter (`RUST_LOG`, falling back to `info`).
    pub fn init_tracing_subscriber(&self) -> Result<(), TelemetryError> {
        use tracing_subscriber::prelude::*;

        let env_filter =
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

        match (
            self.tracer_provider.as_ref(),
            self.logger_provider.as_ref(),
            self.filter.as_deref(),
        ) {
            (Some(tp), Some(lp), Some(directive)) => {
                let tracer = tp.tracer("redact-gateway");
                let scoped = EnvFilter::try_new(directive)
                    .map_err(|e| TelemetryError::Config(e.to_string()))?;
                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(scoped)
                    .with(tracing_opentelemetry::layer().with_tracer(tracer))
                    .with(
                        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(lp),
                    );
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
            (Some(tp), Some(lp), None) => {
                let tracer = tp.tracer("redact-gateway");
                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(tracing_opentelemetry::layer().with_tracer(tracer))
                    .with(
                        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(lp),
                    );
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
            (Some(tp), None, Some(directive)) => {
                let tracer = tp.tracer("redact-gateway");
                let scoped = EnvFilter::try_new(directive)
                    .map_err(|e| TelemetryError::Config(e.to_string()))?;
                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(scoped)
                    .with(tracing_opentelemetry::layer().with_tracer(tracer));
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
            (Some(tp), None, None) => {
                let tracer = tp.tracer("redact-gateway");
                let subscriber = Registry::default()
                    .with(env_filter)
                    .with(tracing_opentelemetry::layer().with_tracer(tracer));
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
            (None, Some(lp), Some(directive)) => {
                let scoped = EnvFilter::try_new(directive)
                    .map_err(|e| TelemetryError::Config(e.to_string()))?;
                let subscriber = Registry::default().with(env_filter).with(scoped).with(
                    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(lp),
                );
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
            (None, Some(lp), None) => {
                let subscriber = Registry::default().with(env_filter).with(
                    opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge::new(lp),
                );
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
            (None, None, Some(directive)) => {
                let scoped = EnvFilter::try_new(directive)
                    .map_err(|e| TelemetryError::Config(e.to_string()))?;
                let subscriber = Registry::default().with(env_filter).with(scoped);
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
            (None, None, None) => {
                let subscriber = Registry::default().with(env_filter);
                tracing::subscriber::set_global_default(subscriber)
                    .map_err(|e| TelemetryError::Config(format!("set global subscriber: {e}")))?;
            }
        }
        Ok(())
    }

    /// Shut down all providers.
    pub fn shutdown(&self) {
        if let Some(p) = &self.tracer_provider {
            let _ = p.shutdown();
        }
        if let Some(p) = &self.meter_provider {
            let _ = p.shutdown();
        }
        if let Some(p) = &self.logger_provider {
            let _ = p.shutdown();
        }
    }

    /// Wrap in a guard that shuts down on drop.
    pub fn into_guard(self) -> TelemetryGuard {
        TelemetryGuard {
            telemetry: self,
            shutdown: false,
        }
    }
}

/// Layers produced by [`Telemetry::tracing_layers`].
pub struct TracingLayers<S> {
    /// Trace export layer.
    pub otel_trace:
        Option<tracing_opentelemetry::OpenTelemetryLayer<S, opentelemetry_sdk::trace::Tracer>>,
    /// Logs bridge layer.
    pub otel_logs: Option<
        opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge<
            SdkLoggerProvider,
            SdkLogger,
        >,
    >,
    /// Optional scoped filter from [`TelemetrySettings::filter`].
    pub filter: Option<EnvFilter>,
    _marker: std::marker::PhantomData<S>,
}

/// Bootstrap traces, metrics and logs from settings and standard `OTEL_*` env vars.
pub fn init(settings: &TelemetrySettings) -> Result<Telemetry, TelemetryError> {
    if sdk_disabled() {
        install_propagators();
        return Ok(Telemetry {
            tracer_provider: None,
            meter_provider: None,
            logger_provider: None,
            metrics: Metrics::noop(),
            trace_level: settings.operations,
            genai_attributes: settings.genai_attributes,
            filter: settings.filter.clone(),
            disabled: true,
            summary: serde_json::json!({
                "disabled": true,
                "operations": settings.operations.as_str(),
                "traces_exporter": "none",
                "metrics_exporter": "none",
                "logs_exporter": "none",
            }),
            #[cfg(feature = "prometheus")]
            prometheus_registry: None,
        });
    }

    install_propagators();
    let resource = build_resource();

    let traces_exporter = env_exporter("OTEL_TRACES_EXPORTER");
    let metrics_exporters = env_exporters("OTEL_METRICS_EXPORTER");
    let logs_exporter = env_exporter("OTEL_LOGS_EXPORTER");

    let tracer_provider = build_tracer_provider(&resource, &traces_exporter)?;
    #[cfg(feature = "prometheus")]
    let (meter_provider, prometheus_registry) =
        build_meter_provider(&resource, &metrics_exporters)?;
    #[cfg(not(feature = "prometheus"))]
    let (meter_provider, _) = build_meter_provider(&resource, &metrics_exporters)?;
    let logger_provider = build_logger_provider(&resource, &logs_exporter)?;

    if let Some(ref provider) = tracer_provider {
        global::set_tracer_provider(provider.clone());
    }
    if let Some(ref provider) = meter_provider {
        global::set_meter_provider(provider.clone());
    }

    let metrics = match &meter_provider {
        Some(provider) => {
            let meter = opentelemetry::metrics::MeterProvider::meter(provider, "redact-gateway");
            Metrics::new(&meter)
        }
        None => Metrics::noop(),
    };

    let summary = serde_json::json!({
        "disabled": false,
        "operations": settings.operations.as_str(),
        "genai_attributes": settings.genai_attributes,
        "service_name": std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| "redact-gateway".into()),
        "service_version": env!("CARGO_PKG_VERSION"),
        "traces_exporter": traces_exporter,
        "metrics_exporter": metrics_exporters.join(","),
        "logs_exporter": logs_exporter,
        "otlp_endpoint": std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok(),
        "otlp_protocol": std::env::var("OTEL_EXPORTER_OTLP_PROTOCOL").ok(),
        "sampler": std::env::var("OTEL_TRACES_SAMPLER").unwrap_or_else(|_| "parentbased_always_on".into()),
        "propagators": std::env::var("OTEL_PROPAGATORS").unwrap_or_else(|_| "tracecontext,baggage".into()),
    });

    Ok(Telemetry {
        tracer_provider,
        meter_provider,
        logger_provider,
        metrics,
        trace_level: settings.operations,
        genai_attributes: settings.genai_attributes,
        filter: settings.filter.clone(),
        disabled: false,
        summary,
        #[cfg(feature = "prometheus")]
        prometheus_registry,
    })
}

fn sdk_disabled() -> bool {
    matches!(
        std::env::var("OTEL_SDK_DISABLED").as_deref(),
        Ok("true") | Ok("1") | Ok("TRUE") | Ok("True")
    )
}

fn build_resource() -> Resource {
    let mut builder = Resource::builder();
    if std::env::var_os("OTEL_SERVICE_NAME").is_none() {
        builder = builder.with_service_name("redact-gateway");
    }
    builder = builder.with_attribute(KeyValue::new(
        semconv::SERVICE_VERSION,
        env!("CARGO_PKG_VERSION"),
    ));
    builder.build()
}

fn env_exporter(name: &str) -> String {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_exporter)
}

fn env_exporters(name: &str) -> Vec<String> {
    let raw = std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_exporter);
    raw.split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn default_exporter() -> String {
    #[cfg(feature = "otlp")]
    {
        "otlp".to_string()
    }
    #[cfg(not(feature = "otlp"))]
    {
        "none".to_string()
    }
}

fn install_propagators() {
    let list =
        std::env::var("OTEL_PROPAGATORS").unwrap_or_else(|_| "tracecontext,baggage".to_string());
    let mut propagators: Vec<Box<dyn TextMapPropagator + Send + Sync>> = Vec::new();
    for name in list.split(',') {
        match name.trim().to_ascii_lowercase().as_str() {
            "tracecontext" => propagators.push(Box::new(TraceContextPropagator::new())),
            "baggage" => propagators.push(Box::new(BaggagePropagator::new())),
            "none" | "" => {}
            other => {
                tracing::warn!(
                    propagator = other,
                    "unsupported OTEL_PROPAGATORS entry ignored"
                );
            }
        }
    }
    if propagators.is_empty() {
        propagators.push(Box::new(TraceContextPropagator::new()));
        propagators.push(Box::new(BaggagePropagator::new()));
    }
    global::set_text_map_propagator(TextMapCompositePropagator::new(propagators));
}

fn build_tracer_provider(
    resource: &Resource,
    exporter: &str,
) -> Result<Option<SdkTracerProvider>, TelemetryError> {
    match exporter {
        "none" => Ok(None),
        "console" => {
            let provider = SdkTracerProvider::builder()
                .with_resource(resource.clone())
                .with_simple_exporter(console::ConsoleSpanExporter)
                .build();
            Ok(Some(provider))
        }
        "otlp" => {
            #[cfg(feature = "otlp")]
            {
                let exporter = opentelemetry_otlp::SpanExporter::builder()
                    .build()
                    .map_err(|e| TelemetryError::Exporter(e.to_string()))?;
                let provider = SdkTracerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(exporter)
                    .build();
                Ok(Some(provider))
            }
            #[cfg(not(feature = "otlp"))]
            {
                Err(TelemetryError::Config(
                    "OTEL_TRACES_EXPORTER=otlp requires the `otlp` feature".into(),
                ))
            }
        }
        other => Err(TelemetryError::Config(format!(
            "unsupported OTEL_TRACES_EXPORTER `{other}` (expected otlp, console, none)"
        ))),
    }
}

fn build_meter_provider(
    resource: &Resource,
    exporters: &[String],
) -> Result<(Option<SdkMeterProvider>, OptionPrometheusRegistry), TelemetryError> {
    let push_exporters: Vec<&str> = exporters
        .iter()
        .map(|s| s.as_str())
        .filter(|s| *s != "none")
        .collect();

    #[cfg(feature = "prometheus")]
    let registry = prometheus::Registry::new();

    let mut builder = SdkMeterProvider::builder().with_resource(resource.clone());

    #[cfg(feature = "prometheus")]
    {
        let exporter = opentelemetry_prometheus::exporter()
            .with_registry(registry.clone())
            .build()
            .map_err(|e| TelemetryError::Exporter(e.to_string()))?;
        builder = builder.with_reader(exporter);
    }

    for exporter in &push_exporters {
        match *exporter {
            "console" => {
                builder = builder.with_periodic_exporter(console::ConsoleMetricExporter::default());
            }
            "otlp" => {
                #[cfg(feature = "otlp")]
                {
                    let exporter = opentelemetry_otlp::MetricExporter::builder()
                        .build()
                        .map_err(|e| TelemetryError::Exporter(e.to_string()))?;
                    builder = builder.with_periodic_exporter(exporter);
                }
                #[cfg(not(feature = "otlp"))]
                {
                    return Err(TelemetryError::Config(
                        "OTEL_METRICS_EXPORTER=otlp requires the `otlp` feature".into(),
                    ));
                }
            }
            other => {
                return Err(TelemetryError::Config(format!(
                    "unsupported OTEL_METRICS_EXPORTER `{other}` (expected otlp, console, none)"
                )));
            }
        }
    }

    #[cfg(feature = "prometheus")]
    {
        let _ = push_exporters;
        Ok((Some(builder.build()), Some(registry)))
    }
    #[cfg(not(feature = "prometheus"))]
    {
        if push_exporters.is_empty() {
            return Ok((None, ()));
        }
        Ok((Some(builder.build()), ()))
    }
}

#[cfg(feature = "prometheus")]
type OptionPrometheusRegistry = Option<prometheus::Registry>;
#[cfg(not(feature = "prometheus"))]
type OptionPrometheusRegistry = ();

fn build_logger_provider(
    resource: &Resource,
    exporter: &str,
) -> Result<Option<SdkLoggerProvider>, TelemetryError> {
    match exporter {
        "none" => Ok(None),
        "console" => {
            let provider = SdkLoggerProvider::builder()
                .with_resource(resource.clone())
                .with_simple_exporter(console::ConsoleLogExporter)
                .build();
            Ok(Some(provider))
        }
        "otlp" => {
            #[cfg(feature = "otlp")]
            {
                let exporter = opentelemetry_otlp::LogExporter::builder()
                    .build()
                    .map_err(|e| TelemetryError::Exporter(e.to_string()))?;
                let provider = SdkLoggerProvider::builder()
                    .with_resource(resource.clone())
                    .with_batch_exporter(exporter)
                    .build();
                Ok(Some(provider))
            }
            #[cfg(not(feature = "otlp"))]
            {
                Err(TelemetryError::Config(
                    "OTEL_LOGS_EXPORTER=otlp requires the `otlp` feature".into(),
                ))
            }
        }
        other => Err(TelemetryError::Config(format!(
            "unsupported OTEL_LOGS_EXPORTER `{other}` (expected otlp, console, none)"
        ))),
    }
}

/// Extract the W3C trace context (and baggage) from inbound HTTP headers.
pub fn extract_context(headers: &axum::http::HeaderMap) -> opentelemetry::Context {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderMapExtractor(headers)))
}

/// Inject the current context into outbound HTTP headers.
pub fn inject_context(headers: &mut reqwest::header::HeaderMap) {
    global::get_text_map_propagator(|propagator| {
        propagator.inject(&mut HeaderMapInjector(headers));
    });
}

/// Inject a specific context into outbound headers.
pub fn inject_context_with(
    context: &opentelemetry::Context,
    headers: &mut reqwest::header::HeaderMap,
) {
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(context, &mut HeaderMapInjector(headers));
    });
}

struct HeaderMapExtractor<'a>(&'a axum::http::HeaderMap);

impl Extractor for HeaderMapExtractor<'_> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

struct HeaderMapInjector<'a>(&'a mut reqwest::header::HeaderMap);

impl Injector for HeaderMapInjector<'_> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = reqwest::header::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = reqwest::header::HeaderValue::from_str(&value) {
                self.0.insert(name, val);
            }
        }
    }
}
