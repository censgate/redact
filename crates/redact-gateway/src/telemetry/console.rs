// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Simple console exporters used when `OTEL_*_EXPORTER=console`.
//!
//! These print one line per export batch for local debugging. Production
//! deployments should use OTLP.

use std::time::Duration;

use opentelemetry_sdk::error::{OTelSdkError, OTelSdkResult};
use opentelemetry_sdk::logs::{LogBatch, LogExporter};
use opentelemetry_sdk::metrics::data::ResourceMetrics;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::Temporality;
use opentelemetry_sdk::trace::{SpanData, SpanExporter};

/// Prints finished spans to stdout.
#[derive(Debug, Default)]
pub struct ConsoleSpanExporter;

impl SpanExporter for ConsoleSpanExporter {
    async fn export(&self, batch: Vec<SpanData>) -> OTelSdkResult {
        for span in batch {
            println!(
                "otel.trace name={} trace_id={} span_id={} kind={:?} status={:?}",
                span.name,
                span.span_context.trace_id(),
                span.span_context.span_id(),
                span.span_kind,
                span.status
            );
        }
        Ok(())
    }
}

/// Prints metric collections to stdout.
#[derive(Debug, Default)]
pub struct ConsoleMetricExporter {
    temporality: Temporality,
}

impl PushMetricExporter for ConsoleMetricExporter {
    async fn export(&self, metrics: &ResourceMetrics) -> OTelSdkResult {
        for scope in metrics.scope_metrics() {
            for metric in scope.metrics() {
                println!(
                    "otel.metric name={} unit={} scope={}",
                    metric.name(),
                    metric.unit(),
                    scope.scope().name()
                );
            }
        }
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

/// Prints log records to stdout.
#[derive(Debug, Default)]
pub struct ConsoleLogExporter;

impl LogExporter for ConsoleLogExporter {
    async fn export(&self, batch: LogBatch<'_>) -> OTelSdkResult {
        for (record, scope) in batch.iter() {
            println!(
                "otel.log scope={} event={:?} severity={:?}",
                scope.name(),
                record.event_name(),
                record.severity_number()
            );
        }
        Ok(())
    }

    fn shutdown_with_timeout(&self, _timeout: Duration) -> OTelSdkResult {
        let _ = _timeout;
        Ok(())
    }
}

/// Map lock poisoning into an SDK error (unused helper kept for symmetry).
#[allow(dead_code)]
fn lock_err(err: impl std::fmt::Debug) -> OTelSdkError {
    OTelSdkError::InternalFailure(format!("{err:?}"))
}
