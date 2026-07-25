// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Audit sinks.
//!
//! The gateway only emits records. Durable retention (immutable / WORM object
//! storage, SIEM pipelines, etc.) is the operator's responsibility — typically
//! via an OpenTelemetry Collector receiving OTLP logs. No database is
//! implemented here.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use async_trait::async_trait;
use opentelemetry::logs::{AnyValue, Logger, LoggerProvider, Severity};
use opentelemetry_sdk::logs::SdkLoggerProvider;

use super::{AuditError, AuditEvent, AuditSink};
use crate::telemetry::semconv;

/// Discards all events.
#[derive(Debug, Default)]
pub struct NoopSink;

#[async_trait]
impl AuditSink for NoopSink {
    fn name(&self) -> &'static str {
        "noop"
    }

    async fn emit(&self, _event: &AuditEvent) -> Result<(), AuditError> {
        Ok(())
    }
}

/// Writes one JSON object per line to stdout.
#[derive(Debug)]
pub struct StdoutSink {
    include_entity_types: bool,
}

impl StdoutSink {
    /// Create a stdout sink.
    pub fn new(include_entity_types: bool) -> Self {
        Self {
            include_entity_types,
        }
    }
}

#[async_trait]
impl AuditSink for StdoutSink {
    fn name(&self) -> &'static str {
        "stdout"
    }

    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json = event.to_json(self.include_entity_types);
        println!("{json}");
        Ok(())
    }
}

/// Appends one JSON object per line to a file.
///
/// Parent directories are created on construction. The file handle is reopened
/// after a failed write so external rotation is tolerated.
#[derive(Debug)]
pub struct FileSink {
    path: PathBuf,
    include_entity_types: bool,
    file: Mutex<File>,
}

impl FileSink {
    /// Open (or create) the audit file, creating parent directories as needed.
    pub fn new(path: impl Into<PathBuf>, include_entity_types: bool) -> Result<Self, AuditError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                AuditError::Sink(format!("create audit directory {}: {e}", parent.display()))
            })?;
        }
        let file = open_append(&path)?;
        Ok(Self {
            path,
            include_entity_types,
            file: Mutex::new(file),
        })
    }

    fn write_line(&self, line: &str) -> Result<(), AuditError> {
        let mut guard = self
            .file
            .lock()
            .map_err(|e| AuditError::Sink(format!("audit file lock: {e}")))?;
        if let Err(err) = writeln!(guard, "{line}").and_then(|_| guard.flush()) {
            // Reopen and retry once (handles external rotation / truncated fd).
            *guard = open_append(&self.path)?;
            writeln!(guard, "{line}")
                .and_then(|_| guard.flush())
                .map_err(|e| AuditError::Sink(format!("audit file write after reopen: {e}")))?;
            let _ = err;
        }
        Ok(())
    }
}

fn open_append(path: &Path) -> Result<File, AuditError> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|e| AuditError::Sink(format!("open audit file {}: {e}", path.display())))
}

#[async_trait]
impl AuditSink for FileSink {
    fn name(&self) -> &'static str {
        "file"
    }

    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let json = event.to_json(self.include_entity_types);
        let line = serde_json::to_string(&json)
            .map_err(|e| AuditError::Sink(format!("serialize audit event: {e}")))?;
        self.write_line(&line)
    }
}

/// Emits OpenTelemetry `LogRecord`s with `event.name` and audit fields.
///
/// Trace correlation is attached when `trace_id` / `span_id` are present on the
/// event. Retention and immutability remain the collector pipeline's job.
#[derive(Debug)]
pub struct OtlpSink {
    provider: SdkLoggerProvider,
    include_entity_types: bool,
}

impl OtlpSink {
    /// Create a sink bound to the process logger provider.
    pub fn new(provider: &SdkLoggerProvider, include_entity_types: bool) -> Self {
        Self {
            provider: provider.clone(),
            include_entity_types,
        }
    }
}

#[async_trait]
impl AuditSink for OtlpSink {
    fn name(&self) -> &'static str {
        "otlp"
    }

    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError> {
        let logger = self.provider.logger("redact-gateway.audit");
        let mut record = logger.create_log_record();
        opentelemetry::logs::LogRecord::set_event_name(&mut record, event.event_name);
        opentelemetry::logs::LogRecord::set_severity_number(&mut record, Severity::Info);
        opentelemetry::logs::LogRecord::set_body(
            &mut record,
            AnyValue::from(format!("audit:{}", event.event_name)),
        );

        let mut attrs: Vec<(opentelemetry::Key, AnyValue)> = vec![
            (semconv::EVENT_NAME.into(), event.event_name.into()),
            ("event.id".into(), event.event_id.clone().into()),
            ("action".into(), event.action.clone().into()),
            ("outcome".into(), event.outcome.as_str().into()),
            ("profile".into(), event.profile.clone().into()),
            ("tenant".into(), event.tenant.clone().into()),
            ("redactions".into(), AnyValue::Int(event.redactions as i64)),
            (
                "tokens_issued".into(),
                AnyValue::Int(event.tokens_issued as i64),
            ),
        ];
        if let Some(session) = &event.session_id {
            attrs.push(("session_id".into(), session.clone().into()));
        }
        if let Some(subject) = &event.subject {
            attrs.push(("subject".into(), subject.clone().into()));
        }
        if self.include_entity_types && !event.entity_types.is_empty() {
            let list: AnyValue = event
                .entity_types
                .iter()
                .cloned()
                .map(AnyValue::from)
                .collect();
            attrs.push(("entity_types".into(), list));
        }
        for (entity, count) in &event.entity_counts {
            attrs.push((
                format!("entity_counts.{entity}").into(),
                AnyValue::Int(*count as i64),
            ));
        }
        if !event.blocked_entities.is_empty() {
            let list: AnyValue = event
                .blocked_entities
                .iter()
                .cloned()
                .map(AnyValue::from)
                .collect();
            attrs.push(("blocked_entities".into(), list));
        }
        if let Some(digest) = &event.content_sha256 {
            attrs.push(("content_sha256".into(), digest.clone().into()));
        }
        if let Some(status) = event.upstream_status {
            attrs.push(("upstream_status".into(), AnyValue::Int(i64::from(status))));
        }
        if let Some(err) = &event.error_type {
            attrs.push((semconv::ERROR_TYPE.into(), err.clone().into()));
        }

        opentelemetry::logs::LogRecord::add_attributes(&mut record, attrs);

        if let (Some(tid), Some(sid)) = (&event.trace_id, &event.span_id) {
            if let (Ok(trace_id), Ok(span_id)) = (
                opentelemetry::trace::TraceId::from_hex(tid),
                opentelemetry::trace::SpanId::from_hex(sid),
            ) {
                opentelemetry::logs::LogRecord::set_trace_context(
                    &mut record,
                    trace_id,
                    span_id,
                    None,
                );
            }
        }

        logger.emit(record);
        Ok(())
    }

    async fn flush(&self) -> Result<(), AuditError> {
        self.provider
            .force_flush()
            .map_err(|e| AuditError::Sink(e.to_string()))
    }
}
