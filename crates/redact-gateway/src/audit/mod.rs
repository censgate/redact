// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Audit emission as an OpenTelemetry Logs concern.
//!
//! The gateway only **emits** audit records. Durable, immutable or WORM
//! retention is the operator's sink responsibility (for example an
//! OpenTelemetry Collector pipeline writing to object storage). This module
//! does not implement a database.

pub mod sinks;

use std::collections::BTreeMap;
use std::fmt::Debug;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::Serialize;
use thiserror::Error;
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::{AuditExport, AuditSettings};
use crate::redact::RedactionOutcome;
use crate::telemetry::semconv;

pub use sinks::{FileSink, NoopSink, OtlpSink, StdoutSink};

/// Audit emission failures.
#[derive(Debug, Error)]
pub enum AuditError {
    /// The configured sink rejected the record.
    #[error("audit sink error: {0}")]
    Sink(String),
    /// Configuration is incomplete or inconsistent.
    #[error("audit configuration error: {0}")]
    Config(String),
    /// The dispatcher has been shut down.
    #[error("audit dispatcher shut down")]
    ShutDown,
}

/// High-level outcome recorded on an audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    /// Request was allowed to proceed.
    Allowed,
    /// Policy blocked the payload.
    Blocked,
    /// Authentication / authorization denied the caller.
    Denied,
    /// Processing failed.
    Error,
}

impl AuditOutcome {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Blocked => "blocked",
            Self::Denied => "denied",
            Self::Error => "error",
        }
    }
}

/// A single audit record. Never carries prompt text, completions, or entity values.
#[derive(Debug, Clone, Serialize)]
pub struct AuditEvent {
    /// Stable event name (`redact.gateway.request`, …).
    pub event_name: &'static str,
    /// Random UUID v4.
    pub event_id: String,
    /// Event timestamp (UTC).
    pub timestamp: DateTime<Utc>,
    /// Gateway action (for example `chat.completions`).
    pub action: String,
    /// High-level outcome.
    pub outcome: AuditOutcome,
    /// Policy profile name.
    pub profile: String,
    /// Tenant identifier.
    pub tenant: String,
    /// Optional session id.
    pub session_id: Option<String>,
    /// Optional subject (caller id), never a secret.
    pub subject: Option<String>,
    /// Number of redactions applied.
    pub redactions: usize,
    /// Tokens minted.
    pub tokens_issued: usize,
    /// Detected entity types (omitted from sinks when configured off).
    pub entity_types: Vec<String>,
    /// Counts per entity type.
    pub entity_counts: BTreeMap<String, usize>,
    /// Entity types that triggered a block.
    pub blocked_entities: Vec<String>,
    /// SHA-256 of the **redacted** payload, never the original.
    pub content_sha256: Option<String>,
    /// Upstream HTTP status when known.
    pub upstream_status: Option<u16>,
    /// Low-cardinality error class.
    pub error_type: Option<String>,
    /// Correlated trace id.
    pub trace_id: Option<String>,
    /// Correlated span id.
    pub span_id: Option<String>,
}

/// Context fields that accompany a [`RedactionOutcome`] when building an event.
#[derive(Debug, Clone, Default)]
pub struct AuditContext {
    /// Event name constant.
    pub event_name: &'static str,
    /// Gateway action.
    pub action: String,
    /// Outcome.
    pub outcome: Option<AuditOutcome>,
    /// Policy profile.
    pub profile: String,
    /// Tenant.
    pub tenant: String,
    /// Session id.
    pub session_id: Option<String>,
    /// Subject.
    pub subject: Option<String>,
    /// Digest of the redacted payload.
    pub content_sha256: Option<String>,
    /// Upstream status.
    pub upstream_status: Option<u16>,
    /// Error type.
    pub error_type: Option<String>,
    /// Trace id.
    pub trace_id: Option<String>,
    /// Span id.
    pub span_id: Option<String>,
    /// Whether to include entity type names.
    pub include_entity_types: bool,
}

impl AuditEvent {
    /// Build an event from a redaction outcome and request context.
    pub fn from_outcome(outcome: &RedactionOutcome, ctx: AuditContext) -> Self {
        let audit_outcome = ctx.outcome.unwrap_or_else(|| {
            if outcome.is_blocked() {
                AuditOutcome::Blocked
            } else {
                AuditOutcome::Allowed
            }
        });
        let entity_types = if ctx.include_entity_types {
            outcome.entity_types()
        } else {
            Vec::new()
        };
        Self {
            event_name: if ctx.event_name.is_empty() {
                semconv::event::RESPONSE
            } else {
                ctx.event_name
            },
            event_id: Uuid::new_v4().to_string(),
            timestamp: Utc::now(),
            action: ctx.action,
            outcome: audit_outcome,
            profile: ctx.profile,
            tenant: ctx.tenant,
            session_id: ctx.session_id,
            subject: ctx.subject,
            redactions: outcome.redactions_applied,
            tokens_issued: outcome.tokens_issued,
            entity_types,
            entity_counts: outcome.entity_counts.clone(),
            blocked_entities: outcome.blocked_entities.clone(),
            content_sha256: ctx.content_sha256,
            upstream_status: ctx.upstream_status,
            error_type: ctx.error_type,
            trace_id: ctx.trace_id,
            span_id: ctx.span_id,
        }
    }

    /// JSON object suitable for line-oriented sinks.
    pub fn to_json(&self, include_entity_types: bool) -> serde_json::Value {
        let mut map = serde_json::Map::new();
        map.insert("event_name".into(), self.event_name.into());
        map.insert("event_id".into(), self.event_id.clone().into());
        map.insert("timestamp".into(), self.timestamp.to_rfc3339().into());
        map.insert("action".into(), self.action.clone().into());
        map.insert("outcome".into(), self.outcome.as_str().into());
        map.insert("profile".into(), self.profile.clone().into());
        map.insert("tenant".into(), self.tenant.clone().into());
        if let Some(v) = &self.session_id {
            map.insert("session_id".into(), v.clone().into());
        }
        if let Some(v) = &self.subject {
            map.insert("subject".into(), v.clone().into());
        }
        map.insert("redactions".into(), self.redactions.into());
        map.insert("tokens_issued".into(), self.tokens_issued.into());
        if include_entity_types {
            map.insert(
                "entity_types".into(),
                serde_json::to_value(&self.entity_types).unwrap_or_default(),
            );
        }
        map.insert(
            "entity_counts".into(),
            serde_json::to_value(&self.entity_counts).unwrap_or_default(),
        );
        map.insert(
            "blocked_entities".into(),
            serde_json::to_value(&self.blocked_entities).unwrap_or_default(),
        );
        if let Some(v) = &self.content_sha256 {
            map.insert("content_sha256".into(), v.clone().into());
        }
        if let Some(v) = self.upstream_status {
            map.insert("upstream_status".into(), v.into());
        }
        if let Some(v) = &self.error_type {
            map.insert("error_type".into(), v.clone().into());
        }
        if let Some(v) = &self.trace_id {
            map.insert("trace_id".into(), v.clone().into());
        }
        if let Some(v) = &self.span_id {
            map.insert("span_id".into(), v.clone().into());
        }
        serde_json::Value::Object(map)
    }
}

/// Destination for audit records.
#[async_trait]
pub trait AuditSink: Send + Sync + Debug {
    /// Stable sink name for diagnostics.
    fn name(&self) -> &'static str;

    /// Emit one audit event.
    async fn emit(&self, event: &AuditEvent) -> Result<(), AuditError>;

    /// Flush buffered state. Default is a no-op.
    async fn flush(&self) -> Result<(), AuditError> {
        Ok(())
    }
}

enum DispatchMsg {
    Event(Box<AuditEvent>),
    Flush(tokio::sync::oneshot::Sender<Result<(), AuditError>>),
    Shutdown,
}

/// Non-blocking audit dispatcher with a bounded queue and background worker.
pub struct AuditDispatcher {
    tx: mpsc::Sender<DispatchMsg>,
    dropped: Arc<AtomicU64>,
    include_entity_types: bool,
    sink_name: &'static str,
}

impl std::fmt::Debug for AuditDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditDispatcher")
            .field("sink", &self.sink_name)
            .field("dropped", &self.dropped())
            .finish()
    }
}

impl AuditDispatcher {
    /// Enqueue an event. Never blocks the request path.
    ///
    /// On a full queue the record is dropped, the drop counter is incremented,
    /// and a rate-limited warning is logged.
    pub fn emit(&self, event: AuditEvent) {
        match self.tx.try_send(DispatchMsg::Event(Box::new(event))) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Rate-limit: warn on the first drop and every 100 thereafter.
                if n == 1 || n.is_multiple_of(100) {
                    tracing::warn!(
                        dropped = n,
                        sink = self.sink_name,
                        "audit queue full; dropping records"
                    );
                }
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let n = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                if n == 1 || n.is_multiple_of(100) {
                    tracing::warn!(
                        dropped = n,
                        sink = self.sink_name,
                        "audit dispatcher closed; dropping records"
                    );
                }
            }
        }
    }

    /// Number of records dropped because the queue was full or closed.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Whether entity types are included in emitted JSON / attributes.
    pub fn include_entity_types(&self) -> bool {
        self.include_entity_types
    }

    /// Ask the worker to flush the sink.
    pub async fn flush(&self) -> Result<(), AuditError> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(DispatchMsg::Flush(tx))
            .await
            .map_err(|_| AuditError::ShutDown)?;
        rx.await.map_err(|_| AuditError::ShutDown)?
    }

    /// Stop the background worker.
    pub async fn shutdown(&self) -> Result<(), AuditError> {
        let _ = self.tx.send(DispatchMsg::Shutdown).await;
        Ok(())
    }
}

/// Build a dispatcher for the configured audit sink.
///
/// `logger_provider` is required when `export` is [`AuditExport::Otlp`].
pub fn build_dispatcher(
    settings: &AuditSettings,
    logger_provider: Option<&opentelemetry_sdk::logs::SdkLoggerProvider>,
) -> Result<AuditDispatcher, AuditError> {
    let sink: Arc<dyn AuditSink> = match settings.export {
        AuditExport::Off => Arc::new(NoopSink),
        AuditExport::Stdout => Arc::new(StdoutSink::new(settings.include_entity_types)),
        AuditExport::File => {
            let path = settings.file_path.clone().ok_or_else(|| {
                AuditError::Config("audit export is file but no path is configured".into())
            })?;
            Arc::new(FileSink::new(path, settings.include_entity_types)?)
        }
        AuditExport::Otlp => {
            let provider = logger_provider.ok_or_else(|| {
                AuditError::Config(
                    "audit export is otlp but no OpenTelemetry logger provider was supplied".into(),
                )
            })?;
            Arc::new(OtlpSink::new(provider, settings.include_entity_types))
        }
    };

    let capacity = settings.queue_capacity.max(1);
    let (tx, rx) = mpsc::channel(capacity);
    let dropped = Arc::new(AtomicU64::new(0));
    let sink_name = sink.name();
    let include_entity_types = settings.include_entity_types;

    tokio::spawn(run_worker(rx, sink));

    Ok(AuditDispatcher {
        tx,
        dropped,
        include_entity_types,
        sink_name,
    })
}

async fn run_worker(mut rx: mpsc::Receiver<DispatchMsg>, sink: Arc<dyn AuditSink>) {
    while let Some(msg) = rx.recv().await {
        match msg {
            DispatchMsg::Event(event) => {
                if let Err(err) = emit_with_retry(sink.as_ref(), &event).await {
                    tracing::warn!(error = %err, sink = sink.name(), "audit emit failed");
                }
            }
            DispatchMsg::Flush(reply) => {
                let result = sink.flush().await;
                let _ = reply.send(result);
            }
            DispatchMsg::Shutdown => {
                let _ = sink.flush().await;
                break;
            }
        }
    }
}

async fn emit_with_retry(sink: &dyn AuditSink, event: &AuditEvent) -> Result<(), AuditError> {
    const ATTEMPTS: u32 = 3;
    let mut delay = Duration::from_millis(10);
    let mut last_err = None;
    for attempt in 0..ATTEMPTS {
        match sink.emit(event).await {
            Ok(()) => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if attempt + 1 < ATTEMPTS {
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2);
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| AuditError::Sink("unknown".into())))
}
