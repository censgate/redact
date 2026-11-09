// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Bounded expiry-maintenance worker for the indexed token store.
//!
//! The worker walks an operator-supplied, authorized inventory of
//! subject-bound `(tenant, context)` pairs and calls
//! [`IndexedStore::purge_expired`] for each eligible context until it reports
//! zero, in batches of at most [`MAX_BATCH`] entries. It never enumerates
//! storage, never deletes identity reservations and never starts a legacy
//! migration: contexts that were not already imported are skipped.
//!
//! Progress is a durable, identifier-free cursor (inventory digest and index)
//! written atomically after every context, so an interrupted run resumes
//! without repeating completed work. Purging is idempotent, so resuming the
//! interrupted context is always safe. One run holds an exclusive lock and
//! keeps one batch in flight.
//!
//! Failure is closed: integrity, invalid-state and unexpected errors stop the
//! run immediately without advancing the cursor. Transient unavailability is
//! retried with bounded exponential backoff, then stops the run the same way.
//!
//! Telemetry records only counts, durations and low-cardinality outcomes. No
//! tenant, context, token, value or credential reaches metrics, spans, logs,
//! the checkpoint or the run summary.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use opentelemetry::metrics::{Counter, Gauge, Histogram, Meter};
use opentelemetry::KeyValue;
use redact_token_store::{Error, MAX_BATCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::Instrument;

use super::indexed::{IndexedStore, MaintenanceState};
use super::TokenMapError;
use crate::telemetry::semconv;

/// Maximum inventory entries accepted for one pass.
pub const MAX_INVENTORY_ENTRIES: usize = 1_000_000;
/// Maximum inventory file size in bytes.
pub const MAX_INVENTORY_BYTES: usize = 256 * 1024 * 1024;
/// Maximum tenant or context length, matching the storage scope bound.
pub const MAX_IDENTIFIER_BYTES: usize = 1024;
/// Upper bound on attempts per operation, including the first.
pub const MAX_ATTEMPTS: u32 = 10;
const CHECKPOINT_VERSION: u32 = 1;

/// Metric: batches attempted. Unit `{batch}`.
pub const METRIC_BATCHES: &str = "redact.gateway.tokenstore.maintenance.batches";
/// Metric: batch duration. Unit `s`.
pub const METRIC_BATCH_DURATION: &str = "redact.gateway.tokenstore.maintenance.batch.duration";
/// Metric: expired ciphertexts cleared. Unit `{entry}`.
pub const METRIC_CLEARED: &str = "redact.gateway.tokenstore.maintenance.entries_cleared";
/// Metric: contexts visited, by outcome. Unit `{context}`.
pub const METRIC_CONTEXTS: &str = "redact.gateway.tokenstore.maintenance.contexts";
/// Metric: transient retries. Unit `{retry}`.
pub const METRIC_RETRIES: &str = "redact.gateway.tokenstore.maintenance.retries";
/// Metric: contexts remaining in the current pass. Unit `{context}`.
pub const METRIC_BACKLOG: &str = "redact.gateway.tokenstore.maintenance.backlog.contexts";
/// Metric: age of the current pass. Unit `s`.
pub const METRIC_PASS_AGE: &str = "redact.gateway.tokenstore.maintenance.pass.age";
/// Span name for one run.
pub const SPAN_RUN: &str = "redact.gateway.tokenstore.maintenance.run";
/// Span name for one purge batch.
pub const SPAN_BATCH: &str = "redact.gateway.tokenstore.maintenance.batch";

/// Setup and fatal run failures. Messages never contain identifiers.
#[derive(Debug, thiserror::Error)]
pub enum MaintenanceError {
    /// Limits are zero, exceed the storage bound or are otherwise unsafe.
    #[error("invalid maintenance limits: {0}")]
    Limits(&'static str),
    /// The inventory is malformed, oversized or unreadable.
    #[error("invalid maintenance inventory: {0}")]
    Inventory(&'static str),
    /// The checkpoint is unreadable, corrupt or bound to another inventory.
    #[error("maintenance checkpoint rejected: {0}")]
    Checkpoint(&'static str),
    /// Another worker holds the lock, or a crashed run left it behind.
    #[error("maintenance lock is held; confirm no worker is running, then remove the lock file")]
    Locked,
    /// Local filesystem failure while persisting progress.
    #[error("maintenance progress could not be persisted")]
    Io,
}

/// Bounded run limits. Defaults follow the beta specification: batches of at
/// most 256 and one batch in flight.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Entries cleared per batch (1..=256).
    pub batch_limit: usize,
    /// Batches per context before the run stops and resumes it next time.
    pub max_batches_per_context: u32,
    /// Contexts visited per run.
    pub max_contexts_per_run: usize,
    /// Attempts per operation for transient failures (1..=10).
    pub max_attempts: u32,
    /// First retry delay; doubled up to `max_backoff`.
    pub initial_backoff: Duration,
    /// Retry delay ceiling.
    pub max_backoff: Duration,
    /// Wall-clock budget for the run; checked before every batch.
    pub run_deadline: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            batch_limit: MAX_BATCH,
            max_batches_per_context: 1024,
            max_contexts_per_run: 10_000,
            max_attempts: 5,
            initial_backoff: Duration::from_millis(250),
            max_backoff: Duration::from_secs(10),
            run_deadline: Duration::from_secs(55 * 60),
        }
    }
}

impl Limits {
    /// Reject unbounded or out-of-range limits.
    pub fn validate(&self) -> Result<(), MaintenanceError> {
        if self.batch_limit == 0 || self.batch_limit > MAX_BATCH {
            return Err(MaintenanceError::Limits("batch limit must be 1..=256"));
        }
        if self.max_batches_per_context == 0 || self.max_contexts_per_run == 0 {
            return Err(MaintenanceError::Limits("budgets must be non-zero"));
        }
        if self.max_attempts == 0 || self.max_attempts > MAX_ATTEMPTS {
            return Err(MaintenanceError::Limits("attempts must be 1..=10"));
        }
        if self.initial_backoff > self.max_backoff || self.max_backoff > Duration::from_secs(300) {
            return Err(MaintenanceError::Limits("backoff must be bounded"));
        }
        if self.run_deadline.is_zero() || self.run_deadline > Duration::from_secs(24 * 3600) {
            return Err(MaintenanceError::Limits("deadline must be 1s..=24h"));
        }
        Ok(())
    }
}

/// One authorized subject-bound context. Deliberately not `Debug`.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct Subject {
    tenant: String,
    context: String,
}

/// Authorized inventory supplied by the owning system, one JSON object per
/// line: `{"tenant":"…","context":"…"}`. Deliberately not `Debug`.
pub struct Inventory {
    subjects: Vec<Subject>,
    digest: String,
}

impl Inventory {
    /// Parse and bound an inventory. Any malformed line rejects the whole file.
    pub fn parse(bytes: &[u8]) -> Result<Self, MaintenanceError> {
        if bytes.len() > MAX_INVENTORY_BYTES {
            return Err(MaintenanceError::Inventory("file exceeds size bound"));
        }
        let text = std::str::from_utf8(bytes)
            .map_err(|_| MaintenanceError::Inventory("file is not UTF-8"))?;
        let mut subjects = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if subjects.len() == MAX_INVENTORY_ENTRIES {
                return Err(MaintenanceError::Inventory("entry count exceeds bound"));
            }
            // Parse failures are reported without echoing the line.
            let subject: Subject = serde_json::from_str(line)
                .map_err(|_| MaintenanceError::Inventory("malformed entry"))?;
            if [&subject.tenant, &subject.context]
                .iter()
                .any(|s| s.is_empty() || s.len() > MAX_IDENTIFIER_BYTES)
            {
                return Err(MaintenanceError::Inventory(
                    "identifier length out of range",
                ));
            }
            subjects.push(subject);
        }
        let digest = hex(&Sha256::digest(bytes));
        Ok(Self { subjects, digest })
    }

    /// Read and parse an inventory file.
    pub fn load(path: &Path) -> Result<Self, MaintenanceError> {
        let metadata =
            std::fs::metadata(path).map_err(|_| MaintenanceError::Inventory("unreadable"))?;
        if metadata.len() > MAX_INVENTORY_BYTES as u64 {
            return Err(MaintenanceError::Inventory("file exceeds size bound"));
        }
        let bytes = std::fs::read(path).map_err(|_| MaintenanceError::Inventory("unreadable"))?;
        Self::parse(&bytes)
    }

    /// Number of subjects.
    pub fn len(&self) -> usize {
        self.subjects.len()
    }

    /// Whether the inventory is empty.
    pub fn is_empty(&self) -> bool {
        self.subjects.is_empty()
    }

    /// SHA-256 of the inventory bytes; binds the durable cursor.
    pub fn digest(&self) -> &str {
        &self.digest
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Durable, identifier-free progress record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Format version.
    pub version: u32,
    /// Digest of the inventory this cursor indexes.
    pub inventory_sha256: String,
    /// Inventory length at pass start.
    pub inventory_len: usize,
    /// Monotonic pass number.
    pub pass: u64,
    /// Next inventory index to visit; equal to `inventory_len` when complete.
    pub next_index: usize,
    /// Pass start, Unix milliseconds.
    pub pass_started_ms: i64,
    /// Last persistence, Unix milliseconds.
    pub updated_ms: i64,
}

impl Checkpoint {
    fn complete(&self) -> bool {
        self.next_index >= self.inventory_len
    }
}

/// Exclusive single-worker lock; removed on drop.
struct LockGuard(PathBuf);

impl LockGuard {
    fn acquire(path: PathBuf) -> Result<Self, MaintenanceError> {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut file) => {
                let _ = writeln!(file, "pid={}", std::process::id());
                let _ = file.sync_all();
                Ok(Self(path))
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(MaintenanceError::Locked)
            }
            Err(_) => Err(MaintenanceError::Io),
        }
    }
}

impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Durable cursor storage with atomic replace.
pub struct CheckpointStore {
    path: PathBuf,
}

impl CheckpointStore {
    /// Use `path` for the checkpoint and `path.lock` for the worker lock.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    fn lock_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_owned();
        name.push(".lock");
        PathBuf::from(name)
    }

    /// Read the checkpoint, if any. A corrupt file fails closed.
    pub fn read(&self) -> Result<Option<Checkpoint>, MaintenanceError> {
        match std::fs::read(&self.path) {
            Ok(bytes) => {
                let checkpoint: Checkpoint = serde_json::from_slice(&bytes)
                    .map_err(|_| MaintenanceError::Checkpoint("corrupt"))?;
                if checkpoint.version != CHECKPOINT_VERSION {
                    return Err(MaintenanceError::Checkpoint("unsupported version"));
                }
                if checkpoint.next_index > checkpoint.inventory_len {
                    return Err(MaintenanceError::Checkpoint("cursor beyond inventory"));
                }
                Ok(Some(checkpoint))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(_) => Err(MaintenanceError::Io),
        }
    }

    /// Atomically replace the checkpoint (write, fsync, rename, fsync dir).
    pub fn write(&self, checkpoint: &Checkpoint) -> Result<(), MaintenanceError> {
        let mut tmp = self.path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let bytes = serde_json::to_vec(checkpoint).map_err(|_| MaintenanceError::Io)?;
        {
            let mut file = std::fs::File::create(&tmp).map_err(|_| MaintenanceError::Io)?;
            file.write_all(&bytes).map_err(|_| MaintenanceError::Io)?;
            file.sync_all().map_err(|_| MaintenanceError::Io)?;
        }
        std::fs::rename(&tmp, &self.path).map_err(|_| MaintenanceError::Io)?;
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if let Ok(dir) = std::fs::File::open(dir) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }
}

/// Storage operations the worker needs. Implemented by [`IndexedStore`];
/// tests substitute fakes.
#[async_trait::async_trait]
pub trait ExpiryTarget: Send + Sync {
    /// Stable, low-cardinality backend label.
    fn backend(&self) -> &'static str;
    /// Eligibility without importing or cleaning legacy state.
    async fn state(&self, tenant: &str, context: &str) -> Result<MaintenanceState, TokenMapError>;
    /// Clear at most `limit` expired ciphertexts; return the count cleared.
    async fn purge(
        &self,
        tenant: &str,
        context: &str,
        limit: usize,
    ) -> Result<usize, TokenMapError>;
}

#[async_trait::async_trait]
impl ExpiryTarget for IndexedStore {
    fn backend(&self) -> &'static str {
        super::TokenMapStore::backend_name(self)
    }
    async fn state(&self, tenant: &str, context: &str) -> Result<MaintenanceState, TokenMapError> {
        self.maintenance_state(tenant, context).await
    }
    async fn purge(
        &self,
        tenant: &str,
        context: &str,
        limit: usize,
    ) -> Result<usize, TokenMapError> {
        self.purge_expired(tenant, context, limit).await
    }
}

/// RED instruments for the worker.
#[derive(Debug, Clone)]
pub struct MaintenanceMetrics {
    batches: Counter<u64>,
    batch_duration: Histogram<f64>,
    cleared: Counter<u64>,
    contexts: Counter<u64>,
    retries: Counter<u64>,
    backlog: Gauge<u64>,
    pass_age: Gauge<f64>,
}

impl MaintenanceMetrics {
    /// Build instruments from a meter.
    pub fn new(meter: &Meter) -> Self {
        Self {
            batches: meter
                .u64_counter(METRIC_BATCHES)
                .with_description("Expiry-maintenance purge batches by outcome")
                .with_unit("{batch}")
                .build(),
            batch_duration: meter
                .f64_histogram(METRIC_BATCH_DURATION)
                .with_description("Duration of expiry-maintenance purge batches")
                .with_unit("s")
                .with_boundaries(semconv::HTTP_DURATION_BOUNDS.to_vec())
                .build(),
            cleared: meter
                .u64_counter(METRIC_CLEARED)
                .with_description("Expired ciphertexts cleared; reservations are retained")
                .with_unit("{entry}")
                .build(),
            contexts: meter
                .u64_counter(METRIC_CONTEXTS)
                .with_description("Inventory contexts visited by outcome")
                .with_unit("{context}")
                .build(),
            retries: meter
                .u64_counter(METRIC_RETRIES)
                .with_description("Transient expiry-maintenance retries")
                .with_unit("{retry}")
                .build(),
            backlog: meter
                .u64_gauge(METRIC_BACKLOG)
                .with_description("Inventory contexts remaining in the current pass")
                .with_unit("{context}")
                .build(),
            pass_age: meter
                .f64_gauge(METRIC_PASS_AGE)
                .with_description("Age of the current maintenance pass")
                .with_unit("s")
                .build(),
        }
    }

    /// No-op instruments.
    pub fn noop() -> Self {
        let provider = opentelemetry::metrics::noop::NoopMeterProvider::new();
        Self::new(&opentelemetry::metrics::MeterProvider::meter(
            &provider,
            "redact-gateway",
        ))
    }

    fn batch(&self, backend: &'static str, secs: f64, error: Option<&'static str>) {
        let mut attrs = vec![
            KeyValue::new(semconv::REDACT_TOKENMAP_BACKEND, backend),
            KeyValue::new("outcome", if error.is_some() { "error" } else { "ok" }),
        ];
        if let Some(error) = error {
            attrs.push(KeyValue::new(semconv::ERROR_TYPE, error));
        }
        self.batches.add(1, &attrs);
        self.batch_duration.record(secs, &attrs);
    }
}

/// Final per-context classification, also used as a metric attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContextOutcome {
    Drained,
    Retired,
    NotImported,
    CleanupPending,
}

impl ContextOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Drained => "drained",
            Self::Retired => "retired",
            Self::NotImported => "not_imported",
            Self::CleanupPending => "cleanup_pending",
        }
    }
}

/// Why a run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    /// Every inventory entry of the pass was visited.
    PassComplete,
    /// Per-run context budget reached; the next run resumes.
    ContextBudget,
    /// A context still had expired entries after its batch budget.
    BatchBudget,
    /// The wall-clock deadline was reached.
    Deadline,
    /// A failure stopped the run without advancing past the failing context.
    Failed,
}

/// Identifier-free run summary.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    /// Pass number.
    pub pass: u64,
    /// Stop reason; `None` only before the run starts.
    pub stop_reason: Option<StopReason>,
    /// Content-free error category when `stop_reason` is `failed`.
    pub error_type: Option<&'static str>,
    /// Contexts fully visited this run.
    pub contexts_visited: u64,
    /// Contexts purged until zero.
    pub drained: u64,
    /// Retired contexts skipped.
    pub retired: u64,
    /// Never-imported contexts skipped without migrating them.
    pub not_imported: u64,
    /// Imported contexts awaiting legacy cleanup, skipped.
    pub cleanup_pending: u64,
    /// Purge batches completed.
    pub batches: u64,
    /// Expired ciphertexts cleared.
    pub cleared: u64,
    /// Transient retries performed.
    pub retries: u64,
    /// Contexts remaining in this pass.
    pub remaining_contexts: u64,
    /// Seconds since this pass started.
    pub pass_age_secs: f64,
}

impl Summary {
    /// Whether the run ended in a failure.
    pub fn failed(&self) -> bool {
        self.stop_reason == Some(StopReason::Failed)
    }
}

enum Classified {
    Transient(&'static str),
    Fatal(&'static str),
}

fn classify(error: &TokenMapError) -> Classified {
    match error {
        TokenMapError::Indexed(Error::Unavailable) => {
            Classified::Transient("token_store_unavailable")
        }
        TokenMapError::Indexed(Error::Busy) => Classified::Transient("token_store_busy"),
        TokenMapError::Unavailable(_) => Classified::Transient("token_map_unavailable"),
        TokenMapError::Indexed(Error::Integrity) => Classified::Fatal("token_store_integrity"),
        TokenMapError::Indexed(Error::Invalid) => Classified::Fatal("token_store_invalid"),
        TokenMapError::Indexed(Error::Retired) => Classified::Fatal("token_store_retired"),
        TokenMapError::Indexed(Error::Capacity) => Classified::Fatal("token_store_capacity"),
        TokenMapError::Conflict(_) => Classified::Fatal("token_map_conflict"),
        TokenMapError::Disabled => Classified::Fatal("token_map_disabled"),
        TokenMapError::Backend(_) => Classified::Fatal("token_map_backend"),
    }
}

/// Expiry-maintenance worker.
pub struct Worker<'a, T: ExpiryTarget + ?Sized> {
    target: &'a T,
    limits: Limits,
    metrics: MaintenanceMetrics,
}

enum Visit {
    Done(ContextOutcome),
    BatchBudget,
    Deadline,
    Failed(&'static str),
}

impl<'a, T: ExpiryTarget + ?Sized> Worker<'a, T> {
    /// Build a worker after validating limits.
    pub fn new(
        target: &'a T,
        limits: Limits,
        metrics: MaintenanceMetrics,
    ) -> Result<Self, MaintenanceError> {
        limits.validate()?;
        Ok(Self {
            target,
            limits,
            metrics,
        })
    }

    /// Run one bounded slice of the current pass.
    ///
    /// `restart_pass` discards an unfinished cursor bound to a different
    /// inventory; without it such a cursor fails closed.
    pub async fn run(
        &self,
        inventory: &Inventory,
        store: &CheckpointStore,
        restart_pass: bool,
    ) -> Result<Summary, MaintenanceError> {
        let _lock = LockGuard::acquire(store.lock_path())?;
        let now = chrono::Utc::now().timestamp_millis();
        let mut checkpoint = match store.read()? {
            Some(previous)
                if previous.inventory_sha256 == inventory.digest()
                    && previous.inventory_len == inventory.len()
                    && !previous.complete() =>
            {
                previous
            }
            Some(previous) if previous.complete() || restart_pass => Checkpoint {
                version: CHECKPOINT_VERSION,
                inventory_sha256: inventory.digest().to_string(),
                inventory_len: inventory.len(),
                pass: previous.pass + 1,
                next_index: 0,
                pass_started_ms: now,
                updated_ms: now,
            },
            Some(_) => {
                return Err(MaintenanceError::Checkpoint(
                    "unfinished pass is bound to a different inventory",
                ))
            }
            None => Checkpoint {
                version: CHECKPOINT_VERSION,
                inventory_sha256: inventory.digest().to_string(),
                inventory_len: inventory.len(),
                pass: 1,
                next_index: 0,
                pass_started_ms: now,
                updated_ms: now,
            },
        };
        store.write(&checkpoint)?;

        let span = tracing::info_span!(
            target: semconv::target::TOKENMAP,
            "redact.gateway.tokenstore.maintenance.run",
            otel.name = SPAN_RUN,
            redact.tokenmap.backend = self.target.backend(),
            pass = checkpoint.pass,
            stop_reason = tracing::field::Empty,
            "error.type" = tracing::field::Empty,
            cleared = tracing::field::Empty,
            batches = tracing::field::Empty,
        );
        let summary = self
            .run_pass(inventory, store, &mut checkpoint)
            .instrument(span.clone())
            .await?;
        if let Some(reason) = summary.stop_reason {
            span.record("stop_reason", format!("{reason:?}").as_str());
        }
        if let Some(error) = summary.error_type {
            span.record("error.type", error);
        }
        span.record("cleared", summary.cleared);
        span.record("batches", summary.batches);
        Ok(summary)
    }

    async fn run_pass(
        &self,
        inventory: &Inventory,
        store: &CheckpointStore,
        checkpoint: &mut Checkpoint,
    ) -> Result<Summary, MaintenanceError> {
        let started = Instant::now();
        let mut summary = Summary {
            pass: checkpoint.pass,
            ..Summary::default()
        };
        let mut visited_this_run = 0usize;
        let stop = loop {
            if checkpoint.next_index >= inventory.len() {
                break StopReason::PassComplete;
            }
            if visited_this_run >= self.limits.max_contexts_per_run {
                break StopReason::ContextBudget;
            }
            if started.elapsed() >= self.limits.run_deadline {
                break StopReason::Deadline;
            }
            let subject = &inventory.subjects[checkpoint.next_index];
            match self.visit(subject, started, &mut summary).await {
                Visit::Done(outcome) => {
                    self.metrics.contexts.add(
                        1,
                        &[
                            KeyValue::new(semconv::REDACT_TOKENMAP_BACKEND, self.target.backend()),
                            KeyValue::new("outcome", outcome.as_str()),
                        ],
                    );
                    match outcome {
                        ContextOutcome::Drained => summary.drained += 1,
                        ContextOutcome::Retired => summary.retired += 1,
                        ContextOutcome::NotImported => summary.not_imported += 1,
                        ContextOutcome::CleanupPending => summary.cleanup_pending += 1,
                    }
                    summary.contexts_visited += 1;
                    visited_this_run += 1;
                    checkpoint.next_index += 1;
                    checkpoint.updated_ms = chrono::Utc::now().timestamp_millis();
                    store.write(checkpoint)?;
                }
                Visit::BatchBudget => break StopReason::BatchBudget,
                Visit::Deadline => break StopReason::Deadline,
                Visit::Failed(error) => {
                    self.metrics.contexts.add(
                        1,
                        &[
                            KeyValue::new(semconv::REDACT_TOKENMAP_BACKEND, self.target.backend()),
                            KeyValue::new("outcome", "failed"),
                            KeyValue::new(semconv::ERROR_TYPE, error),
                        ],
                    );
                    summary.error_type = Some(error);
                    break StopReason::Failed;
                }
            }
        };
        summary.stop_reason = Some(stop);
        summary.remaining_contexts = (inventory.len() - checkpoint.next_index) as u64;
        summary.pass_age_secs =
            ((chrono::Utc::now().timestamp_millis() - checkpoint.pass_started_ms).max(0) as f64)
                / 1000.0;
        let backend = [KeyValue::new(
            semconv::REDACT_TOKENMAP_BACKEND,
            self.target.backend(),
        )];
        self.metrics
            .backlog
            .record(summary.remaining_contexts, &backend);
        self.metrics
            .pass_age
            .record(summary.pass_age_secs, &backend);
        Ok(summary)
    }

    async fn visit(&self, subject: &Subject, started: Instant, summary: &mut Summary) -> Visit {
        let state = match self
            .with_retries(summary, || {
                self.target.state(&subject.tenant, &subject.context)
            })
            .await
        {
            Ok(state) => state,
            Err(error) => return Visit::Failed(error),
        };
        match state {
            MaintenanceState::Retired => return Visit::Done(ContextOutcome::Retired),
            MaintenanceState::NotImported => return Visit::Done(ContextOutcome::NotImported),
            MaintenanceState::CleanupPending => return Visit::Done(ContextOutcome::CleanupPending),
            MaintenanceState::Eligible => {}
        }
        for _ in 0..self.limits.max_batches_per_context {
            if started.elapsed() >= self.limits.run_deadline {
                return Visit::Deadline;
            }
            let span = tracing::info_span!(
                target: semconv::target::TOKENMAP,
                "redact.gateway.tokenstore.maintenance.batch",
                otel.name = SPAN_BATCH,
                redact.tokenmap.backend = self.target.backend(),
                limit = self.limits.batch_limit,
                cleared = tracing::field::Empty,
                "error.type" = tracing::field::Empty,
            );
            let limit = self.limits.batch_limit;
            let result = self
                .with_retries(summary, || {
                    self.target.purge(&subject.tenant, &subject.context, limit)
                })
                .instrument(span.clone())
                .await;
            match result {
                Ok(cleared) if cleared > limit => {
                    // A backend that over-reports is not trusted further.
                    span.record("error.type", "token_store_integrity");
                    return Visit::Failed("token_store_integrity");
                }
                Ok(cleared) => {
                    span.record("cleared", cleared as u64);
                    summary.batches += 1;
                    summary.cleared += cleared as u64;
                    self.metrics.cleared.add(
                        cleared as u64,
                        &[KeyValue::new(
                            semconv::REDACT_TOKENMAP_BACKEND,
                            self.target.backend(),
                        )],
                    );
                    if cleared == 0 {
                        return Visit::Done(ContextOutcome::Drained);
                    }
                }
                Err(error) => {
                    span.record("error.type", error);
                    return Visit::Failed(error);
                }
            }
        }
        Visit::BatchBudget
    }

    /// Run one operation with bounded retries for transient failures. Every
    /// attempt is recorded as a batch-level RED sample.
    async fn with_retries<F, Fut, R>(
        &self,
        summary: &mut Summary,
        mut operation: F,
    ) -> Result<R, &'static str>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<R, TokenMapError>>,
    {
        let mut backoff = self.limits.initial_backoff;
        let backend = self.target.backend();
        for attempt in 1..=self.limits.max_attempts {
            let begun = Instant::now();
            let result = operation().await;
            let secs = begun.elapsed().as_secs_f64();
            match result {
                Ok(value) => {
                    self.metrics.batch(backend, secs, None);
                    return Ok(value);
                }
                Err(error) => match classify(&error) {
                    Classified::Fatal(kind) => {
                        self.metrics.batch(backend, secs, Some(kind));
                        tracing::warn!(
                            target: semconv::target::TOKENMAP,
                            error_type = kind,
                            "token-store maintenance stopped on a non-retryable error"
                        );
                        return Err(kind);
                    }
                    Classified::Transient(kind) => {
                        self.metrics.batch(backend, secs, Some(kind));
                        if attempt == self.limits.max_attempts {
                            tracing::warn!(
                                target: semconv::target::TOKENMAP,
                                error_type = kind,
                                attempts = attempt,
                                "token-store maintenance retry budget exhausted"
                            );
                            return Err(kind);
                        }
                        summary.retries += 1;
                        self.metrics.retries.add(
                            1,
                            &[
                                KeyValue::new(semconv::REDACT_TOKENMAP_BACKEND, backend),
                                KeyValue::new(semconv::ERROR_TYPE, kind),
                            ],
                        );
                        tokio::time::sleep(backoff).await;
                        backoff = (backoff * 2).min(self.limits.max_backoff);
                    }
                },
            }
        }
        Err("token_store_unavailable")
    }
}
