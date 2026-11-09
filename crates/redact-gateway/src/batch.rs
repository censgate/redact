// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Admission for field-preserving `/v1/redact` batches.
//!
//! One caller deadline covers the queue, detection and the token-map write.
//! Waiters are counted with a drop guard so a cancelled handler does not
//! permanently occupy a queue slot. Scalar `text` requests do not take a permit.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant as TokioInstant;

use crate::config::ServerSettings;
use crate::telemetry::metrics::Metrics;

/// How many texts[] requests may detect at once, and how many may wait.
#[derive(Clone, Debug)]
pub struct BatchGate {
    permits: Arc<Semaphore>,
    queue: Duration,
    depth: usize,
    waiters: Arc<AtomicUsize>,
}

/// Why a texts[] request was not admitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitFail {
    /// The queue is full, or the configured queue wait elapsed before the deadline.
    Overload,
    /// The caller's deadline elapsed while the request was still queued.
    Deadline,
    /// The semaphore closed.
    Closed,
}

/// Records one redact RED sample when dropped, unless already recorded.
///
/// Rate, errors and duration all use the same mode and outcome. Duration
/// starts when the guard is created, which is before admission.
pub struct RedGuard {
    metrics: Metrics,
    started: Instant,
    /// `text` or `texts`.
    pub mode: &'static str,
    /// `completed`, `error`, `overload` or `deadline`.
    pub outcome: &'static str,
    recorded: bool,
}

impl RedGuard {
    /// Start the caller-visible timer. The default outcome is `error`.
    pub fn new(metrics: Metrics, mode: &'static str) -> Self {
        Self {
            metrics,
            started: Instant::now(),
            mode,
            outcome: "error",
            recorded: false,
        }
    }

    /// Elapsed time since the guard was created.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

impl Drop for RedGuard {
    fn drop(&mut self) {
        if self.recorded {
            return;
        }
        self.recorded = true;
        self.metrics
            .record_redact_red(self.mode, self.outcome, self.elapsed().as_secs_f64());
    }
}

struct WaiterGuard {
    waiters: Arc<AtomicUsize>,
}

impl Drop for WaiterGuard {
    fn drop(&mut self) {
        self.waiters.fetch_sub(1, Ordering::AcqRel);
    }
}

impl BatchGate {
    /// Build a gate from already validated settings.
    pub fn from_settings(settings: &ServerSettings) -> Self {
        let inflight = usize::try_from(settings.redact_batch_inflight)
            .unwrap_or(1)
            .max(1);
        let depth = usize::try_from(settings.redact_batch_queue_depth).unwrap_or(0);
        Self {
            permits: Arc::new(Semaphore::new(inflight)),
            queue: Duration::from_millis(settings.redact_batch_queue_ms),
            depth,
            waiters: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Requests currently waiting for a permit.
    pub fn waiters(&self) -> usize {
        self.waiters.load(Ordering::Acquire)
    }

    /// Take a permit, or fail without starting detection.
    ///
    /// `deadline` is the caller's remaining budget. Queue time consumes it.
    /// The configured queue wait cannot extend it. Dropping the returned
    /// future releases the waiter slot.
    pub async fn acquire(&self, deadline: TokioInstant) -> Result<OwnedSemaphorePermit, AdmitFail> {
        if let Ok(permit) = self.permits.clone().try_acquire_owned() {
            return Ok(permit);
        }
        if self.depth == 0 || self.queue.is_zero() {
            return Err(if TokioInstant::now() >= deadline {
                AdmitFail::Deadline
            } else {
                AdmitFail::Overload
            });
        }

        let previous = self.waiters.fetch_add(1, Ordering::AcqRel);
        let _guard = WaiterGuard {
            waiters: Arc::clone(&self.waiters),
        };
        if previous >= self.depth {
            return Err(AdmitFail::Overload);
        }

        let now = TokioInstant::now();
        if now >= deadline {
            return Err(AdmitFail::Deadline);
        }
        let remaining = deadline.saturating_duration_since(now);
        let wait = remaining.min(self.queue);
        if wait.is_zero() {
            return Err(AdmitFail::Deadline);
        }

        match tokio::time::timeout(wait, self.permits.clone().acquire_owned()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_)) => Err(AdmitFail::Closed),
            Err(_) => {
                if TokioInstant::now() >= deadline {
                    Err(AdmitFail::Deadline)
                } else {
                    Err(AdmitFail::Overload)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::metrics::Metrics;

    fn gate(inflight: usize, queue: Duration, depth: usize) -> BatchGate {
        BatchGate {
            permits: Arc::new(Semaphore::new(inflight)),
            queue,
            depth,
            waiters: Arc::new(AtomicUsize::new(0)),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn dropping_a_queued_waiter_releases_the_slot() {
        let gate = gate(1, Duration::from_secs(5), 2);
        let hold = gate
            .acquire(TokioInstant::now() + Duration::from_secs(30))
            .await
            .unwrap();
        let queued = gate.clone();
        let task = tokio::spawn(async move {
            queued
                .acquire(TokioInstant::now() + Duration::from_secs(30))
                .await
        });
        tokio::task::yield_now().await;
        assert_eq!(gate.waiters(), 1);
        task.abort();
        let _ = task.await;
        tokio::task::yield_now().await;
        assert_eq!(gate.waiters(), 0);
        drop(hold);
        let again = gate
            .acquire(TokioInstant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        drop(again);
        assert_eq!(gate.waiters(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn queued_request_expires_on_the_caller_deadline() {
        let gate = gate(1, Duration::from_secs(5), 4);
        let hold = gate
            .acquire(TokioInstant::now() + Duration::from_secs(30))
            .await
            .unwrap();
        let queued = gate.clone();
        let task = tokio::spawn(async move {
            queued
                .acquire(TokioInstant::now() + Duration::from_millis(50))
                .await
        });
        tokio::time::sleep(Duration::from_millis(50)).await;
        let err = task.await.unwrap().unwrap_err();
        assert_eq!(err, AdmitFail::Deadline);
        assert_eq!(gate.waiters(), 0);
        drop(hold);
    }

    #[tokio::test(start_paused = true)]
    async fn queue_depth_fails_closed_without_waiting() {
        let gate = gate(1, Duration::from_secs(5), 1);
        let hold = gate
            .acquire(TokioInstant::now() + Duration::from_secs(30))
            .await
            .unwrap();
        let first = gate.clone();
        let waiting = tokio::spawn(async move {
            first
                .acquire(TokioInstant::now() + Duration::from_secs(30))
                .await
        });
        tokio::task::yield_now().await;
        let err = gate
            .acquire(TokioInstant::now() + Duration::from_secs(30))
            .await
            .unwrap_err();
        assert_eq!(err, AdmitFail::Overload);
        assert_eq!(gate.waiters(), 1);
        waiting.abort();
        let _ = waiting.await;
        drop(hold);
        assert_eq!(gate.waiters(), 0);
    }

    #[test]
    fn red_guard_records_once_on_drop() {
        let metrics = Metrics::noop();
        let mut guard = RedGuard::new(metrics, "texts");
        guard.outcome = "overload";
        drop(guard);
    }
}
