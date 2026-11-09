//! Expiry-maintenance worker: bounds, idempotent resume, fail-closed stops and
//! identifier-free telemetry, against a scripted in-process target.
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use redact_gateway::vault::indexed::MaintenanceState;
use redact_gateway::vault::maintenance::{
    CheckpointStore, ExpiryTarget, Inventory, Limits, MaintenanceError, MaintenanceMetrics,
    StopReason, Worker,
};
use redact_gateway::vault::TokenMapError;
use redact_token_store::Error;

#[derive(Default)]
struct Context {
    state: Option<MaintenanceState>,
    expired: usize,
    /// Errors returned by the next purge calls, in order.
    failures: Vec<Error>,
    purge_calls: usize,
    state_calls: usize,
    over_report: bool,
    delay: Option<Duration>,
}

#[derive(Default)]
struct Fake {
    contexts: Mutex<HashMap<String, Context>>,
    max_limit_seen: Mutex<usize>,
}

impl Fake {
    fn with(entries: Vec<(&str, Context)>) -> Self {
        Self {
            contexts: Mutex::new(
                entries
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v))
                    .collect(),
            ),
            ..Default::default()
        }
    }
    fn purge_calls(&self, context: &str) -> usize {
        self.contexts.lock().unwrap()[context].purge_calls
    }
    fn state_calls(&self, context: &str) -> usize {
        self.contexts.lock().unwrap()[context].state_calls
    }
    fn expired(&self, context: &str) -> usize {
        self.contexts.lock().unwrap()[context].expired
    }
}

fn eligible(expired: usize) -> Context {
    Context {
        state: Some(MaintenanceState::Eligible),
        expired,
        ..Default::default()
    }
}

fn in_state(state: MaintenanceState) -> Context {
    Context {
        state: Some(state),
        ..Default::default()
    }
}

#[async_trait::async_trait]
impl ExpiryTarget for Fake {
    fn backend(&self) -> &'static str {
        "fake"
    }
    async fn state(&self, tenant: &str, context: &str) -> Result<MaintenanceState, TokenMapError> {
        assert_eq!(tenant, "tenant-canary-7f3a");
        let mut contexts = self.contexts.lock().unwrap();
        let entry = contexts.get_mut(context).expect("context in fake");
        entry.state_calls += 1;
        Ok(entry.state.expect("state configured"))
    }
    async fn purge(
        &self,
        _tenant: &str,
        context: &str,
        limit: usize,
    ) -> Result<usize, TokenMapError> {
        {
            let mut max = self.max_limit_seen.lock().unwrap();
            *max = (*max).max(limit);
        }
        let delay = self.contexts.lock().unwrap()[context].delay;
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        let mut contexts = self.contexts.lock().unwrap();
        let entry = contexts.get_mut(context).expect("context in fake");
        assert_eq!(
            entry.state,
            Some(MaintenanceState::Eligible),
            "purge called for an ineligible context"
        );
        entry.purge_calls += 1;
        if !entry.failures.is_empty() {
            return Err(TokenMapError::Indexed(entry.failures.remove(0)));
        }
        if entry.over_report {
            return Ok(limit + 1);
        }
        let cleared = entry.expired.min(limit);
        entry.expired -= cleared;
        Ok(cleared)
    }
}

fn inventory(contexts: &[&str]) -> Inventory {
    let lines: Vec<String> = contexts
        .iter()
        .map(|c| serde_json::json!({"tenant":"tenant-canary-7f3a","context":c}).to_string())
        .collect();
    Inventory::parse(lines.join("\n").as_bytes()).unwrap()
}

fn checkpoint_path() -> PathBuf {
    std::env::temp_dir().join(format!("maint-{}.json", uuid::Uuid::new_v4()))
}

fn fast() -> Limits {
    Limits {
        initial_backoff: Duration::from_millis(1),
        max_backoff: Duration::from_millis(2),
        ..Limits::default()
    }
}

fn worker<'a>(fake: &'a Fake, limits: Limits) -> Worker<'a, Fake> {
    Worker::new(fake, limits, MaintenanceMetrics::noop()).unwrap()
}

#[tokio::test]
async fn drains_eligible_until_zero_and_skips_without_migrating() {
    let fake = Fake::with(vec![
        ("ctx-a", eligible(600)),
        ("ctx-retired", in_state(MaintenanceState::Retired)),
        ("ctx-absent", in_state(MaintenanceState::NotImported)),
        ("ctx-pending", in_state(MaintenanceState::CleanupPending)),
    ]);
    let inv = inventory(&["ctx-a", "ctx-retired", "ctx-absent", "ctx-pending"]);
    let path = checkpoint_path();
    let store = CheckpointStore::new(&path);
    let summary = worker(&fake, fast())
        .run(&inv, &store, false)
        .await
        .unwrap();
    assert_eq!(summary.stop_reason, Some(StopReason::PassComplete));
    assert_eq!(summary.cleared, 600);
    // 256 + 256 + 88, then the required confirming zero.
    assert_eq!(summary.batches, 4);
    assert_eq!(fake.purge_calls("ctx-a"), 4);
    assert_eq!(fake.expired("ctx-a"), 0);
    assert_eq!(*fake.max_limit_seen.lock().unwrap(), 256);
    assert_eq!(
        (
            summary.drained,
            summary.retired,
            summary.not_imported,
            summary.cleanup_pending
        ),
        (1, 1, 1, 1)
    );
    for ctx in ["ctx-retired", "ctx-absent", "ctx-pending"] {
        assert_eq!(fake.purge_calls(ctx), 0, "{ctx} must not be purged");
    }
    assert_eq!(summary.remaining_contexts, 0);
    let cp = store.read().unwrap().unwrap();
    assert_eq!((cp.next_index, cp.inventory_len, cp.pass), (4, 4, 1));
    let raw = std::fs::read_to_string(&path).unwrap();
    let rendered = serde_json::to_string(&summary).unwrap();
    for text in [&raw, &rendered] {
        assert!(!text.contains("canary"), "identifier leaked: {text}");
        assert!(!text.contains("ctx-"), "identifier leaked: {text}");
    }
    assert!(
        !path.with_extension("json.lock").exists(),
        "lock not released"
    );
}

#[tokio::test]
async fn transient_exhaustion_stops_and_resume_is_idempotent() {
    let mut flaky = eligible(5);
    flaky.failures = vec![Error::Unavailable, Error::Busy, Error::Unavailable];
    let fake = Fake::with(vec![("ctx-a", eligible(10)), ("ctx-b", flaky)]);
    let inv = inventory(&["ctx-a", "ctx-b"]);
    let store = CheckpointStore::new(checkpoint_path());
    let limits = Limits {
        max_attempts: 2,
        ..fast()
    };
    let first = worker(&fake, limits.clone())
        .run(&inv, &store, false)
        .await
        .unwrap();
    assert!(first.failed());
    assert_eq!(first.error_type, Some("token_store_busy"));
    assert_eq!(first.retries, 1);
    assert_eq!(store.read().unwrap().unwrap().next_index, 1);
    let a_calls = fake.purge_calls("ctx-a");
    // One more transient failure is consumed by the first retry of run two.
    let second = worker(&fake, limits)
        .run(&inv, &store, false)
        .await
        .unwrap();
    assert_eq!(second.stop_reason, Some(StopReason::PassComplete));
    assert_eq!(
        second.pass, first.pass,
        "resume must continue the same pass"
    );
    assert_eq!(
        fake.purge_calls("ctx-a"),
        a_calls,
        "completed context repeated"
    );
    assert_eq!(fake.expired("ctx-b"), 0);
    assert_eq!(second.cleared, 5);
}

#[tokio::test]
async fn integrity_and_invalid_fail_closed_without_advancing() {
    let kinds: [fn() -> Error; 3] = [|| Error::Integrity, || Error::Invalid, || Error::Capacity];
    for make in kinds {
        let error = make();
        let mut broken = eligible(3);
        broken.failures = vec![make(), make()];
        let fake = Fake::with(vec![
            ("ctx-a", eligible(1)),
            ("ctx-b", broken),
            ("ctx-c", eligible(1)),
        ]);
        let inv = inventory(&["ctx-a", "ctx-b", "ctx-c"]);
        let store = CheckpointStore::new(checkpoint_path());
        let summary = worker(&fake, fast())
            .run(&inv, &store, false)
            .await
            .unwrap();
        assert!(summary.failed(), "{error:?}");
        assert_eq!(summary.retries, 0, "non-retryable {error:?} was retried");
        assert_eq!(fake.purge_calls("ctx-b"), 1);
        assert_eq!(
            fake.state_calls("ctx-c"),
            0,
            "worker continued past failure"
        );
        assert_eq!(store.read().unwrap().unwrap().next_index, 1);
        // The failing context is retried, never skipped.
        let again = worker(&fake, fast())
            .run(&inv, &store, false)
            .await
            .unwrap();
        assert!(again.failed());
        assert_eq!(store.read().unwrap().unwrap().next_index, 1);
    }
}

#[tokio::test]
async fn over_reporting_backend_is_treated_as_integrity_failure() {
    let mut liar = eligible(0);
    liar.over_report = true;
    let fake = Fake::with(vec![("ctx-a", liar)]);
    let store = CheckpointStore::new(checkpoint_path());
    let summary = worker(&fake, fast())
        .run(&inventory(&["ctx-a"]), &store, false)
        .await
        .unwrap();
    assert!(summary.failed());
    assert_eq!(summary.error_type, Some("token_store_integrity"));
    assert_eq!(summary.cleared, 0);
}

#[tokio::test]
async fn batch_budget_and_context_budget_resume_where_they_stopped() {
    let fake = Fake::with(vec![("ctx-a", eligible(25)), ("ctx-b", eligible(1))]);
    let inv = inventory(&["ctx-a", "ctx-b"]);
    let store = CheckpointStore::new(checkpoint_path());
    let tight = Limits {
        batch_limit: 10,
        max_batches_per_context: 2,
        ..fast()
    };
    let first = worker(&fake, tight.clone())
        .run(&inv, &store, false)
        .await
        .unwrap();
    assert_eq!(first.stop_reason, Some(StopReason::BatchBudget));
    assert_eq!(first.cleared, 20);
    assert_eq!(store.read().unwrap().unwrap().next_index, 0);
    let one = Limits {
        max_contexts_per_run: 1,
        ..tight
    };
    let second = worker(&fake, one.clone())
        .run(&inv, &store, false)
        .await
        .unwrap();
    assert_eq!(second.stop_reason, Some(StopReason::ContextBudget));
    assert_eq!(second.cleared, 5);
    assert_eq!(second.remaining_contexts, 1);
    let third = worker(&fake, one).run(&inv, &store, false).await.unwrap();
    assert_eq!(third.stop_reason, Some(StopReason::PassComplete));
    assert_eq!(fake.expired("ctx-b"), 0);
}

#[tokio::test]
async fn deadline_stops_before_the_next_batch() {
    let mut slow = eligible(1000);
    slow.delay = Some(Duration::from_millis(30));
    let fake = Fake::with(vec![("ctx-a", slow)]);
    let store = CheckpointStore::new(checkpoint_path());
    let limits = Limits {
        batch_limit: 1,
        run_deadline: Duration::from_millis(50),
        ..fast()
    };
    let summary = worker(&fake, limits)
        .run(&inventory(&["ctx-a"]), &store, false)
        .await
        .unwrap();
    assert_eq!(summary.stop_reason, Some(StopReason::Deadline));
    assert!(summary.batches >= 1 && summary.batches <= 3);
    assert_eq!(store.read().unwrap().unwrap().next_index, 0);
}

#[tokio::test]
async fn cursor_is_bound_to_inventory_and_passes_roll_over() {
    let fake = Fake::with(vec![("ctx-a", eligible(0)), ("ctx-b", eligible(0))]);
    let store = CheckpointStore::new(checkpoint_path());
    let one = Limits {
        max_contexts_per_run: 1,
        ..fast()
    };
    let both = inventory(&["ctx-a", "ctx-b"]);
    worker(&fake, one.clone())
        .run(&both, &store, false)
        .await
        .unwrap();
    let other = inventory(&["ctx-b"]);
    let refused = worker(&fake, one.clone()).run(&other, &store, false).await;
    assert!(matches!(refused, Err(MaintenanceError::Checkpoint(_))));
    let restarted = worker(&fake, one.clone())
        .run(&other, &store, true)
        .await
        .unwrap();
    assert_eq!(restarted.pass, 2);
    assert_eq!(restarted.stop_reason, Some(StopReason::PassComplete));
    // A completed pass accepts a refreshed inventory and starts the next pass.
    let next = worker(&fake, fast())
        .run(&both, &store, false)
        .await
        .unwrap();
    assert_eq!(next.pass, 3);
    assert_eq!(next.stop_reason, Some(StopReason::PassComplete));
}

#[tokio::test]
async fn held_lock_and_corrupt_checkpoint_fail_closed() {
    let fake = Fake::with(vec![("ctx-a", eligible(1))]);
    let path = checkpoint_path();
    let store = CheckpointStore::new(&path);
    let lock = PathBuf::from(format!("{}.lock", path.display()));
    std::fs::write(&lock, "pid=1").unwrap();
    let held = worker(&fake, fast())
        .run(&inventory(&["ctx-a"]), &store, false)
        .await;
    assert!(matches!(held, Err(MaintenanceError::Locked)));
    assert_eq!(fake.state_calls("ctx-a"), 0);
    assert!(lock.exists(), "a foreign lock must not be removed");
    std::fs::remove_file(&lock).unwrap();
    std::fs::write(&path, "{not json").unwrap();
    let corrupt = worker(&fake, fast())
        .run(&inventory(&["ctx-a"]), &store, false)
        .await;
    assert!(matches!(corrupt, Err(MaintenanceError::Checkpoint(_))));
    assert_eq!(fake.state_calls("ctx-a"), 0);
}

#[test]
fn limits_are_bounded() {
    let fake = Fake::default();
    for limits in [
        Limits {
            batch_limit: 0,
            ..Limits::default()
        },
        Limits {
            batch_limit: 257,
            ..Limits::default()
        },
        Limits {
            max_attempts: 0,
            ..Limits::default()
        },
        Limits {
            max_attempts: 11,
            ..Limits::default()
        },
        Limits {
            max_batches_per_context: 0,
            ..Limits::default()
        },
        Limits {
            max_contexts_per_run: 0,
            ..Limits::default()
        },
        Limits {
            run_deadline: Duration::ZERO,
            ..Limits::default()
        },
        Limits {
            max_backoff: Duration::from_secs(301),
            ..Limits::default()
        },
    ] {
        assert!(matches!(
            Worker::new(&fake, limits, MaintenanceMetrics::noop()),
            Err(MaintenanceError::Limits(_))
        ));
    }
    assert!(Worker::new(&fake, Limits::default(), MaintenanceMetrics::noop()).is_ok());
}

#[test]
fn inventory_rejects_malformed_input_without_echoing_it() {
    for bad in [
        "{\"tenant\":\"secret-canary\"}",
        "{\"tenant\":\"secret-canary\",\"context\":\"\"}",
        "{\"tenant\":\"secret-canary\",\"context\":\"c\",\"extra\":1}",
        "not json secret-canary",
    ] {
        let error = Inventory::parse(bad.as_bytes()).err().expect(bad);
        assert!(!error.to_string().contains("secret-canary"));
    }
    let long = "x".repeat(1025);
    let line = serde_json::json!({"tenant":"t","context":long}).to_string();
    assert!(Inventory::parse(line.as_bytes()).is_err());
    let ok = Inventory::parse(b"\n{\"tenant\":\"t\",\"context\":\"c\"}\n\n").unwrap();
    assert_eq!(ok.len(), 1);
    assert_eq!(ok.digest().len(), 64);
}
