//! A pruned-history import emits a distinct event and counter with counts
//! only. Own binary: the thread-local subscriber must see every callsite.
#![cfg(feature = "vault")]
use redact_gateway::config::TraceLevel;
use redact_gateway::redact::token::{Dek, TokenMapping};
use redact_gateway::telemetry::testing::{init_test, test_settings};
use redact_gateway::vault::{
    pruned_evidence_digest, session_path, Kv2Store, LegacyHistoryPolicy, PathFingerprint,
    PrunedEvidence, PrunedHistoryPolicy, PrunedProof, TokenMapError, TokenMapStore,
    PRUNED_IMPORT_EVENT, PRUNED_IMPORT_METRIC, PRUNED_REJECTION_EVENT, PRUNED_REJECTION_METRIC,
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tracing_subscriber::layer::SubscriberExt;

#[derive(Clone, Default)]
struct Events(Arc<Mutex<Vec<String>>>);

struct Capture(Events);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(&self, event: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        struct Fields(String);
        impl tracing::field::Visit for Fields {
            fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
                self.0.push_str(&format!("{}={value:?};", field.name()));
            }
        }
        let mut fields = Fields(String::new());
        event.record(&mut fields);
        self.0 .0.lock().unwrap().push(fields.0);
    }
}

#[tokio::test]
#[ignore = "requires isolated OpenBao source"]
async fn pruned_proof_acceptance_and_rejection_emit_non_secret_events_and_counters() {
    let test = init_test(&test_settings(TraceLevel::Basic)).expect("telemetry");
    let events = Events::default();
    let _guard = tracing::subscriber::set_default(
        tracing_subscriber::registry().with(Capture(events.clone())),
    );
    let credential = std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap())
        .unwrap()
        .trim()
        .to_string();
    let settings = redact_gateway::config::VaultSettings {
        backend: redact_gateway::config::VaultBackend::VaultKv2,
        address: Some(std::env::var("TOKEN_STORE_BAO_ADDR").unwrap()),
        token: Some(credential.clone()),
        path_prefix: format!("pruned-telemetry-{}", uuid::Uuid::new_v4()),
        ..Default::default()
    };
    let key = Dek::from_bytes([7; 32]);
    let tenant = "tenant-canary";
    let session = "session-canary";
    let path = session_path(&settings.path_prefix, tenant, session);
    let base = settings.address.as_ref().unwrap();
    let client = reqwest::Client::new();
    let send = |request: reqwest::RequestBuilder| {
        let credential = credential.clone();
        async move {
            request
                .header("X-Vault-Token", credential)
                .send()
                .await
                .unwrap()
                .error_for_status()
                .unwrap();
        }
    };
    send(
        client
            .post(format!("{base}/v1/secret/metadata/{path}"))
            .json(&json!({"max_versions": 2})),
    )
    .await;
    let rows: Vec<_> = (1..=5)
        .map(|n| TokenMapping {
            token: format!("[PERSON_{n}]"),
            entity_type: "PERSON".into(),
            sealed_value: key.seal(&format!("value-canary-{n}")).unwrap(),
            created_at: chrono::Utc::now(),
        })
        .collect();
    for n in 1..=5 {
        send(
            client
                .post(format!("{base}/v1/secret/data/{path}"))
                .json(&json!({"data":{"mappings": &rows[..n],"expires_at": chrono::Utc::now() + chrono::Duration::hours(1)}})),
        )
        .await;
    }
    // Operator inventory is values-free and generated after the writes.
    let metadata: serde_json::Value = client
        .get(format!("{base}/v1/secret/metadata/{path}"))
        .header("X-Vault-Token", &credential)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let metadata = &metadata["data"];
    let now = chrono::Utc::now();
    let mut evidence = PrunedEvidence {
        evidence_id: "review-canary".into(),
        generated_at: now,
        not_after: now + chrono::Duration::hours(1),
        identity_epoch: now - chrono::Duration::days(1),
        entries: Default::default(),
    };
    let unlisted = Kv2Store::from_settings(&settings)
        .unwrap()
        .with_history_policy(LegacyHistoryPolicy {
            pruned: PrunedHistoryPolicy::Proven(PrunedProof {
                evidence: evidence.clone(),
            }),
            ..Default::default()
        });
    assert!(matches!(
        unlisted.freeze(tenant, session).await,
        Err(TokenMapError::Indexed(redact_token_store::Error::Integrity))
    ));
    evidence.entries.insert(
        pruned_evidence_digest(&path),
        PathFingerprint {
            current_version: metadata["current_version"].as_u64().unwrap(),
            oldest_version: metadata["oldest_version"].as_u64().unwrap(),
            key_created_time: metadata["created_time"].as_str().unwrap().into(),
            updated_time: metadata["updated_time"].as_str().unwrap().into(),
        },
    );
    let store = Kv2Store::from_settings(&settings)
        .unwrap()
        .with_history_policy(LegacyHistoryPolicy {
            pruned: PrunedHistoryPolicy::Proven(PrunedProof { evidence }),
            ..Default::default()
        });
    store.freeze(tenant, session).await.unwrap();
    // The idempotent repeat must not count the same import twice.
    store.freeze(tenant, session).await.unwrap();

    let captured = events.0.lock().unwrap().clone();
    let matching: Vec<_> = captured
        .iter()
        .filter(|line| line.contains(PRUNED_IMPORT_EVENT))
        .collect();
    assert_eq!(matching.len(), 1, "{captured:?}");
    let line = matching[0];
    assert!(line.contains("retained_versions=2"), "{line}");
    assert!(line.contains("oldest_retained_version=4"), "{line}");
    assert!(line.contains("current_version=5"), "{line}");
    // Only this crate's event is under test; the HTTP client library logs its
    // own request URLs, which is outside this change.
    for canary in ["canary", settings.path_prefix.as_str(), "PERSON"] {
        assert!(!line.contains(canary), "{line}");
    }
    let rejected: Vec<_> = captured
        .iter()
        .filter(|line| line.contains(PRUNED_REJECTION_EVENT))
        .collect();
    assert_eq!(rejected.len(), 1);
    assert!(
        rejected[0].contains("reason=\"no_entry\""),
        "{}",
        rejected[0]
    );
    for canary in [
        "canary",
        settings.path_prefix.as_str(),
        "PERSON",
        path.as_str(),
        credential.as_str(),
    ] {
        assert!(!rejected[0].contains(canary));
    }

    // A complete-history (unpruned) context created before the epoch is
    // rejected with its own bounded reason and never imported.
    let complete = "complete-canary";
    let complete_path = session_path(&settings.path_prefix, tenant, complete);
    send(
        client
            .post(format!("{base}/v1/secret/data/{complete_path}"))
            .json(&json!({"data":{"mappings": &rows[..1],"expires_at": chrono::Utc::now() + chrono::Duration::hours(1)}})),
    )
    .await;
    let late_epoch = chrono::Utc::now() + chrono::Duration::hours(1);
    let pre_epoch = Kv2Store::from_settings(&settings)
        .unwrap()
        .with_history_policy(LegacyHistoryPolicy {
            pruned: PrunedHistoryPolicy::Proven(PrunedProof {
                evidence: PrunedEvidence {
                    evidence_id: "review-canary".into(),
                    generated_at: now,
                    not_after: now + chrono::Duration::hours(1),
                    identity_epoch: late_epoch,
                    entries: Default::default(),
                },
            }),
            ..Default::default()
        });
    assert!(matches!(
        pre_epoch.freeze(tenant, complete).await,
        Err(TokenMapError::Indexed(redact_token_store::Error::Integrity))
    ));
    let captured = events.0.lock().unwrap().clone();
    let pre_epoch_events: Vec<_> = captured
        .iter()
        .filter(|line| line.contains(PRUNED_REJECTION_EVENT) && line.contains("pre_epoch_context"))
        .collect();
    assert_eq!(pre_epoch_events.len(), 1, "{captured:?}");
    for canary in ["canary", settings.path_prefix.as_str(), "PERSON"] {
        assert!(!pre_epoch_events[0].contains(canary));
    }

    test.flush();
    let metrics = test.collect_metrics();
    let counter = metrics
        .iter()
        .find(|m| m.name == PRUNED_IMPORT_METRIC)
        .unwrap_or_else(|| panic!("missing {PRUNED_IMPORT_METRIC}"));
    assert_eq!(counter.unit, "{context}");
    assert!(
        counter.data_debug.contains("value: 1"),
        "{}",
        counter.data_debug
    );
    assert!(!counter.data_debug.contains("canary"));
    let rejection_counter = metrics
        .iter()
        .find(|m| m.name == PRUNED_REJECTION_METRIC)
        .expect("rejection counter");
    assert!(rejection_counter.data_debug.contains("value: 1"));
    assert!(rejection_counter.data_debug.contains("no_entry"));
    assert!(rejection_counter.data_debug.contains("pre_epoch_context"));
    assert!(!rejection_counter.data_debug.contains("canary"));
}
