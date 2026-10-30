// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Parallel `/v1/redact` calls on one session must not fail because two
//! requests minted the same token label.
//!
//! Every request resumes the session, mints labels from a per-request counter
//! and then merges its new mappings into the store. Requests that all read the
//! session before any of them writes therefore mint the same label (and seal
//! with a fresh random nonce, so even identical values differ as ciphertext).
//! The store rejects the late writers as a merge conflict; the handler must
//! re-read and re-mint instead of surfacing a 503.

mod support;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::http::StatusCode;
use redact_gateway::redact::token::TokenMapping;
use redact_gateway::routes::{create_router, AppState};
use redact_gateway::vault::{CredentialLineage, MemoryStore, TokenMapError, TokenMapStore};
use serde_json::json;
use support::*;
use tokio::sync::Barrier;

const PARALLEL: usize = 4;
const SESSION: &str = "shared-session";

/// Delegates to a [`MemoryStore`] but, once armed, holds the first
/// `PARALLEL` reads at a barrier so every request observes the same snapshot
/// before any request writes. This makes the interleaving deterministic.
#[derive(Debug)]
struct GatedStore {
    inner: MemoryStore,
    barrier: Barrier,
    gated_reads_left: AtomicUsize,
    put_calls: AtomicUsize,
    always_conflict: bool,
}

impl GatedStore {
    fn new(always_conflict: bool) -> Self {
        Self {
            inner: MemoryStore::new(3600),
            barrier: Barrier::new(PARALLEL),
            gated_reads_left: AtomicUsize::new(0),
            put_calls: AtomicUsize::new(0),
            always_conflict,
        }
    }

    fn arm(&self) {
        self.gated_reads_left.store(PARALLEL, Ordering::SeqCst);
    }
}

#[async_trait::async_trait]
impl TokenMapStore for GatedStore {
    fn backend_name(&self) -> &'static str {
        "memory"
    }

    async fn put(
        &self,
        tenant: &str,
        session: &str,
        mappings: &[TokenMapping],
    ) -> Result<(), TokenMapError> {
        self.put_calls.fetch_add(1, Ordering::SeqCst);
        if self.always_conflict {
            return Err(TokenMapError::Conflict("forced".to_string()));
        }
        self.inner.put(tenant, session, mappings).await
    }

    async fn get(&self, tenant: &str, session: &str) -> Result<Vec<TokenMapping>, TokenMapError> {
        let gated = self
            .gated_reads_left
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
            .is_ok();
        let snapshot = self.inner.get(tenant, session).await;
        if gated {
            self.barrier.wait().await;
        }
        snapshot
    }

    async fn delete(&self, tenant: &str, session: &str) -> Result<(), TokenMapError> {
        self.inner.delete(tenant, session).await
    }

    async fn get_lineage(
        &self,
        tenant: &str,
        subject: &str,
    ) -> Result<CredentialLineage, TokenMapError> {
        self.inner.get_lineage(tenant, subject).await
    }

    async fn put_lineage(
        &self,
        tenant: &str,
        subject: &str,
        lineage: &CredentialLineage,
    ) -> Result<(), TokenMapError> {
        self.inner.put_lineage(tenant, subject, lineage).await
    }

    async fn health(&self) -> Result<(), TokenMapError> {
        Ok(())
    }
}

async fn harness(store: Arc<GatedStore>) -> (AppState, axum::Router) {
    let upstream = mock_json_upstream(chat_response("ok")).await;
    let mut config = config_for(&upstream);
    config.vault.backend = redact_gateway::config::VaultBackend::Memory;
    config.policy = Arc::new(policy_with(tokenize_profile(true)));
    let mut state = state_for(config).await;
    state.tokens = store;
    let router = create_router(state.clone());
    (state, router)
}

async fn redact(router: axum::Router, email: &str) -> TestResponse {
    post_json(
        router,
        "/v1/redact",
        json!({"text": format!("mail {email}"), "session_id": SESSION}),
    )
    .await
}

fn token_in(response: &TestResponse) -> String {
    let body = response.json();
    let text = body["text"].as_str().unwrap();
    let open = text.find('[').expect("a token in the redacted text");
    let close = text.find(']').expect("a closing bracket");
    text[open..=close].to_string()
}

/// Every stored label maps to one plaintext, and the store never holds two
/// rows for one label.
fn stored_plaintexts(state: &AppState, mappings: &[TokenMapping]) -> BTreeMap<String, String> {
    let mut by_label = BTreeMap::new();
    for mapping in mappings {
        let plaintext = state.dek.open(&mapping.sealed_value).unwrap();
        let prior = by_label.insert(mapping.token.clone(), plaintext);
        assert!(prior.is_none(), "label {} stored twice", mapping.token);
    }
    by_label
}

#[tokio::test]
async fn parallel_requests_with_distinct_values_all_succeed_and_restore() {
    let store = Arc::new(GatedStore::new(false));
    let (state, router) = harness(store.clone()).await;

    let seeded = redact(router.clone(), "seed@example.com").await;
    assert_eq!(seeded.status, StatusCode::OK, "{}", seeded.body);
    let seeded_token = token_in(&seeded);

    store.arm();
    let emails: Vec<String> = (0..PARALLEL)
        .map(|i| format!("user{i}@example.com"))
        .collect();
    let mut tasks = Vec::new();
    for email in emails.clone() {
        let router = router.clone();
        tasks.push(tokio::spawn(async move {
            let response = redact(router, &email).await;
            (email, response)
        }));
    }

    let mut label_for_email = BTreeMap::new();
    for task in tasks {
        let (email, response) = task.await.unwrap();
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        label_for_email.insert(email, token_in(&response));
    }

    let labels: BTreeSet<_> = label_for_email.values().cloned().collect();
    assert_eq!(
        labels.len(),
        PARALLEL,
        "labels must be unique: {label_for_email:?}"
    );
    assert!(
        !labels.contains(&seeded_token),
        "seed label must not be reissued"
    );

    let stored = stored_plaintexts(&state, &store.inner.get("default", SESSION).await.unwrap());
    assert_eq!(stored.len(), PARALLEL + 1);
    assert_eq!(stored[&seeded_token], "seed@example.com");
    for (email, label) in &label_for_email {
        assert_eq!(&stored[label], email, "label must restore to its own value");
    }
}

#[tokio::test]
async fn parallel_requests_with_the_same_value_converge_on_one_label() {
    let store = Arc::new(GatedStore::new(false));
    let (state, router) = harness(store.clone()).await;

    store.arm();
    let mut tasks = Vec::new();
    for _ in 0..PARALLEL {
        let router = router.clone();
        tasks.push(tokio::spawn(async move {
            redact(router, "shared@example.com").await
        }));
    }

    let mut labels = BTreeSet::new();
    for task in tasks {
        let response = task.await.unwrap();
        assert_eq!(response.status, StatusCode::OK, "{}", response.body);
        labels.insert(token_in(&response));
    }
    assert_eq!(labels.len(), 1, "one value must keep one label: {labels:?}");

    let stored = stored_plaintexts(&state, &store.inner.get("default", SESSION).await.unwrap());
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[labels.iter().next().unwrap()], "shared@example.com");
}

#[tokio::test]
async fn persistent_merge_conflict_still_fails_closed_after_bounded_retries() {
    let store = Arc::new(GatedStore::new(true));
    let (_state, router) = harness(store.clone()).await;

    let response = redact(router, "alice@example.com").await;

    assert_eq!(response.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        response.body.contains("token map write failed"),
        "{}",
        response.body
    );
    let puts = store.put_calls.load(Ordering::SeqCst);
    assert!(
        (2..=16).contains(&puts),
        "expected a bounded number of retries, saw {puts}"
    );
    assert!(store
        .inner
        .get("default", SESSION)
        .await
        .unwrap()
        .is_empty());
}
