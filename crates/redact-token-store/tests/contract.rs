use redact_token_store::{Entry, Error, Scope, TokenStore, Vault, MAX_BATCH};
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

fn facade(store: Arc<dyn TokenStore>) -> Vault {
    Vault::new(store, [7; 32], 32, Duration::from_secs(10)).unwrap()
}

async fn contract(store: Arc<dyn TokenStore>) {
    let vault = Arc::new(facade(store.clone()));
    let peer = Arc::new(facade(store.clone()));
    let context = uuid::Uuid::new_v4().to_string();
    let scope = vault
        .scope("synthetic-tenant-one", "synthetic-owner-one", &context)
        .unwrap();
    let foreign_tenant = vault
        .scope("synthetic-tenant-two", "synthetic-owner-one", &context)
        .unwrap();
    let foreign_owner = vault
        .scope("synthetic-tenant-one", "synthetic-owner-two", &context)
        .unwrap();
    let values = vec![
        ("PERSON".into(), "Example Person".into()),
        ("EMAIL_ADDRESS".into(), "fixture@example.invalid".into()),
    ];
    let tokens = vault
        .intern(&scope, &values, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        peer.intern(&scope, &values, Duration::from_secs(120))
            .await
            .unwrap(),
        tokens
    );
    assert_eq!(
        peer.resolve(
            &scope,
            &[tokens[1].clone(), tokens[0].clone(), tokens[1].clone()]
        )
        .await
        .unwrap(),
        vec![
            Some(values[1].1.clone()),
            Some(values[0].1.clone()),
            Some(values[1].1.clone())
        ]
    );
    assert_eq!(
        vault.resolve(&foreign_tenant, &tokens).await.unwrap(),
        vec![None, None]
    );
    assert_eq!(
        vault.resolve(&foreign_owner, &tokens).await.unwrap(),
        vec![None, None]
    );
    let tampered = facade(Arc::new(TamperedExpiry {
        inner: store.clone(),
    }));
    assert_eq!(
        tampered.resolve(&scope, &tokens).await,
        Err(Error::Integrity)
    );
    let large = vec![("PERSON".into(), "Synthetic value ".repeat(1024))];
    let large_tokens = vault
        .intern(&scope, &large, Duration::from_secs(60))
        .await
        .unwrap();
    let counting = Arc::new(CountingResolve {
        inner: store.clone(),
        requested: AtomicUsize::new(0),
    });
    let bounded = facade(counting.clone());
    assert_eq!(
        bounded
            .resolve(&scope, &vec![large_tokens[0].clone(); MAX_BATCH])
            .await,
        Err(Error::Capacity)
    );
    assert_eq!(
        counting.requested.load(Ordering::SeqCst),
        1,
        "duplicates reached the backend"
    );
    let ordered = bounded
        .resolve(
            &scope,
            &[
                large_tokens[0].clone(),
                tokens[0].clone(),
                large_tokens[0].clone(),
            ],
        )
        .await
        .unwrap();
    assert_eq!(
        ordered,
        vec![
            Some(large[0].1.clone()),
            Some(values[0].1.clone()),
            Some(large[0].1.clone())
        ]
    );
    assert_eq!(counting.requested.load(Ordering::SeqCst), 2);
    assert!(matches!(
        store
            .resolve(&scope, &vec![large_tokens[0].clone(); MAX_BATCH])
            .await,
        Err(Error::Capacity)
    ));
    assert_eq!(
        vault
            .intern(
                &scope,
                &[("PERSON".into(), "example person's".into())],
                Duration::from_secs(60)
            )
            .await
            .unwrap(),
        vec![tokens[0].clone()]
    );
    assert_eq!(
        vault
            .resolve(&scope, &vec!["unknown".into(); MAX_BATCH + 1])
            .await,
        Err(Error::Invalid)
    );
    let mut workers = tokio::task::JoinSet::new();
    for n in 0..16 {
        let replica = if n % 2 == 0 {
            vault.clone()
        } else {
            peer.clone()
        };
        let scope = scope.clone();
        workers.spawn(async move {
            for _ in 0..20 {
                match replica
                    .intern(
                        &scope,
                        &[("PERSON".into(), "Concurrent Fixture".into())],
                        Duration::from_secs(60),
                    )
                    .await
                {
                    Err(Error::Busy) => tokio::task::yield_now().await,
                    result => return result.unwrap()[0].clone(),
                }
            }
            panic!("contention did not converge")
        });
    }
    let mut concurrent_token = None;
    while let Some(result) = workers.join_next().await {
        let result = result.unwrap();
        if let Some(expected) = &concurrent_token {
            assert_eq!(&result, expected);
        } else {
            concurrent_token = Some(result);
        }
    }
    // Simulate response loss AFTER the durable commit. A peer retries without
    // the first replica's proposal or in-memory state and gets the same identity.
    let flaky = facade(Arc::new(LostResponse {
        inner: store.clone(),
        lose: AtomicBool::new(true),
    }));
    let retry_value = vec![("PERSON".into(), "Retry Fixture".into())];
    assert_eq!(
        flaky
            .intern(&scope, &retry_value, Duration::from_secs(60))
            .await,
        Err(Error::Unavailable)
    );
    let retried = flaky
        .intern(&scope, &retry_value, Duration::from_secs(60))
        .await
        .unwrap();
    assert_eq!(
        peer.intern(&scope, &retry_value, Duration::from_secs(60))
            .await
            .unwrap(),
        retried
    );

    let expiry_scope = vault
        .scope(
            "synthetic-tenant-one",
            "synthetic-owner-one",
            &format!("{context}-expiry"),
        )
        .unwrap();
    let expired = vault
        .intern(&expiry_scope, &values, Duration::from_millis(80))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        vault.resolve(&expiry_scope, &expired).await.unwrap(),
        vec![None, None]
    );
    assert_eq!(
        vault
            .intern(&expiry_scope, &values, Duration::from_secs(60))
            .await,
        Err(Error::Retired)
    );

    // Erasure races a new writer. Either the writer linearizes first and is
    // erased, or it observes retirement. Neither order permits resurrection.
    let race_values = [("PERSON".into(), "Race Fixture".into())];
    let (erased, writer) = tokio::join!(
        vault.retire(&scope),
        peer.intern(&scope, &race_values, Duration::from_secs(60))
    );
    erased.unwrap();
    assert!(writer.is_ok() || matches!(writer, Err(Error::Retired) | Err(Error::Busy)));
    vault.retire(&scope).await.unwrap();
    assert_eq!(
        peer.resolve(&scope, &tokens).await.unwrap(),
        vec![None, None]
    );
    assert_eq!(
        peer.intern(&scope, &values, Duration::from_secs(60)).await,
        Err(Error::Retired)
    );
    // Erasing an absent context also fences first creation.
    vault.retire(&foreign_owner).await.unwrap();
    assert_eq!(
        vault
            .intern(&foreign_owner, &values, Duration::from_secs(60))
            .await,
        Err(Error::Retired)
    );
    // A collision halfway through an intern must roll back the entire batch.
    let rollback_scope = vault
        .scope(
            "synthetic-tenant-one",
            "synthetic-owner-one",
            &format!("{context}-rollback"),
        )
        .unwrap();
    let entries: Vec<_> = (1..=2)
        .map(|n| Entry {
            fingerprint: format!("{n:064x}"),
            token: "[PERSON_collision_fixture]".into(),
            sealed: "opaque synthetic ciphertext".into(),
            expires_ms: chrono::Utc::now().timestamp_millis() + 60000,
        })
        .collect();
    assert!(matches!(
        store.intern(&rollback_scope, &entries).await,
        Err(Error::Integrity)
    ));
    let found = store
        .resolve(&rollback_scope, &[entries[0].token.clone()])
        .await
        .unwrap();
    assert!(
        found[0].is_none(),
        "failed batch leaked a partial allocation"
    );
}

struct TamperedExpiry {
    inner: Arc<dyn TokenStore>,
}

struct CountingResolve {
    inner: Arc<dyn TokenStore>,
    requested: AtomicUsize,
}
#[async_trait::async_trait]
impl TokenStore for CountingResolve {
    fn backend(&self) -> &'static str {
        "counting"
    }
    async fn intern(&self, s: &Scope, e: &[Entry]) -> Result<Vec<Entry>, Error> {
        self.inner.intern(s, e).await
    }
    async fn resolve(&self, s: &Scope, t: &[String]) -> Result<Vec<Option<Entry>>, Error> {
        self.requested.store(t.len(), Ordering::SeqCst);
        self.inner.resolve(s, t).await
    }
    async fn retire(&self, s: &Scope) -> Result<(), Error> {
        self.inner.retire(s).await
    }
}
#[async_trait::async_trait]
impl TokenStore for TamperedExpiry {
    fn backend(&self) -> &'static str {
        "fault_injection"
    }
    async fn intern(&self, scope: &Scope, entries: &[Entry]) -> Result<Vec<Entry>, Error> {
        self.inner.intern(scope, entries).await
    }
    async fn resolve(&self, scope: &Scope, tokens: &[String]) -> Result<Vec<Option<Entry>>, Error> {
        let mut entries = self.inner.resolve(scope, tokens).await?;
        for entry in entries.iter_mut().flatten() {
            entry.expires_ms += 1;
        }
        Ok(entries)
    }
    async fn retire(&self, scope: &Scope) -> Result<(), Error> {
        self.inner.retire(scope).await
    }
}

#[tokio::test]
async fn admission_and_deadline_fail_closed() {
    struct Pending {
        entered: tokio::sync::Notify,
    }
    #[async_trait::async_trait]
    impl TokenStore for Pending {
        fn backend(&self) -> &'static str {
            "pending"
        }
        async fn intern(&self, _: &Scope, _: &[Entry]) -> Result<Vec<Entry>, Error> {
            unreachable!()
        }
        async fn resolve(&self, _: &Scope, _: &[String]) -> Result<Vec<Option<Entry>>, Error> {
            self.entered.notify_one();
            std::future::pending().await
        }
        async fn retire(&self, _: &Scope) -> Result<(), Error> {
            unreachable!()
        }
    }
    let store = Arc::new(Pending {
        entered: tokio::sync::Notify::new(),
    });
    let vault = Arc::new(Vault::new(store.clone(), [7; 32], 1, Duration::from_millis(50)).unwrap());
    let scope = vault
        .scope("synthetic-tenant", "synthetic-owner", "principal-wide-v1")
        .unwrap();
    let peer = vault.clone();
    let peer_scope = scope.clone();
    let first =
        tokio::spawn(async move { peer.resolve(&peer_scope, &["[PERSON_1]".into()]).await });
    store.entered.notified().await;
    assert_eq!(
        vault.resolve(&scope, &["[PERSON_1]".into()]).await,
        Err(Error::Busy)
    );
    assert_eq!(first.await.unwrap(), Err(Error::Unavailable));
    assert_eq!(
        vault.resolve(&scope, &["[PERSON_1]".into()]).await,
        Err(Error::Unavailable)
    );
}

#[tokio::test]
async fn elapsed_deadline_cannot_return_a_ready_backend_result() {
    struct SlowReady;
    #[async_trait::async_trait]
    impl TokenStore for SlowReady {
        fn backend(&self) -> &'static str {
            "deadline_fixture"
        }
        async fn intern(&self, _: &Scope, _: &[Entry]) -> Result<Vec<Entry>, Error> {
            unreachable!()
        }
        async fn resolve(&self, _: &Scope, t: &[String]) -> Result<Vec<Option<Entry>>, Error> {
            // Simulate synchronous work in a ready future. timeout() alone
            // cannot preempt this; the facade must check its total deadline.
            std::thread::sleep(Duration::from_millis(10));
            Ok(vec![None; t.len()])
        }
        async fn retire(&self, _: &Scope) -> Result<(), Error> {
            unreachable!()
        }
    }
    let vault = Vault::new(Arc::new(SlowReady), [7; 32], 1, Duration::from_millis(1)).unwrap();
    let scope = vault
        .scope("synthetic-tenant", "synthetic-owner", "context")
        .unwrap();
    assert_eq!(
        vault.resolve(&scope, &["[PERSON_1]".into()]).await,
        Err(Error::Unavailable)
    );
}

struct LostResponse {
    inner: Arc<dyn TokenStore>,
    lose: AtomicBool,
}
#[async_trait::async_trait]
impl TokenStore for LostResponse {
    fn backend(&self) -> &'static str {
        "fault_injection"
    }
    async fn intern(&self, scope: &Scope, entries: &[Entry]) -> Result<Vec<Entry>, Error> {
        let result = self.inner.intern(scope, entries).await?;
        if self.lose.swap(false, Ordering::SeqCst) {
            Err(Error::Unavailable)
        } else {
            Ok(result)
        }
    }
    async fn resolve(&self, scope: &Scope, tokens: &[String]) -> Result<Vec<Option<Entry>>, Error> {
        self.inner.resolve(scope, tokens).await
    }
    async fn retire(&self, scope: &Scope) -> Result<(), Error> {
        self.inner.retire(scope).await
    }
}

#[tokio::test]
#[ignore = "requires isolated OpenBao: TOKEN_STORE_BAO_ADDR and TOKEN_STORE_BAO_TOKEN_FILE"]
async fn openbao_contract() {
    let token =
        std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE").unwrap()).unwrap();
    let store = redact_token_store::openbao::OpenBao::new(
        &std::env::var("TOKEN_STORE_BAO_ADDR").unwrap(),
        "secret",
        "contract",
        token.trim().into(),
        Duration::from_secs(5),
    )
    .unwrap();
    contract(Arc::new(store)).await;
}

#[tokio::test]
#[ignore = "requires isolated migrated PostgreSQL and non-owner TOKEN_STORE_PG_URL"]
async fn postgres_contract() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .acquire_timeout(Duration::from_secs(2))
        .connect(&std::env::var("TOKEN_STORE_PG_URL").unwrap())
        .await
        .unwrap();
    let store = redact_token_store::postgres::Postgres::new(pool.clone())
        .await
        .unwrap();
    contract(Arc::new(store)).await;
    // RLS denies a direct query with no tenant setting, even after pooled use.
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM redact_tokens_v1.entries")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(rows, 0);
    // Runtime role cannot bypass policy by addressing child partitions.
    assert!(sqlx::query("SELECT * FROM redact_tokens_v1.entries_p0")
        .fetch_all(&pool)
        .await
        .is_err());
}

#[test]
fn scopes_are_length_framed_and_principal_isolated() {
    struct Never;
    #[async_trait::async_trait]
    impl TokenStore for Never {
        fn backend(&self) -> &'static str {
            "never"
        }
        async fn intern(&self, _: &Scope, _: &[Entry]) -> Result<Vec<Entry>, Error> {
            unreachable!()
        }
        async fn resolve(&self, _: &Scope, _: &[String]) -> Result<Vec<Option<Entry>>, Error> {
            unreachable!()
        }
        async fn retire(&self, _: &Scope) -> Result<(), Error> {
            unreachable!()
        }
    }
    let vault = facade(Arc::new(Never));
    assert_ne!(
        vault.scope("ab", "c", "d").unwrap(),
        vault.scope("a", "bc", "d").unwrap()
    );
    assert_ne!(
        vault.scope("tenant", "one", "context").unwrap(),
        vault.scope("tenant", "two", "context").unwrap()
    );
    assert!(vault.scope("", "owner", "context").is_err());
}
