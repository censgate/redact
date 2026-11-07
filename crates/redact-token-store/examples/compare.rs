//! Synthetic storage-only comparison; never contacts a deployed gateway.
use redact_token_store::{Error, TokenStore, Vault};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let worker = std::env::var("TOKEN_STORE_BENCH_WORKER").unwrap_or_else(|_| "0".into());
    println!("backend,worker,initial_context_size,start_records,batch,concurrency,operation,samples,p50_us,p95_us,p99_us,ops_per_second,errors");
    for backend in ["postgres", "openbao"] {
        let store: Arc<dyn TokenStore> = if backend == "postgres" {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(8)
                .acquire_timeout(Duration::from_secs(2))
                .connect(&std::env::var("TOKEN_STORE_PG_URL")?)
                .await?;
            Arc::new(redact_token_store::postgres::Postgres::new(pool).await?)
        } else {
            let token = std::fs::read_to_string(std::env::var("TOKEN_STORE_BAO_TOKEN_FILE")?)?;
            Arc::new(redact_token_store::openbao::OpenBao::new(
                &std::env::var("TOKEN_STORE_BAO_ADDR")?,
                "secret",
                "bench",
                token.trim().into(),
                Duration::from_secs(5),
            )?)
        };
        for size in [10, 1000, 10000] {
            let vault = Arc::new(Vault::new(
                store.clone(),
                [19; 32],
                32,
                Duration::from_secs(10),
            )?);
            let context = format!("synthetic-bench-{worker}-{size}-{}", uuid::Uuid::new_v4());
            let scope = vault.scope(
                "synthetic-benchmark-tenant",
                "synthetic-benchmark-principal",
                &context,
            )?;
            let mut tokens = vec![];
            let mut capacity = false;
            for start in (0..size).step_by(128) {
                let values: Vec<_> = (start..(start + 128).min(size))
                    .map(|n| {
                        (
                            "EMAIL_ADDRESS".into(),
                            format!("fixture-{n}@example.invalid"),
                        )
                    })
                    .collect();
                match vault
                    .intern(&scope, &values, Duration::from_secs(3600))
                    .await
                {
                    Ok(t) => tokens.extend(t),
                    Err(Error::Capacity) => {
                        capacity = true;
                        break;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
            if capacity {
                println!(
                    "{backend},{worker},{size},{},0,0,setup_capacity,0,0,0,0,0,1",
                    tokens.len()
                );
                retire_to_completion(&vault, &scope).await?;
                continue;
            }
            let mut current_records = size;
            for batch in [1, 8] {
                for concurrency in [1, 8] {
                    for operation in ["resolve", "reuse", "new"] {
                        let started = Instant::now();
                        let mut tasks = tokio::task::JoinSet::new();
                        for lane in 0..concurrency {
                            let vault = vault.clone();
                            let scope = scope.clone();
                            let refs = tokens[..batch].to_vec();
                            tasks.spawn(async move {
                                let mut samples = Vec::new(); let mut errors = 0;
                                for iteration in 0..32 {
                                    let started = Instant::now();
                                    let result = match operation {
                                        "resolve" => vault.resolve(&scope, &refs).await.map(|_| ()),
                                        "reuse" => {
                                            let values: Vec<_> = (0..batch).map(|n| ("EMAIL_ADDRESS".into(), format!("fixture-{n}@example.invalid"))).collect();
                                            vault.intern(&scope, &values, Duration::from_secs(3600)).await.map(|_| ())
                                        },
                                        _ => {
                                            let values: Vec<_> = (0..batch).map(|n| ("EMAIL_ADDRESS".into(), format!("new-{batch}-{concurrency}-{lane}-{iteration}-{n}@example.invalid"))).collect();
                                            vault.intern(&scope, &values, Duration::from_secs(3600)).await.map(|_| ())
                                        }
                                    };
                                    if result.is_err() { errors += 1; } else {
                                        samples.push(started.elapsed().as_micros() as u64);
                                    }
                                }
                                (samples, errors)
                            });
                        }
                        let mut samples = vec![];
                        let mut errors = 0;
                        while let Some(result) = tasks.join_next().await {
                            let (mut times, count) = result?;
                            samples.append(&mut times);
                            errors += count;
                        }
                        let elapsed = started.elapsed().as_secs_f64();
                        samples.sort_unstable();
                        let percentile = |p: usize| {
                            if samples.is_empty() {
                                0
                            } else {
                                samples[(samples.len() - 1) * p / 100]
                            }
                        };
                        println!("{backend},{worker},{size},{current_records},{batch},{concurrency},{operation},{},{},{},{},{:.1},{errors}", samples.len(), percentile(50), percentile(95), percentile(99), samples.len() as f64/elapsed);
                        if operation == "new" {
                            current_records += samples.len() * batch;
                        }
                    }
                }
            }
            retire_to_completion(&vault, &scope).await?;
        }
    }
    Ok(())
}

async fn retire_to_completion(
    vault: &redact_token_store::Vault,
    scope: &redact_token_store::Scope,
) -> anyhow::Result<()> {
    for _ in 0..64 {
        match vault.retire(scope).await {
            Ok(()) => return Ok(()),
            Err(redact_token_store::Error::Busy) => tokio::task::yield_now().await,
            Err(error) => return Err(error.into()),
        }
    }
    anyhow::bail!("bounded retirement did not complete")
}
