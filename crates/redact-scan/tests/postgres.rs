//! Postgres acceptance tests. Skipped unless `REDACT_SCAN_INTEGRATION=1`.

mod support;

use clap::Parser;
use redact_scan::cli::Cli;
use redact_scan::layers::ScanLayer;
use redact_scan::run_scan;
use redact_scan::safety::connect_readonly;
use sqlx::postgres::PgPoolOptions;
use std::time::{Duration, Instant};
use support::fixture::{self, Fixture};
use testcontainers_modules::postgres::Postgres;
use testcontainers_modules::testcontainers::runners::AsyncRunner;
use testcontainers_modules::testcontainers::ImageExt;

fn enabled() -> bool {
    std::env::var("REDACT_SCAN_INTEGRATION").ok().as_deref() == Some("1")
}

fn seed() -> u64 {
    std::env::var("REDACT_SCAN_FIXTURE_SEED")
        .ok()
        .and_then(|s| {
            s.strip_prefix("0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok())
                .or_else(|| s.parse().ok())
        })
        .unwrap_or_else(rand::random)
}

async fn start_postgres() -> (
    testcontainers_modules::testcontainers::ContainerAsync<Postgres>,
    String,
    String,
) {
    let container = Postgres::default()
        .with_tag("16-alpine")
        .with_cmd([
            "postgres",
            "-c",
            "shared_preload_libraries=pg_stat_statements",
        ])
        .start()
        .await
        .expect("start postgres");
    let host = container.get_host().await.expect("host").to_string();
    let port = container.get_host_port_ipv4(5432).await.expect("port");
    let admin = format!("postgres://postgres:postgres@{host}:{port}/postgres");
    let scanner = format!("postgres://scanner:scan-pass-not-super@{host}:{port}/postgres");
    (container, admin, scanner)
}

async fn admin_pool(url: &str) -> sqlx::PgPool {
    PgPoolOptions::new()
        .max_connections(2)
        .connect(url)
        .await
        .expect("admin connect")
}

async fn prepare_roles(admin: &sqlx::PgPool) {
    sqlx::query("CREATE EXTENSION IF NOT EXISTS pg_stat_statements")
        .execute(admin)
        .await
        .expect("pg_stat_statements");
    sqlx::query(
        "CREATE ROLE scanner LOGIN PASSWORD 'scan-pass-not-super' NOSUPERUSER NOCREATEDB NOCREATEROLE",
    )
    .execute(admin)
    .await
    .expect("create scanner");
    sqlx::query("GRANT USAGE ON SCHEMA public TO scanner")
        .execute(admin)
        .await
        .expect("grant usage");
    sqlx::query("GRANT pg_read_all_stats TO scanner")
        .execute(admin)
        .await
        .ok();
}

async fn grant_select(admin: &sqlx::PgPool) {
    sqlx::query("GRANT SELECT ON ALL TABLES IN SCHEMA public TO scanner")
        .execute(admin)
        .await
        .expect("grant select");
}

fn scan_cli(url: &str, layers: &str) -> Cli {
    Cli::parse_from([
        "redact-scan",
        "--url",
        url,
        "--schema",
        "public",
        "--layers",
        layers,
        "--sample-rows",
        "200",
    ])
}

#[tokio::test]
async fn acceptance_randomized_fixture() {
    if !enabled() {
        eprintln!("skipping: set REDACT_SCAN_INTEGRATION=1");
        return;
    }
    let seed = seed();
    eprintln!("redact-scan fixture seed={seed:#x}");
    let (_c, admin_url, scanner_url) = start_postgres().await;
    let admin = admin_pool(&admin_url).await;
    prepare_roles(&admin).await;

    let (fx, stmts) = Fixture::generate(seed);
    fixture::apply(&admin, &stmts).await.expect("apply fixture");
    sqlx::query("ANALYZE")
        .execute(&admin)
        .await
        .expect("analyze");
    grant_select(&admin).await;
    sqlx::query("SELECT pg_stat_statements_reset()")
        .execute(&admin)
        .await
        .ok();

    let super_err = run_scan(&scan_cli(&admin_url, "0,0.5"))
        .await
        .expect_err("superuser must be refused");
    assert!(
        super_err
            .to_string()
            .to_ascii_lowercase()
            .contains("superuser"),
        "{super_err}"
    );

    let l05 = run_scan(&scan_cli(&scanner_url, "0,0.5"))
        .await
        .expect("l0+l0.5");
    let found: Vec<(String, String)> = l05
        .findings
        .iter()
        .map(|f| {
            let table = f.table.rsplit('.').next().unwrap_or(&f.table).to_string();
            (table, f.column.clone())
        })
        .collect();
    let pii_hits = fx
        .pii
        .iter()
        .filter(|p| found.iter().any(|f| f == *p))
        .count();
    assert!(
        pii_hits * 5 >= fx.pii.len() * 4,
        "L0+L0.5 found {pii_hits}/{} PII columns: {found:?}",
        fx.pii.len()
    );
    for c in &fx.clean {
        assert!(
            !found.iter().any(|f| f == c),
            "clean column {}.{} appeared in L0+L0.5",
            c.0,
            c.1
        );
    }

    let queries: Vec<String> = sqlx::query_scalar("SELECT query FROM pg_stat_statements")
        .fetch_all(&admin)
        .await
        .unwrap_or_default();
    for (table, _) in fx.pii.iter().chain(fx.clean.iter()) {
        for q in &queries {
            let lower = q.to_ascii_lowercase();
            if lower.contains(&format!("from {table}"))
                || lower.contains(&format!("from public.{table}"))
                || lower.contains(&format!("from \"{table}\""))
            {
                panic!("L0+L0.5 issued user-table SELECT: {q}");
            }
        }
    }

    let full = run_scan(&scan_cli(&scanner_url, "0,0.5,1,2"))
        .await
        .expect("full scan");
    let full_found: Vec<(String, String)> = full
        .findings
        .iter()
        .map(|f| {
            let table = f.table.rsplit('.').next().unwrap_or(&f.table).to_string();
            (table, f.column.clone())
        })
        .collect();
    for p in &fx.pii {
        assert!(
            full_found.iter().any(|f| f == p),
            "missing PII column {}.{}",
            p.0,
            p.1
        );
    }
    for c in &fx.clean {
        assert!(
            !full_found.iter().any(|f| f == c),
            "clean column {}.{} produced a finding",
            c.0,
            c.1
        );
    }

    let json = serde_json::to_string(&full).expect("json");
    for secret in &fx.secret_values {
        assert!(
            !json.contains(secret),
            "report leaked fixture value {secret}"
        );
    }
}

#[tokio::test]
async fn bad_password_is_scrubbed() {
    if !enabled() {
        eprintln!("skipping: set REDACT_SCAN_INTEGRATION=1");
        return;
    }
    let (_c, admin_url, _) = start_postgres().await;
    let secret = "super-secret-db-pass";
    let bad = admin_url.replace("postgres:postgres", &format!("postgres:{secret}"));
    let err = match connect_readonly(&bad, Duration::from_secs(5), "public").await {
        Ok(_) => panic!("auth should fail"),
        Err(e) => e,
    };
    let shown = format!("{err}");
    let debug = format!("{err:?}");
    assert!(!shown.contains(secret), "{shown}");
    assert!(!debug.contains(secret), "{debug}");
}

#[tokio::test]
async fn five_hundred_tables_l0_l05_under_ten_seconds() {
    if !enabled() {
        eprintln!("skipping: set REDACT_SCAN_INTEGRATION=1");
        return;
    }
    let (_c, admin_url, scanner_url) = start_postgres().await;
    let admin = admin_pool(&admin_url).await;
    prepare_roles(&admin).await;
    for i in 0..500 {
        sqlx::query(&format!(
            "CREATE TABLE t_bulk_{i} (id int, note text, email text)"
        ))
        .execute(&admin)
        .await
        .expect("create");
    }
    grant_select(&admin).await;
    let start = Instant::now();
    let report = run_scan(&scan_cli(&scanner_url, "0,0.5"))
        .await
        .expect("bulk scan");
    let elapsed = start.elapsed();
    assert!(
        elapsed < Duration::from_secs(10),
        "L0+L0.5 on 500 tables took {elapsed:?}"
    );
    assert!(report.sampling.layers.contains(&ScanLayer::Metadata));
}
