// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Scan orchestration for layers 0 and 0.5.

use chrono::Utc;
use uuid::Uuid;

use crate::canonical::hex_sha256;
use crate::catalog::{candidates, l0_findings, load_columns};
use crate::cli::Cli;
use crate::detect::pattern_pack_label;
use crate::error::ScanError;
use crate::layers::ScanLayer;
use crate::report::{Finding, Sampling, ScanReport, Scanner, Target};
use crate::safety::{connect_readonly, host_db_from_url};
use crate::stats::l05_findings;

/// Run the selected layers and return a finalized report.
pub async fn run_scan(cli: &Cli) -> Result<ScanReport, ScanError> {
    let url = cli
        .url
        .as_deref()
        .ok_or_else(|| ScanError::new("--url is required to scan"))?;
    let layers = cli.parsed_layers().map_err(ScanError::new)?;
    let timeout = cli.statement_timeout().map_err(ScanError::new)?;
    let (host, database) = host_db_from_url(url)?;
    let fingerprint = fingerprint(&host, &database, &cli.schema);
    drop(host);

    let safe = connect_readonly(url, timeout, &cli.schema).await?;
    let version: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&safe.pool)
        .await
        .map_err(|e| safe.scrub(e))?;

    let columns = load_columns(&safe.pool, &cli.schema)
        .await
        .map_err(|e| safe.scrub(e))?;

    let mut findings: Vec<Finding> = Vec::new();
    if layers.contains(&ScanLayer::Metadata) {
        findings.extend(l0_findings(&columns));
    }
    let cand = candidates(&columns, &findings);
    if layers.contains(&ScanLayer::Stats) {
        findings.extend(l05_findings(&safe.pool, &cli.schema, &cand).await?);
    }
    if layers.contains(&ScanLayer::Sample) || layers.contains(&ScanLayer::Json) {
        tracing::warn!("layers 1 and 2 are not implemented in this revision");
    }

    findings = dedup_findings(findings);

    let report = ScanReport {
        scan_id: Uuid::new_v4(),
        scanned_at: Utc::now(),
        target: Target {
            fingerprint,
            engine: "postgres".into(),
            version,
        },
        scanner: Scanner {
            version: env!("CARGO_PKG_VERSION").into(),
            pattern_pack: pattern_pack_label(),
        },
        sampling: Sampling {
            layers,
            rows_per_column: cli.sample_rows,
            method: "TABLESAMPLE SYSTEM".into(),
        },
        findings,
        content_hash: String::new(),
    };
    report.finalize().map_err(ScanError::new)
}

fn fingerprint(host: &str, database: &str, schema: &str) -> String {
    hex_sha256(format!("{host}|{database}|{schema}").as_bytes())
}

fn dedup_findings(mut findings: Vec<Finding>) -> Vec<Finding> {
    findings.sort_by(|a, b| {
        a.table
            .cmp(&b.table)
            .then(a.column.cmp(&b.column))
            .then(a.json_path.cmp(&b.json_path))
            .then(a.entity_type.as_str().cmp(b.entity_type.as_str()))
    });
    findings.dedup_by(|a, b| {
        a.table == b.table
            && a.column == b.column
            && a.json_path == b.json_path
            && a.entity_type == b.entity_type
    });
    findings
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::EvidenceClass;
    use redact_core::EntityType;

    #[test]
    fn fingerprint_is_hex_and_stable() {
        let a = fingerprint("db.example", "app", "public");
        let b = fingerprint("db.example", "app", "public");
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, fingerprint("other", "app", "public"));
    }

    #[test]
    fn dedup_keeps_one_row_per_location_type() {
        let f = Finding {
            table: "public.t".into(),
            column: "c".into(),
            json_path: None,
            entity_type: EntityType::EmailAddress,
            layer: ScanLayer::Metadata,
            match_count: 0,
            sampled_rows: 0,
            confidence: 0.8,
            evidence_class: EvidenceClass::NameHeuristic,
        };
        let out = dedup_findings(vec![f.clone(), f]);
        assert_eq!(out.len(), 1);
    }
}
