// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Layer 0.5: `pg_stats` most-common values and histogram bounds.

use sqlx::PgPool;

use crate::catalog::ColumnMeta;
use crate::detect::detect_types;
use crate::error::ScanError;
use crate::layers::ScanLayer;
use crate::report::{EvidenceClass, Finding};

/// Scan planner statistics. Never echoes MCV / histogram values into findings.
pub async fn l05_findings(
    pool: &PgPool,
    schema: &str,
    candidates: &[&ColumnMeta],
) -> Result<Vec<Finding>, ScanError> {
    let rows = sqlx::query_as::<_, (String, String, Option<String>, Option<String>, Option<f32>)>(
        r#"
        SELECT tablename, attname,
               most_common_vals::text,
               histogram_bounds::text,
               n_distinct
        FROM pg_stats
        WHERE schemaname = $1
        "#,
    )
    .bind(schema)
    .fetch_all(pool)
    .await;
    let rows = match rows {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!("layer 0.5 skipped (pg_stats unavailable): {e}");
            return Ok(Vec::new());
        }
    };

    let wanted: std::collections::HashSet<(&str, &str)> = candidates
        .iter()
        .map(|c| (c.table.as_str(), c.column.as_str()))
        .collect();

    let mut out = Vec::new();
    for (table, column, mcv, hist, _n_distinct) in rows {
        if !wanted.contains(&(table.as_str(), column.as_str())) {
            continue;
        }
        let mut texts = Vec::new();
        if let Some(v) = mcv {
            texts.push(v);
        }
        if let Some(v) = hist {
            texts.push(v);
        }
        if texts.is_empty() {
            continue;
        }
        let blob = texts.join(" ");
        let hits = detect_types(&blob);
        drop(blob);
        drop(texts);
        if hits.is_empty() {
            continue;
        }
        let sampled = hits.len() as u64;
        let (entity_type, confidence) = hits
            .into_iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .expect("hits non-empty");
        out.push(Finding {
            table: format!("{schema}.{table}"),
            column,
            json_path: None,
            entity_type,
            layer: ScanLayer::Stats,
            match_count: sampled,
            sampled_rows: sampled,
            confidence,
            evidence_class: EvidenceClass::PgStats,
        });
    }
    Ok(out)
}
