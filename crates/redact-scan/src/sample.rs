// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Layer 1: bounded `TABLESAMPLE SYSTEM` of candidate columns.

use sqlx::PgPool;

use crate::catalog::ColumnMeta;
use crate::detect::detect_types;
use crate::error::ScanError;
use crate::ident::{qualify_table, quote_ident};
use crate::layers::ScanLayer;
use crate::report::{EvidenceClass, Finding};

/// Sample ordinary tables only (`relkind` `r`/`p`). Views are skipped.
pub async fn l1_findings(
    pool: &PgPool,
    columns: &[&ColumnMeta],
    sample_rows: u32,
) -> Result<Vec<Finding>, ScanError> {
    let mut out = Vec::new();
    for col in columns {
        if col.relkind != "r" && col.relkind != "p" {
            continue;
        }
        if crate::score::is_json_type(&col.udt) {
            continue;
        }
        if let Some(finding) = sample_column(pool, col, sample_rows).await? {
            out.push(finding);
        }
    }
    Ok(out)
}

/// `TABLESAMPLE` percent: `clamp(1, 100, 200 * sample_rows / n_live_tup)`.
pub fn tablesample_percent(n_live_tup: u64, sample_rows: u32) -> f64 {
    if n_live_tup == 0 {
        return 1.0;
    }
    (200.0 * f64::from(sample_rows) / n_live_tup as f64).clamp(1.0, 100.0)
}

async fn sample_column(
    pool: &PgPool,
    col: &ColumnMeta,
    sample_rows: u32,
) -> Result<Option<Finding>, ScanError> {
    let table = qualify_table(&col.schema, &col.table).map_err(ScanError::new)?;
    let column = quote_ident(&col.column).map_err(ScanError::new)?;
    let n = col.n_live_tup.max(0) as u64;
    let limit = i64::from(sample_rows.max(1));
    let sql = if n > 0 && n <= u64::from(sample_rows) {
        format!("SELECT {column}::text FROM {table} LIMIT {limit}")
    } else {
        let pct = (tablesample_percent(n, sample_rows) * 100.0).round() / 100.0;
        format!("SELECT {column}::text FROM {table} TABLESAMPLE SYSTEM ({pct}) LIMIT {limit}")
    };

    let values: Vec<Option<String>> = sqlx::query_scalar(&sql)
        .fetch_all(pool)
        .await
        .map_err(ScanError::new)?;
    let sampled = values.len() as u64;
    if sampled == 0 {
        return Ok(None);
    }

    let mut match_count = 0u64;
    let mut best: Option<(redact_core::EntityType, f32)> = None;
    for v in values.into_iter().flatten() {
        let hits = detect_types(&v);
        if hits.is_empty() {
            continue;
        }
        match_count += 1;
        for (ty, score) in hits {
            match &best {
                Some((_, s)) if *s >= score => {}
                _ => best = Some((ty, score)),
            }
        }
    }
    let Some((entity_type, confidence)) = best else {
        return Ok(None);
    };
    Ok(Some(Finding {
        table: format!("{}.{}", col.schema, col.table),
        column: col.column.clone(),
        json_path: None,
        entity_type,
        layer: ScanLayer::Sample,
        match_count,
        sampled_rows: sampled,
        confidence,
        evidence_class: EvidenceClass::TableSample,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percent_clamps_and_never_uses_full_random_order() {
        assert_eq!(tablesample_percent(0, 1000), 1.0);
        assert!((tablesample_percent(10_000, 1000) - 20.0).abs() < 1e-9);
        assert_eq!(tablesample_percent(100, 1000), 100.0);
    }
}
