// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Layer 2: JSON/JSONB path sampling.

use serde_json::Value;
use sqlx::PgPool;
use std::collections::BTreeMap;

use crate::catalog::ColumnMeta;
use crate::detect::detect_types;
use crate::error::ScanError;
use crate::ident::{qualify_table, quote_ident};
use crate::layers::ScanLayer;
use crate::report::{EvidenceClass, Finding};
use crate::score::is_json_type;

/// Sample JSON columns and emit path-level findings. Values are dropped.
pub async fn l2_findings(
    pool: &PgPool,
    columns: &[&ColumnMeta],
    sample_rows: u32,
) -> Result<Vec<Finding>, ScanError> {
    let mut out = Vec::new();
    for col in columns {
        if !is_json_type(&col.udt) {
            continue;
        }
        if col.relkind != "r" && col.relkind != "p" {
            continue;
        }
        out.extend(scan_json_column(pool, col, sample_rows).await?);
    }
    Ok(out)
}

async fn scan_json_column(
    pool: &PgPool,
    col: &ColumnMeta,
    sample_rows: u32,
) -> Result<Vec<Finding>, ScanError> {
    let table = qualify_table(&col.schema, &col.table).map_err(ScanError::new)?;
    let column = quote_ident(&col.column).map_err(ScanError::new)?;
    let limit = i64::from(sample_rows.max(1));
    let sql = format!("SELECT {column}::text FROM {table} LIMIT {limit}");
    let docs: Vec<Option<String>> = sqlx::query_scalar(&sql)
        .fetch_all(pool)
        .await
        .map_err(ScanError::new)?;

    let mut by_path: BTreeMap<String, (u64, u64, redact_core::EntityType, f32)> = BTreeMap::new();
    let mut sampled_docs = 0u64;
    for raw in docs.into_iter().flatten() {
        sampled_docs += 1;
        let Ok(value) = serde_json::from_str::<Value>(&raw) else {
            continue;
        };
        let mut paths = Vec::new();
        walk(&value, "$", &mut paths);
        for (path, text) in paths {
            let hits = detect_types(&text);
            if hits.is_empty() {
                continue;
            }
            let (ty, score) = hits
                .into_iter()
                .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                .expect("hits non-empty");
            let entry = by_path.entry(path).or_insert((0, 0, ty.clone(), score));
            entry.0 += 1;
            entry.1 = sampled_docs;
            if score > entry.3 {
                entry.2 = ty;
                entry.3 = score;
            }
        }
    }

    Ok(by_path
        .into_iter()
        .map(
            |(json_path, (match_count, sampled_rows, entity_type, confidence))| Finding {
                table: format!("{}.{}", col.schema, col.table),
                column: col.column.clone(),
                json_path: Some(json_path),
                entity_type,
                layer: ScanLayer::Json,
                match_count,
                sampled_rows,
                confidence,
                evidence_class: EvidenceClass::JsonPath,
            },
        )
        .collect())
}

fn walk(value: &Value, path: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Number(n) => out.push((path.to_string(), n.to_string())),
        Value::Object(map) => {
            for (k, v) in map {
                let child = format!("{path}.{k}");
                walk(v, &child, out);
            }
        }
        Value::Array(items) => {
            for (i, v) in items.iter().enumerate() {
                let child = format!("{path}[{i}]");
                walk(v, &child, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walks_nested_paths() {
        let v = serde_json::json!({"customer":{"email":"a@b.c"},"n":1});
        let mut paths = Vec::new();
        walk(&v, "$", &mut paths);
        assert!(paths.iter().any(|(p, _)| p == "$.customer.email"));
        assert!(paths.iter().any(|(p, _)| p == "$.n"));
    }
}
