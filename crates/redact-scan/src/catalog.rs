// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Layer 0: `pg_catalog` / `information_schema` metadata. No user-table reads.

use sqlx::PgPool;

use crate::error::ScanError;
use crate::layers::ScanLayer;
use crate::report::{EvidenceClass, Finding};
use crate::score::{is_date_type, is_inet_type, is_json_type, is_textish, name_entity};

/// Catalog row for one column.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct ColumnMeta {
    /// Schema name.
    pub schema: String,
    /// Table / view name.
    pub table: String,
    /// Column name.
    pub column: String,
    /// `pg_type.typname`.
    pub udt: String,
    /// `pg_class.relkind` (`r`, `p`, `v`, `m`).
    pub relkind: String,
    /// Estimated live tuples (`0` if unknown).
    pub n_live_tup: i64,
    /// Column comment, if any.
    pub comment: Option<String>,
    /// Unique btree on this text-like column.
    pub unique_text: bool,
    /// Table has an FK toward a subject-like table.
    pub fk_to_subject: bool,
}

/// Load column metadata for `schema`. Never `SELECT`s user tables.
pub async fn load_columns(pool: &PgPool, schema: &str) -> Result<Vec<ColumnMeta>, ScanError> {
    let rows = sqlx::query_as::<_, ColumnMeta>(
        r#"
        SELECT
          n.nspname AS schema,
          c.relname AS table,
          a.attname AS column,
          t.typname AS udt,
          c.relkind::text AS relkind,
          COALESCE(s.n_live_tup, 0) AS n_live_tup,
          col_description(c.oid, a.attnum) AS comment,
          EXISTS (
            SELECT 1
            FROM pg_index i
            JOIN pg_attribute ia ON ia.attrelid = i.indrelid AND ia.attnum = ANY (i.indkey)
            WHERE i.indrelid = c.oid
              AND i.indisunique
              AND ia.attname = a.attname
              AND t.typname IN ('varchar', 'text', 'bpchar', 'citext')
          ) AS unique_text,
          EXISTS (
            SELECT 1
            FROM pg_constraint fk
            JOIN pg_class ref ON ref.oid = fk.confrelid
            WHERE fk.conrelid = c.oid
              AND fk.contype = 'f'
              AND (
                ref.relname ILIKE '%user%'
                OR ref.relname ILIKE '%customer%'
                OR ref.relname ILIKE '%subject%'
                OR ref.relname ILIKE '%patient%'
                OR ref.relname ILIKE '%account%'
              )
          ) AS fk_to_subject
        FROM pg_attribute a
        JOIN pg_class c ON c.oid = a.attrelid
        JOIN pg_namespace n ON n.oid = c.relnamespace
        JOIN pg_type t ON t.oid = a.atttypid
        LEFT JOIN pg_stat_user_tables s ON s.relid = c.oid
        WHERE n.nspname = $1
          AND a.attnum > 0
          AND NOT a.attisdropped
          AND c.relkind IN ('r', 'p', 'v', 'm')
        ORDER BY c.relname, a.attnum
        "#,
    )
    .bind(schema)
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

/// Emit L0 findings from names and native types. JSON/unconstrained text
/// without a name match are candidates only.
pub fn l0_findings(columns: &[ColumnMeta]) -> Vec<Finding> {
    let mut out = Vec::new();
    for col in columns {
        let table = format!("{}.{}", col.schema, col.table);
        if let Some((entity_type, confidence)) = name_entity(&col.column) {
            out.push(Finding {
                table,
                column: col.column.clone(),
                json_path: None,
                entity_type,
                layer: ScanLayer::Metadata,
                match_count: 0,
                sampled_rows: 0,
                confidence,
                evidence_class: EvidenceClass::NameHeuristic,
            });
            continue;
        }
        if is_inet_type(&col.udt) {
            out.push(Finding {
                table,
                column: col.column.clone(),
                json_path: None,
                entity_type: redact_core::EntityType::IpAddress,
                layer: ScanLayer::Metadata,
                match_count: 0,
                sampled_rows: 0,
                confidence: 0.8,
                evidence_class: EvidenceClass::TypeSignal,
            });
        }
        let _ = (
            col.unique_text,
            col.fk_to_subject,
            is_json_type(&col.udt),
            is_textish(&col.udt),
            is_date_type(&col.udt),
            &col.comment,
        );
    }
    out
}

/// Columns worth examining in later layers.
pub fn candidates<'a>(columns: &'a [ColumnMeta], findings: &[Finding]) -> Vec<&'a ColumnMeta> {
    columns
        .iter()
        .filter(|c| {
            if is_json_type(&c.udt) || is_inet_type(&c.udt) || is_textish(&c.udt) {
                return true;
            }
            if c.unique_text || c.fk_to_subject {
                return true;
            }
            let q = format!("{}.{}", c.schema, c.table);
            findings
                .iter()
                .any(|f| f.table == q && f.column == c.column)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn col(name: &str, udt: &str) -> ColumnMeta {
        ColumnMeta {
            schema: "public".into(),
            table: "t".into(),
            column: name.into(),
            udt: udt.into(),
            relkind: "r".into(),
            n_live_tup: 10,
            comment: None,
            unique_text: false,
            fk_to_subject: false,
        }
    }

    #[test]
    fn name_match_is_finding_json_is_candidate_only() {
        let cols = vec![
            col("email", "text"),
            col("payload", "jsonb"),
            col("n", "int4"),
        ];
        let findings = l0_findings(&cols);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].column, "email");
        let cand = candidates(&cols, &findings);
        assert!(cand.iter().any(|c| c.column == "payload"));
        assert!(cand.iter().all(|c| c.column != "n"));
    }

    #[test]
    fn inet_without_name_is_type_signal() {
        let cols = vec![col("src", "inet")];
        let findings = l0_findings(&cols);
        assert_eq!(findings[0].evidence_class, EvidenceClass::TypeSignal);
    }
}
