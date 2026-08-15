// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use chrono::{DateTime, Utc};
use redact_core::EntityType;
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use uuid::Uuid;

use crate::canonical::content_hash;
use crate::layers::ScanLayer;

/// How a finding was produced. Never carries a matched value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    /// Column or table name matched a known PII token.
    NameHeuristic,
    /// Native column type (for example `inet`) implied an entity.
    TypeSignal,
    /// Unique index on text-like data (candidate boost only).
    UniqueIndex,
    /// Foreign key toward a subject-like table (candidate boost only).
    FkTopology,
    /// Planner statistics (`most_common_vals` / `histogram_bounds`).
    PgStats,
    /// Bounded table sample.
    TableSample,
    /// JSON document path sample.
    JsonPath,
}

/// A PII location. This type must not grow a field that can hold a sample value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    /// Qualified table name (`schema.table`).
    pub table: String,
    /// Column name.
    pub column: String,
    /// JSON path for layer 2 findings (`$.customer.email`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_path: Option<String>,
    /// Detected entity type (SCREAMING_SNAKE_CASE in JSON).
    pub entity_type: EntityType,
    /// Layer that produced the finding.
    pub layer: ScanLayer,
    /// How many sampled cells matched. Zero for metadata-only findings.
    pub match_count: u64,
    /// How many cells were examined. Zero for metadata-only findings.
    pub sampled_rows: u64,
    /// Detector or heuristic confidence in `0.0..=1.0`.
    pub confidence: f32,
    /// Why this location was reported.
    pub evidence_class: EvidenceClass,
}

/// Hashed scan target. Never a connection string or hostname.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    /// `sha256(host|database|schema)` hex digest.
    pub fingerprint: String,
    /// Database engine (`postgres`).
    pub engine: String,
    /// Server version string from the engine.
    pub version: String,
}

/// Scanner identity recorded in the report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scanner {
    /// `CARGO_PKG_VERSION` of `redact-scan`.
    pub version: String,
    /// Built-in pattern pack label (`builtin@<count>`).
    pub pattern_pack: String,
}

/// Sampling configuration used for the run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sampling {
    /// Layers that were selected.
    pub layers: Vec<ScanLayer>,
    /// `--sample-rows` limit.
    pub rows_per_column: u32,
    /// Sampling method (`TABLESAMPLE SYSTEM`).
    pub method: String,
}

/// Value-free scan report. `content_hash` is computed after the other fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    /// Random identifier for this run.
    pub scan_id: Uuid,
    /// UTC timestamp when the report was assembled.
    pub scanned_at: DateTime<Utc>,
    /// Hashed target identity.
    pub target: Target,
    /// Scanner version and pattern pack.
    pub scanner: Scanner,
    /// Selected layers and sample size.
    pub sampling: Sampling,
    /// Locations only — never values.
    pub findings: Vec<Finding>,
    /// SHA-256 of canonical JSON with this field omitted.
    pub content_hash: String,
}

impl ScanReport {
    /// Fill [`ScanReport::content_hash`] from the other fields.
    pub fn finalize(mut self) -> Result<Self, anyhow::Error> {
        self.content_hash.clear();
        self.content_hash = content_hash(&self)?;
        Ok(self)
    }
}

/// Local debug samples. Never serialized into [`ScanReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSamples {
    /// Scan that produced the sidecar file.
    pub scan_id: Uuid,
    /// Operator note. Must not be merged into [`ScanReport`].
    pub notes: String,
    /// Local previews. Never copied into [`ScanReport`].
    pub samples: Vec<DebugSample>,
}

/// One local debug preview. Sidecar only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSample {
    /// Qualified table name.
    pub table: String,
    /// Column name.
    pub column: String,
    /// JSON path when the preview came from layer 2.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_path: Option<String>,
    /// Truncated cell text. Sidecar only.
    pub preview: String,
}

thread_local! {
    static SAMPLE_SINK: RefCell<Option<Vec<DebugSample>>> = const { RefCell::new(None) };
}

/// Start collecting sidecar previews for `--include-samples`.
pub fn enable_sample_sink() {
    SAMPLE_SINK.with(|s| *s.borrow_mut() = Some(Vec::new()));
}

/// Record a sidecar preview. No-op unless [`enable_sample_sink`] was called.
pub fn record_sample(table: &str, column: &str, json_path: Option<&str>, preview: &str) {
    SAMPLE_SINK.with(|s| {
        if let Some(buf) = s.borrow_mut().as_mut() {
            if buf.len() >= 32 {
                return;
            }
            let preview: String = preview.chars().take(64).collect();
            buf.push(DebugSample {
                table: table.into(),
                column: column.into(),
                json_path: json_path.map(str::to_string),
                preview,
            });
        }
    });
}

/// Take collected sidecar previews.
pub fn take_samples() -> Vec<DebugSample> {
    SAMPLE_SINK.with(|s| s.borrow_mut().take().unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finding_json_has_no_value_keys() {
        let f = Finding {
            table: "public.t".into(),
            column: "c".into(),
            json_path: None,
            entity_type: EntityType::EmailAddress,
            layer: ScanLayer::Sample,
            match_count: 1,
            sampled_rows: 10,
            confidence: 0.9,
            evidence_class: EvidenceClass::TableSample,
        };
        let s = serde_json::to_string(&f).unwrap();
        let value: serde_json::Value = serde_json::from_str(&s).unwrap();
        let keys = object_keys(&value);
        for banned in ["value", "sample", "text", "most_common"] {
            assert!(
                !keys.iter().any(|k| k == banned),
                "finding JSON unexpectedly contains key {banned}: {s}"
            );
        }
    }

    fn object_keys(value: &serde_json::Value) -> Vec<String> {
        match value {
            serde_json::Value::Object(map) => {
                let mut keys: Vec<String> = map.keys().cloned().collect();
                for v in map.values() {
                    keys.extend(object_keys(v));
                }
                keys
            }
            serde_json::Value::Array(items) => items.iter().flat_map(object_keys).collect(),
            _ => Vec::new(),
        }
    }
}
