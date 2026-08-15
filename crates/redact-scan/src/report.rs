// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use chrono::{DateTime, Utc};
use redact_core::EntityType;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::canonical::content_hash;
use crate::layers::ScanLayer;

/// How a finding was produced. Never carries a matched value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceClass {
    NameHeuristic,
    TypeSignal,
    UniqueIndex,
    FkTopology,
    PgStats,
    TableSample,
    JsonPath,
}

/// A PII location. This type must not grow a field that can hold a sample value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Finding {
    pub table: String,
    pub column: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_path: Option<String>,
    pub entity_type: EntityType,
    pub layer: ScanLayer,
    pub match_count: u64,
    pub sampled_rows: u64,
    pub confidence: f32,
    pub evidence_class: EvidenceClass,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Target {
    pub fingerprint: String,
    pub engine: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Scanner {
    pub version: String,
    pub pattern_pack: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sampling {
    pub layers: Vec<ScanLayer>,
    pub rows_per_column: u32,
    pub method: String,
}

/// Value-free scan report. `content_hash` is computed after the other fields.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ScanReport {
    pub scan_id: Uuid,
    pub scanned_at: DateTime<Utc>,
    pub target: Target,
    pub scanner: Scanner,
    pub sampling: Sampling,
    pub findings: Vec<Finding>,
    pub content_hash: String,
}

impl ScanReport {
    pub fn finalize(mut self) -> Result<Self, anyhow::Error> {
        self.content_hash.clear();
        self.content_hash = content_hash(&self)?;
        Ok(self)
    }
}

/// Local debug samples. Never serialized into [`ScanReport`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSamples {
    pub scan_id: Uuid,
    pub notes: String,
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
