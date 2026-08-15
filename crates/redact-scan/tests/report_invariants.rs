use chrono::{TimeZone, Utc};
use redact_core::EntityType;
use redact_scan::layers::ScanLayer;
use redact_scan::report::{EvidenceClass, Finding, Sampling, ScanReport, Scanner, Target};
use uuid::Uuid;

#[test]
fn report_json_omits_value_bearing_keys() {
    let report = ScanReport {
        scan_id: Uuid::nil(),
        scanned_at: Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap(),
        target: Target {
            fingerprint: "abc".into(),
            engine: "postgres".into(),
            version: "16".into(),
        },
        scanner: Scanner {
            version: "0.9.1".into(),
            pattern_pack: "builtin@54".into(),
        },
        sampling: Sampling {
            layers: vec![ScanLayer::Metadata],
            rows_per_column: 1000,
            method: "TABLESAMPLE SYSTEM".into(),
        },
        findings: vec![Finding {
            table: "public.t".into(),
            column: "c".into(),
            json_path: None,
            entity_type: EntityType::EmailAddress,
            layer: ScanLayer::Sample,
            match_count: 3,
            sampled_rows: 10,
            confidence: 0.9,
            evidence_class: EvidenceClass::TableSample,
        }],
        content_hash: String::new(),
    }
    .finalize()
    .unwrap();

    let json = serde_json::to_string(&report).unwrap();
    let value: serde_json::Value = serde_json::from_str(&json).unwrap();
    let keys = object_keys(&value);
    for banned in ["value", "sample", "text", "most_common"] {
        assert!(
            !keys.iter().any(|k| k == banned),
            "report JSON contains banned key {banned}: {json}"
        );
    }
    assert!(!report.content_hash.is_empty());
    assert!(!json.contains("postgres://"));
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
