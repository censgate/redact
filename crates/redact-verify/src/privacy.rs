//! Recursive privacy-field checks for envelopes, bodies, and stored evidence.

use serde_json::Value;
use std::collections::BTreeSet;

/// Result of inspecting a JSON value for forbidden or opaque fields.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct PrivacyFindings {
    pub forbidden: Option<&'static str>,
    pub raw_commitment_present: bool,
    pub unkeyed_commitment: bool,
}

const FORBIDDEN_KEYS: &[&str] = &[
    "payload",
    "ledger_ingest_token",
    "authorization",
    "private_key",
    "content_fingerprint",
    "raw_input_hash",
    "raw_input_sha256",
    "raw_content_sha256",
    "raw_payload_hash",
    "raw_payload_sha256",
    "raw_sha256",
];

/// Checks raw literal markers and parsed object keys recursively.
pub(crate) fn inspect(raw: &[u8], value: &Value) -> PrivacyFindings {
    let mut findings = PrivacyFindings::default();
    if raw
        .windows(b"\"payload\"".len())
        .any(|window| window == b"\"payload\"")
    {
        findings.forbidden = Some("payload_field_forbidden");
        return findings;
    }
    visit(value, &mut findings);
    findings
}

fn visit(value: &Value, findings: &mut PrivacyFindings) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if FORBIDDEN_KEYS.iter().any(|forbidden| key == forbidden) {
                    findings.forbidden = Some(match key.as_str() {
                        "payload" => "payload_field_forbidden",
                        "content_fingerprint" => "content_fingerprint_forbidden",
                        "raw_input_hash" | "raw_input_sha256" | "raw_content_sha256"
                        | "raw_payload_hash" | "raw_payload_sha256" | "raw_sha256" => {
                            "raw_hash_field_forbidden"
                        }
                        _ => "secret_field_forbidden",
                    });
                    return;
                }
                if key == "censgate_raw_commitment" || key == "raw_commitment" {
                    findings.raw_commitment_present = true;
                    if explicitly_unkeyed(child) {
                        findings.unkeyed_commitment = true;
                        findings.forbidden = Some("unkeyed_raw_commitment_forbidden");
                        return;
                    }
                }
                if is_raw_origin_descriptor(key, child) {
                    findings.forbidden = Some("raw_hash_origin_forbidden");
                    return;
                }
                visit(child, findings);
                if findings.forbidden.is_some() {
                    return;
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                visit(item, findings);
                if findings.forbidden.is_some() {
                    return;
                }
            }
        }
        _ => {}
    }
}

fn explicitly_unkeyed(value: &Value) -> bool {
    match value {
        Value::Object(map) => {
            let keyed_false = map.get("keyed").is_some_and(|v| v == false)
                || map.get("is_keyed").is_some_and(|v| v == false);
            let alg = ["algorithm", "alg", "hash_algorithm", "scheme"]
                .iter()
                .filter_map(|k| map.get(*k).and_then(Value::as_str))
                .any(|s| {
                    let normalized = s.to_ascii_lowercase().replace(['-', '_'], "");
                    normalized == "sha256" || normalized == "sha256raw"
                });
            keyed_false || (alg && map.get("key_id").is_none() && map.get("keyed").is_none())
        }
        Value::String(value) => {
            let lower = value.to_ascii_lowercase();
            lower.contains("unkeyed")
                || lower.contains("plain sha-256")
                || lower.contains("raw sha256")
        }
        _ => false,
    }
}

fn is_raw_origin_descriptor(key: &str, value: &Value) -> bool {
    if matches!(key, "censgate_raw_commitment" | "raw_commitment") {
        return false;
    }
    let lower_key = key.to_ascii_lowercase();
    let descriptor_key = lower_key.contains("hash")
        || lower_key.contains("fingerprint")
        || lower_key.contains("digest");
    let object_descriptor = value.as_object().is_some_and(|object| {
        object.keys().any(|name| {
            matches!(
                name.as_str(),
                "hash" | "digest" | "fingerprint" | "algorithm" | "hash_algorithm"
            )
        })
    });
    if !descriptor_key && !object_descriptor {
        return false;
    }
    let mut labels = BTreeSet::new();
    collect_origin_labels(value, &mut labels);
    labels.iter().any(|label| {
        let normalized = label.to_ascii_lowercase().replace(['-', '_', ' '], "");
        matches!(
            normalized.as_str(),
            "raw" | "rawinput" | "rawcontent" | "preredaction" | "unredacted"
        )
    })
}

fn collect_origin_labels(value: &Value, labels: &mut BTreeSet<String>) {
    match value {
        Value::Object(map) => {
            for (key, child) in map {
                if matches!(
                    key.as_str(),
                    "origin" | "hash_origin" | "data_origin" | "material_origin" | "stage"
                ) {
                    if let Some(value) = child.as_str() {
                        labels.insert(value.to_owned());
                    }
                }
                collect_origin_labels(child, labels);
            }
        }
        Value::Array(items) => items
            .iter()
            .for_each(|item| collect_origin_labels(item, labels)),
        _ => {}
    }
}
