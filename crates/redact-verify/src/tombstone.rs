//! redact-tombstone-v1 replacement extension.
//!
//! This locally specified extension is not present in the current platform
//! reference format. A valid authority signature authenticates the erasure
//! declaration; it cannot establish physical deletion or restore event data.

use crate::canonical::normalize_timestamp;
use crate::crypto::verify_ed25519;
use crate::keys::TrustedKeys;
use crate::model::CheckStatus;
use crate::wire::{Batch, GENESIS};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

const TOMBSTONE_FIELDS: &[&str] = &[
    "chain_id",
    "erased_at",
    "prev_hash",
    "reason_code",
    "record_hash",
    "record_id",
    "schema_version",
    "sequence_number",
    "sig_alg",
    "signer_kid",
    "signature",
    "tenant_id",
];

/// Result of checking one tombstone replacement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TombstoneResult {
    /// Verification status for the replacement declaration.
    pub status: CheckStatus,
    /// Stable reason code.
    pub reason: &'static str,
}

/// Verifies a replacement tombstone against the retained chain record.
pub(crate) fn verify_tombstone(
    value: &Value,
    batch: &Batch,
    effective_tenant: &str,
    trusted: &TrustedKeys,
) -> TombstoneResult {
    let Some(object) = value.as_object() else {
        return result(CheckStatus::Fail, "invalid_tombstone");
    };
    if batch.event.is_some()
        || !batch
            .raw
            .as_object()
            .is_some_and(|obj| obj.get("event").is_some_and(Value::is_null))
        || batch.record.canonical.is_some()
        || batch.raw.as_object().is_some_and(|obj| {
            obj.contains_key("signature") || obj.contains_key("original_signature")
        })
        || batch
            .record
            .raw
            .as_object()
            .is_some_and(|obj| obj.contains_key("canonical"))
    {
        return result(CheckStatus::Fail, "original_evidence_retained");
    }

    let Some(schema) = object.get("schema_version").and_then(Value::as_u64) else {
        return result(CheckStatus::Fail, "invalid_tombstone_version");
    };
    if schema != 1 {
        return result(CheckStatus::Unproven, "unsupported_tombstone_version");
    }
    if object.keys().map(String::as_str).collect::<BTreeSet<_>>()
        != TOMBSTONE_FIELDS.iter().copied().collect::<BTreeSet<_>>()
    {
        return result(CheckStatus::Fail, "invalid_tombstone_fields");
    }
    if get_string(object, "sig_alg") != Some("Ed25519") {
        return result(CheckStatus::Fail, "invalid_tombstone_algorithm");
    }
    if get_string(object, "signature").is_none_or(str::is_empty) {
        return result(CheckStatus::Fail, "tombstone_signature_missing");
    }
    let Some(sequence) = object.get("sequence_number").and_then(Value::as_u64) else {
        return result(CheckStatus::Fail, "invalid_tombstone_sequence");
    };
    if sequence == 0 || sequence > 9_007_199_254_740_991 {
        return result(CheckStatus::Fail, "invalid_tombstone_sequence");
    }
    let Some(erased_at_raw) = get_string(object, "erased_at") else {
        return result(CheckStatus::Fail, "invalid_tombstone_time");
    };
    let erased_value = Value::String(erased_at_raw.to_owned());
    let Ok(erased_at) = normalize_timestamp(Some(&erased_value)) else {
        return result(CheckStatus::Fail, "invalid_tombstone_time");
    };
    let previous = if batch.record.prev_hash.is_empty() {
        GENESIS
    } else {
        &batch.record.prev_hash
    };
    let identity_matches = get_string(object, "record_id") == Some(batch.record.event_id.as_str())
        && sequence == batch.record.seq
        && get_string(object, "chain_id") == Some(batch.record.chain_id.as_str())
        && get_string(object, "record_hash") == Some(batch.record.hash.as_str())
        && get_string(object, "prev_hash") == Some(previous)
        && get_string(object, "tenant_id") == Some(effective_tenant);
    if !identity_matches
        || get_string(object, "reason_code").is_none_or(str::is_empty)
        || get_string(object, "signer_kid").is_none_or(str::is_empty)
    {
        return result(CheckStatus::Fail, "tombstone_identity_mismatch");
    }
    let Some(authority) = &trusted.erasure_authority else {
        return result(CheckStatus::Unproven, "erasure_authority_missing");
    };
    if get_string(object, "signer_kid") != Some(authority.signer_kid.as_str()) {
        return result(CheckStatus::Fail, "tombstone_signer_mismatch");
    }
    let Some(signature) = get_string(object, "signature") else {
        return result(CheckStatus::Fail, "tombstone_signature_missing");
    };
    let input = signature_input(object, &erased_at);
    match verify_ed25519(authority, &input, signature) {
        Ok(()) => result(CheckStatus::Pass, "signed_tombstone_verified"),
        Err(reason) => result(CheckStatus::Fail, reason),
    }
}

fn signature_input(object: &Map<String, Value>, erased_at: &str) -> Vec<u8> {
    // Fixed member set and ASCII names make this compact sorted object JCS-safe.
    let ordered = [
        (
            "chain_id",
            get_string(object, "chain_id")
                .unwrap_or_default()
                .to_owned(),
        ),
        ("erased_at", erased_at.to_owned()),
        (
            "prev_hash",
            get_string(object, "prev_hash")
                .unwrap_or_default()
                .to_owned(),
        ),
        (
            "reason_code",
            get_string(object, "reason_code")
                .unwrap_or_default()
                .to_owned(),
        ),
        (
            "record_hash",
            get_string(object, "record_hash")
                .unwrap_or_default()
                .to_owned(),
        ),
        (
            "record_id",
            get_string(object, "record_id")
                .unwrap_or_default()
                .to_owned(),
        ),
        ("schema_version", "1".to_owned()),
        (
            "sequence_number",
            object
                .get("sequence_number")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                .to_string(),
        ),
        (
            "sig_alg",
            get_string(object, "sig_alg").unwrap_or_default().to_owned(),
        ),
        (
            "signer_kid",
            get_string(object, "signer_kid")
                .unwrap_or_default()
                .to_owned(),
        ),
        (
            "tenant_id",
            get_string(object, "tenant_id")
                .unwrap_or_default()
                .to_owned(),
        ),
    ];
    let mut json = String::from("redact-tombstone|v1|{");
    for (index, (name, value)) in ordered.iter().enumerate() {
        if index > 0 {
            json.push(',');
        }
        json.push_str(&serde_json::to_string(name).expect("static string"));
        json.push(':');
        if *name == "schema_version" || *name == "sequence_number" {
            json.push_str(value);
        } else {
            json.push_str(&serde_json::to_string(value).expect("string value"));
        }
    }
    json.push('}');
    json.into_bytes()
}

fn get_string<'a>(object: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    object.get(key).and_then(Value::as_str)
}

fn result(status: CheckStatus, reason: &'static str) -> TombstoneResult {
    TombstoneResult { status, reason }
}
