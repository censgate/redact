//! Offline sealed-pack verification orchestration.

use crate::canonical::CanonicalEvent;
use crate::chain::{check_continuity, record_hash, record_signature_input};
use crate::crypto::{
    decode_signature, sha256_hex, signature_version, verify_ed25519, verify_tree_head,
};
use crate::error::InputError;
use crate::keys::{bind_embedded_keys, embedded_chain_version, TrustedKeys};
use crate::model::{
    AatRecord, AnchoringStatus, Canonicalisation, CheckResult, CheckStatus, CoverageReport,
    Principal, RecordPhase, RecordReport, VerificationIssue, VerificationReport,
    VerificationResult,
};
use crate::privacy;
use crate::tombstone::verify_tombstone;
use crate::wire::{parse_body, parse_envelope, Batch, Body, Envelope, GENESIS};
use serde_json::{Map, Value};
use std::collections::HashSet;

/// Verifies an encoded sealed pack using independently trusted local keys.
pub fn verify_pack(raw: &[u8], trusted: &TrustedKeys) -> Result<VerificationReport, InputError> {
    let envelope = parse_envelope(raw)?;
    let body = parse_body(&envelope.body)?;
    if matches!(envelope.schema_version, 0 | 1)
        && matches!(body.schema_version, 0 | 1)
        && !legacy_anchor_format(&envelope, &body)
    {
        validate_signature_encodings(&envelope, &body)?;
    }
    Ok(verify_decoded(raw, envelope, body, trusted))
}

fn validate_signature_encodings(envelope: &Envelope, body: &Body) -> Result<(), InputError> {
    if !envelope.body_signature.is_empty() {
        decode_signature(&envelope.body_signature)?;
    }
    for batch in &body.batches {
        if !batch.signature.is_empty() {
            decode_signature(&batch.signature)?;
        }
        if let Some(tombstone) = &batch.tombstone {
            if tombstone.get("schema_version").and_then(Value::as_u64) == Some(1) {
                if let Some(signature) = tombstone.get("signature").and_then(Value::as_str) {
                    if !signature.is_empty() {
                        decode_signature(signature)?;
                    }
                }
            }
        }
    }
    if let Some(r1) = &body.r1 {
        if !r1.signature.is_empty() && !r1.merkle_root.trim().is_empty() {
            decode_signature(&r1.signature)?;
        }
    }
    Ok(())
}

pub(crate) fn verify_decoded(
    raw_pack: &[u8],
    envelope: Envelope,
    body: Body,
    trusted: &TrustedKeys,
) -> VerificationReport {
    let mut issues = Vec::new();
    let mut fail = false;
    let mut unproven = false;
    let mut add_issue = |code: &str, message: &str, required: bool, status: CheckStatus| {
        issues.push(VerificationIssue {
            code: code.to_owned(),
            message: message.to_owned(),
            required,
        });
        if required {
            fail |= status == CheckStatus::Fail;
            unproven |= status == CheckStatus::Unproven;
        }
    };

    let effective_tenant = if !envelope.tenant_id.is_empty() {
        envelope.tenant_id.clone()
    } else {
        body.tenant_id.clone()
    };

    let envelope_privacy = privacy::inspect(raw_pack, &envelope.raw);
    let body_privacy = privacy::inspect(&envelope.body, &body.raw);
    for finding in [envelope_privacy, body_privacy] {
        if let Some(code) = finding.forbidden {
            add_issue(
                code,
                "forbidden privacy field is present",
                true,
                CheckStatus::Fail,
            );
        }
    }

    let mut raw_commitment_present = false;
    if envelope_privacy.raw_commitment_present || body_privacy.raw_commitment_present {
        raw_commitment_present = true;
    }
    if envelope_privacy.unkeyed_commitment || body_privacy.unkeyed_commitment {
        add_issue(
            "unkeyed_raw_commitment_forbidden",
            "raw commitment declares unkeyed hashing",
            true,
            CheckStatus::Fail,
        );
    }

    let supported_schema =
        matches!(envelope.schema_version, 0 | 1) && matches!(body.schema_version, 0 | 1);
    if !supported_schema {
        add_issue(
            "unsupported_schema_version",
            "pack schema version is unsupported",
            true,
            CheckStatus::Unproven,
        );
        for batch in &body.batches {
            if let Some(canonical) = &batch.record.canonical {
                if let Ok(value) = serde_json::from_slice::<Value>(canonical) {
                    let finding = privacy::inspect(canonical, &value);
                    if let Some(code) = finding.forbidden {
                        add_issue(
                            code,
                            "forbidden privacy field is present in stored canonical evidence",
                            true,
                            CheckStatus::Fail,
                        );
                    }
                    if finding.unkeyed_commitment {
                        add_issue(
                            "unkeyed_raw_commitment_forbidden",
                            "raw commitment declares unkeyed hashing",
                            true,
                            CheckStatus::Fail,
                        );
                    }
                    raw_commitment_present |= finding.raw_commitment_present;
                }
            }
        }
        if !envelope.pack_id.is_empty()
            && !body.pack_id.is_empty()
            && envelope.pack_id != body.pack_id
        {
            add_issue(
                "pack_id_mismatch",
                "envelope and body pack identifiers disagree",
                true,
                CheckStatus::Fail,
            );
        }
        if !envelope.tenant_id.is_empty()
            && !body.tenant_id.is_empty()
            && envelope.tenant_id != body.tenant_id
        {
            add_issue(
                "tenant_id_mismatch",
                "envelope and body tenant identifiers disagree",
                true,
                CheckStatus::Fail,
            );
        }
        let key_binding = match bind_embedded_keys(trusted, body.keys.as_ref()) {
            Ok(()) => check(CheckStatus::Pass, true, "embedded_keys_match_or_absent"),
            Err(reason) => {
                let status = if reason == "unsupported_curve" {
                    CheckStatus::Unproven
                } else {
                    CheckStatus::Fail
                };
                add_issue(
                    reason,
                    "embedded public key does not match independent trust material",
                    true,
                    status,
                );
                check(status, true, reason)
            }
        };
        let (tree_head_signature, anchoring_status) = match body.r1.as_ref() {
            Some(r1) if !r1.merkle_root.trim().is_empty() && !r1.signature.trim().is_empty() => (
                check(CheckStatus::Unproven, true, "unsupported_schema_version"),
                AnchoringStatus::Unproven,
            ),
            _ => (
                check(CheckStatus::NotAnchored, false, "r1_absent"),
                AnchoringStatus::NotAnchored,
            ),
        };
        drop(add_issue);
        let mut sorted: Vec<_> = body.batches.iter().collect();
        sorted.sort_by_key(|batch| batch.record.seq);
        let first_sequence = sorted.first().map(|batch| batch.record.seq);
        let last_sequence = sorted.last().map(|batch| batch.record.seq);
        let record_ids = sorted
            .iter()
            .map(|batch| batch.record.event_id.clone())
            .collect();
        return VerificationReport {
            result: if fail {
                VerificationResult::Fail
            } else {
                VerificationResult::Unproven
            },
            checked: 0,
            erased: 0,
            record_ids,
            records: Vec::new(),
            body_hash: check(CheckStatus::Unproven, true, "unsupported_schema_version"),
            body_signature: check(CheckStatus::Unproven, true, "unsupported_schema_version"),
            key_binding,
            tree_head_signature,
            anchoring_status,
            merkle_inclusion: check(
                CheckStatus::Unproven,
                false,
                "current_format_has_no_inclusion_proof",
            ),
            external_anchoring: external_anchoring(&envelope, &body),
            raw_commitment: if raw_commitment_present {
                check(
                    CheckStatus::Unproven,
                    false,
                    "opaque_keyed_commitment_not_checked_offline",
                )
            } else {
                check(CheckStatus::NotAnchored, false, "raw_commitment_absent")
            },
            coverage: CoverageReport {
                filtered: body.scope.filtered(),
                first_sequence,
                last_sequence,
                gaps: Vec::new(),
                continuity: check(CheckStatus::Unproven, true, "unsupported_schema_version"),
                tail_completeness: check(
                    CheckStatus::Unproven,
                    false,
                    "current_format_has_no_authenticated_coverage_boundary",
                ),
                global_completeness: check(
                    CheckStatus::Unproven,
                    false,
                    "current_format_has_no_authenticated_coverage_boundary",
                ),
            },
            issues,
        };
    }

    let body_hash_actual = sha256_hex(&envelope.body);
    let body_hash = if !envelope.body_hash.is_empty()
        && body_hash_actual.eq_ignore_ascii_case(&envelope.body_hash)
    {
        check(CheckStatus::Pass, true, "body_hash_matches_exact_bytes")
    } else {
        add_issue(
            "body_hash_mismatch",
            "body hash does not match exact decoded bytes",
            true,
            CheckStatus::Fail,
        );
        check(CheckStatus::Fail, true, "body_hash_mismatch")
    };

    let body_signature = if envelope.body_signature.is_empty() {
        add_issue(
            "body_signature_missing",
            "required pack signature is missing",
            true,
            CheckStatus::Fail,
        );
        check(CheckStatus::Fail, true, "body_signature_missing")
    } else {
        let input = format!(
            "anchor-pack|v1|{}|{}|{}",
            envelope.pack_id, effective_tenant, envelope.body_hash
        );
        match verify_ed25519(&trusted.chain, input.as_bytes(), &envelope.body_signature) {
            Ok(()) => check(CheckStatus::Pass, true, "pack_signature_valid"),
            Err(reason) => {
                add_issue(
                    reason,
                    "pack signature verification failed",
                    true,
                    CheckStatus::Fail,
                );
                check(CheckStatus::Fail, true, reason)
            }
        }
    };

    let key_binding = match bind_embedded_keys(trusted, body.keys.as_ref()) {
        Ok(()) => check(CheckStatus::Pass, true, "embedded_keys_match_or_absent"),
        Err(reason) => {
            let status = if reason == "unsupported_curve" {
                CheckStatus::Unproven
            } else {
                CheckStatus::Fail
            };
            add_issue(
                reason,
                "embedded public key does not match independent trust material",
                true,
                status,
            );
            check(status, true, reason)
        }
    };

    if !envelope.pack_id.is_empty() && !body.pack_id.is_empty() && envelope.pack_id != body.pack_id
    {
        add_issue(
            "pack_id_mismatch",
            "envelope and body pack identifiers disagree",
            true,
            CheckStatus::Fail,
        );
    }
    if !envelope.tenant_id.is_empty()
        && !body.tenant_id.is_empty()
        && envelope.tenant_id != body.tenant_id
    {
        add_issue(
            "tenant_id_mismatch",
            "envelope and body tenant identifiers disagree",
            true,
            CheckStatus::Fail,
        );
    }
    if legacy_anchor_format(&envelope, &body) {
        add_issue(
            "unsupported_legacy_anchor_format",
            "proof-only R1/R2 and attestation inputs are not supported",
            true,
            CheckStatus::Unproven,
        );
    }
    let unsupported_profile = body.batches.iter().any(|batch| {
        ["canonicalisation", "canonicalization"]
            .iter()
            .filter_map(|key| metadata_value(batch, key).and_then(Value::as_str))
            .any(|profile| profile != "platform_v1")
    });
    if unsupported_profile {
        add_issue(
            "unsupported_canonicalisation",
            "native canonicalisation profile is unsupported",
            true,
            CheckStatus::Unproven,
        );
    }

    let declared_version = embedded_chain_version(body.keys.as_ref(), trusted.chain_version);
    let mut rows: Vec<&Batch> = body.batches.iter().collect();
    rows.sort_by_key(|batch| batch.record.seq);
    let filtered = body.scope.filtered();
    let continuity_result = check_continuity(&rows, filtered);
    let mut continuity_failed = false;
    let gaps = continuity_result.gaps.clone();
    for code in continuity_result.issues {
        let (message, status) = match code {
            "zero_sequence" => ("record sequence number is zero", CheckStatus::Fail),
            "sequence_prefix_gap" => (
                "unfiltered export does not begin at sequence one",
                CheckStatus::Fail,
            ),
            "genesis_prev_hash_mismatch" => (
                "sequence one has an invalid previous hash",
                CheckStatus::Fail,
            ),
            "chain_link_mismatch" => ("adjacent records do not link", CheckStatus::Fail),
            "sequence_gap" => ("unfiltered export has a sequence gap", CheckStatus::Fail),
            "sequence_overflow" => ("sequence increment overflowed", CheckStatus::Fail),
            _ => ("record continuity check failed", CheckStatus::Fail),
        };
        add_issue(code, message, true, status);
        continuity_failed = true;
    }
    let mut record_reports = Vec::with_capacity(rows.len());
    let mut record_ids = Vec::with_capacity(rows.len());
    let mut seen_sequences = HashSet::new();
    let mut seen_ids = HashSet::new();
    let mut seen_chain_ids = HashSet::new();
    let mut erased = 0usize;

    if rows.is_empty() {
        add_issue(
            "empty_batches",
            "pack contains no records",
            true,
            CheckStatus::Fail,
        );
        continuity_failed = true;
    }
    for batch in rows.iter() {
        let record = &batch.record;
        if !seen_sequences.insert(record.seq) {
            add_issue(
                "duplicate_sequence",
                "record sequence number is duplicated",
                true,
                CheckStatus::Fail,
            );
            continuity_failed = true;
        }
        if !seen_ids.insert(record.event_id.clone()) {
            add_issue(
                "duplicate_record_id",
                "record identifier is duplicated",
                true,
                CheckStatus::Fail,
            );
        }
        seen_chain_ids.insert(record.chain_id.as_str());

        if let Some(tombstone) = &batch.tombstone {
            let tombstone_result = verify_tombstone(tombstone, batch, &effective_tenant, trusted);
            if tombstone_result.status == CheckStatus::Pass {
                erased += 1;
            } else {
                add_issue(
                    tombstone_result.reason,
                    "tombstone replacement did not verify",
                    true,
                    tombstone_result.status,
                );
            }
            record_ids.push(record.event_id.clone());
            let normalized = normalized_record(batch, None, None, trusted, false)
                .unwrap_or_else(|_| empty_record(record));
            let original_status = if tombstone_result.status == CheckStatus::Pass {
                CheckStatus::Erased
            } else {
                tombstone_result.status
            };
            let original_reason = if tombstone_result.status == CheckStatus::Pass {
                "signed_tombstone_original_canonical_absent"
            } else {
                tombstone_result.reason
            };
            record_reports.push(RecordReport {
                record: normalized,
                hash: check(original_status, true, original_reason),
                signature: check(tombstone_result.status, true, tombstone_result.reason),
                canonical: check(original_status, true, original_reason),
                original_record: check(tombstone_result.status, true, tombstone_result.reason),
            });
            continue;
        }
        let Some(event_value) = &batch.event else {
            add_issue(
                "event_missing",
                "ordinary record has no event",
                true,
                CheckStatus::Fail,
            );
            record_reports.push(failed_record(batch, "event_missing"));
            continue;
        };
        let canonical_event = match CanonicalEvent::from_value(event_value) {
            Ok(event) => event,
            Err(error) => {
                add_issue(
                    error.code,
                    "event fields have invalid types",
                    true,
                    CheckStatus::Fail,
                );
                record_reports.push(failed_record(batch, error.code));
                continue;
            }
        };
        if canonical_event.event_id != record.event_id {
            add_issue(
                "record_id_mismatch",
                "event and chain record identifiers disagree",
                true,
                CheckStatus::Fail,
            );
        }
        if let Some(native_id) = metadata_value(batch, "record_id").and_then(Value::as_str) {
            if !native_id.is_empty() && native_id != record.event_id {
                add_issue(
                    "record_id_mismatch",
                    "native and legacy record identifiers disagree",
                    true,
                    CheckStatus::Fail,
                );
            }
        }
        if let Err(code) = check_native_principal(batch, &canonical_event.caller) {
            add_issue(
                code,
                "native principal contradicts its legacy identifier",
                true,
                CheckStatus::Fail,
            );
        }
        if let Err(code) = validate_native_metadata(batch) {
            add_issue(
                code,
                "native record metadata has an invalid shape or value",
                true,
                CheckStatus::Fail,
            );
        }
        let signer_kid = metadata_value(batch, "signer_kid")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty());
        if let Some(signer_kid) = signer_kid {
            if signer_kid != trusted.chain.signer_kid {
                add_issue(
                    "signer_kid_mismatch",
                    "record signer identifier does not match the trusted key",
                    true,
                    CheckStatus::Fail,
                );
            }
        }
        if has_native_extensions(batch) {
            add_issue(
                "native_extensions_pack_signed_only",
                "native additions are covered by the pack signature but excluded from the platform-v1 record hash",
                false,
                CheckStatus::Unproven,
            );
        }

        let profile_supported = !metadata_value(batch, "canonicalisation")
            .or_else(|| metadata_value(batch, "canonicalization"))
            .and_then(Value::as_str)
            .is_some_and(|profile| profile != "platform_v1");
        let canonical = profile_supported.then(|| canonical_event.encode());
        let hash_check = if !profile_supported {
            check(CheckStatus::Unproven, true, "unsupported_record_format")
        } else if record_hash(
            &record.prev_hash,
            canonical
                .as_deref()
                .expect("supported profile has canonical bytes"),
            &canonical_event.event_id,
            &canonical_event.timestamp,
        ) == record.hash
        {
            check(CheckStatus::Pass, true, "record_hash_matches")
        } else {
            add_issue(
                "record_hash_mismatch",
                "record hash does not match its platform-v1 projection",
                true,
                CheckStatus::Fail,
            );
            check(CheckStatus::Fail, true, "record_hash_mismatch")
        };

        let canonical_check = match &record.canonical {
            None => check(CheckStatus::Pass, false, "stored_canonical_omitted"),
            Some(stored) => {
                let canonical_value = serde_json::from_slice::<Value>(stored).ok();
                if let Some(value) = &canonical_value {
                    let finding = privacy::inspect(stored, value);
                    if let Some(code) = finding.forbidden {
                        add_issue(
                            code,
                            "forbidden privacy field is present in stored canonical evidence",
                            true,
                            CheckStatus::Fail,
                        );
                    }
                    if finding.unkeyed_commitment {
                        add_issue(
                            "unkeyed_raw_commitment_forbidden",
                            "raw commitment declares unkeyed hashing",
                            true,
                            CheckStatus::Fail,
                        );
                    }
                    raw_commitment_present |= finding.raw_commitment_present;
                }
                if !profile_supported {
                    check(CheckStatus::Unproven, true, "unsupported_record_format")
                } else if Some(stored.as_slice()) == canonical.as_deref() {
                    check(CheckStatus::Pass, true, "stored_canonical_matches")
                } else {
                    add_issue(
                        "stored_canonical_mismatch",
                        "stored canonical bytes differ from recomputed bytes",
                        true,
                        CheckStatus::Fail,
                    );
                    check(CheckStatus::Fail, true, "stored_canonical_mismatch")
                }
            }
        };
        let signature_check = if !profile_supported {
            check(CheckStatus::Unproven, true, "unsupported_record_format")
        } else if batch.signature.is_empty() {
            add_issue(
                "record_signature_missing",
                "required record signature is missing",
                true,
                CheckStatus::Fail,
            );
            check(CheckStatus::Fail, true, "record_signature_missing")
        } else {
            let signature_input =
                record_signature_input(&record.chain_id, record.seq, &record.hash);
            match verify_ed25519(&trusted.chain, &signature_input, &batch.signature) {
                Err(reason) => {
                    add_issue(
                        reason,
                        "record signature verification failed",
                        true,
                        CheckStatus::Fail,
                    );
                    check(CheckStatus::Fail, true, reason)
                }
                Ok(()) => {
                    let marker = signature_version(&batch.signature);
                    let versions_valid = if let Some(version) = marker {
                        (declared_version == 0 || version == declared_version)
                            && (batch.key_version == 0 || version == batch.key_version)
                    } else {
                        declared_version == 0 && batch.key_version == 0
                    };
                    if versions_valid {
                        check(CheckStatus::Pass, true, "record_signature_valid")
                    } else {
                        add_issue(
                            "key_version_mismatch",
                            "record signature version does not match declared versions",
                            true,
                            CheckStatus::Fail,
                        );
                        check(CheckStatus::Fail, true, "key_version_mismatch")
                    }
                }
            }
        };

        let canonical_json = record
            .canonical
            .as_ref()
            .and_then(|bytes| serde_json::from_slice(bytes).ok());
        let normalized = normalized_record(
            batch,
            Some(&canonical_event),
            canonical_json.as_ref(),
            trusted,
            true,
        )
        .unwrap_or_else(|_| empty_record(record));
        record_ids.push(record.event_id.clone());
        record_reports.push(RecordReport {
            record: normalized,
            hash: hash_check,
            signature: signature_check,
            canonical: canonical_check,
            original_record: check(CheckStatus::Pass, true, "original_record_present"),
        });
    }

    if seen_chain_ids.len() > 1 {
        add_issue(
            "mixed_chain_ids",
            "pack contains records from multiple chains",
            true,
            CheckStatus::Fail,
        );
        continuity_failed = true;
    }
    let continuity = if continuity_failed {
        check(CheckStatus::Fail, true, "continuity_failed")
    } else {
        check(CheckStatus::Pass, true, "continuity_checked")
    };

    let (tree_head_signature, anchoring_status) = match body.r1.as_ref() {
        None => (
            check(CheckStatus::NotAnchored, false, "r1_absent"),
            AnchoringStatus::NotAnchored,
        ),
        Some(r1) if r1.merkle_root.trim().is_empty() || r1.signature.trim().is_empty() => (
            check(
                CheckStatus::NotAnchored,
                false,
                "r1_root_or_signature_absent",
            ),
            AnchoringStatus::NotAnchored,
        ),
        Some(r1) => match trusted.tree_head.as_ref() {
            None => {
                add_issue(
                    "tree_head_key_missing",
                    "signed tree head has no independent verification key",
                    true,
                    CheckStatus::Unproven,
                );
                (
                    check(CheckStatus::Unproven, true, "tree_head_key_missing"),
                    AnchoringStatus::Unproven,
                )
            }
            Some(key) => {
                let input = format!("anchor-root|v1|{}", r1.merkle_root);
                match verify_tree_head(key, input.as_bytes(), &r1.signature) {
                    Ok(()) => (
                        check(CheckStatus::Pass, true, "tree_head_signature_valid"),
                        AnchoringStatus::Pass,
                    ),
                    Err(reason) => {
                        add_issue(
                            reason,
                            "tree-head signature verification failed",
                            true,
                            CheckStatus::Fail,
                        );
                        (
                            check(CheckStatus::Fail, true, reason),
                            AnchoringStatus::Fail,
                        )
                    }
                }
            }
        },
    };
    drop(add_issue);
    let raw_commitment = if raw_commitment_present {
        check(
            CheckStatus::Unproven,
            false,
            "opaque_keyed_commitment_not_checked_offline",
        )
    } else {
        check(CheckStatus::NotAnchored, false, "raw_commitment_absent")
    };
    let merkle_inclusion = check(
        CheckStatus::Unproven,
        false,
        "current_format_has_no_inclusion_proof",
    );
    let coverage = CoverageReport {
        filtered,
        first_sequence: rows.first().map(|row| row.record.seq),
        last_sequence: rows.last().map(|row| row.record.seq),
        gaps,
        continuity,
        tail_completeness: check(
            CheckStatus::Unproven,
            false,
            "current_format_has_no_authenticated_coverage_boundary",
        ),
        global_completeness: check(
            CheckStatus::Unproven,
            false,
            "current_format_has_no_authenticated_coverage_boundary",
        ),
    };

    for issue in &issues {
        if issue.required {
            if issue.code.contains("missing") && issue.code == "tree_head_key_missing" {
                unproven = true;
            }
            if matches!(
                issue.code.as_str(),
                "unsupported_schema_version"
                    | "unsupported_legacy_anchor_format"
                    | "unsupported_canonicalisation"
            ) {
                unproven = true;
            }
        }
    }
    let required_failure = body_hash.status == CheckStatus::Fail
        || body_signature.status == CheckStatus::Fail
        || key_binding.status == CheckStatus::Fail
        || tree_head_signature.required && tree_head_signature.status == CheckStatus::Fail
        || coverage.continuity.status == CheckStatus::Fail
        || record_reports.iter().any(|record| {
            [
                &record.hash,
                &record.signature,
                &record.canonical,
                &record.original_record,
            ]
            .iter()
            .any(|check| check.required && check.status == CheckStatus::Fail)
        })
        || issues
            .iter()
            .any(|issue| issue.required && is_failure_code(&issue.code));
    let required_unproven = tree_head_signature.required
        && tree_head_signature.status == CheckStatus::Unproven
        || record_reports.iter().any(|record| {
            [
                &record.hash,
                &record.signature,
                &record.canonical,
                &record.original_record,
            ]
            .iter()
            .any(|check| check.required && check.status == CheckStatus::Unproven)
        })
        || issues
            .iter()
            .any(|issue| issue.required && is_unproven_code(&issue.code));
    let result = if required_failure || fail {
        VerificationResult::Fail
    } else if required_unproven || unproven {
        VerificationResult::Unproven
    } else if erased > 0 {
        VerificationResult::Erased
    } else {
        VerificationResult::Pass
    };

    VerificationReport {
        result,
        checked: rows.len(),
        erased,
        record_ids,
        records: record_reports,
        body_hash,
        body_signature,
        key_binding,
        tree_head_signature,
        anchoring_status,
        merkle_inclusion,
        external_anchoring: external_anchoring(&envelope, &body),
        raw_commitment,
        coverage,
        issues,
    }
}

/// Optional EUTL/Rekor external anchoring. Informational only (`required=false`):
/// it never passes offline because no pinned EUTL snapshot or Rekor log key is
/// compiled in, and it never changes the overall result.
fn external_anchoring(envelope: &Envelope, body: &Body) -> CheckResult {
    let present = envelope
        .raw
        .get("attestation")
        .is_some_and(|v| !v.is_null())
        || body.raw.get("r2").is_some_and(|v| !v.is_null())
        || body
            .raw
            .get("r1")
            .and_then(|r1| r1.get("rekor"))
            .is_some_and(|v| !v.is_null());
    if present {
        check(
            CheckStatus::Unproven,
            false,
            "external_anchor_present_eutl_rekor_trust_not_pinned",
        )
    } else {
        check(CheckStatus::Unproven, false, "external_anchor_absent")
    }
}

fn check(status: CheckStatus, required: bool, reason: &str) -> CheckResult {
    CheckResult {
        status,
        required,
        reason: reason.to_owned(),
    }
}

fn is_failure_code(code: &str) -> bool {
    !matches!(
        code,
        "unsupported_schema_version"
            | "unsupported_legacy_anchor_format"
            | "unsupported_canonicalisation"
            | "tree_head_key_missing"
            | "erasure_authority_missing"
            | "unsupported_tombstone_version"
            | "unsupported_curve"
    )
}

fn is_unproven_code(code: &str) -> bool {
    matches!(
        code,
        "unsupported_schema_version"
            | "unsupported_legacy_anchor_format"
            | "unsupported_canonicalisation"
            | "tree_head_key_missing"
            | "erasure_authority_missing"
            | "unsupported_tombstone_version"
            | "unsupported_curve"
    )
}

fn legacy_anchor_format(envelope: &Envelope, body: &Body) -> bool {
    envelope.raw.get("attestation").is_some()
        || body.raw.get("seq_range").is_some()
        || body.raw.get("tip").is_some()
        || body.raw.get("r2").is_some()
        || body.raw.get("r1").is_some_and(|r1| {
            [
                "path",
                "merkle_proof",
                "tree_size",
                "leaf_index",
                "rekor",
                "tsa",
            ]
            .iter()
            .any(|key| r1.get(*key).is_some())
        })
}

fn check_native_principal(batch: &Batch, caller: &str) -> Result<(), &'static str> {
    let Some(principal) = metadata_value(batch, "principal").filter(|value| !value.is_null())
    else {
        return Ok(());
    };
    let Some(object) = principal.as_object() else {
        return Err("invalid_principal");
    };
    let id = object
        .get("id")
        .and_then(Value::as_str)
        .ok_or("invalid_principal")?;
    if !caller.is_empty() && id != caller {
        return Err("principal_caller_mismatch");
    }
    Ok(())
}

fn has_native_extensions(batch: &Batch) -> bool {
    [
        "principal",
        "trust_level",
        "record_phase",
        "agent_id",
        "agent_version",
        "parent_record_id",
        "run_id",
        "action_detail",
        "signer_kid",
        "canonical_json",
        "canonicalisation",
        "canonicalization",
    ]
    .iter()
    .any(|key| metadata_value(batch, key).is_some())
}

fn metadata_value<'a>(batch: &'a Batch, key: &str) -> Option<&'a Value> {
    batch
        .event
        .as_ref()
        .and_then(|event| event.get(key))
        .or_else(|| batch.record.raw.get(key))
        .or_else(|| batch.raw.get(key))
}

fn validate_native_metadata(batch: &Batch) -> Result<(), &'static str> {
    for key in [
        "trust_level",
        "record_phase",
        "agent_id",
        "agent_version",
        "parent_record_id",
        "run_id",
        "signer_kid",
        "record_id",
    ] {
        if metadata_value(batch, key).is_some_and(|value| !value.is_null() && !value.is_string()) {
            return Err("invalid_native_metadata");
        }
    }
    if metadata_value(batch, "record_phase")
        .and_then(Value::as_str)
        .is_some_and(|phase| !matches!(phase, "pre" | "post" | "concurrent"))
    {
        return Err("invalid_record_phase");
    }
    if metadata_value(batch, "action_detail")
        .is_some_and(|value| !value.is_null() && !value.is_object())
    {
        return Err("invalid_action_detail");
    }
    for key in ["canonicalisation", "canonicalization"] {
        if metadata_value(batch, key).is_some_and(|value| !value.is_null() && !value.is_string()) {
            return Err("invalid_canonicalisation");
        }
    }
    if let Some(principal) = metadata_value(batch, "principal").filter(|value| !value.is_null()) {
        let Some(object) = principal.as_object() else {
            return Err("invalid_principal");
        };
        if object.get("id").is_none_or(|value| !value.is_string()) {
            return Err("invalid_principal");
        }
        for key in ["type", "principal_type", "role", "authority"] {
            if object
                .get(key)
                .is_some_and(|value| !value.is_null() && !value.is_string())
            {
                return Err("invalid_principal");
            }
        }
    }
    Ok(())
}

fn normalized_record(
    batch: &Batch,
    canonical: Option<&CanonicalEvent>,
    canonical_json: Option<&Value>,
    trusted: &TrustedKeys,
    include_event: bool,
) -> Result<AatRecord, ()> {
    let native_principal = metadata_value(batch, "principal").filter(|value| !value.is_null());
    let caller = canonical.map(|event| event.caller.as_str()).unwrap_or("");
    let principal = if let Some(native) = native_principal {
        let object = native.as_object().ok_or(())?;
        let id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or(())?
            .to_owned();
        Some(Principal {
            id,
            principal_type: object
                .get("type")
                .or_else(|| object.get("principal_type"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            role: object
                .get("role")
                .and_then(Value::as_str)
                .map(str::to_owned),
            authority: object
                .get("authority")
                .and_then(Value::as_str)
                .map(str::to_owned),
            native_fields: Some(native.clone()),
        })
    } else if !caller.is_empty() {
        Some(Principal {
            id: caller.to_owned(),
            principal_type: None,
            role: None,
            authority: None,
            native_fields: None,
        })
    } else {
        None
    };
    let mut action_detail = metadata_value(batch, "action_detail")
        .cloned()
        .unwrap_or_else(|| Value::Object(Map::new()));
    if !action_detail.is_object() {
        return Err(());
    }
    if let (Some(object), Some(canonical)) = (action_detail.as_object_mut(), canonical) {
        add_detail(object, "censgate_event_name", &canonical.event_name);
        add_detail(object, "censgate_profile", &canonical.profile);
        add_detail(
            object,
            "censgate_redacted_content_sha256",
            &canonical.content_sha256,
        );
        add_detail(object, "censgate_region", &canonical.region);
        add_detail(object, "censgate_shard", &canonical.shard);
        add_detail(object, "censgate_epoch", &canonical.epoch);
        add_detail(
            object,
            "censgate_gateway_instance",
            &canonical.gateway_instance,
        );
        add_detail(object, "censgate_error_type", &canonical.error_type);
        add_detail(object, "censgate_trace_id", &canonical.trace_id);
        add_detail(object, "censgate_span_id", &canonical.span_id);
        add_detail(object, "censgate_boundary", &canonical.boundary);
        add_detail(
            object,
            "censgate_destination_class",
            &canonical.destination_class,
        );
        add_detail(
            object,
            "censgate_destination_vendor",
            &canonical.destination_vendor,
        );
        add_detail(object, "censgate_destination_id", &canonical.destination_id);
        object
            .entry("censgate_redactions")
            .or_insert_with(|| serde_json::json!(canonical.redactions));
        object
            .entry("censgate_tokens_issued")
            .or_insert_with(|| serde_json::json!(canonical.tokens_issued));
        if let Some(types) = &canonical.entity_types {
            object.insert("censgate_entity_types".into(), serde_json::json!(types));
        }
    }
    let record_phase = match metadata_value(batch, "record_phase").and_then(Value::as_str) {
        None => None,
        Some("pre") => Some(RecordPhase::Pre),
        Some("post") => Some(RecordPhase::Post),
        Some("concurrent") => Some(RecordPhase::Concurrent),
        Some(_) => None,
    };
    let native_string = |key: &str| -> Result<Option<String>, ()> {
        match metadata_value(batch, key) {
            None | Some(Value::Null) => Ok(None),
            Some(Value::String(value)) => Ok(Some(value.clone())),
            _ => Err(()),
        }
    };
    let timestamp = canonical
        .map(|event| event.timestamp.clone())
        .unwrap_or_default();
    let record_id = if include_event {
        metadata_value(batch, "record_id")
            .and_then(Value::as_str)
            .unwrap_or(&batch.record.event_id)
    } else {
        &batch.record.event_id
    };
    let prev_hash = if batch.record.prev_hash.is_empty() || batch.record.prev_hash == GENESIS {
        None
    } else {
        Some(batch.record.prev_hash.clone())
    };
    let canonical_profile = canonical_json
        .filter(|_| {
            !metadata_value(batch, "canonicalisation")
                .or_else(|| metadata_value(batch, "canonicalization"))
                .and_then(Value::as_str)
                .is_some_and(|profile| profile != "platform_v1")
        })
        .map(|_| Canonicalisation::PlatformV1);
    let signer_kid = native_string("signer_kid")?;
    if signer_kid
        .as_deref()
        .is_some_and(|kid| kid != trusted.chain.signer_kid)
    {
        return Err(());
    }
    Ok(AatRecord {
        record_id: record_id.to_owned(),
        sequence_number: batch.record.seq,
        chain_id: batch.record.chain_id.clone(),
        tenant_id: canonical
            .map(|event| event.tenant_id.clone())
            .or_else(|| {
                batch
                    .tombstone
                    .as_ref()
                    .and_then(|value| value.get("tenant_id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .unwrap_or_default(),
        record_hash: batch.record.hash.clone(),
        prev_hash,
        timestamp,
        action_type: canonical
            .map(|event| event.action.clone())
            .unwrap_or_default(),
        outcome: canonical
            .map(|event| event.outcome.clone())
            .unwrap_or_default(),
        subject_ref: canonical
            .map(|event| event.subject_ref.clone())
            .unwrap_or_default(),
        session_id: canonical
            .map(|event| event.session_id.clone())
            .unwrap_or_default(),
        principal,
        trust_level: native_string("trust_level")?,
        record_phase,
        agent_id: native_string("agent_id")?,
        agent_version: native_string("agent_version")?,
        parent_record_id: native_string("parent_record_id")?,
        run_id: native_string("run_id")?,
        action_detail,
        signer_kid,
        canonical_json: canonical_json.cloned(),
        canonicalisation: canonical_profile,
    })
}

fn add_detail(object: &mut Map<String, Value>, key: &str, value: &str) {
    if !value.is_empty() {
        object
            .entry(key.to_owned())
            .or_insert_with(|| Value::String(value.to_owned()));
    }
}

fn empty_record(record: &crate::wire::Record) -> AatRecord {
    AatRecord {
        record_id: record.event_id.clone(),
        sequence_number: record.seq,
        chain_id: record.chain_id.clone(),
        tenant_id: String::new(),
        record_hash: record.hash.clone(),
        prev_hash: if record.prev_hash.is_empty() || record.prev_hash == GENESIS {
            None
        } else {
            Some(record.prev_hash.clone())
        },
        timestamp: String::new(),
        action_type: String::new(),
        outcome: String::new(),
        subject_ref: String::new(),
        session_id: String::new(),
        principal: None,
        trust_level: None,
        record_phase: None,
        agent_id: None,
        agent_version: None,
        parent_record_id: None,
        run_id: None,
        action_detail: Value::Object(Map::new()),
        signer_kid: None,
        canonical_json: None,
        canonicalisation: None,
    }
}

fn failed_record(batch: &Batch, reason: &str) -> RecordReport {
    RecordReport {
        record: empty_record(&batch.record),
        hash: check(CheckStatus::Fail, true, reason),
        signature: check(CheckStatus::Fail, true, reason),
        canonical: check(CheckStatus::Fail, true, reason),
        original_record: check(CheckStatus::Fail, true, reason),
    }
}
