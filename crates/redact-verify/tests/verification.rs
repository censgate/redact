mod common;

use base64::Engine;
use common::{canonical_event, fixture_from_body, public_key_hex, signer_kid, valid_fixture};
use ed25519_dalek::{Signer, SigningKey};
use redact_verify::{verify_pack, CheckStatus, VerificationResult};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[test]
fn verifies_current_pack_and_ignores_embedded_claim() {
    let fixture = valid_fixture();
    let report = verify_pack(&fixture.raw, &fixture.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Pass);
    assert_eq!(report.checked, 1);
    assert_eq!(report.record_ids, ["test-record-1"]);
    assert_eq!(report.records[0].record.action_type, "chat");
    assert_eq!(
        report.records[0].record.principal.as_ref().unwrap().id,
        "test-principal"
    );
    assert_eq!(report.tree_head_signature.status, CheckStatus::NotAnchored);
    assert_eq!(report.merkle_inclusion.status, CheckStatus::Unproven);
    assert_eq!(VerificationResult::Erased.exit_code(), 3);
    assert_eq!(VerificationResult::Unproven.exit_code(), 2);
}

#[test]
fn accepts_byte_array_body_and_rejects_object_fallback() {
    let fixture = valid_fixture();
    let mut array_envelope = fixture.envelope.clone();
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(array_envelope["body"].as_str().unwrap())
        .unwrap();
    array_envelope["body"] = Value::Array(body_bytes.into_iter().map(|byte| json!(byte)).collect());
    let report = verify_pack(
        &serde_json::to_vec(&array_envelope).unwrap(),
        &fixture.trusted,
    )
    .unwrap();
    assert_eq!(report.result, VerificationResult::Pass);

    let mut object_envelope = fixture.envelope;
    object_envelope["body"] = json!({"schema_version": 1});
    let error = verify_pack(
        &serde_json::to_vec(&object_envelope).unwrap(),
        &fixture.trusted,
    )
    .unwrap_err();
    assert_eq!(error.code, "invalid_byte_field");
}

#[test]
fn rejects_bad_signature_encoding_and_preserves_empty_signature_failure() {
    let fixture = valid_fixture();
    let mut malformed = fixture.envelope.clone();
    malformed["body_signature"] = json!("not standard base64");
    let error =
        verify_pack(&serde_json::to_vec(&malformed).unwrap(), &fixture.trusted).unwrap_err();
    assert_eq!(error.code, "invalid_signature_encoding");

    let mut missing = fixture.envelope;
    missing["body_signature"] = json!("");
    let report = verify_pack(&serde_json::to_vec(&missing).unwrap(), &fixture.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "body_signature_missing"));
}

#[test]
fn event_and_stored_canonical_tampering_fail_independently() {
    let fixture = valid_fixture();
    let mut body = fixture.body.clone();
    body["batches"][0]["event"]["action"] = json!("synthetic-action-change");
    let tampered_event = fixture_from_body(
        body,
        fixture.signing_key.clone(),
        "test-tenant",
        "test-pack",
    );
    let report = verify_pack(&tampered_event.raw, &tampered_event.trusted).unwrap();
    assert_eq!(report.body_signature.status, CheckStatus::Pass);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "record_hash_mismatch"));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "stored_canonical_mismatch"));

    let mut body = fixture.body;
    body["batches"][0]["record"]["canonical"] =
        json!(base64::engine::general_purpose::STANDARD.encode(b"{}"));
    let tampered_canonical =
        fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&tampered_canonical.raw, &tampered_canonical.trusted).unwrap();
    assert_eq!(report.records[0].hash.status, CheckStatus::Pass);
    assert_eq!(report.records[0].canonical.status, CheckStatus::Fail);
}

#[test]
fn exact_body_hash_detects_whitespace_and_uppercase_literal_is_signed() {
    let fixture = valid_fixture();
    let mut whitespace_envelope = fixture.envelope.clone();
    let mut body = base64::engine::general_purpose::STANDARD
        .decode(whitespace_envelope["body"].as_str().unwrap())
        .unwrap();
    body.push(b' ');
    whitespace_envelope["body"] = json!(base64::engine::general_purpose::STANDARD.encode(body));
    let report = verify_pack(
        &serde_json::to_vec(&whitespace_envelope).unwrap(),
        &fixture.trusted,
    )
    .unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert_eq!(report.body_hash.status, CheckStatus::Fail);
    assert_eq!(report.body_signature.status, CheckStatus::Pass);

    let mut uppercase = fixture.envelope;
    let declared = uppercase["body_hash"]
        .as_str()
        .unwrap()
        .to_ascii_uppercase();
    let signature = fixture
        .signing_key
        .sign(format!("anchor-pack|v1|test-pack|test-tenant|{declared}").as_bytes());
    uppercase["body_hash"] = json!(declared);
    uppercase["body_signature"] =
        json!(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));
    let report = verify_pack(&serde_json::to_vec(&uppercase).unwrap(), &fixture.trusted).unwrap();
    assert_eq!(report.body_hash.status, CheckStatus::Pass);
    assert_eq!(report.body_signature.status, CheckStatus::Pass);
}

#[test]
fn recursive_privacy_checks_reject_escaped_payload_and_raw_hashes() {
    let fixture = valid_fixture();
    let mut body = fixture.body.clone();
    body["extension"] = json!({"payload": "synthetic fixture marker"});
    let changed = fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&changed.raw, &changed.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "payload_field_forbidden"));

    let mut body = changed.body;
    body["extension"] = json!({"raw_input_sha256": "00"});
    let changed = fixture_from_body(body, changed.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&changed.raw, &changed.trusted).unwrap();
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "raw_hash_field_forbidden"));

    let mut raw_body = base64::engine::general_purpose::STANDARD
        .decode(changed.envelope["body"].as_str().unwrap())
        .unwrap();
    let literal_key = b"\"raw_input_sha256\"";
    let escaped_key = br#""raw_input_\u0073ha256""#;
    let position = raw_body
        .windows(literal_key.len())
        .position(|window| window == literal_key)
        .unwrap();
    raw_body.splice(
        position..position + literal_key.len(),
        escaped_key.iter().copied(),
    );
    let mut envelope = changed.envelope;
    let body_hash = hex::encode(Sha256::digest(&raw_body));
    let signature = changed
        .signing_key
        .sign(format!("anchor-pack|v1|test-pack|test-tenant|{body_hash}").as_bytes());
    envelope["body"] = json!(base64::engine::general_purpose::STANDARD.encode(raw_body));
    envelope["body_hash"] = json!(body_hash);
    envelope["body_signature"] =
        json!(base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()));
    let report = verify_pack(&serde_json::to_vec(&envelope).unwrap(), &changed.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "raw_hash_field_forbidden"));
}

#[test]
fn filtered_later_start_is_allowed_but_unfiltered_prefix_is_not() {
    let fixture = valid_fixture();
    let mut body = fixture.body.clone();
    body["batches"][0]["record"]["seq"] = json!(3);
    let hash = body["batches"][0]["record"]["hash"]
        .as_str()
        .unwrap()
        .to_owned();
    body["batches"][0]["signature"] = json!(base64::engine::general_purpose::STANDARD.encode(
        fixture
            .signing_key
            .sign(format!("test-chain|3|{hash}").as_bytes())
            .to_bytes()
    ));
    body["scope"] = json!({"run_id": "synthetic-filter"});
    let filtered = fixture_from_body(
        body.clone(),
        fixture.signing_key.clone(),
        "test-tenant",
        "test-pack",
    );
    let report = verify_pack(&filtered.raw, &filtered.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Pass);
    assert!(report.coverage.filtered);
    assert_eq!(report.coverage.first_sequence, Some(3));

    body.as_object_mut().unwrap().remove("scope");
    let unfiltered = fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&unfiltered.raw, &unfiltered.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "sequence_prefix_gap"));
}

#[test]
fn future_schema_is_unproven_and_versions_constrain_bare_signatures() {
    let fixture = valid_fixture();
    let mut body = fixture.body.clone();
    body["schema_version"] = json!(2);
    let unsupported = fixture_from_body(
        body,
        fixture.signing_key.clone(),
        "test-tenant",
        "test-pack",
    );
    let report = verify_pack(&unsupported.raw, &unsupported.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Unproven);

    let mut unsupported_envelope = unsupported.envelope.clone();
    unsupported_envelope["body_hash"] = json!("00");
    let report = verify_pack(
        &serde_json::to_vec(&unsupported_envelope).unwrap(),
        &unsupported.trusted,
    )
    .unwrap();
    assert_eq!(report.result, VerificationResult::Unproven);
    assert_eq!(report.body_hash.status, CheckStatus::Unproven);

    let mut body = fixture.body;
    body["keys"] = json!({"chain": {
        "version": 2,
        "public_key": public_key_hex(&fixture.signing_key)
    }});
    let versioned = fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&versioned.raw, &versioned.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "key_version_mismatch"));

    let marker_fixture = valid_fixture();
    let mut body = marker_fixture.body;
    let signature = body["batches"][0]["signature"].as_str().unwrap().to_owned();
    body["batches"][0]["signature"] = json!(format!("vault:v1:{signature}"));
    let marked = fixture_from_body(body, marker_fixture.signing_key, "test-tenant", "test-pack");
    assert_eq!(
        verify_pack(&marked.raw, &marked.trusted).unwrap().result,
        VerificationResult::Pass
    );
}

#[test]
fn public_ed25519_key_encodings_and_embedded_binding() {
    let fixture = valid_fixture();
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/platform_v1_golden.json")).unwrap();
    let key_bytes = fixture.signing_key.verifying_key().to_bytes();
    let padded = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let unpadded = padded.trim_end_matches('=');
    assert!(redact_verify::TrustedKeys::from_ed25519(&padded).is_ok());
    assert!(redact_verify::TrustedKeys::from_ed25519(unpadded).is_ok());
    assert!(redact_verify::TrustedKeys::from_ed25519(
        golden["ed25519_public_pem"].as_str().unwrap()
    )
    .is_ok());

    let different_key = SigningKey::from_bytes(&[9; 32]);
    let mut body = fixture.body;
    body["keys"] = json!({"chain": {"public_key": public_key_hex(&different_key)}});
    let embedded = fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&embedded.raw, &embedded.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert_eq!(report.key_binding.status, CheckStatus::Fail);
}

#[test]
fn unsupported_native_canonicalisation_is_not_checked_as_platform_v1() {
    let fixture = valid_fixture();
    let mut body = fixture.body;
    body["batches"][0]["event"]["canonicalisation"] = json!("native_jcs");
    let unsupported = fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&unsupported.raw, &unsupported.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Unproven);
    assert_eq!(report.records[0].hash.status, CheckStatus::Unproven);
}

#[test]
fn empty_exports_and_duplicate_rows_fail() {
    let fixture = valid_fixture();
    let mut empty_body = fixture.body.clone();
    empty_body["batches"] = json!([]);
    let empty = fixture_from_body(
        empty_body,
        fixture.signing_key.clone(),
        "test-tenant",
        "test-pack",
    );
    assert_eq!(
        verify_pack(&empty.raw, &empty.trusted).unwrap().result,
        VerificationResult::Fail
    );

    let mut duplicate_body = fixture.body;
    let row = duplicate_body["batches"][0].clone();
    duplicate_body["batches"].as_array_mut().unwrap().push(row);
    let duplicate = fixture_from_body(
        duplicate_body,
        fixture.signing_key,
        "test-tenant",
        "test-pack",
    );
    let report = verify_pack(&duplicate.raw, &duplicate.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "duplicate_sequence"));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "duplicate_record_id"));
}

#[test]
fn native_metadata_is_preserved_and_raw_commitment_is_opaque() {
    let fixture = valid_fixture();
    let mut body = fixture.body.clone();
    body["batches"][0]["event"]["principal"] = json!({
        "id": "test-principal",
        "type": "service",
        "authority": "local-test"
    });
    body["batches"][0]["event"]["trust_level"] = json!("local");
    body["batches"][0]["event"]["record_phase"] = json!("post");
    body["batches"][0]["event"]["agent_version"] = json!("test-agent-v1");
    body["batches"][0]["event"]["action_detail"] = json!({
        "censgate_raw_commitment": "opaque-test-commitment"
    });
    let native = fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&native.raw, &native.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Pass);
    assert_eq!(
        report.records[0].record.trust_level.as_deref(),
        Some("local")
    );
    assert_eq!(
        report.records[0].record.record_phase,
        Some(redact_verify::RecordPhase::Post)
    );
    assert_eq!(
        report.records[0].record.agent_version.as_deref(),
        Some("test-agent-v1")
    );
    assert_eq!(
        report.records[0].record.action_detail["censgate_raw_commitment"],
        "opaque-test-commitment"
    );
    assert_eq!(report.raw_commitment.status, CheckStatus::Unproven);
    assert_eq!(
        report.raw_commitment.reason,
        "opaque_keyed_commitment_not_checked_offline"
    );
}

#[test]
fn body_tenant_fallback_is_signed_and_identity_conflicts_fail() {
    let fixture = valid_fixture();
    let mut envelope = fixture.envelope.clone();
    envelope["tenant_id"] = json!("");
    let report = verify_pack(&serde_json::to_vec(&envelope).unwrap(), &fixture.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Pass);

    let mut body = fixture.body;
    body["pack_id"] = json!("different-test-pack");
    let conflict = fixture_from_body(body, fixture.signing_key, "test-tenant", "test-pack");
    let report = verify_pack(&conflict.raw, &conflict.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.code == "pack_id_mismatch"));
}

#[test]
fn verifies_signed_tombstone_extension_and_reports_erased() {
    let ledger = SigningKey::from_bytes(&[7; 32]);
    let authority = SigningKey::from_bytes(&[8; 32]);
    let previous = "0000000000000000000000000000000000000000000000000000000000000000";
    let record_hash = "ab".repeat(32);
    let kid = signer_kid(&authority);
    let erased_at = "2025-02-01T00:00:00Z";
    let signed_fields = format!(
        r#"{{"chain_id":"test-chain","erased_at":"{erased_at}","prev_hash":"{previous}","reason_code":"gdpr_erasure","record_hash":"{record_hash}","record_id":"test-record-1","schema_version":1,"sequence_number":1,"sig_alg":"Ed25519","signer_kid":"{kid}","tenant_id":"test-tenant"}}"#
    );
    let signature = authority.sign(format!("redact-tombstone|v1|{signed_fields}").as_bytes());
    let body = json!({
        "schema_version": 1,
        "pack_id": "test-pack",
        "tenant_id": "test-tenant",
        "batches": [{
            "event": null,
            "record": {
                "seq": 1,
                "prev_hash": "",
                "hash": record_hash,
                "event_id": "test-record-1",
                "chain_id": "test-chain"
            },
            "tombstone": {
                "schema_version": 1,
                "record_id": "test-record-1",
                "sequence_number": 1,
                "chain_id": "test-chain",
                "record_hash": record_hash,
                "prev_hash": previous,
                "tenant_id": "test-tenant",
                "erased_at": erased_at,
                "reason_code": "gdpr_erasure",
                "signer_kid": kid,
                "sig_alg": "Ed25519",
                "signature": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            }
        }]
    });
    let fixture = fixture_from_body(body, ledger, "test-tenant", "test-pack");
    let trusted = fixture
        .trusted
        .with_erasure_authority(&public_key_hex(&authority))
        .unwrap();
    let report = verify_pack(&fixture.raw, &trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Erased);
    assert_eq!(report.erased, 1);
    assert_eq!(report.records[0].hash.status, CheckStatus::Erased);
    assert_eq!(
        report.records[0].hash.reason,
        "signed_tombstone_original_canonical_absent"
    );
}

#[test]
fn missing_erasure_authority_is_unproven() {
    let ledger = SigningKey::from_bytes(&[7; 32]);
    let authority = SigningKey::from_bytes(&[8; 32]);
    let previous = "0000000000000000000000000000000000000000000000000000000000000000";
    let hash = "cd".repeat(32);
    let kid = signer_kid(&authority);
    let signed_fields = format!(
        r#"{{"chain_id":"test-chain","erased_at":"2025-02-01T00:00:00Z","prev_hash":"{previous}","reason_code":"gdpr_erasure","record_hash":"{hash}","record_id":"test-record-1","schema_version":1,"sequence_number":1,"sig_alg":"Ed25519","signer_kid":"{kid}","tenant_id":"test-tenant"}}"#
    );
    let signature = authority.sign(format!("redact-tombstone|v1|{signed_fields}").as_bytes());
    let body = json!({
        "schema_version": 1,
        "pack_id": "test-pack",
        "tenant_id": "test-tenant",
        "batches": [{
            "event": null,
            "record": {"seq": 1, "prev_hash": "", "hash": hash, "event_id": "test-record-1", "chain_id": "test-chain"},
            "tombstone": {
                "schema_version": 1, "record_id": "test-record-1", "sequence_number": 1,
                "chain_id": "test-chain", "record_hash": hash, "prev_hash": previous,
                "tenant_id": "test-tenant", "erased_at": "2025-02-01T00:00:00Z",
                "reason_code": "gdpr_erasure", "signer_kid": kid, "sig_alg": "Ed25519",
                "signature": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
            }
        }]
    });
    let fixture = fixture_from_body(body, ledger, "test-tenant", "test-pack");
    let report = verify_pack(&fixture.raw, &fixture.trusted).unwrap();
    assert_eq!(report.result, VerificationResult::Unproven);
    assert_eq!(
        report.records[0].original_record.reason,
        "erasure_authority_missing"
    );
}

#[test]
fn verifies_independent_p256_and_p384_tree_head_signatures_without_claiming_inclusion() {
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/platform_v1_golden.json")).unwrap();
    for (curve, pem_name, signature_name) in [
        ("P-256", "p256_public_pem", "p256_signature"),
        ("P-384", "p384_public_pem", "p384_signature"),
    ] {
        let base = valid_fixture();
        let mut body = base.body.clone();
        body["r1"] = json!({
            "merkle_root": "test-root",
            "signature": golden[signature_name]
        });
        let fixture = fixture_from_body(body, base.signing_key, "test-tenant", "test-pack");
        let trusted = fixture
            .trusted
            .with_tree_head(golden[pem_name].as_str().unwrap())
            .unwrap();
        let report = verify_pack(&fixture.raw, &trusted).unwrap();
        assert_eq!(report.result, VerificationResult::Pass, "{curve}");
        assert_eq!(
            report.anchoring_status,
            redact_verify::AnchoringStatus::Pass
        );
        assert_eq!(report.merkle_inclusion.status, CheckStatus::Unproven);

        let mut changed_body = fixture.body.clone();
        changed_body["r1"]["merkle_root"] = json!("mutated-root");
        let changed = fixture_from_body(
            changed_body,
            fixture.signing_key,
            "test-tenant",
            "test-pack",
        );
        let trusted = changed
            .trusted
            .with_tree_head(golden[pem_name].as_str().unwrap())
            .unwrap();
        let report = verify_pack(&changed.raw, &trusted).unwrap();
        assert_eq!(report.result, VerificationResult::Fail, "{curve}");
        assert_eq!(
            report.anchoring_status,
            redact_verify::AnchoringStatus::Fail
        );
    }
}

#[test]
fn timestamp_and_entity_projection_have_frozen_golden() {
    let fixture = valid_fixture();
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/platform_v1_golden.json")).unwrap();
    assert_eq!(
        canonical_event(),
        golden["canonical_json"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        fixture.body["batches"][0]["record"]["hash"],
        golden["record_hash"]
    );
    assert_eq!(
        fixture.body["batches"][0]["signature"],
        golden["record_signature"]
    );
    assert_eq!(
        public_key_hex(&fixture.signing_key),
        golden["trusted_public_key"]
    );
    assert_eq!(
        canonical_event(),
        fixture.body["batches"][0]["record"]["canonical"]
            .as_str()
            .map(|encoded| base64::engine::general_purpose::STANDARD
                .decode(encoded)
                .unwrap())
            .unwrap()
    );
    assert_eq!(
        fixture.body["batches"][0]["record"]["hash"],
        hex::encode(Sha256::digest(
            [
                b"0000000000000000000000000000000000000000000000000000000000000000".as_slice(),
                canonical_event().as_slice(),
                b"test-record-1",
                b"2025-01-02T03:04:05Z",
            ]
            .concat()
        ))
    );
}
