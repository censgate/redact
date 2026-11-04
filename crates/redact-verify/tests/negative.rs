//! Negative and boundary tests: tombstones, tree head, ordering/overflow,
//! key-version precedence. All keys are deterministic throwaway test keys.
mod common;

use base64::Engine;
use common::{fixture_from_body, public_key_hex, record_hash, signer_kid, valid_fixture};
use ed25519_dalek::{Signer, SigningKey};
use redact_verify::{verify_pack, AnchoringStatus, CheckStatus, TrustedKeys, VerificationResult};
use serde_json::{json, Value};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;
const TS: &str = "2025-01-02T03:04:05Z";
const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

fn ledger() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn canonical(id: &str) -> Vec<u8> {
    format!(r#"{{"action":"chat","boundary":"","caller":"test-principal","content_sha256":"","destination_class":"","destination_id":"","destination_vendor":"","entity_types":null,"epoch":"","error_type":"","event_id":"{id}","event_name":"test.event","gateway_instance":"","outcome":"allowed","profile":"strict","redactions":0,"region":"test-region","session_id":"","shard":"","span_id":"","subject_ref":"","tenant_id":"test-tenant","timestamp":"{TS}","tokens_issued":0,"trace_id":""}}"#).into_bytes()
}

/// One signed batch. `marker` is an optional `vault:vN` signature prefix.
fn batch(key: &SigningKey, seq: u64, prev: &str, marker: Option<&str>, key_version: i64) -> Value {
    let id = format!("test-record-{seq}");
    let c = canonical(&id);
    let hash = record_hash(prev, &c, &id, TS);
    let sig = B64.encode(
        key.sign(format!("test-chain|{seq}|{hash}").as_bytes())
            .to_bytes(),
    );
    let sig = match marker {
        Some(m) => format!("{m}:{sig}"),
        None => sig,
    };
    json!({
        "event": {
            "event_id": id, "event_name": "test.event", "timestamp": TS,
            "tenant_id": "test-tenant", "region": "test-region", "action": "chat",
            "outcome": "allowed", "profile": "strict", "caller": "test-principal",
            "entity_types": null
        },
        "record": {"seq": seq, "prev_hash": prev, "hash": hash, "event_id": id, "chain_id": "test-chain"},
        "signature": sig,
        "key_version": key_version
    })
}

fn body(batches: Vec<Value>) -> Value {
    json!({"schema_version": 1, "pack_id": "test-pack", "tenant_id": "test-tenant",
           "region": "test-region", "batches": batches})
}

fn hash_of(b: &Value) -> String {
    b["record"]["hash"].as_str().unwrap().to_owned()
}

fn has_issue(report: &redact_verify::VerificationReport, code: &str) -> bool {
    report.issues.iter().any(|i| i.code == code)
}

/// A linked chain 1..=n.
fn chain(n: u64) -> Vec<Value> {
    let k = ledger();
    let mut out = Vec::new();
    let mut prev = String::new();
    for seq in 1..=n {
        let b = batch(&k, seq, &prev, None, 0);
        prev = hash_of(&b);
        out.push(b);
    }
    out
}

fn run(body: Value) -> redact_verify::VerificationReport {
    let f = fixture_from_body(body, ledger(), "test-tenant", "test-pack");
    verify_pack(&f.raw, &f.trusted).unwrap()
}

// ---------- batch ordering and overflow ----------

#[test]
fn out_of_order_batches_are_sorted_and_pass() {
    let mut batches = chain(3);
    batches.reverse();
    let report = run(body(batches));
    assert_eq!(
        report.result,
        VerificationResult::Pass,
        "{:?}",
        report.issues
    );
    assert_eq!(
        report.record_ids,
        ["test-record-1", "test-record-2", "test-record-3"]
    );
}

#[test]
fn broken_link_in_middle_fails_even_when_each_record_self_consistent() {
    let k = ledger();
    let b1 = batch(&k, 1, "", None, 0);
    let b2 = batch(&k, 2, &"ee".repeat(32), None, 0); // signed, hashed, but wrong prev
    let report = run(body(vec![b1, b2]));
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(has_issue(&report, "chain_link_mismatch"));
}

#[test]
fn broken_link_inside_filtered_slice_fails() {
    let k = ledger();
    let b5 = batch(&k, 5, &"aa".repeat(32), None, 0);
    let b6 = batch(&k, 6, &"bb".repeat(32), None, 0);
    let mut b = body(vec![b5, b6]);
    b["scope"] = json!({"session_id": "test-session"});
    let report = run(b);
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(has_issue(&report, "chain_link_mismatch"));
}

#[test]
fn unfiltered_gap_and_bad_genesis_fail() {
    let mut batches = chain(3);
    batches.remove(1);
    let report = run(body(batches));
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(has_issue(&report, "sequence_gap"));

    let report = run(body(vec![batch(&ledger(), 1, &"12".repeat(32), None, 0)]));
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(has_issue(&report, "genesis_prev_hash_mismatch"));

    let report = run(body(vec![batch(&ledger(), 1, GENESIS, None, 0)]));
    assert_eq!(
        report.result,
        VerificationResult::Pass,
        "{:?}",
        report.issues
    );
}

#[test]
fn zero_and_u64_max_sequences_are_handled_without_overflow() {
    let report = run(body(vec![batch(&ledger(), 0, "", None, 0)]));
    assert_eq!(report.result, VerificationResult::Fail);
    assert!(has_issue(&report, "zero_sequence"));

    // Top of the u64 range: checked increment must not wrap to 0 and
    // must link MAX-1 -> MAX in a filtered export.
    let k = ledger();
    let a = batch(&k, u64::MAX - 1, &"aa".repeat(32), None, 0);
    let z = batch(&k, u64::MAX, &hash_of(&a), None, 0);
    let mut b = body(vec![z, a]);
    b["scope"] = json!({"run_id": "test-run"});
    let report = run(b);
    assert_eq!(
        report.result,
        VerificationResult::Pass,
        "{:?}",
        report.issues
    );
    assert_eq!(report.coverage.last_sequence, Some(u64::MAX));
}

#[test]
fn sequence_beyond_u64_is_rejected_not_wrapped() {
    let f = valid_fixture();
    let mut body = f.body.clone();
    body["batches"][0]["record"]["seq"] = json!(18446744073709551616u128.to_string());
    let text = serde_json::to_string(&body)
        .unwrap()
        .replace("\"18446744073709551616\"", "18446744073709551616");
    let raw_body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
    if raw_body.is_null() {
        return; // serde_json without arbitrary_precision cannot even build it
    }
    let fx = fixture_from_body(raw_body, ledger(), "test-tenant", "test-pack");
    match verify_pack(&fx.raw, &fx.trusted) {
        Err(_) => {}
        Ok(r) => assert_ne!(r.result, VerificationResult::Pass),
    }
}

// ---------- key-version precedence ----------

fn keyset(version: i64, embedded: Option<i64>, batches: Vec<Value>) -> (Vec<u8>, TrustedKeys) {
    let mut b = body(batches);
    if let Some(v) = embedded {
        b["keys"] = json!({"chain": {"public_key": public_key_hex(&ledger()), "version": v}});
    }
    let f = fixture_from_body(b, ledger(), "test-tenant", "test-pack");
    let ks = json!({"chain": {"public_key": public_key_hex(&ledger()), "version": version}});
    let trusted = TrustedKeys::from_json(ks.to_string().as_bytes()).unwrap();
    (f.raw, trusted)
}

#[test]
fn trusted_version_constrains_signature_marker() {
    let k = ledger();
    let (raw, t) = keyset(2, None, vec![batch(&k, 1, "", Some("vault:v2"), 0)]);
    assert_eq!(
        verify_pack(&raw, &t).unwrap().result,
        VerificationResult::Pass
    );

    let (raw, t) = keyset(2, None, vec![batch(&k, 1, "", Some("vault:v3"), 0)]);
    let r = verify_pack(&raw, &t).unwrap();
    assert_eq!(r.result, VerificationResult::Fail);
    assert!(has_issue(&r, "key_version_mismatch"));

    // Bare signature is only accepted when no version is declared anywhere.
    let (raw, t) = keyset(2, None, vec![batch(&k, 1, "", None, 0)]);
    assert_eq!(
        verify_pack(&raw, &t).unwrap().result,
        VerificationResult::Fail
    );
}

#[test]
fn embedded_nonzero_version_takes_precedence_over_trusted() {
    let k = ledger();
    let (raw, t) = keyset(2, Some(3), vec![batch(&k, 1, "", Some("vault:v3"), 0)]);
    let r = verify_pack(&raw, &t).unwrap();
    assert_eq!(r.result, VerificationResult::Pass, "{:?}", r.issues);

    let (raw, t) = keyset(2, Some(3), vec![batch(&k, 1, "", Some("vault:v2"), 0)]);
    assert_eq!(
        verify_pack(&raw, &t).unwrap().result,
        VerificationResult::Fail
    );

    // Embedded version 0 means "unset": trusted version still applies.
    let (raw, t) = keyset(2, Some(0), vec![batch(&k, 1, "", Some("vault:v3"), 0)]);
    assert_eq!(
        verify_pack(&raw, &t).unwrap().result,
        VerificationResult::Fail
    );
}

#[test]
fn batch_key_version_must_match_marker() {
    let k = ledger();
    let (raw, t) = keyset(0, None, vec![batch(&k, 1, "", Some("vault:v2"), 2)]);
    assert_eq!(
        verify_pack(&raw, &t).unwrap().result,
        VerificationResult::Pass
    );
    let (raw, t) = keyset(0, None, vec![batch(&k, 1, "", Some("vault:v2"), 4)]);
    let r = verify_pack(&raw, &t).unwrap();
    assert_eq!(r.result, VerificationResult::Fail);
    assert!(has_issue(&r, "key_version_mismatch"));
}

#[test]
fn embedded_chain_key_mismatch_fails() {
    let mut b = body(chain(1));
    b["keys"] = json!({"chain": {"public_key": public_key_hex(&SigningKey::from_bytes(&[9; 32]))}});
    let r = run(b);
    assert_eq!(r.result, VerificationResult::Fail);
    assert!(has_issue(&r, "embedded_chain_key_mismatch"));
}

// ---------- tree head ----------

fn golden() -> Value {
    serde_json::from_str(include_str!("fixtures/platform_v1_golden.json")).unwrap()
}

fn with_r1(signature: &str, embedded_tree_head: Option<&str>) -> Value {
    let mut b = body(chain(1));
    b["r1"] = json!({"merkle_root": "test-root", "signature": signature});
    if let Some(pem) = embedded_tree_head {
        b["keys"] = json!({
            "chain": {"public_key": public_key_hex(&ledger())},
            "tree_head": {"public_key": pem}
        });
    }
    b
}

#[test]
fn tree_head_bad_der_fails() {
    let g = golden();
    let f = fixture_from_body(
        with_r1(&B64.encode(b"not-der"), None),
        ledger(),
        "test-tenant",
        "test-pack",
    );
    let t = f
        .trusted
        .with_tree_head(g["p256_public_pem"].as_str().unwrap())
        .unwrap();
    let r = verify_pack(&f.raw, &t).unwrap();
    assert_eq!(r.result, VerificationResult::Fail);
    assert_eq!(r.anchoring_status, AnchoringStatus::Fail);
}

#[test]
fn tree_head_signed_by_other_curve_key_fails() {
    let g = golden();
    let sig = g["p384_signature"].as_str().unwrap();
    let f = fixture_from_body(with_r1(sig, None), ledger(), "test-tenant", "test-pack");
    let t = f
        .trusted
        .with_tree_head(g["p256_public_pem"].as_str().unwrap())
        .unwrap();
    let r = verify_pack(&f.raw, &t).unwrap();
    assert_eq!(r.result, VerificationResult::Fail);
    assert_eq!(r.anchoring_status, AnchoringStatus::Fail);
}

#[test]
fn embedded_only_tree_head_key_is_unproven() {
    let g = golden();
    let r = run(with_r1(
        g["p256_signature"].as_str().unwrap(),
        Some(g["p256_public_pem"].as_str().unwrap()),
    ));
    assert_eq!(r.result, VerificationResult::Unproven);
    assert_eq!(r.anchoring_status, AnchoringStatus::Unproven);
    assert!(has_issue(&r, "tree_head_key_missing"));
}

#[test]
fn independent_and_embedded_tree_head_key_mismatch_fails() {
    let g = golden();
    let f = fixture_from_body(
        with_r1(
            g["p256_signature"].as_str().unwrap(),
            Some(g["p384_public_pem"].as_str().unwrap()),
        ),
        ledger(),
        "test-tenant",
        "test-pack",
    );
    let t = f
        .trusted
        .with_tree_head(g["p256_public_pem"].as_str().unwrap())
        .unwrap();
    let r = verify_pack(&f.raw, &t).unwrap();
    assert_eq!(r.result, VerificationResult::Fail);
    assert!(has_issue(&r, "embedded_tree_head_key_mismatch"));
}

// ---------- tombstones ----------

struct Tomb {
    record_id: String,
    tenant_id: String,
    record_hash: String,
    erased_at: String,
}

fn tomb_default() -> Tomb {
    Tomb {
        record_id: "test-record-1".into(),
        tenant_id: "test-tenant".into(),
        record_hash: "ab".repeat(32),
        erased_at: "2025-02-01T00:00:00Z".into(),
    }
}

/// Builds a tombstoned pack. `signed` are the fields actually signed;
/// `shown` are the fields placed in the pack. `signer` signs, `kid_of` names.
fn tomb_pack(signed: &Tomb, shown: &Tomb, signer: &SigningKey, kid_of: &SigningKey) -> Value {
    let kid = signer_kid(kid_of);
    let fields = format!(
        r#"{{"chain_id":"test-chain","erased_at":"{}","prev_hash":"{GENESIS}","reason_code":"gdpr_erasure","record_hash":"{}","record_id":"{}","schema_version":1,"sequence_number":1,"sig_alg":"Ed25519","signer_kid":"{kid}","tenant_id":"{}"}}"#,
        signed.erased_at, signed.record_hash, signed.record_id, signed.tenant_id
    );
    let sig = signer.sign(format!("redact-tombstone|v1|{fields}").as_bytes());
    json!({
        "schema_version": 1, "pack_id": "test-pack", "tenant_id": "test-tenant",
        "batches": [{
            "event": null,
            "record": {"seq": 1, "prev_hash": "", "hash": "ab".repeat(32),
                       "event_id": "test-record-1", "chain_id": "test-chain"},
            "tombstone": {
                "schema_version": 1, "record_id": shown.record_id, "sequence_number": 1,
                "chain_id": "test-chain", "record_hash": shown.record_hash, "prev_hash": GENESIS,
                "tenant_id": shown.tenant_id, "erased_at": shown.erased_at,
                "reason_code": "gdpr_erasure", "signer_kid": kid, "sig_alg": "Ed25519",
                "signature": B64.encode(sig.to_bytes())
            }
        }]
    })
}

fn authority() -> SigningKey {
    SigningKey::from_bytes(&[8; 32])
}

fn run_tomb(b: Value) -> redact_verify::VerificationReport {
    let f = fixture_from_body(b, ledger(), "test-tenant", "test-pack");
    let t = f
        .trusted
        .with_erasure_authority(&public_key_hex(&authority()))
        .unwrap();
    verify_pack(&f.raw, &t).unwrap()
}

#[test]
fn tombstone_control_case_is_erased() {
    let d = tomb_default();
    let r = run_tomb(tomb_pack(&d, &d, &authority(), &authority()));
    assert_eq!(r.result, VerificationResult::Erased, "{:?}", r.issues);
}

#[test]
fn tombstone_bad_signature_fails() {
    let d = tomb_default();
    let mut b = tomb_pack(&d, &d, &authority(), &authority());
    let sig = b["batches"][0]["tombstone"]["signature"]
        .as_str()
        .unwrap()
        .to_owned();
    let mut bytes = B64.decode(sig).unwrap();
    bytes[0] ^= 0x01;
    b["batches"][0]["tombstone"]["signature"] = json!(B64.encode(bytes));
    assert_eq!(run_tomb(b).result, VerificationResult::Fail);
}

#[test]
fn tombstone_signed_by_wrong_key_fails() {
    let d = tomb_default();
    let rogue = SigningKey::from_bytes(&[9; 32]);
    // Claims the trusted authority's kid but is signed by a different key.
    let r = run_tomb(tomb_pack(&d, &d, &rogue, &authority()));
    assert_eq!(r.result, VerificationResult::Fail);
    // Names its own kid: no trusted authority matches.
    let r = run_tomb(tomb_pack(&d, &d, &rogue, &rogue));
    assert_ne!(r.result, VerificationResult::Erased);
    assert_ne!(r.result, VerificationResult::Pass);
    // The ledger chain key is not implicitly an erasure authority.
    let r = run_tomb(tomb_pack(&d, &d, &ledger(), &ledger()));
    assert_ne!(r.result, VerificationResult::Erased);
    assert_ne!(r.result, VerificationResult::Pass);
}

#[test]
fn tombstone_mismatched_subject_fails() {
    // Validly signed, but names a different record than the retained one.
    let mut other = tomb_default();
    other.record_id = "test-record-9".into();
    let r = run_tomb(tomb_pack(&other, &other, &authority(), &authority()));
    assert_eq!(r.result, VerificationResult::Fail);

    // Shown fields altered after signing (subject, tenant, hash, time).
    for alter in 0..4 {
        let d = tomb_default();
        let mut shown = tomb_default();
        match alter {
            0 => shown.record_id = "test-record-9".into(),
            1 => shown.tenant_id = "other-tenant".into(),
            2 => shown.record_hash = "cd".repeat(32),
            _ => shown.erased_at = "2025-03-01T00:00:00Z".into(),
        }
        let r = run_tomb(tomb_pack(&d, &shown, &authority(), &authority()));
        assert_eq!(r.result, VerificationResult::Fail, "alteration {alter}");
    }
}

#[test]
fn tombstone_carrying_original_evidence_or_missing_fails() {
    let d = tomb_default();
    let mut b = tomb_pack(&d, &d, &authority(), &authority());
    b["batches"][0]["tombstone"]["original_signature"] = json!("AAAA");
    assert_eq!(run_tomb(b).result, VerificationResult::Fail);

    let mut b = tomb_pack(&d, &d, &authority(), &authority());
    b["batches"][0]["signature"] = json!(B64.encode([0u8; 64]));
    assert_eq!(run_tomb(b).result, VerificationResult::Fail);

    let mut b = tomb_pack(&d, &d, &authority(), &authority());
    b["batches"][0].as_object_mut().unwrap().remove("tombstone");
    assert_eq!(run_tomb(b).result, VerificationResult::Fail);
}

// ---------- optional external anchoring (EUTL/Rekor) ----------

#[test]
fn external_anchoring_is_informational_unproven() {
    let r = run(body(chain(1)));
    assert_eq!(r.result, VerificationResult::Pass);
    assert_eq!(r.external_anchoring.status, CheckStatus::Unproven);
    assert!(!r.external_anchoring.required);
    assert_eq!(r.external_anchoring.reason, "external_anchor_absent");
}
