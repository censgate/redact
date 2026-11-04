//! Locally generated test-only evidence using deterministic throwaway keys.
#![allow(dead_code)]

use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use redact_verify::TrustedKeys;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const TEST_CHAIN: &str = "test-chain";
const TEST_TENANT: &str = "test-tenant";
const TEST_PACK: &str = "test-pack";
const EVENT_ID: &str = "test-record-1";
const TEST_SEED: [u8; 32] = [7; 32];

/// A locally signed test pack and the matching throwaway trust source.
pub struct Fixture {
    /// Serialized sealed pack envelope.
    pub raw: Vec<u8>,
    /// Decoded body object.
    pub body: Value,
    /// Envelope object.
    pub envelope: Value,
    /// Deterministic test-only signing key.
    pub signing_key: SigningKey,
    /// Matching local public trust key.
    pub trusted: TrustedKeys,
}

/// Builds a valid one-record pack with deterministic, fake values.
pub fn valid_fixture() -> Fixture {
    let signing_key = SigningKey::from_bytes(&TEST_SEED);
    let canonical = canonical_event();
    let hash = record_hash("", &canonical, EVENT_ID, "2025-01-02T03:04:05Z");
    let record_signature = signing_key.sign(format!("{TEST_CHAIN}|1|{hash}").as_bytes());
    let body = json!({
        "schema_version": 1,
        "pack_id": TEST_PACK,
        "tenant_id": TEST_TENANT,
        "region": "test-region",
        "batches": [{
            "event": {
                "event_id": EVENT_ID,
                "event_name": "test.event",
                "timestamp": "2025-01-02T03:04:05Z",
                "tenant_id": TEST_TENANT,
                "region": "test-region",
                "action": "chat",
                "outcome": "allowed",
                "profile": "strict",
                "caller": "test-principal",
                "entity_types": null
            },
            "record": {
                "seq": 1,
                "prev_hash": "",
                "hash": hash,
                "event_id": EVENT_ID,
                "chain_id": TEST_CHAIN,
                "canonical": base64::engine::general_purpose::STANDARD.encode(canonical)
            },
            "signature": base64::engine::general_purpose::STANDARD.encode(record_signature.to_bytes()),
            "key_version": 0
        }],
        "verify": { "pass": false }
    });
    fixture_from_body(body, signing_key, TEST_TENANT, TEST_PACK)
}

/// Signs exact serialized body bytes and constructs its outer envelope.
pub fn fixture_from_body(
    body: Value,
    signing_key: SigningKey,
    tenant: &str,
    pack: &str,
) -> Fixture {
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let body_hash = hex::encode(Sha256::digest(&body_bytes));
    let signature =
        signing_key.sign(format!("anchor-pack|v1|{pack}|{tenant}|{body_hash}").as_bytes());
    let envelope = json!({
        "schema_version": 1,
        "pack_id": pack,
        "tenant_id": tenant,
        "body": base64::engine::general_purpose::STANDARD.encode(&body_bytes),
        "body_hash": body_hash,
        "body_signature": base64::engine::general_purpose::STANDARD.encode(signature.to_bytes())
    });
    let raw = serde_json::to_vec(&envelope).unwrap();
    let trusted =
        TrustedKeys::from_ed25519(&hex::encode(signing_key.verifying_key().to_bytes())).unwrap();
    Fixture {
        raw,
        body,
        envelope,
        signing_key,
        trusted,
    }
}

/// Returns the independently frozen canonical bytes for the one-record fixture.
pub fn canonical_event() -> Vec<u8> {
    br#"{"action":"chat","boundary":"","caller":"test-principal","content_sha256":"","destination_class":"","destination_id":"","destination_vendor":"","entity_types":null,"epoch":"","error_type":"","event_id":"test-record-1","event_name":"test.event","gateway_instance":"","outcome":"allowed","profile":"strict","redactions":0,"region":"test-region","session_id":"","shard":"","span_id":"","subject_ref":"","tenant_id":"test-tenant","timestamp":"2025-01-02T03:04:05Z","tokens_issued":0,"trace_id":""}"#.to_vec()
}

/// Returns an Ed25519 test public key as lower-case hexadecimal.
pub fn public_key_hex(key: &SigningKey) -> String {
    hex::encode(key.verifying_key().to_bytes())
}

/// Recomputes the current record hash formula for generated fixtures.
pub fn record_hash(prev: &str, canonical: &[u8], event_id: &str, timestamp: &str) -> String {
    let genesis = "0000000000000000000000000000000000000000000000000000000000000000";
    let mut data = Vec::new();
    data.extend_from_slice(if prev.is_empty() {
        genesis.as_bytes()
    } else {
        prev.as_bytes()
    });
    data.extend_from_slice(canonical);
    data.extend_from_slice(event_id.as_bytes());
    data.extend_from_slice(timestamp.as_bytes());
    hex::encode(Sha256::digest(data))
}

/// Computes the RFC 7638 Ed25519 thumbprint used in local tombstone fixtures.
pub fn signer_kid(key: &SigningKey) -> String {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let thumbprint = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint.as_bytes()))
}
