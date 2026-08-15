use assert_cmd::Command;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs;
use tempfile::tempdir;

fn write_pack(dir: &std::path::Path, env: &serde_json::Value) -> std::path::PathBuf {
    let p = dir.join("pack.json");
    fs::write(&p, serde_json::to_vec(env).unwrap()).unwrap();
    p
}

#[test]
fn stripped_attestation_exit_1_unproven() {
    let dir = tempdir().unwrap();
    let inner = br#"{"schema_version":1,"pack_id":"p1","tenant_id":"acme","seq_range":{"from":1,"to":1},"tip":{"chain_id":"acme/local/default/e0","seq":1,"hash":"aa"},"batches":[{"event":{"event_id":"e1"},"record":{"seq":1,"prev_hash":"0000000000000000000000000000000000000000000000000000000000000000","hash":"aa","event_id":"e1","chain_id":"acme/local/default/e0"},"signature":"sig"}]}"#;
    let body_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, inner);
    let hash = hex::encode(Sha256::digest(inner));
    let env = json!({
        "schema_version": 1,
        "pack_id": "p1",
        "tenant_id": "acme",
        "body": body_b64,
        "body_hash": hash,
        "body_signature": "vault:v1:AA",
        "attestation": {}
    });
    let pack = write_pack(dir.path(), &env);
    let pk = dir.path().join("pk.hex");
    fs::write(&pk, "00".repeat(32)).unwrap();
    let output = Command::cargo_bin("redact-verify")
        .unwrap()
        .args([
            "--pack",
            pack.to_str().unwrap(),
            "--pubkey",
            pk.to_str().unwrap(),
            "--format",
            "json",
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let out = String::from_utf8_lossy(&output.stdout);
    assert!(
        out.contains("unproven") || out.contains("r2_stripped") || out.contains("pack_anchored"),
        "{out}"
    );
}

#[test]
fn malformed_exit_2() {
    let dir = tempdir().unwrap();
    let pack = dir.path().join("bad.json");
    fs::write(&pack, b"not-json").unwrap();
    let pk = dir.path().join("pk.hex");
    fs::write(&pk, "00".repeat(32)).unwrap();
    Command::cargo_bin("redact-verify")
        .unwrap()
        .args([
            "--pack",
            pack.to_str().unwrap(),
            "--pubkey",
            pk.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}
