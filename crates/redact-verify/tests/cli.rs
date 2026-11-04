mod common;

use assert_cmd::Command;
use common::valid_fixture;
use std::fs;
use tempfile::tempdir;

#[test]
fn cli_passes_locally_and_online_flag_is_reserved_offline() {
    let fixture = valid_fixture();
    let dir = tempdir().unwrap();
    let pack = dir.path().join("pack.json");
    let key = dir.path().join("chain.pub");
    fs::write(&pack, fixture.raw).unwrap();
    fs::write(
        &key,
        hex::encode(fixture.signing_key.verifying_key().to_bytes()),
    )
    .unwrap();
    let output = Command::cargo_bin("redact-verify")
        .unwrap()
        .args([
            "--pack",
            pack.to_str().unwrap(),
            "--pubkey",
            key.to_str().unwrap(),
            "--format",
            "json",
            "--online",
        ])
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["result"], "pass");
    assert!(String::from_utf8_lossy(&output.stderr).contains(
        "--online is reserved; verification remains offline and no network calls are made."
    ));
}

#[test]
fn cli_malformed_pack_exits_unproven_and_keys_are_exclusive() {
    let dir = tempdir().unwrap();
    let pack = dir.path().join("pack.json");
    let key = dir.path().join("chain.pub");
    let keys = dir.path().join("keys.json");
    fs::write(&pack, b"not-json").unwrap();
    fs::write(&key, "00").unwrap();
    fs::write(&keys, "{}").unwrap();
    let output = Command::cargo_bin("redact-verify")
        .unwrap()
        .args([
            "--pack",
            pack.to_str().unwrap(),
            "--pubkey",
            key.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("unproven"));

    Command::cargo_bin("redact-verify")
        .unwrap()
        .args([
            "--pack",
            pack.to_str().unwrap(),
            "--pubkey",
            key.to_str().unwrap(),
            "--keys",
            keys.to_str().unwrap(),
        ])
        .assert()
        .code(2);
}
