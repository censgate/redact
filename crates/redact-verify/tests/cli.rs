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

fn run_cli(pack: &std::path::Path, key: &std::path::Path, format: &str) -> (Option<i32>, String) {
    let out = Command::cargo_bin("redact-verify")
        .unwrap()
        .args([
            "--pack",
            pack.to_str().unwrap(),
            "--pubkey",
            key.to_str().unwrap(),
            "--format",
            format,
        ])
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
    )
}

#[test]
fn json_and_text_output_agree_on_pass_and_fail() {
    let fixture = valid_fixture();
    let dir = tempdir().unwrap();
    let key = dir.path().join("chain.pub");
    fs::write(
        &key,
        hex::encode(fixture.signing_key.verifying_key().to_bytes()),
    )
    .unwrap();

    let good = dir.path().join("good.json");
    fs::write(&good, &fixture.raw).unwrap();
    let mut env = fixture.envelope.clone();
    env["body_hash"] = serde_json::json!("00".repeat(32));
    let bad = dir.path().join("bad.json");
    fs::write(&bad, serde_json::to_vec(&env).unwrap()).unwrap();

    for (pack, expected) in [(&good, "pass"), (&bad, "fail")] {
        let (jc, js) = run_cli(pack, &key, "json");
        let (tc, ts) = run_cli(pack, &key, "text");
        assert_eq!(jc, tc, "exit codes differ");
        let j: serde_json::Value = serde_json::from_str(&js).unwrap();
        assert_eq!(j["result"], expected);
        let text: std::collections::HashMap<&str, &str> =
            ts.lines().filter_map(|l| l.split_once('=')).collect();
        assert_eq!(text["result"], j["result"].as_str().unwrap());
        assert_eq!(text["checked"], j["checked"].to_string());
        assert_eq!(text["erased"], j["erased"].to_string());
        for field in [
            "body_hash",
            "body_signature",
            "key_binding",
            "merkle_inclusion",
        ] {
            assert_eq!(text[field], j[field]["status"].as_str().unwrap(), "{field}");
        }
        assert_eq!(
            text["anchoring_status"],
            j["anchoring_status"].as_str().unwrap()
        );
        assert!(text["external_anchoring"]
            .starts_with(j["external_anchoring"]["status"].as_str().unwrap()));
        for issue in j["issues"].as_array().unwrap() {
            assert!(ts.contains(&format!("issue={}", issue["code"].as_str().unwrap())));
        }
    }
}
