use redact_scan::error::ScanError;
use redact_scan::scrub::{scrub, scrub_secret};

#[test]
fn password_absent_from_formatted_error() {
    let secret = "super-secret-db-pass";
    let raw = format!("password authentication failed for postgres://app:{secret}@db/prod");
    let err = ScanError::with_secret(raw, secret);
    let shown = format!("{err}");
    let debug = format!("{err:?}");
    assert!(!shown.contains(secret));
    assert!(!debug.contains(secret));
    assert!(!scrub(&shown).contains(secret));
}

#[test]
fn scrub_secret_replaces_raw_token() {
    let out = scrub_secret("boom hunter2 boom", "hunter2");
    assert!(!out.contains("hunter2"));
    assert!(out.contains("***"));
}
