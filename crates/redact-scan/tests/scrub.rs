use redact_scan::error::ScanError;
use redact_scan::scrub::{scrub, scrub_secret};

#[test]
fn new_scrubs_url_password_from_display_and_debug() {
    let secret = "super-secret-db-pass";
    let raw = format!("password authentication failed for postgres://app:{secret}@db/prod");
    let err = ScanError::new(raw);
    let shown = format!("{err}");
    let debug = format!("{err:?}");
    assert!(!shown.contains(secret));
    assert!(!debug.contains(secret));
    assert!(shown.contains("app:***@"));
}

#[test]
fn new_scrubs_percent_encoded_password() {
    let err = ScanError::new("connect postgres://app:p%40ssword@db/prod failed");
    let shown = format!("{err}");
    let debug = format!("{err:?}");
    assert!(!shown.contains("p%40ssword"));
    assert!(!shown.contains("p@ssword"));
    assert!(!shown.contains("ssword"));
    assert!(!debug.contains("p@ssword"));
}

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
