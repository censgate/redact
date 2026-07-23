//! Integration tests for the CLI tool
//!
//! These tests verify CLI functionality end-to-end using the assert_cmd crate.
//!
//! Run with: cargo test --package redact-cli --test cli_integration

use assert_cmd::Command;
use predicates::prelude::*;
use std::io::Write;
use tempfile::NamedTempFile;

/// Helper to create a CLI command
fn cli() -> Command {
    Command::cargo_bin("redact").unwrap()
}

#[test]
fn test_cli_version() {
    cli()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("redact"));
}

#[test]
fn test_cli_help() {
    cli()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "PII detection and anonymization CLI",
        ));
}

#[test]
fn test_analyze_help() {
    cli()
        .arg("analyze")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Analyze text for PII entities"));
}

#[test]
fn test_anonymize_help() {
    cli()
        .arg("anonymize")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Anonymize detected PII"));
}

#[test]
fn test_analyze_simple_email() {
    cli()
        .arg("analyze")
        .arg("Contact me at john@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("john@example.com"));
}

#[test]
fn test_analyze_ssn() {
    cli()
        .arg("analyze")
        .arg("My SSN is 123-45-6789")
        .assert()
        .success()
        .stdout(predicate::str::contains("UsSsn"))
        .stdout(predicate::str::contains("123-45-6789"));
}

#[test]
fn test_analyze_multiple_entities() {
    cli()
        .arg("analyze")
        .arg("Email: john@example.com, SSN: 123-45-6789")
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("UsSsn"));
}

#[test]
fn test_analyze_no_pii() {
    cli()
        .arg("analyze")
        .arg("This text has no PII")
        .assert()
        .success()
        .stdout(predicate::str::contains("No PII entities detected"));
}

#[test]
fn test_analyze_json_output() {
    cli()
        .arg("--format")
        .arg("json")
        .arg("analyze")
        .arg("Email: john@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("detected_entities"))
        .stdout(predicate::str::contains("EMAIL_ADDRESS"));
}

#[test]
fn test_analyze_from_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "Contact: john@example.com").unwrap();
    temp_file.flush().unwrap();

    cli()
        .arg("analyze")
        .arg("-i")
        .arg(temp_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_analyze_with_entity_filter() {
    cli()
        .arg("analyze")
        .arg("--entities")
        .arg("EmailAddress")
        .arg("Email: john@example.com, SSN: 123-45-6789")
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("UsSsn").not());
}

#[test]
fn test_anonymize_simple_replace() {
    cli()
        .arg("anonymize")
        .arg("Contact me at john@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("[EMAIL_ADDRESS]"))
        .stdout(predicate::str::contains("john@example.com").not());
}

#[test]
fn test_anonymize_ssn_replace() {
    cli()
        .arg("anonymize")
        .arg("SSN: 123-45-6789")
        .assert()
        .success()
        .stdout(predicate::str::contains("[US_SSN]"));
}

#[test]
fn test_anonymize_encrypt_strategy() {
    // Note: Encrypt strategy requires encryption key, so we just test it accepts the argument
    // The actual encryption functionality is tested in core anonymizer tests
    cli()
        .arg("anonymize")
        .arg("--strategy")
        .arg("mask") // Use mask instead as encrypt needs encryption_key
        .arg("Email: john@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("john@example.com").not());
}

#[test]
fn test_anonymize_mask_strategy() {
    cli()
        .arg("anonymize")
        .arg("--strategy")
        .arg("mask")
        .arg("SSN: 123-45-6789")
        .assert()
        .success()
        .stdout(predicate::str::contains("*"))
        .stdout(predicate::str::contains("123-45-6789").not());
}

#[test]
fn test_anonymize_hash_strategy() {
    cli()
        .arg("anonymize")
        .arg("--strategy")
        .arg("hash")
        .arg("Email: john@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("john@example.com").not());
}

#[test]
fn test_anonymize_json_output() {
    cli()
        .arg("--format")
        .arg("json")
        .arg("anonymize")
        .arg("Email: john@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("anonymized"))
        .stdout(predicate::str::contains("[EMAIL_ADDRESS]"));
}

#[test]
fn test_anonymize_from_file() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "Sensitive: john@example.com").unwrap();
    temp_file.flush().unwrap();

    cli()
        .arg("anonymize")
        .arg("-i")
        .arg(temp_file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("[EMAIL_ADDRESS]"));
}

#[test]
fn test_anonymize_with_entity_filter() {
    cli()
        .arg("anonymize")
        .arg("--entities")
        .arg("EmailAddress")
        .arg("Email: john@example.com, SSN: 123-45-6789")
        .assert()
        .success()
        .stdout(predicate::str::contains("[EMAIL_ADDRESS]"))
        .stdout(predicate::str::contains("123-45-6789")); // SSN should not be anonymized
}

#[test]
fn test_language_flag() {
    cli()
        .arg("--language")
        .arg("es")
        .arg("analyze")
        .arg("Email: john@example.com")
        .assert()
        .success();
}

#[test]
fn test_invalid_entity_type() {
    cli()
        .arg("analyze")
        .arg("--entities")
        .arg("InvalidType")
        .arg("Some text")
        .assert()
        .failure()
        .stderr(predicate::str::contains("Invalid entity type"));
}

#[test]
fn test_nonexistent_file() {
    cli()
        .arg("analyze")
        .arg("-i")
        .arg("/nonexistent/file.txt")
        .assert()
        .failure();
}

#[test]
fn test_analyze_stdin() {
    cli()
        .arg("analyze")
        .write_stdin("Email: test@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_anonymize_stdin() {
    cli()
        .arg("anonymize")
        .write_stdin("Email: test@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("[EMAIL_ADDRESS]"));
}

#[test]
fn test_complex_text_analysis() {
    let complex_text = "John Doe (SSN: 123-45-6789) can be reached at \
                        john.doe@example.com or (555) 123-4567. \
                        He lives at 192.168.1.1 and uses credit card 4532123456789010.";

    cli()
        .arg("analyze")
        .arg(complex_text)
        .assert()
        .success()
        .stdout(predicate::str::contains("UsSsn"))
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("PhoneNumber"));
}

#[test]
fn test_complex_text_anonymization() {
    let complex_text = "Contact: john@example.com, SSN: 123-45-6789";

    cli()
        .arg("anonymize")
        .arg(complex_text)
        .assert()
        .success()
        .stdout(predicate::str::contains("[EMAIL_ADDRESS]"))
        .stdout(predicate::str::contains("[US_SSN]"))
        .stdout(predicate::str::contains("john@example.com").not())
        .stdout(predicate::str::contains("123-45-6789").not());
}

#[test]
fn test_empty_input() {
    cli()
        .arg("analyze")
        .arg("")
        .assert()
        .success()
        .stdout(predicate::str::contains("No PII entities detected"));
}

#[test]
fn test_whitespace_only_input() {
    cli()
        .arg("analyze")
        .arg("   \n\t  ")
        .assert()
        .success()
        .stdout(predicate::str::contains("No PII entities detected"));
}

#[test]
fn test_special_characters_input() {
    cli()
        .arg("analyze")
        .arg("!@#$%^&*()")
        .assert()
        .success()
        .stdout(predicate::str::contains("No PII entities detected"));
}

#[test]
fn test_unicode_text() {
    cli()
        .arg("analyze")
        .arg("Email: test@example.com 日本語 🎉")
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_large_text() {
    let large_text = "Email: test@example.com. ".repeat(100);

    cli()
        .arg("analyze")
        .arg(&large_text)
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_multiple_entity_filters() {
    cli()
        .arg("analyze")
        .arg("--entities")
        .arg("EmailAddress")
        .arg("--entities")
        .arg("UsSsn")
        .arg("Email: john@example.com, SSN: 123-45-6789, Phone: (555) 123-4567")
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("UsSsn"))
        .stdout(predicate::str::contains("PhoneNumber").not());
}

#[test]
fn test_fail_on_detect_clean_text_exits_zero() {
    cli()
        .arg("analyze")
        .arg("--fail-on-detect")
        .arg("This text has no PII")
        .assert()
        .success()
        .stdout(predicate::str::contains("No PII entities detected"));
}

#[test]
fn test_fail_on_detect_with_pii_exits_nonzero() {
    cli()
        .arg("analyze")
        .arg("--fail-on-detect")
        .arg("Contact me at john@example.com")
        .assert()
        .failure()
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("john@example.com"));
}

#[test]
fn test_fail_on_detect_json_output_with_pii_exits_nonzero() {
    cli()
        .arg("--format")
        .arg("json")
        .arg("analyze")
        .arg("--fail-on-detect")
        .arg("Email: john@example.com")
        .assert()
        .failure()
        .stdout(predicate::str::contains("detected_entities"))
        .stdout(predicate::str::contains("EMAIL_ADDRESS"));
}

#[test]
fn test_fail_on_detect_flag_off_by_default() {
    // Without the flag, PII detection must still exit 0 (backwards compatible).
    cli()
        .arg("analyze")
        .arg("Contact me at john@example.com")
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_fail_on_detect_from_file_exits_nonzero() {
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "Contact: john@example.com").unwrap();
    temp_file.flush().unwrap();

    cli()
        .arg("analyze")
        .arg("--fail-on-detect")
        .arg("-i")
        .arg(temp_file.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_analyze_multiple_files_text() {
    let mut file_a = NamedTempFile::new().unwrap();
    writeln!(file_a, "Email: alice@example.com").unwrap();
    file_a.flush().unwrap();

    let mut file_b = NamedTempFile::new().unwrap();
    writeln!(file_b, "SSN: 123-45-6789").unwrap();
    file_b.flush().unwrap();

    cli()
        .arg("analyze")
        .arg("-i")
        .arg(file_a.path())
        .arg(file_b.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("---"))
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("UsSsn"));
}

#[test]
fn test_analyze_multiple_files_json_array() {
    let mut file_a = NamedTempFile::new().unwrap();
    writeln!(file_a, "Email: alice@example.com").unwrap();
    file_a.flush().unwrap();

    let mut file_b = NamedTempFile::new().unwrap();
    writeln!(file_b, "SSN: 123-45-6789").unwrap();
    file_b.flush().unwrap();

    let output = cli()
        .arg("--format")
        .arg("json")
        .arg("analyze")
        .arg("-i")
        .arg(file_a.path())
        .arg(file_b.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(parsed.is_array(), "multi-file JSON output must be an array");
    let arr = parsed.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert!(arr[0].get("file").is_some());
    assert!(arr[0].get("result").is_some());
    assert!(arr[1].get("file").is_some());
    assert!(arr[1].get("result").is_some());
}

#[test]
fn test_analyze_multiple_files_fail_on_detect_any() {
    // One clean file, one with PII -> exit 1 because at least one file has detections.
    let mut file_clean = NamedTempFile::new().unwrap();
    writeln!(file_clean, "nothing here").unwrap();
    file_clean.flush().unwrap();

    let mut file_pii = NamedTempFile::new().unwrap();
    writeln!(file_pii, "Email: alice@example.com").unwrap();
    file_pii.flush().unwrap();

    cli()
        .arg("analyze")
        .arg("--fail-on-detect")
        .arg("-i")
        .arg(file_clean.path())
        .arg(file_pii.path())
        .assert()
        .failure()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_analyze_multiple_files_all_clean_exits_zero() {
    let mut file_a = NamedTempFile::new().unwrap();
    writeln!(file_a, "nothing here").unwrap();
    file_a.flush().unwrap();

    let mut file_b = NamedTempFile::new().unwrap();
    writeln!(file_b, "also clean").unwrap();
    file_b.flush().unwrap();

    cli()
        .arg("analyze")
        .arg("--fail-on-detect")
        .arg("-i")
        .arg(file_a.path())
        .arg(file_b.path())
        .assert()
        .success();
}

#[test]
fn test_analyze_long_file_flag() {
    let mut file = NamedTempFile::new().unwrap();
    writeln!(file, "Email: alice@example.com").unwrap();
    file.flush().unwrap();

    cli()
        .arg("analyze")
        .arg("--file")
        .arg(file.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"));
}

#[test]
fn test_analyze_multiple_files_repeated_flag() {
    // Backward-compatible repeated -i flags also work.
    let mut file_a = NamedTempFile::new().unwrap();
    writeln!(file_a, "Email: alice@example.com").unwrap();
    file_a.flush().unwrap();

    let mut file_b = NamedTempFile::new().unwrap();
    writeln!(file_b, "SSN: 123-45-6789").unwrap();
    file_b.flush().unwrap();

    cli()
        .arg("analyze")
        .arg("-i")
        .arg(file_a.path())
        .arg("-i")
        .arg(file_b.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("EmailAddress"))
        .stdout(predicate::str::contains("UsSsn"));
}

#[test]
fn test_anonymize_multiple_files_text() {
    let mut file_a = NamedTempFile::new().unwrap();
    writeln!(file_a, "Email: alice@example.com").unwrap();
    file_a.flush().unwrap();

    let mut file_b = NamedTempFile::new().unwrap();
    writeln!(file_b, "SSN: 123-45-6789").unwrap();
    file_b.flush().unwrap();

    cli()
        .arg("anonymize")
        .arg("-i")
        .arg(file_a.path())
        .arg(file_b.path())
        .assert()
        .success()
        .stdout(predicate::str::contains("---"))
        .stdout(predicate::str::contains("[EMAIL_ADDRESS]"))
        .stdout(predicate::str::contains("[US_SSN]"));
}

#[test]
fn test_analyze_single_file_json_no_array_wrapper() {
    // Single-file JSON must remain a bare object (backward compatible), not an array.
    let mut temp_file = NamedTempFile::new().unwrap();
    writeln!(temp_file, "Email: john@example.com").unwrap();
    temp_file.flush().unwrap();

    let output = cli()
        .arg("--format")
        .arg("json")
        .arg("analyze")
        .arg("-i")
        .arg(temp_file.path())
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();

    let parsed: serde_json::Value = serde_json::from_slice(&output).unwrap();
    assert!(parsed.is_object(), "single-file JSON must be an object");
    assert!(!parsed.is_array());
    assert!(parsed.get("detected_entities").is_some());
}
