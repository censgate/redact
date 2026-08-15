// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Integration tests for YAML pattern pack loading.

use std::path::PathBuf;
use std::sync::Arc;

use redact_core::types::EntityType;
use redact_core::{AnalyzerEngine, Recognizer};
use redact_gateway::packs::{load_packs, PackError};
use tempfile::tempdir;

fn repo_patterns_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../patterns")
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/packs")
}

#[test]
fn loads_all_shipped_repo_pattern_packs() {
    let patterns = repo_patterns_dir();
    assert!(
        patterns.is_dir(),
        "expected shipped packs at {}",
        patterns.display()
    );

    let (recognizer, report) = load_packs(&[patterns]).expect("repo packs should load");
    let recognizer = recognizer.expect("repo packs should yield a recognizer");

    assert_eq!(report.packs_loaded, 5, "expected all five shipped packs");
    assert!(
        report.patterns_loaded > 0,
        "expected nonzero patterns, got {}",
        report.patterns_loaded
    );
    assert_eq!(
        report.patterns_skipped, 0,
        "shipped packs must compile: {:?}",
        report.errors
    );
    assert!(report.sources.len() >= 5);

    // Assemble at run time so committed source has no contiguous secret-shaped
    // literal (GitHub secret scanning false positive).
    let aws_key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let text = format!("Email user@example.com and key {aws_key}");
    let hits = recognizer.analyze(&text, "en").expect("analyze");
    assert!(
        hits.iter().any(|h| {
            h.entity_type == EntityType::EmailAddress
                && h.text.as_deref() == Some("user@example.com")
        }),
        "email not detected: {hits:?}"
    );
    assert!(
        hits.iter().any(|h| {
            h.entity_type == EntityType::AwsAccessKey && h.text.as_deref() == Some(aws_key.as_str())
        }),
        "aws key not detected: {hits:?}"
    );
}

#[test]
fn loads_fixture_directory_recursively_and_ignores_non_yaml() {
    let tmp = tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("nested")).unwrap();
    std::fs::copy(
        fixtures_dir().join("basic.yaml"),
        tmp.path().join("basic.yaml"),
    )
    .unwrap();
    std::fs::copy(
        fixtures_dir().join("nested/aws.yaml"),
        tmp.path().join("nested/aws.yaml"),
    )
    .unwrap();
    std::fs::copy(
        fixtures_dir().join("invalid_regex.yaml"),
        tmp.path().join("invalid_regex.yaml"),
    )
    .unwrap();
    std::fs::write(tmp.path().join("readme.txt"), "not a pack").unwrap();

    let (recognizer, report) = load_packs(&[tmp.path().to_path_buf()]).expect("fixtures load");
    let recognizer = recognizer.expect("fixture recognizer");

    assert!(report.packs_loaded >= 2);
    assert!(report.patterns_loaded >= 2);
    assert!(
        report.patterns_skipped >= 1,
        "invalid_regex.yaml should skip"
    );
    assert!(
        !report.sources.iter().any(|p| p.ends_with("readme.txt")),
        "non-yaml files must be ignored"
    );

    let aws_key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
    let hits = recognizer
        .analyze(&format!("ping user@example.com {aws_key}"), "en")
        .unwrap();
    assert!(hits
        .iter()
        .any(|h| h.text.as_deref() == Some("user@example.com")));
    assert!(hits
        .iter()
        .any(|h| h.text.as_deref() == Some(aws_key.as_str())));
}

#[test]
fn loads_from_temp_directory() {
    let tmp = tempdir().unwrap();
    let pack_path = tmp.path().join("temp_pack.yaml");
    std::fs::write(
        &pack_path,
        r#"
version: "1.0"
name: "temp_pack"
patterns:
  - id: "global_email"
    regex: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    confidence: 0.9
    enabled: true
"#,
    )
    .unwrap();

    let (recognizer, report) = load_packs(&[tmp.path().to_path_buf()]).unwrap();
    let recognizer = recognizer.unwrap();
    assert_eq!(report.packs_loaded, 1);
    assert_eq!(report.patterns_loaded, 1);
    assert!(recognizer.pack_names().contains(&"temp_pack".to_string()));

    let hits = recognizer.analyze("a@b.co", "en").unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].entity_type, EntityType::EmailAddress);
}

#[test]
fn missing_path_is_a_hard_error() {
    let missing = PathBuf::from("/tmp/redact-gateway-packs-definitely-missing-xyz");
    let err = load_packs(std::slice::from_ref(&missing)).unwrap_err();
    match err {
        PackError::PathNotFound(path) => assert_eq!(path, missing),
        other => panic!("expected PathNotFound, got {other}"),
    }
}

#[test]
fn recognizer_composes_with_analyzer_engine() {
    let basic = fixtures_dir().join("basic.yaml");
    let (recognizer, report) = load_packs(&[basic]).unwrap();
    assert_eq!(report.patterns_loaded, 1);
    let recognizer = recognizer.unwrap();

    let mut engine = AnalyzerEngine::new();
    engine
        .recognizer_registry_mut()
        .add_recognizer(Arc::new(recognizer));

    let result = engine
        .analyze("Contact alice@example.com please", None)
        .unwrap();
    assert!(
        result
            .detected_entities
            .iter()
            .any(|e| e.text.as_deref() == Some("alice@example.com")),
        "engine detections: {:?}",
        result.detected_entities
    );
}

fn pack_noise_corpus() -> String {
    // SHA-1 (40 hex), MD5 (32 hex), a short assignment, a generic hooks URL,
    // and a Stripe publishable key. None of these should become secret types
    // via the default pack path or a quarantined credentials.yaml.
    format!(
        "sha1 {sha1} md5 {md5} api_key=not-a-secret hooks {hooks} stripe {pk}",
        sha1 = "a".repeat(40),
        md5 = "b".repeat(32),
        hooks = "https://hooks.zapier.com/hooks/catch/123456/abcdef/",
        pk = format!("{}{}_{}", "pk", "_test", "a".repeat(24)),
    )
}

fn assert_no_pack_secret_bombs(hits: &[redact_core::types::RecognizerResult], label: &str) {
    let forbidden = hits.iter().filter(|h| {
        matches!(
            h.entity_type,
            EntityType::PrivateKey | EntityType::SlackWebhook | EntityType::StripeApiKey
        ) || matches!(
            &h.entity_type,
            EntityType::Custom(name)
                if name.eq_ignore_ascii_case("AWS_SECRET_KEY")
                    || name.eq_ignore_ascii_case("AZURE_KEY")
                    || name.eq_ignore_ascii_case("API_KEY")
                    || name.eq_ignore_ascii_case("GENERIC_API_KEY")
        )
    });
    let leaked: Vec<_> = forbidden
        .map(|h| format!("{:?} {:?}", h.entity_type, h.text))
        .collect();
    assert!(
        leaked.is_empty(),
        "{label}: unexpected secret-shaped pack hits: {leaked:?} from {hits:?}"
    );
}

#[test]
fn default_compliance_pii_path_emits_no_secret_bombs() {
    let patterns = repo_patterns_dir();
    let paths = [patterns.join("compliance"), patterns.join("pii")];
    let (recognizer, report) = load_packs(&paths).expect("default packs should load");
    assert!(report.packs_loaded >= 2, "report: {report:?}");
    let recognizer = recognizer.expect("default packs should yield a recognizer");

    let hits = recognizer
        .analyze(&pack_noise_corpus(), "en")
        .expect("analyze");
    assert_no_pack_secret_bombs(&hits, "default compliance:pii path");
}

#[test]
fn explicit_credentials_yaml_emits_no_secret_bombs() {
    let credentials = repo_patterns_dir().join("security/credentials.yaml");
    let (recognizer, report) = load_packs(&[credentials]).expect("credentials.yaml should parse");
    assert_eq!(report.patterns_skipped, 0, "errors: {:?}", report.errors);
    // Disabled bombs must not compile. Prefix rules that remain (AWS AKIA,
    // GitHub, Slack token, Google, JWT, PEM, DB URL) may still load.
    let corpus = pack_noise_corpus();
    match recognizer {
        None => {}
        Some(recognizer) => {
            let hits = recognizer.analyze(&corpus, "en").expect("analyze");
            assert_no_pack_secret_bombs(&hits, "explicit credentials.yaml");
        }
    }
}

#[test]
fn optional_and_quarantine_dirs_are_not_auto_discovered() {
    let tmp = tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join("optional")).unwrap();
    std::fs::create_dir_all(tmp.path().join("quarantine")).unwrap();
    std::fs::write(
        tmp.path().join("optional/hidden.yaml"),
        r#"
name: hidden_optional
patterns:
  - id: "global_email"
    regex: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    enabled: true
"#,
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("quarantine/hidden.yaml"),
        r#"
name: hidden_quarantine
patterns:
  - id: "global_email"
    regex: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    enabled: true
"#,
    )
    .unwrap();

    let (recognizer, report) = load_packs(&[tmp.path().to_path_buf()]).unwrap();
    assert_eq!(report.packs_loaded, 0, "skipped dirs must not load: {report:?}");
    assert!(recognizer.is_none());
}
