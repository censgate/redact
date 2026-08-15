// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Runtime loading of YAML pattern packs into a [`redact_core::Recognizer`].
//!
//! Operators point the gateway at files or directories under `packs.paths`. Each
//! YAML document follows the public pattern-pack schema shipped in
//! `/patterns/**/*.yaml`. Patterns are compiled once at load time; a single
//! bad third-party regex is skipped (and reported) rather than taking the
//! process down.

use std::collections::BTreeSet;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;
use serde::Deserialize;
use thiserror::Error;

use redact_core::types::{EntityType, RecognizerResult};
use redact_core::Recognizer;

fn default_true() -> bool {
    true
}

fn default_confidence() -> f32 {
    0.5
}

/// Errors raised while discovering or parsing pattern packs.
#[derive(Debug, Error)]
pub enum PackError {
    /// A configured path does not exist on disk.
    #[error("pattern pack path does not exist: {0}")]
    PathNotFound(PathBuf),

    /// The path could not be read.
    #[error("failed to read pattern pack {path}: {source}")]
    Io {
        /// Path that failed.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// YAML contents could not be deserialized.
    #[error("failed to parse pattern pack {origin}: {message}")]
    Parse {
        /// File path or logical origin label.
        origin: String,
        /// Human-readable parse failure.
        message: String,
    },
}

/// Summary of a [`load_packs`] invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackLoadReport {
    /// Number of YAML pack documents successfully parsed.
    pub packs_loaded: usize,
    /// Number of enabled patterns whose regex compiled.
    pub patterns_loaded: usize,
    /// Number of patterns skipped (invalid regex, or similar).
    pub patterns_skipped: usize,
    /// Absolute or relative paths of pack files that contributed patterns.
    pub sources: Vec<PathBuf>,
    /// Non-fatal problems encountered while loading.
    pub errors: Vec<String>,
}

/// A deserialized YAML pattern pack document.
///
/// Unknown top-level fields are ignored so third-party packs can carry
/// extra metadata without breaking the gateway.
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PatternPack {
    /// Optional logical name; when absent, loaders derive one from the
    /// file stem or the `origin` argument to [`load_pack_str`].
    #[serde(default)]
    pub name: Option<String>,
    /// Schema / pack format version.
    #[serde(default)]
    pub version: Option<String>,
    /// Framework label (for example `"UK-GDPR"`).
    #[serde(default)]
    pub framework: Option<String>,
    /// Jurisdiction label.
    #[serde(default)]
    pub jurisdiction: Option<String>,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Last-updated date string from the pack author.
    #[serde(default)]
    pub last_updated: Option<String>,
    /// Pattern entries in this pack.
    #[serde(default)]
    pub patterns: Vec<PatternDefinition>,
}

/// A single detection pattern inside a [`PatternPack`].
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct PatternDefinition {
    /// Stable pattern identifier (required).
    pub id: String,
    /// Regular expression source (required).
    pub regex: String,
    /// Display name.
    #[serde(default)]
    pub name: Option<String>,
    /// Coarse category from the pack author (for example `"contact"`).
    #[serde(default)]
    pub category: Option<String>,
    /// Explicit entity type override (for example `"EMAIL_ADDRESS"`).
    #[serde(default)]
    pub entity_type: Option<String>,
    /// Detection confidence in `[0.0, 1.0]`. Defaults to `0.5`.
    #[serde(default = "default_confidence")]
    pub confidence: f32,
    /// Human-readable description.
    #[serde(default)]
    pub description: Option<String>,
    /// Illustrative matches.
    #[serde(default)]
    pub examples: Vec<String>,
    /// Suggested replacement token.
    #[serde(default)]
    pub replacement: Option<String>,
    /// When `false`, the pattern is ignored at load time. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

/// Resolve the [`EntityType`] for a pattern definition.
///
/// Resolution order:
/// 1. Explicit `entity_type` field, passed through [`EntityType::from`].
/// 2. Heuristic derived from `id`: strip a known scope prefix
///    (`global_`, `sec_`, `uk_`, `us_`, `hipaa_`, `ccpa_`), apply the
///    alias table below, then [`EntityType::from`].
/// 3. Fallback: uppercase `id` (or `category` when `id` is empty) via
///    [`EntityType::from`], which yields a built-in variant when the name
///    matches and [`EntityType::Custom`] otherwise.
///
/// Alias highlights (stem → entity name): `email` → `EMAIL_ADDRESS`,
/// `phone*` → `PHONE_NUMBER` (or `UK_PHONE_NUMBER` when the id is
/// `uk_phone`), `credit_card` → `CREDIT_CARD`, `iban` → `IBAN_CODE`,
/// `ssn` → `US_SSN`, `ni_number` → `UK_NINO`, `nhs_number` → `UK_NHS`,
/// `aws_access_key` → `AWS_ACCESS_KEY`, `github_token` → `GITHUB_TOKEN`,
/// `slack_token` → `SLACK_TOKEN`, `stripe_key` → `STRIPE_API_KEY`,
/// `jwt_token` → `JWT_TOKEN`, `ssh_private_key` → `PRIVATE_KEY`,
/// `db_connection_string` / `jdbc_url` → `DATABASE_CONNECTION_STRING`.
pub fn entity_type_for_pattern(def: &PatternDefinition) -> EntityType {
    if let Some(ref explicit) = def.entity_type {
        return EntityType::from(explicit.clone());
    }

    let id = def.id.as_str();
    if id.is_empty() {
        if let Some(ref category) = def.category {
            return EntityType::from(category.to_ascii_uppercase());
        }
        return EntityType::from("UNKNOWN".to_string());
    }

    if let Some(name) = alias_for_id(id) {
        return EntityType::from(name.to_string());
    }

    let stem = strip_scope_prefix(id);
    if let Some(name) = alias_for_stem(stem, id) {
        return EntityType::from(name.to_string());
    }

    EntityType::from(stem.to_ascii_uppercase())
}

fn strip_scope_prefix(id: &str) -> &str {
    for prefix in ["global_", "sec_", "uk_", "us_", "hipaa_", "ccpa_"] {
        if let Some(rest) = id.strip_prefix(prefix) {
            if !rest.is_empty() {
                return rest;
            }
        }
    }
    id
}

fn alias_for_id(id: &str) -> Option<&'static str> {
    Some(match id {
        "uk_phone" => "UK_PHONE_NUMBER",
        "uk_ni_number" => "UK_NINO",
        "uk_nhs_number" => "UK_NHS",
        "uk_passport" => "UK_PASSPORT_NUMBER",
        "uk_driving_licence" => "UK_DRIVER_LICENSE",
        "uk_postcode" => "UK_POSTCODE",
        "uk_sort_code" => "UK_SORT_CODE",
        "uk_company_number" => "UK_COMPANY_NUMBER",
        "ccpa_drivers_license" | "hipaa_certificate_numbers" => "US_DRIVER_LICENSE",
        "ccpa_ssn" | "hipaa_ssn" => "US_SSN",
        "ccpa_zip_code" | "hipaa_zip_code" => "US_ZIP_CODE",
        "hipaa_mrn" | "ccpa_medical_record" => "MEDICAL_RECORD_NUMBER",
        "sec_webhook_url" => "SLACK_WEBHOOK",
        _ => return None,
    })
}

fn alias_for_stem(stem: &str, full_id: &str) -> Option<&'static str> {
    Some(match stem {
        "email" => "EMAIL_ADDRESS",
        "phone" | "phone_intl" | "phone_common" => {
            if full_id.starts_with("uk_") {
                "UK_PHONE_NUMBER"
            } else {
                "PHONE_NUMBER"
            }
        }
        "credit_card" => "CREDIT_CARD",
        "iban" => "IBAN_CODE",
        "ipv4" | "ipv6" | "ip_address" | "ip_addresses" => "IP_ADDRESS",
        "mac_address" => "MAC_ADDRESS",
        "url" | "web_urls" => "URL",
        "domain" => "DOMAIN_NAME",
        "full_name" | "name" => "PERSON",
        "uuid" => "GUID",
        "hash_md5" => "MD5_HASH",
        "hash_sha256" => "SHA256_HASH",
        "ssn" => "US_SSN",
        "aws_access_key" => "AWS_ACCESS_KEY",
        "github_token" => "GITHUB_TOKEN",
        "slack_token" => "SLACK_TOKEN",
        "stripe_key" => "STRIPE_API_KEY",
        "google_api_key" => "GOOGLE_API_KEY",
        "jwt_token" => "JWT_TOKEN",
        "ssh_private_key" => "PRIVATE_KEY",
        "db_connection_string" | "jdbc_url" => "DATABASE_CONNECTION_STRING",
        "ni_number" => "UK_NINO",
        "nhs_number" => "UK_NHS",
        "passport" => "PASSPORT_NUMBER",
        "driving_licence" | "drivers_license" => "US_DRIVER_LICENSE",
        "postcode" => "UK_POSTCODE",
        "sort_code" => "UK_SORT_CODE",
        "company_number" => "UK_COMPANY_NUMBER",
        "zip_code" => "US_ZIP_CODE",
        "medical_record" | "mrn" => "MEDICAL_RECORD_NUMBER",
        "bank_account" | "account_number" | "account_numbers" => "US_BANK_NUMBER",
        "dates" | "date_iso" | "date_common" => "DATE_TIME",
        "coordinates" | "address" => "LOCATION",
        _ => return None,
    })
}

/// Parse a YAML pattern pack from an in-memory string.
///
/// `origin` is used in error messages and, when the document has no
/// `name` field, becomes the pack's logical name.
///
/// Documents are parsed strictly. A pack that does not parse is reported
/// rather than repaired, because silently rewriting a pattern would change
/// what it matches.
pub fn load_pack_str(yaml: &str, origin: &str) -> Result<PatternPack, PackError> {
    let mut pack: PatternPack = serde_norway::from_str(yaml).map_err(|e| PackError::Parse {
        origin: origin.to_string(),
        message: e.to_string(),
    })?;
    if pack.name.is_none() {
        pack.name = Some(pack_name_from_origin(origin));
    }
    Ok(pack)
}

fn pack_name_from_origin(origin: &str) -> String {
    let path = Path::new(origin);
    path.file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(origin)
        .to_string()
}

/// Load pattern packs from files and/or directories.
///
/// Each path may be a `*.yaml` / `*.yml` file or a directory (recursed in
/// sorted order). Non-YAML files inside directories are ignored. A missing
/// path is a hard [`PackError::PathNotFound`].
///
/// Returns [`None`] for the recognizer when zero patterns compiled
/// successfully.
pub fn load_packs(
    paths: &[PathBuf],
) -> Result<(Option<PackRecognizer>, PackLoadReport), PackError> {
    let mut report = PackLoadReport::default();
    let mut compiled: Vec<CompiledPattern> = Vec::new();
    let mut pack_names: BTreeSet<String> = BTreeSet::new();

    let mut files = Vec::new();
    for path in paths {
        collect_yaml_files(path, &mut files)?;
    }
    files.sort();
    files.dedup();

    for file in files {
        match load_pack_file(&file, &mut report, &mut compiled, &mut pack_names) {
            Ok(()) => {}
            Err(e) => report.errors.push(e.to_string()),
        }
    }

    if compiled.is_empty() {
        return Ok((None, report));
    }

    Ok((
        Some(PackRecognizer::from_compiled(
            pack_names.into_iter().collect(),
            compiled,
        )),
        report,
    ))
}

fn collect_yaml_files(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), PackError> {
    if !path.exists() {
        return Err(PackError::PathNotFound(path.to_path_buf()));
    }

    if path.is_file() {
        out.push(path.to_path_buf());
        return Ok(());
    }

    let mut entries = fs::read_dir(path)
        .map_err(|source| PackError::Io {
            path: path.to_path_buf(),
            source,
        })?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|source| PackError::Io {
            path: path.to_path_buf(),
            source,
        })?;
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let child = entry.path();
        if child.is_dir() {
            // Opt-in / quarantined trees are never auto-discovered, even when
            // the operator points CENSGATE_PATTERN_PACKS at the packs root.
            // An explicit file path still loads.
            if is_skipped_pack_dir(&child) {
                continue;
            }
            collect_yaml_files(&child, out)?;
        } else if is_yaml_path(&child) {
            out.push(child);
        }
    }
    Ok(())
}

fn is_yaml_path(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some("yaml" | "yml")
    )
}

fn is_skipped_pack_dir(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("optional" | "quarantine")
    )
}

fn load_pack_file(
    path: &Path,
    report: &mut PackLoadReport,
    compiled: &mut Vec<CompiledPattern>,
    pack_names: &mut BTreeSet<String>,
) -> Result<(), PackError> {
    let yaml = fs::read_to_string(path).map_err(|source| PackError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let origin = path.display().to_string();
    let pack = load_pack_str(&yaml, &origin)?;
    let pack_name = pack
        .name
        .clone()
        .unwrap_or_else(|| pack_name_from_origin(&origin));

    compile_pack_patterns(&pack_name, &pack, report, compiled);
    report.packs_loaded += 1;
    report.sources.push(path.to_path_buf());
    pack_names.insert(pack_name);
    Ok(())
}

fn compile_pack_patterns(
    pack_name: &str,
    pack: &PatternPack,
    report: &mut PackLoadReport,
    compiled: &mut Vec<CompiledPattern>,
) {
    for pattern in &pack.patterns {
        if !pattern.enabled {
            continue;
        }
        match Regex::new(&pattern.regex) {
            Ok(regex) => {
                compiled.push(CompiledPattern {
                    pack_name: pack_name.to_string(),
                    pattern_id: pattern.id.clone(),
                    entity_type: entity_type_for_pattern(pattern),
                    regex,
                    confidence: pattern.confidence.clamp(0.0, 1.0),
                });
                report.patterns_loaded += 1;
            }
            Err(err) => {
                tracing::warn!(
                    pack = %pack_name,
                    pattern_id = %pattern.id,
                    error = %err,
                    "skipping pattern with invalid regex"
                );
                report.patterns_skipped += 1;
                report.errors.push(format!(
                    "pack `{pack_name}` pattern `{}`: invalid regex: {err}",
                    pattern.id
                ));
            }
        }
    }
}

#[derive(Clone)]
struct CompiledPattern {
    pack_name: String,
    pattern_id: String,
    entity_type: EntityType,
    regex: Regex,
    confidence: f32,
}

impl fmt::Debug for CompiledPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledPattern")
            .field("pack_name", &self.pack_name)
            .field("pattern_id", &self.pattern_id)
            .field("entity_type", &self.entity_type)
            .field("regex", &self.regex.as_str())
            .field("confidence", &self.confidence)
            .finish()
    }
}

/// Recognizer backed by one or more loaded YAML pattern packs.
#[derive(Debug, Clone)]
pub struct PackRecognizer {
    recognizer_name: String,
    pack_names: Vec<String>,
    patterns: Vec<CompiledPattern>,
    supported_entities: Vec<EntityType>,
    min_score: f32,
}

impl PackRecognizer {
    fn from_compiled(pack_names: Vec<String>, patterns: Vec<CompiledPattern>) -> Self {
        let supported_entities = unique_entities(&patterns);
        Self {
            recognizer_name: "pack_recognizer".to_string(),
            pack_names,
            patterns,
            supported_entities,
            min_score: 0.0,
        }
    }

    /// Logical names of packs currently included in this recognizer.
    pub fn pack_names(&self) -> &[String] {
        &self.pack_names
    }

    /// Keep only patterns that belong to the named packs.
    ///
    /// An empty `names` slice keeps every pack (no-op filter). Unknown names
    /// are ignored.
    pub fn with_only_packs(mut self, names: &[String]) -> Self {
        if names.is_empty() {
            return self;
        }
        let allowed: BTreeSet<&str> = names.iter().map(String::as_str).collect();
        self.patterns
            .retain(|p| allowed.contains(p.pack_name.as_str()));
        self.pack_names.retain(|n| allowed.contains(n.as_str()));
        self.supported_entities = unique_entities(&self.patterns);
        self
    }

    /// Override the minimum confidence score applied during analysis.
    pub fn with_min_score(mut self, min_score: f32) -> Self {
        self.min_score = min_score.clamp(0.0, 1.0);
        self
    }

    /// Number of compiled patterns currently active.
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }
}

fn unique_entities(patterns: &[CompiledPattern]) -> Vec<EntityType> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for pattern in patterns {
        let key = pattern.entity_type.as_str().to_string();
        if seen.insert(key) {
            out.push(pattern.entity_type.clone());
        }
    }
    out
}

impl Recognizer for PackRecognizer {
    fn name(&self) -> &str {
        &self.recognizer_name
    }

    fn supported_entities(&self) -> &[EntityType] {
        &self.supported_entities
    }

    fn analyze(&self, text: &str, language: &str) -> anyhow::Result<Vec<RecognizerResult>> {
        if !self.supports_language(language) {
            return Ok(Vec::new());
        }

        let mut results = Vec::new();
        for pattern in &self.patterns {
            if pattern.confidence < self.min_score {
                continue;
            }
            for mat in pattern.regex.find_iter(text) {
                let score = pattern.confidence;
                if score < self.min_score {
                    continue;
                }
                results.push(
                    RecognizerResult::new(
                        pattern.entity_type.clone(),
                        mat.start(),
                        mat.end(),
                        score,
                        self.name(),
                    )
                    .with_text(text)
                    .with_context(serde_json::json!({
                        "pack": pattern.pack_name,
                        "pattern_id": pattern.pattern_id,
                    })),
                );
            }
        }
        Ok(results)
    }

    fn min_score(&self) -> f32 {
        self.min_score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_PACK: &str = r#"
version: "1.0"
framework: "Test"
patterns:
  - id: "global_email"
    name: "Email"
    category: "contact"
    regex: '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'
    confidence: 0.95
    enabled: true
  - id: "disabled_thing"
    regex: 'DISABLED'
    enabled: false
  - id: "low_conf"
    regex: 'LOWCONF'
    confidence: 0.2
    enabled: true
"#;

    #[test]
    fn parses_schema_with_defaults() {
        let pack = load_pack_str(
            r#"
patterns:
  - id: "only_required"
    regex: 'abc'
"#,
            "inline",
        )
        .unwrap();
        assert_eq!(pack.name.as_deref(), Some("inline"));
        assert_eq!(pack.patterns.len(), 1);
        let p = &pack.patterns[0];
        assert!(p.enabled);
        assert!((p.confidence - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn ignores_unknown_top_level_metadata() {
        let pack = load_pack_str(
            r#"
version: "1.0"
author: "third-party"
custom_meta: { foo: 1 }
patterns:
  - id: "x"
    regex: 'x'
"#,
            "custom.yaml",
        )
        .unwrap();
        assert_eq!(pack.patterns[0].id, "x");
    }

    #[test]
    fn disabled_patterns_are_not_compiled() {
        let pack = load_pack_str(SAMPLE_PACK, "sample").unwrap();
        let mut report = PackLoadReport::default();
        let mut compiled = Vec::new();
        compile_pack_patterns("sample", &pack, &mut report, &mut compiled);
        assert_eq!(report.patterns_loaded, 2);
        assert!(compiled.iter().all(|p| p.pattern_id != "disabled_thing"));
        let recognizer = PackRecognizer::from_compiled(vec!["sample".into()], compiled);
        let hits = recognizer.analyze("DISABLED LOWCONF", "en").unwrap();
        assert!(hits.iter().all(|h| h.text.as_deref() != Some("DISABLED")));
        assert!(hits.iter().any(|h| h.text.as_deref() == Some("LOWCONF")));
    }

    #[test]
    fn invalid_regex_is_skipped_and_reported() {
        let pack = load_pack_str(
            r#"
patterns:
  - id: "bad"
    regex: '(unclosed'
  - id: "good"
    regex: 'ok'
"#,
            "badpack",
        )
        .unwrap();
        let mut report = PackLoadReport::default();
        let mut compiled = Vec::new();
        compile_pack_patterns("badpack", &pack, &mut report, &mut compiled);
        assert_eq!(report.patterns_loaded, 1);
        assert_eq!(report.patterns_skipped, 1);
        assert_eq!(compiled.len(), 1);
        assert!(!report.errors.is_empty());
    }

    #[test]
    fn entity_type_mapping_uses_explicit_field() {
        let def = PatternDefinition {
            id: "global_email".into(),
            regex: "x".into(),
            name: None,
            category: Some("contact".into()),
            entity_type: Some("CREDIT_CARD".into()),
            confidence: 0.9,
            description: None,
            examples: vec![],
            replacement: None,
            enabled: true,
        };
        assert_eq!(entity_type_for_pattern(&def), EntityType::CreditCard);
    }

    #[test]
    fn entity_type_mapping_from_id_aliases() {
        let email = PatternDefinition {
            id: "global_email".into(),
            regex: "x".into(),
            name: None,
            category: Some("contact".into()),
            entity_type: None,
            confidence: 0.9,
            description: None,
            examples: vec![],
            replacement: None,
            enabled: true,
        };
        assert_eq!(entity_type_for_pattern(&email), EntityType::EmailAddress);

        let aws = PatternDefinition {
            id: "sec_aws_access_key".into(),
            regex: "x".into(),
            name: None,
            category: None,
            entity_type: None,
            confidence: 0.9,
            description: None,
            examples: vec![],
            replacement: None,
            enabled: true,
        };
        assert_eq!(entity_type_for_pattern(&aws), EntityType::AwsAccessKey);

        let nino = PatternDefinition {
            id: "uk_ni_number".into(),
            regex: "x".into(),
            name: None,
            category: None,
            entity_type: None,
            confidence: 0.9,
            description: None,
            examples: vec![],
            replacement: None,
            enabled: true,
        };
        assert_eq!(entity_type_for_pattern(&nino), EntityType::UkNino);

        let generic = PatternDefinition {
            id: "sec_generic_api_key".into(),
            regex: "x".into(),
            name: None,
            category: None,
            entity_type: None,
            confidence: 0.9,
            description: None,
            examples: vec![],
            replacement: None,
            enabled: true,
        };
        assert_ne!(
            entity_type_for_pattern(&generic),
            EntityType::PrivateKey,
            "generic api_key must not alias to PRIVATE_KEY"
        );
    }

    #[test]
    fn min_confidence_filters_low_scoring_patterns() {
        let pack = load_pack_str(SAMPLE_PACK, "sample").unwrap();
        let mut report = PackLoadReport::default();
        let mut compiled = Vec::new();
        compile_pack_patterns("sample", &pack, &mut report, &mut compiled);
        let recognizer =
            PackRecognizer::from_compiled(vec!["sample".into()], compiled).with_min_score(0.5);
        let text = "user@example.com LOWCONF";
        let hits = recognizer.analyze(text, "en").unwrap();
        assert!(hits
            .iter()
            .any(|h| h.entity_type == EntityType::EmailAddress));
        assert!(hits.iter().all(|h| h.text.as_deref() != Some("LOWCONF")));
        assert!((recognizer.min_score() - 0.5).abs() < f32::EPSILON);
    }

    #[test]
    fn with_only_packs_filters_by_pack_name() {
        let mut report = PackLoadReport::default();
        let mut compiled = Vec::new();
        let a = load_pack_str(
            r#"
patterns:
  - id: "global_email"
    regex: 'A_ONLY'
"#,
            "pack_a",
        )
        .unwrap();
        let b = load_pack_str(
            r#"
patterns:
  - id: "global_email"
    regex: 'B_ONLY'
"#,
            "pack_b",
        )
        .unwrap();
        compile_pack_patterns("pack_a", &a, &mut report, &mut compiled);
        compile_pack_patterns("pack_b", &b, &mut report, &mut compiled);
        let recognizer =
            PackRecognizer::from_compiled(vec!["pack_a".into(), "pack_b".into()], compiled)
                .with_only_packs(&["pack_a".to_string()]);
        assert_eq!(recognizer.pack_names(), &["pack_a".to_string()]);
        let hits = recognizer.analyze("A_ONLY B_ONLY", "en").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].text.as_deref(), Some("A_ONLY"));

        let keep_all = PackRecognizer::from_compiled(vec!["pack_a".into(), "pack_b".into()], {
            let mut report = PackLoadReport::default();
            let mut compiled = Vec::new();
            compile_pack_patterns("pack_a", &a, &mut report, &mut compiled);
            compile_pack_patterns("pack_b", &b, &mut report, &mut compiled);
            compiled
        })
        .with_only_packs(&[]);
        assert_eq!(keep_all.pack_names().len(), 2);
    }

    #[test]
    fn requires_id_and_regex() {
        let err = load_pack_str(
            r#"
patterns:
  - name: "missing id"
    regex: 'x'
"#,
            "bad",
        )
        .unwrap_err();
        assert!(matches!(err, PackError::Parse { .. }));
    }

    #[test]
    fn a_quote_inside_a_single_quoted_regex_is_doubled_per_yaml() {
        let pack = load_pack_str(
            r#"
patterns:
  - id: "sec_password_field"
    regex: '\b(?:password|secret)["\s:=]+([^\s"'']{8,})\b'
"#,
            "creds",
        )
        .unwrap();
        assert_eq!(pack.patterns.len(), 1);
        assert!(pack.patterns[0].regex.contains(r#"[^\s"']"#));
        Regex::new(&pack.patterns[0].regex).expect("regex compiles");
    }

    #[test]
    fn a_malformed_document_is_reported_rather_than_repaired() {
        // A stray `'` inside a single-quoted scalar is invalid YAML. Repairing
        // it in the loader would silently change what the pattern matches.
        let err = load_pack_str(
            r#"
patterns:
  - id: "broken"
    regex: '([^\s"\']{8,})'
"#,
            "creds",
        )
        .unwrap_err();
        assert!(matches!(err, PackError::Parse { .. }));
    }
}
