// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! WebAssembly bindings for the Redact PII engine.
//!
//! ## Scope
//!
//! These bindings expose the **pattern-based** detection and anonymization from
//! [`redact_core`]: the compiled regex entity types (email, phone, SSN, credit cards,
//! IBAN, UK identifiers, crypto addresses, hashes, GUIDs, URLs, IP, dates,
//! secrets and credentials, ...).
//! No ML model is loaded, so the module stays small (~1-3 MB) and fits browser
//! and Cloudflare Workers limits.
//!
//! ## What is NOT available in WASM
//!
//! Contextual named-entity recognition — `PERSON`, `ORGANIZATION`, `LOCATION` in
//! prose like "John met Acme in Boston" — requires an ONNX transformer model
//! (~250-420 MB) plus the ONNX Runtime. That stack does not fit Cloudflare
//! Workers (128 MB isolate, 64 MiB bundle, ~50 ms CPU) and is impractical to
//! inline in a browser WASM module. For name-based detection, call the
//! `redact-api` `:full` service or Cloudflare Workers AI from a Worker and merge
//! the results. See the repository README "WebAssembly" section.
//!
//! ## Example (JavaScript)
//!
//! ```no_run
//! use redact_wasm::RedactEngine;
//! let engine = RedactEngine::new();
//! let analysis = engine.analyze("Contact john@example.com");
//! let redacted = engine.anonymize("Email: john@example.com", "replace");
//! let hashed = engine.anonymize_with_hash("Email: john@example.com", "app-secret-salt");
//! ```
//!
//! `analyze`, `anonymize`, and `anonymize_with_hash` return a JSON string.
//!
//! ## Supported WASM entry point
//!
//! Compile and consume **`redact-wasm`** for `wasm32-unknown-unknown`. Standalone
//! `redact-core` is not a supported WASM target: its RNG backends (`getrandom` /
//! `uuid` JS features) are wired only through this crate.

use redact_core::{
    anonymizers::{AnonymizationStrategy, AnonymizerConfig},
    AnalyzerEngine, EntityType,
};
use wasm_bindgen::prelude::*;

/// PII detection and anonymization engine (pattern-based, including secrets).
#[wasm_bindgen]
pub struct RedactEngine {
    engine: AnalyzerEngine,
}

#[wasm_bindgen]
impl RedactEngine {
    /// Create a new engine with the default pattern recognizer.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            engine: AnalyzerEngine::new(),
        }
    }

    /// Analyze `text` and return a JSON `AnalysisResult` string.
    ///
    /// Returns `{"error": "..."}` if analysis or serialization fails.
    pub fn analyze(&self, text: &str) -> String {
        match self.engine.analyze(text, Some("en")) {
            Ok(result) => serde_json::to_string(&result).unwrap_or_else(|_| {
                r#"{"error":"failed to serialize analysis result"}"#.to_string()
            }),
            Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
        }
    }

    /// Analyze `text` for the entity types in `entities_json` (JSON string array).
    pub fn analyze_with_entities(&self, text: &str, entities_json: &str) -> String {
        match parse_entity_list(entities_json) {
            Ok(types) => match self.engine.analyze_with_entities(text, &types, Some("en")) {
                Ok(result) => serde_json::to_string(&result).unwrap_or_else(|_| {
                    r#"{"error":"failed to serialize analysis result"}"#.to_string()
                }),
                Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
            },
            Err(msg) => serde_json::json!({ "error": msg }).to_string(),
        }
    }

    /// Analyze `text` with the listed entity types disabled (`entities_json` is a JSON array).
    pub fn analyze_excluding(&self, text: &str, entities_json: &str) -> String {
        match parse_entity_list(entities_json) {
            Ok(disabled) => {
                let keep: Vec<EntityType> = engine_entity_types(&self.engine)
                    .into_iter()
                    .filter(|t| !disabled.contains(t))
                    .collect();
                if keep.is_empty() {
                    return serde_json::json!({
                        "error": "analyze_excluding removed every entity type"
                    })
                    .to_string();
                }
                match self.engine.analyze_with_entities(text, &keep, Some("en")) {
                    Ok(result) => serde_json::to_string(&result).unwrap_or_else(|_| {
                        r#"{"error":"failed to serialize analysis result"}"#.to_string()
                    }),
                    Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
                }
            }
            Err(msg) => serde_json::json!({ "error": msg }).to_string(),
        }
    }

    /// Anonymize `text` with the given strategy and return a JSON `AnalysisResult`
    /// string (with `anonymized` populated).
    ///
    /// `strategy` is one of `replace` or `mask` (case-insensitive).
    ///
    /// `hash` is rejected here: unsalted hashes of low-entropy PII are enumerable.
    /// Call [`Self::anonymize_with_hash`] with a non-empty caller-provided salt instead.
    /// `encrypt` is also rejected (no key material in this two-argument binding).
    pub fn anonymize(&self, text: &str, strategy: &str) -> String {
        let strat = match parse_strategy(strategy) {
            Ok(s) => s,
            Err(msg) => return serde_json::json!({ "error": msg }).to_string(),
        };
        match strat {
            AnonymizationStrategy::Hash => {
                return serde_json::json!({
                    "error": "strategy 'hash' requires a non-empty salt; use anonymize_with_hash(text, salt)"
                })
                .to_string();
            }
            AnonymizationStrategy::Encrypt => {
                return serde_json::json!({
                    "error": "strategy 'encrypt' is not supported in the WASM binding (no key material)"
                })
                .to_string();
            }
            AnonymizationStrategy::Replace | AnonymizationStrategy::Mask => {}
            other => {
                return serde_json::json!({
                    "error": format!(
                        "strategy '{:?}' is not supported in the WASM binding; use replace or mask",
                        other
                    )
                })
                .to_string();
            }
        }
        let config = AnonymizerConfig {
            strategy: strat,
            ..Default::default()
        };
        self.run_anonymize(text, &config)
    }

    /// Anonymize `text` with the hash strategy using a required non-empty `salt`.
    ///
    /// The salt is caller-provided key material for deterministic pseudonymization.
    /// Empty salt is rejected; a random salt is never generated (that would break
    /// stable pseudonyms across runs).
    pub fn anonymize_with_hash(&self, text: &str, salt: &str) -> String {
        if salt.is_empty() {
            return serde_json::json!({
                "error": "hash salt must be a non-empty string (caller-provided key material)"
            })
            .to_string();
        }
        let config = AnonymizerConfig {
            strategy: AnonymizationStrategy::Hash,
            hash_salt: Some(salt.to_string()),
            ..Default::default()
        };
        self.run_anonymize(text, &config)
    }

    /// Return a JSON array of the entity type strings the pattern recognizer detects.
    ///
    /// Useful for callers to know which entities are available in the WASM build
    /// (versus NER-only types like `PERSON`/`ORGANIZATION`/`LOCATION`).
    pub fn supported_entities(&self) -> String {
        let mut labels: Vec<String> = engine_entity_types(&self.engine)
            .into_iter()
            .map(|t| t.as_str().to_string())
            .collect();
        labels.sort();
        serde_json::to_string(&labels).unwrap_or_else(|_| "[]".to_string())
    }
}

impl RedactEngine {
    fn run_anonymize(&self, text: &str, config: &AnonymizerConfig) -> String {
        match self.engine.analyze_and_anonymize(text, Some("en"), config) {
            Ok(result) => serde_json::to_string(&result).unwrap_or_else(|_| {
                r#"{"error":"failed to serialize anonymized result"}"#.to_string()
            }),
            Err(e) => serde_json::json!({ "error": e.to_string() }).to_string(),
        }
    }
}

fn engine_entity_types(engine: &AnalyzerEngine) -> Vec<EntityType> {
    let mut types = Vec::new();
    for recognizer in engine.recognizer_registry().recognizers() {
        for entity in recognizer.supported_entities() {
            if !types.contains(entity) {
                types.push(entity.clone());
            }
        }
    }
    types
}

fn parse_entity_list(json: &str) -> Result<Vec<EntityType>, String> {
    let labels: Vec<String> =
        serde_json::from_str(json).map_err(|e| format!("invalid entity list: {e}"))?;
    let mut types = Vec::with_capacity(labels.len());
    for label in labels {
        let parsed = EntityType::from(label.clone());
        if matches!(parsed, EntityType::Custom(_)) {
            return Err(format!("unknown entity type: {label}"));
        }
        types.push(parsed);
    }
    Ok(types)
}

fn parse_strategy(s: &str) -> Result<AnonymizationStrategy, String> {
    match s.to_ascii_lowercase().as_str() {
        "replace" => Ok(AnonymizationStrategy::Replace),
        "mask" => Ok(AnonymizationStrategy::Mask),
        "hash" => Ok(AnonymizationStrategy::Hash),
        "encrypt" => Ok(AnonymizationStrategy::Encrypt),
        other => Err(format!(
            "Unknown strategy '{}': expected one of replace, mask, hash, encrypt",
            other
        )),
    }
}

impl Default for RedactEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_engine_constructs() {
        let _ = RedactEngine::new();
    }

    #[test]
    fn analyze_detects_email() {
        let engine = RedactEngine::new();
        let json = engine.analyze("Contact john@example.com");
        assert!(json.contains("EMAIL_ADDRESS"));
        assert!(json.contains("detected_entities"));
    }

    #[test]
    fn analyze_clean_text_has_empty_entities() {
        let engine = RedactEngine::new();
        let json = engine.analyze("nothing to see here");
        assert!(json.contains("\"detected_entities\":[]"));
    }

    #[test]
    fn anonymize_replace_redacts_email() {
        let engine = RedactEngine::new();
        let json = engine.anonymize("Email: john@example.com", "replace");
        assert!(json.contains("[EMAIL_ADDRESS]"));
    }

    #[test]
    fn anonymize_mask_works() {
        let engine = RedactEngine::new();
        let json = engine.anonymize("Email: john@example.com", "mask");
        assert!(json.contains("anonymized"));
    }

    #[test]
    fn anonymize_unknown_strategy_returns_error_json() {
        let engine = RedactEngine::new();
        let json = engine.anonymize("Email: john@example.com", "bogus");
        assert!(json.contains("\"error\""));
        assert!(json.contains("Unknown strategy"));
    }

    #[test]
    fn anonymize_rejects_hash_without_salt() {
        let engine = RedactEngine::new();
        let json = engine.anonymize("Email: john@example.com", "hash");
        assert!(
            json.contains("\"error\""),
            "expected error JSON, got: {json}"
        );
        assert!(
            json.contains("anonymize_with_hash"),
            "error should point callers at anonymize_with_hash: {json}"
        );
        assert!(
            !json.contains("anonymized"),
            "hash must not run unsalted via anonymize: {json}"
        );
    }

    #[test]
    fn anonymize_rejects_encrypt() {
        let engine = RedactEngine::new();
        let json = engine.anonymize("Email: john@example.com", "encrypt");
        assert!(
            json.contains("\"error\""),
            "expected error JSON, got: {json}"
        );
        assert!(
            !json.contains("anonymized"),
            "encrypt must not run without key material: {json}"
        );
    }

    #[test]
    fn anonymize_with_hash_requires_non_empty_salt() {
        let engine = RedactEngine::new();
        let json = engine.anonymize_with_hash("Email: john@example.com", "");
        assert!(
            json.contains("\"error\""),
            "expected error JSON, got: {json}"
        );
        assert!(
            json.to_ascii_lowercase().contains("salt"),
            "error should mention salt: {json}"
        );
        assert!(
            !json.contains("anonymized"),
            "empty salt must not hash: {json}"
        );
    }

    #[test]
    fn anonymize_with_hash_redacts_with_salt() {
        let engine = RedactEngine::new();
        let json = engine.anonymize_with_hash("Email: john@example.com", "app-secret-salt");
        assert!(
            !json.contains("\"error\""),
            "salted hash should succeed: {json}"
        );
        let v: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
        let anonymized = v["anonymized"]["text"].as_str().expect("anonymized.text");
        assert!(
            !anonymized.contains("john@example.com"),
            "original email must be redacted: {anonymized}"
        );
        assert!(
            anonymized.contains("EMAIL_ADDRESS_"),
            "hash strategy uses EMAIL_ADDRESS_<digest> placeholders: {anonymized}"
        );
    }

    #[test]
    fn anonymize_with_hash_is_deterministic_for_same_salt() {
        let engine = RedactEngine::new();
        let a = engine.anonymize_with_hash("SSN 123-45-6789", "tenant-key");
        let b = engine.anonymize_with_hash("SSN 123-45-6789", "tenant-key");
        let va: serde_json::Value = serde_json::from_str(&a).unwrap();
        let vb: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(
            va["anonymized"]["text"], vb["anonymized"]["text"],
            "same salt must yield identical pseudonyms"
        );
        let c = engine.anonymize_with_hash("SSN 123-45-6789", "other-tenant-key");
        let vc: serde_json::Value = serde_json::from_str(&c).unwrap();
        assert_ne!(
            va["anonymized"]["text"], vc["anonymized"]["text"],
            "different salts must change the digest"
        );
    }

    #[test]
    fn supported_entities_lists_pattern_types_and_excludes_ner_types() {
        let engine = RedactEngine::new();
        let json = engine.supported_entities();
        let parsed: Vec<String> = serde_json::from_str(&json).unwrap();
        assert!(parsed.contains(&"EMAIL_ADDRESS".to_string()));
        assert!(parsed.contains(&"US_SSN".to_string()));
        assert!(parsed.contains(&"GENERIC_SECRET".to_string()));
        assert!(parsed.contains(&"AWS_ACCESS_KEY".to_string()));
        assert!(!parsed.contains(&"PERSON".to_string()));
        assert!(!parsed.contains(&"ORGANIZATION".to_string()));
        assert!(!parsed.contains(&"LOCATION".to_string()));
        let mut sorted = parsed.clone();
        sorted.sort();
        assert_eq!(parsed, sorted);
    }

    #[test]
    fn generic_secret_positive_includes_confidence() {
        let engine = RedactEngine::new();
        let secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let text = format!("api_key={secret}");
        let json = engine.analyze(&text);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let hit = v["detected_entities"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["entity_type"] == "GENERIC_SECRET")
            .expect("GENERIC_SECRET");
        let score = hit["score"].as_f64().expect("confidence/score present");
        assert!(
            (0.60..=0.85).contains(&score),
            "GENERIC_SECRET confidence must be in 0.60–0.85, got {score}"
        );
    }

    #[test]
    fn generic_secret_exclusion_password_stopword() {
        let engine = RedactEngine::new();
        let json = engine.analyze("password=password");
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let types: Vec<&str> = v["detected_entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["entity_type"].as_str().unwrap())
            .collect();
        assert!(!types.contains(&"GENERIC_SECRET"));
    }

    #[test]
    fn analyze_excluding_drops_generic_secret() {
        let engine = RedactEngine::new();
        let secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let text = format!("api_key={secret}");
        let all = engine.analyze(&text);
        let all_v: serde_json::Value = serde_json::from_str(&all).unwrap();
        let types: Vec<&str> = all_v["detected_entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["entity_type"].as_str().unwrap())
            .collect();
        assert!(types.contains(&"GENERIC_SECRET") || types.contains(&"MD5_HASH"));
        let filtered = engine.analyze_excluding(&text, r#"["GENERIC_SECRET"]"#);
        let filtered_v: serde_json::Value = serde_json::from_str(&filtered).unwrap();
        let filtered_types: Vec<&str> = filtered_v["detected_entities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["entity_type"].as_str().unwrap())
            .collect();
        assert!(!filtered_types.contains(&"GENERIC_SECRET"));
    }

    #[test]
    fn parse_strategy_is_case_insensitive() {
        assert!(matches!(
            parse_strategy("REPLACE"),
            Ok(AnonymizationStrategy::Replace)
        ));
        assert!(parse_strategy("nope").is_err());
    }
}
