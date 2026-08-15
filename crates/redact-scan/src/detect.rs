// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Pattern-engine wrapper that drops matched text immediately.

use redact_core::recognizers::{pattern::PatternRecognizer, Recognizer};
use redact_core::{AnalyzerEngine, EntityType};

/// Entity types used for value-based layers (L0.5 / L1 / L2).
///
/// Excludes high-false-positive types (`DATE_TIME`, `GUID`, hashes, `URL`)
/// unless a name heuristic already nominated them.
pub fn precision_entities() -> &'static [EntityType] {
    &[
        EntityType::EmailAddress,
        EntityType::PhoneNumber,
        EntityType::IpAddress,
        EntityType::CreditCard,
        EntityType::IbanCode,
        EntityType::Iban,
        EntityType::UsSsn,
        EntityType::UsBankNumber,
        EntityType::UsPassport,
        EntityType::UsDriverLicense,
        EntityType::UkNhs,
        EntityType::UkNino,
        EntityType::PassportNumber,
        EntityType::MedicalRecordNumber,
        EntityType::MedicalLicense,
        EntityType::PrivateKey,
        EntityType::JwtToken,
        EntityType::AwsAccessKey,
        EntityType::GithubToken,
        EntityType::GitlabToken,
        EntityType::SlackToken,
        EntityType::StripeApiKey,
        EntityType::DatabaseConnectionString,
    ]
}

/// Built-in pattern pack label (`builtin@<supported count>`).
pub fn pattern_pack_label() -> String {
    let rec = PatternRecognizer::new();
    format!("builtin@{}", rec.supported_entities().len())
}

/// Run the pattern engine and drop matched text immediately.
pub fn detect_types(text: &str) -> Vec<(EntityType, f32)> {
    detect_types_filtered(text, precision_entities())
}

/// Detect only the listed entity types; never retain `RecognizerResult.text`.
pub fn detect_types_filtered(text: &str, allowed: &[EntityType]) -> Vec<(EntityType, f32)> {
    let engine = AnalyzerEngine::new();
    let Ok(result) = engine.analyze_with_entities(text, allowed, Some("en")) else {
        return Vec::new();
    };
    result
        .detected_entities
        .into_iter()
        .map(|e| (e.entity_type, e.score))
        .collect()
}

/// Parse a `--fail-on` entity token. `any` returns `None`.
pub fn parse_entity_type(s: &str) -> Option<EntityType> {
    let t = s.trim();
    if t.eq_ignore_ascii_case("any") {
        return None;
    }
    Some(EntityType::from(t.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn drops_text_and_finds_email() {
        let hits = detect_types("contact me at user@example.com please");
        assert!(hits.iter().any(|(t, _)| *t == EntityType::EmailAddress));
    }

    #[test]
    fn pattern_pack_is_not_hardcoded() {
        let label = pattern_pack_label();
        assert!(label.starts_with("builtin@"));
        let n: usize = label.rsplit('@').next().unwrap().parse().unwrap();
        assert!(n > 0);
    }
}
