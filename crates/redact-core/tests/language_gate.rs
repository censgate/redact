//! Non-English language codes must not disable pattern or secret detection.

use std::sync::Arc;

use redact_core::{AnalyzerEngine, EntityType, Recognizer, RecognizerResult};

fn probe() -> String {
    // Split so the source does not contain one contiguous sample key.
    let key = format!("{}IOSFODNN7EXAMPLE", "AKIA");
    format!("Email nguyen.anh@example.com, thẻ 4532015112830366, key {key}")
}

fn types_for(language: &str) -> Vec<EntityType> {
    let engine = AnalyzerEngine::new();
    let result = engine.analyze(&probe(), Some(language)).expect("analyze");
    let mut types: Vec<_> = result
        .detected_entities
        .iter()
        .map(|entity| entity.entity_type.clone())
        .collect();
    types.sort_by_key(|entity| format!("{entity:?}"));
    types
}

#[test]
fn non_english_codes_keep_pattern_detections() {
    let english = types_for("en");
    assert!(
        english.len() >= 3,
        "probe should detect email, card, and key, got {english:?}"
    );
    for language in ["vi", "es", "zh", "ja", "xx", ""] {
        assert_eq!(types_for(language), english, "{language}");
    }
}

#[derive(Debug)]
struct EnglishOnly;

impl Recognizer for EnglishOnly {
    fn name(&self) -> &str {
        "english-only"
    }

    fn supported_entities(&self) -> &[EntityType] {
        &[EntityType::Person]
    }

    fn supports_language(&self, language: &str) -> bool {
        language == "en"
    }

    fn analyze(&self, _text: &str, _language: &str) -> anyhow::Result<Vec<RecognizerResult>> {
        panic!("recognizers that reject the language must be skipped");
    }
}

#[test]
fn recognizers_that_reject_the_language_are_skipped() {
    let mut engine = AnalyzerEngine::new();
    engine
        .recognizer_registry_mut()
        .add_recognizer(Arc::new(EnglishOnly));
    let result = engine
        .analyze(&probe(), Some("vi"))
        .expect("pattern detection still runs");
    assert!(result
        .detected_entities
        .iter()
        .any(|entity| entity.entity_type == EntityType::EmailAddress));
}
