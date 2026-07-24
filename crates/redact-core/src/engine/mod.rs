// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::anonymizers::{AnonymizerConfig, AnonymizerRegistry};
use crate::recognizers::{pattern::PatternRecognizer, RecognizerRegistry};
use crate::types::{AnalysisMetadata, AnalysisResult, AnonymizedResult, EntityType};
use anyhow::Result;
use std::sync::Arc;
use std::time::Instant;

/// Monotonic timer for `processing_time_ms`.
///
/// `std::time::Instant::now()` is not implemented on `wasm32-unknown-unknown`
/// (it panics at runtime). On WASM we record no elapsed time; on every other
/// target we use a real `Instant`, preserving native behavior exactly.
struct Timer {
    start: Option<Instant>,
}

impl Timer {
    fn new() -> Self {
        Self {
            #[cfg(not(target_arch = "wasm32"))]
            start: Some(Instant::now()),
            #[cfg(target_arch = "wasm32")]
            start: None,
        }
    }

    fn elapsed_ms(&self) -> u64 {
        self.start
            .map(|s| s.elapsed().as_millis() as u64)
            .unwrap_or(0)
    }
}

/// Main analyzer engine that coordinates recognition and anonymization
#[derive(Debug, Clone)]
pub struct AnalyzerEngine {
    recognizer_registry: RecognizerRegistry,
    anonymizer_registry: AnonymizerRegistry,
    default_language: String,
    model_version: Option<String>,
}

impl AnalyzerEngine {
    /// Create a new analyzer engine with default recognizers
    pub fn new() -> Self {
        let mut recognizer_registry = RecognizerRegistry::new();

        // Add default pattern recognizer
        let pattern_recognizer = Arc::new(PatternRecognizer::new());
        recognizer_registry.add_recognizer(pattern_recognizer);

        Self {
            recognizer_registry,
            anonymizer_registry: AnonymizerRegistry::new(),
            default_language: "en".to_string(),
            model_version: None,
        }
    }

    /// Create a builder for custom configuration
    pub fn builder() -> AnalyzerEngineBuilder {
        AnalyzerEngineBuilder::new()
    }

    /// Set the default language
    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.default_language = language.into();
        self
    }

    /// Set the model version (for NER)
    pub fn with_model_version(mut self, version: impl Into<String>) -> Self {
        self.model_version = Some(version.into());
        self
    }

    /// Get the recognizer registry
    pub fn recognizer_registry(&self) -> &RecognizerRegistry {
        &self.recognizer_registry
    }

    /// Get mutable access to the recognizer registry
    pub fn recognizer_registry_mut(&mut self) -> &mut RecognizerRegistry {
        &mut self.recognizer_registry
    }

    /// Get the anonymizer registry
    pub fn anonymizer_registry(&self) -> &AnonymizerRegistry {
        &self.anonymizer_registry
    }

    /// Get mutable access to the anonymizer registry
    pub fn anonymizer_registry_mut(&mut self) -> &mut AnonymizerRegistry {
        &mut self.anonymizer_registry
    }

    /// Analyze text and detect PII entities
    pub fn analyze(&self, text: &str, language: Option<&str>) -> Result<AnalysisResult> {
        let start = Timer::new();
        let lang = language.unwrap_or(&self.default_language);

        let detected_entities = self.recognizer_registry.analyze(text, lang)?;

        let processing_time_ms = start.elapsed_ms();

        Ok(AnalysisResult {
            original_text: None,
            detected_entities,
            anonymized: None,
            metadata: AnalysisMetadata {
                recognizers_used: self.recognizer_registry.recognizers().len(),
                processing_time_ms,
                language: lang.to_string(),
                model_version: self.model_version.clone(),
            },
        })
    }

    /// Analyze text with specific entity types
    pub fn analyze_with_entities(
        &self,
        text: &str,
        entity_types: &[EntityType],
        language: Option<&str>,
    ) -> Result<AnalysisResult> {
        let start = Timer::new();
        let lang = language.unwrap_or(&self.default_language);

        let detected_entities =
            self.recognizer_registry
                .analyze_with_entities(text, lang, entity_types)?;

        let processing_time_ms = start.elapsed_ms();

        Ok(AnalysisResult {
            original_text: None,
            detected_entities,
            anonymized: None,
            metadata: AnalysisMetadata {
                recognizers_used: self.recognizer_registry.recognizers().len(),
                processing_time_ms,
                language: lang.to_string(),
                model_version: self.model_version.clone(),
            },
        })
    }

    /// Anonymize text based on detected entities
    pub fn anonymize(
        &self,
        text: &str,
        language: Option<&str>,
        config: &AnonymizerConfig,
    ) -> Result<AnonymizedResult> {
        let lang = language.unwrap_or(&self.default_language);

        // First, analyze to detect entities
        let analysis = self.analyze(text, Some(lang))?;

        // Then anonymize
        self.anonymizer_registry
            .anonymize(text, analysis.detected_entities, config)
    }

    /// Analyze and anonymize in one call
    pub fn analyze_and_anonymize(
        &self,
        text: &str,
        language: Option<&str>,
        config: &AnonymizerConfig,
    ) -> Result<AnalysisResult> {
        let start = Timer::new();
        let lang = language.unwrap_or(&self.default_language);

        // Analyze
        let mut result = self.analyze(text, Some(lang))?;

        // Anonymize
        let anonymized =
            self.anonymizer_registry
                .anonymize(text, result.detected_entities.clone(), config)?;

        result.anonymized = Some(anonymized);
        result.metadata.processing_time_ms = start.elapsed_ms();

        Ok(result)
    }
}

impl Default for AnalyzerEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Builder for AnalyzerEngine
pub struct AnalyzerEngineBuilder {
    recognizer_registry: RecognizerRegistry,
    anonymizer_registry: AnonymizerRegistry,
    default_language: String,
    model_version: Option<String>,
}

impl AnalyzerEngineBuilder {
    pub fn new() -> Self {
        Self {
            recognizer_registry: RecognizerRegistry::new(),
            anonymizer_registry: AnonymizerRegistry::new(),
            default_language: "en".to_string(),
            model_version: None,
        }
    }

    pub fn with_recognizer_registry(mut self, registry: RecognizerRegistry) -> Self {
        self.recognizer_registry = registry;
        self
    }

    pub fn with_anonymizer_registry(mut self, registry: AnonymizerRegistry) -> Self {
        self.anonymizer_registry = registry;
        self
    }

    pub fn with_language(mut self, language: impl Into<String>) -> Self {
        self.default_language = language.into();
        self
    }

    pub fn with_model_version(mut self, version: impl Into<String>) -> Self {
        self.model_version = Some(version.into());
        self
    }

    pub fn build(self) -> AnalyzerEngine {
        AnalyzerEngine {
            recognizer_registry: self.recognizer_registry,
            anonymizer_registry: self.anonymizer_registry,
            default_language: self.default_language,
            model_version: self.model_version,
        }
    }
}

impl Default for AnalyzerEngineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::anonymizers::AnonymizationStrategy;

    #[test]
    fn test_analyzer_engine_new() {
        let engine = AnalyzerEngine::new();
        assert_eq!(engine.default_language, "en");
        assert!(!engine.recognizer_registry.recognizers().is_empty());
    }

    #[test]
    fn test_analyze() {
        let engine = AnalyzerEngine::new();
        let text = "Email: john@example.com, Phone: (555) 123-4567";

        let result = engine.analyze(text, None).unwrap();

        assert!(result.detected_entities.len() >= 2);
        assert_eq!(result.metadata.language, "en");
        assert!(result.metadata.processing_time_ms > 0);
    }

    #[test]
    fn test_analyze_with_entities() {
        let engine = AnalyzerEngine::new();
        let text = "Email: john@example.com, Phone: (555) 123-4567";

        let result = engine
            .analyze_with_entities(text, &[EntityType::EmailAddress], None)
            .unwrap();

        assert!(result
            .detected_entities
            .iter()
            .all(|e| e.entity_type == EntityType::EmailAddress));
    }

    #[test]
    fn test_anonymize() {
        let engine = AnalyzerEngine::new();
        let text = "Email: john@example.com";
        let config = AnonymizerConfig {
            strategy: AnonymizationStrategy::Replace,
            ..Default::default()
        };

        let result = engine.anonymize(text, None, &config).unwrap();

        assert!(result.text.contains("[EMAIL_ADDRESS]"));
    }

    #[test]
    fn test_analyze_and_anonymize() {
        let engine = AnalyzerEngine::new();
        let text = "Email: john@example.com, SSN: 123-45-6789";
        let config = AnonymizerConfig {
            strategy: AnonymizationStrategy::Replace,
            ..Default::default()
        };

        let result = engine.analyze_and_anonymize(text, None, &config).unwrap();

        assert!(result.detected_entities.len() >= 2);
        assert!(result.anonymized.is_some());

        let anonymized = result.anonymized.unwrap();
        assert!(anonymized.text.contains("[EMAIL_ADDRESS]"));
        assert!(anonymized.text.contains("[US_SSN]"));
    }

    #[test]
    fn test_builder() {
        let engine = AnalyzerEngine::builder()
            .with_language("es")
            .with_model_version("v1.0.0")
            .build();

        assert_eq!(engine.default_language, "es");
        assert_eq!(engine.model_version, Some("v1.0.0".to_string()));
    }
}
