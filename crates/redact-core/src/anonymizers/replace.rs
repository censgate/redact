// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use super::{apply_anonymization, Anonymizer, AnonymizerConfig};
use crate::types::{AnonymizedResult, RecognizerResult};
use anyhow::Result;
use std::collections::HashMap;

/// Simple replacement anonymizer
#[derive(Debug, Clone)]
pub struct ReplaceAnonymizer {
    custom_replacements: HashMap<String, String>,
}

impl ReplaceAnonymizer {
    pub fn new() -> Self {
        Self {
            custom_replacements: HashMap::new(),
        }
    }

    /// Add a custom replacement for a specific entity type
    pub fn with_replacement(
        mut self,
        entity_type: impl Into<String>,
        replacement: impl Into<String>,
    ) -> Self {
        self.custom_replacements
            .insert(entity_type.into(), replacement.into());
        self
    }
}

impl Default for ReplaceAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Anonymizer for ReplaceAnonymizer {
    fn name(&self) -> &str {
        "ReplaceAnonymizer"
    }

    fn anonymize(
        &self,
        text: &str,
        entities: Vec<RecognizerResult>,
        _config: &AnonymizerConfig,
    ) -> Result<AnonymizedResult> {
        let anonymized_text = apply_anonymization(text, &entities, |entity, _original| {
            // Check for custom replacement
            if let Some(replacement) = self.custom_replacements.get(entity.entity_type.as_str()) {
                replacement.clone()
            } else {
                entity.entity_type.default_replacement()
            }
        });

        Ok(AnonymizedResult {
            text: anonymized_text,
            entities,
            tokens: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn test_replace_anonymizer() {
        let anonymizer = ReplaceAnonymizer::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig::default();

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert_eq!(result.text, "Email: [EMAIL_ADDRESS]");
    }

    #[test]
    fn test_replace_with_custom() {
        let anonymizer =
            ReplaceAnonymizer::new().with_replacement("EMAIL_ADDRESS", "[REDACTED_EMAIL]");

        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig::default();

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert_eq!(result.text, "Email: [REDACTED_EMAIL]");
    }

    #[test]
    fn test_replace_multiple() {
        let anonymizer = ReplaceAnonymizer::new();
        let text = "Email: john@example.com, Phone: 555-1234";
        let entities = vec![
            RecognizerResult::new(EntityType::EmailAddress, 7, 23, 0.9, "test"),
            RecognizerResult::new(EntityType::PhoneNumber, 32, 40, 0.8, "test"), // Fixed positions
        ];
        let config = AnonymizerConfig::default();

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert_eq!(result.text, "Email: [EMAIL_ADDRESS], Phone: [PHONE_NUMBER]");
    }
}
