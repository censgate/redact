// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use super::{apply_anonymization, Anonymizer, AnonymizerConfig};
use crate::types::{AnonymizedResult, RecognizerResult};
use anyhow::Result;

/// Masking anonymizer that partially obscures text
#[derive(Debug, Clone)]
pub struct MaskAnonymizer;

impl MaskAnonymizer {
    pub fn new() -> Self {
        Self
    }

    /// Mask text while preserving structure
    fn mask_text(text: &str, config: &AnonymizerConfig) -> String {
        let len = text.chars().count();
        let start_chars = config.mask_start_chars;
        let end_chars = config.mask_end_chars;
        let mask_char = config.mask_char;

        if start_chars + end_chars >= len {
            // Show entire text if reveal chars exceed length
            return text.to_string();
        }

        let chars: Vec<char> = text.chars().collect();
        let mut result = String::new();

        // Add start characters
        for i in 0..start_chars {
            if i < chars.len() {
                result.push(chars[i]);
            }
        }

        // Add masked middle
        let mask_count = len.saturating_sub(start_chars + end_chars);
        for _ in 0..mask_count {
            result.push(mask_char);
        }

        // Add end characters
        let start_of_end = len.saturating_sub(end_chars);
        for i in start_of_end..len {
            if i < chars.len() {
                result.push(chars[i]);
            }
        }

        result
    }

    /// Mask text while preserving format (e.g., XXX-XX-XXXX)
    fn mask_with_format(text: &str, mask_char: char) -> String {
        text.chars()
            .map(|c| if c.is_alphanumeric() { mask_char } else { c })
            .collect()
    }
}

impl Default for MaskAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Anonymizer for MaskAnonymizer {
    fn name(&self) -> &str {
        "MaskAnonymizer"
    }

    fn anonymize(
        &self,
        text: &str,
        entities: Vec<RecognizerResult>,
        config: &AnonymizerConfig,
    ) -> Result<AnonymizedResult> {
        let anonymized_text = apply_anonymization(text, &entities, |_entity, original| {
            if config.preserve_format {
                Self::mask_with_format(original, config.mask_char)
            } else {
                Self::mask_text(original, config)
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
    fn test_mask_full() {
        let anonymizer = MaskAnonymizer::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig {
            mask_char: '*',
            mask_start_chars: 0,
            mask_end_chars: 0,
            ..Default::default()
        };

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert_eq!(result.text, "Email: ****************");
    }

    #[test]
    fn test_mask_partial() {
        let anonymizer = MaskAnonymizer::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig {
            mask_char: '*',
            mask_start_chars: 2,
            mask_end_chars: 4,
            ..Default::default()
        };

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        // With mask_start_chars=2 and mask_end_chars=4:
        // "john@example.com" (16 chars) → "jo" + 10 stars + ".com"
        assert_eq!(result.text, "Email: jo**********.com");
    }

    #[test]
    fn test_mask_with_format() {
        let anonymizer = MaskAnonymizer::new();
        let text = "SSN: 123-45-6789";
        let entities = vec![RecognizerResult::new(EntityType::UsSsn, 5, 16, 0.9, "test")];
        let config = AnonymizerConfig {
            mask_char: '*',
            preserve_format: true,
            ..Default::default()
        };

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert_eq!(result.text, "SSN: ***-**-****");
    }

    #[test]
    fn test_mask_multiple() {
        let anonymizer = MaskAnonymizer::new();
        let text = "Email: john@example.com, SSN: 123-45-6789";
        let entities = vec![
            RecognizerResult::new(EntityType::EmailAddress, 7, 23, 0.9, "test"),
            RecognizerResult::new(EntityType::UsSsn, 30, 41, 0.9, "test"),
        ];
        let config = AnonymizerConfig {
            mask_char: '*',
            preserve_format: true,
            ..Default::default()
        };

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert!(result.text.contains("****@*******.**"));
        assert!(result.text.contains("***-**-****"));
    }
}
