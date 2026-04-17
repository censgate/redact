// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

pub mod encrypt;
pub mod hash;
pub mod mask;
pub mod registry;
pub mod replace;

pub use registry::AnonymizerRegistry;

use crate::types::{AnonymizedResult, RecognizerResult};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Strategy for anonymization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum AnonymizationStrategy {
    /// Simple text replacement
    #[default]
    Replace,
    /// Partial masking (e.g., ***@***.com)
    Mask,
    /// Irreversible hashing
    Hash,
    /// Reversible encryption
    Encrypt,
    /// Remove entirely
    Redact,
}

/// Configuration for anonymization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizerConfig {
    /// Default strategy to use
    pub strategy: AnonymizationStrategy,

    /// Masking character (for mask strategy)
    #[serde(default = "default_mask_char")]
    pub mask_char: char,

    /// Number of characters to show at start (for mask strategy)
    #[serde(default)]
    pub mask_start_chars: usize,

    /// Number of characters to show at end (for mask strategy)
    #[serde(default)]
    pub mask_end_chars: usize,

    /// Encryption key (for encrypt strategy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,

    /// Salt for hashing (for hash strategy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_salt: Option<String>,

    /// Whether to preserve format (e.g., XXX-XX-XXXX for SSN)
    #[serde(default)]
    pub preserve_format: bool,
}

fn default_mask_char() -> char {
    '*'
}

impl Default for AnonymizerConfig {
    fn default() -> Self {
        Self {
            strategy: AnonymizationStrategy::Replace,
            mask_char: '*',
            mask_start_chars: 0,
            mask_end_chars: 0,
            encryption_key: None,
            hash_salt: None,
            preserve_format: false,
        }
    }
}

/// Trait for all anonymizers
pub trait Anonymizer: Send + Sync + Debug {
    /// Get the name of this anonymizer
    fn name(&self) -> &str;

    /// Anonymize text based on recognized entities
    fn anonymize(
        &self,
        text: &str,
        entities: Vec<RecognizerResult>,
        config: &AnonymizerConfig,
    ) -> Result<AnonymizedResult>;
}

/// Helper to apply anonymization to text
pub fn apply_anonymization(
    text: &str,
    entities: &[RecognizerResult],
    replacement_fn: impl Fn(&RecognizerResult, &str) -> String,
) -> String {
    if entities.is_empty() {
        return text.to_string();
    }

    let mut result = String::with_capacity(text.len());
    let mut last_end = 0;

    // Sort entities by start position
    let mut sorted_entities = entities.to_vec();
    sorted_entities.sort_by_key(|e| e.start);

    for entity in sorted_entities {
        // Add text before this entity
        if entity.start > last_end {
            result.push_str(&text[last_end..entity.start]);
        }

        // Get original text
        let original = if entity.end <= text.len() {
            &text[entity.start..entity.end]
        } else {
            ""
        };

        // Add replacement
        result.push_str(&replacement_fn(&entity, original));

        last_end = entity.end;
    }

    // Add remaining text
    if last_end < text.len() {
        result.push_str(&text[last_end..]);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn test_apply_anonymization() {
        let text = "Email: john@example.com, Phone: 555-1234";
        let entities = vec![
            RecognizerResult::new(EntityType::EmailAddress, 7, 23, 0.9, "test"),
            RecognizerResult::new(EntityType::PhoneNumber, 32, 40, 0.8, "test"), // Fixed positions
        ];

        let result = apply_anonymization(text, &entities, |e, _| {
            format!("[{}]", e.entity_type.as_str())
        });

        assert_eq!(result, "Email: [EMAIL_ADDRESS], Phone: [PHONE_NUMBER]");
    }

    #[test]
    fn test_apply_anonymization_empty() {
        let text = "No PII here";
        let entities = vec![];

        let result = apply_anonymization(text, &entities, |e, _| {
            format!("[{}]", e.entity_type.as_str())
        });

        assert_eq!(result, text);
    }

    #[test]
    fn test_apply_anonymization_adjacent() {
        let text = "AB";
        let entities = vec![
            RecognizerResult::new(EntityType::Person, 0, 1, 0.9, "test"),
            RecognizerResult::new(EntityType::Person, 1, 2, 0.9, "test"),
        ];

        let result = apply_anonymization(text, &entities, |_, _| "X".to_string());

        assert_eq!(result, "XX");
    }
}
