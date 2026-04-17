// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use super::{apply_anonymization, Anonymizer, AnonymizerConfig};
use crate::types::{AnonymizedResult, RecognizerResult};
use anyhow::Result;
use sha2::{Digest, Sha256};

/// Hash anonymizer for irreversible anonymization
#[derive(Debug, Clone)]
pub struct HashAnonymizer {
    algorithm: HashAlgorithm,
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    Sha256,
    Blake3,
}

impl HashAnonymizer {
    pub fn new() -> Self {
        Self {
            algorithm: HashAlgorithm::Sha256,
        }
    }

    pub fn with_algorithm(mut self, algorithm: HashAlgorithm) -> Self {
        self.algorithm = algorithm;
        self
    }

    fn hash_value(&self, value: &str, salt: Option<&str>) -> String {
        let input = if let Some(salt) = salt {
            format!("{}{}", value, salt)
        } else {
            value.to_string()
        };

        match self.algorithm {
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(input.as_bytes());
                let result = hasher.finalize();
                hex::encode(&result[..8]) // Use first 8 bytes for readability
            }
            HashAlgorithm::Blake3 => {
                let hash = blake3::hash(input.as_bytes());
                hex::encode(&hash.as_bytes()[..8]) // Use first 8 bytes for readability
            }
        }
    }
}

impl Default for HashAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Anonymizer for HashAnonymizer {
    fn name(&self) -> &str {
        "HashAnonymizer"
    }

    fn anonymize(
        &self,
        text: &str,
        entities: Vec<RecognizerResult>,
        config: &AnonymizerConfig,
    ) -> Result<AnonymizedResult> {
        let salt = config.hash_salt.as_deref();

        let anonymized_text = apply_anonymization(text, &entities, |entity, original| {
            let hash = self.hash_value(original, salt);
            format!("[{}_{}]", entity.entity_type.as_str(), hash)
        });

        Ok(AnonymizedResult {
            text: anonymized_text,
            entities,
            tokens: None,
        })
    }
}

// Add hex dependency placeholder (we'll add it to Cargo.toml)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn test_hash_anonymizer() {
        let anonymizer = HashAnonymizer::new();
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

        assert!(result.text.starts_with("Email: [EMAIL_ADDRESS_"));
        assert!(result.text.ends_with("]"));
        assert_ne!(result.text, text);
    }

    #[test]
    fn test_hash_consistency() {
        let anonymizer = HashAnonymizer::new();
        let text = "test@example.com";

        let hash1 = anonymizer.hash_value(text, None);
        let hash2 = anonymizer.hash_value(text, None);

        assert_eq!(hash1, hash2, "Hash should be consistent");
    }

    #[test]
    fn test_hash_with_salt() {
        let anonymizer = HashAnonymizer::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig {
            hash_salt: Some("my_salt".to_string()),
            ..Default::default()
        };

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert!(result.text.starts_with("Email: [EMAIL_ADDRESS_"));
    }

    #[test]
    fn test_hash_different_values() {
        let anonymizer = HashAnonymizer::new();

        let hash1 = anonymizer.hash_value("test1@example.com", None);
        let hash2 = anonymizer.hash_value("test2@example.com", None);

        assert_ne!(
            hash1, hash2,
            "Different values should produce different hashes"
        );
    }
}
