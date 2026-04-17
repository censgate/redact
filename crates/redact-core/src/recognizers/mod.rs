// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

pub mod pattern;
pub mod registry;
pub mod validation;

pub use registry::RecognizerRegistry;
pub use validation::validate_entity;

use crate::types::{EntityType, RecognizerResult};
use anyhow::Result;
use std::fmt::Debug;

/// Trait for all PII recognizers
pub trait Recognizer: Send + Sync + Debug {
    /// Get the name of this recognizer
    fn name(&self) -> &str;

    /// Get the entity types this recognizer can detect
    fn supported_entities(&self) -> &[EntityType];

    /// Analyze text and return detected entities
    fn analyze(&self, text: &str, language: &str) -> Result<Vec<RecognizerResult>>;

    /// Get the minimum confidence score for this recognizer
    fn min_score(&self) -> f32 {
        0.0
    }

    /// Check if this recognizer supports the given language
    fn supports_language(&self, language: &str) -> bool {
        language == "en" // Default to English only
    }
}

/// Trait for recognizers that can be loaded from configuration
pub trait ConfigurableRecognizer: Recognizer {
    /// Configuration type for this recognizer
    type Config;

    /// Create a new instance from configuration
    fn from_config(config: Self::Config) -> Result<Self>
    where
        Self: Sized;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct TestRecognizer;

    impl Recognizer for TestRecognizer {
        fn name(&self) -> &str {
            "test"
        }

        fn supported_entities(&self) -> &[EntityType] {
            &[EntityType::Person]
        }

        fn analyze(&self, _text: &str, _language: &str) -> Result<Vec<RecognizerResult>> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_recognizer_trait() {
        let recognizer = TestRecognizer;
        assert_eq!(recognizer.name(), "test");
        assert_eq!(recognizer.supported_entities(), &[EntityType::Person]);
        assert!(recognizer.supports_language("en"));
        assert!(!recognizer.supports_language("es"));
    }
}
