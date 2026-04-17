// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use super::{
    encrypt::EncryptAnonymizer, hash::HashAnonymizer, mask::MaskAnonymizer,
    replace::ReplaceAnonymizer, AnonymizationStrategy, Anonymizer, AnonymizerConfig,
};
use crate::types::{AnonymizedResult, RecognizerResult};
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// Registry for managing anonymizers
#[derive(Clone)]
pub struct AnonymizerRegistry {
    anonymizers: HashMap<AnonymizationStrategy, Arc<dyn Anonymizer>>,
}

impl std::fmt::Debug for AnonymizerRegistry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnonymizerRegistry")
            .field("anonymizer_count", &self.anonymizers.len())
            .finish()
    }
}

impl AnonymizerRegistry {
    /// Create a new registry with default anonymizers
    pub fn new() -> Self {
        let mut registry = Self {
            anonymizers: HashMap::new(),
        };

        // Register default anonymizers
        registry.register(
            AnonymizationStrategy::Replace,
            Arc::new(ReplaceAnonymizer::new()),
        );
        registry.register(AnonymizationStrategy::Mask, Arc::new(MaskAnonymizer::new()));
        registry.register(AnonymizationStrategy::Hash, Arc::new(HashAnonymizer::new()));
        registry.register(
            AnonymizationStrategy::Encrypt,
            Arc::new(EncryptAnonymizer::new()),
        );

        registry
    }

    /// Register an anonymizer for a strategy
    pub fn register(&mut self, strategy: AnonymizationStrategy, anonymizer: Arc<dyn Anonymizer>) {
        self.anonymizers.insert(strategy, anonymizer);
    }

    /// Get an anonymizer for a specific strategy
    pub fn get(&self, strategy: &AnonymizationStrategy) -> Option<Arc<dyn Anonymizer>> {
        self.anonymizers.get(strategy).cloned()
    }

    /// Anonymize text using the specified strategy
    pub fn anonymize(
        &self,
        text: &str,
        entities: Vec<RecognizerResult>,
        config: &AnonymizerConfig,
    ) -> Result<AnonymizedResult> {
        let anonymizer = self
            .get(&config.strategy)
            .ok_or_else(|| anyhow!("Anonymizer not found for strategy: {:?}", config.strategy))?;

        anonymizer.anonymize(text, entities, config)
    }

    /// Get all registered strategies
    pub fn strategies(&self) -> Vec<AnonymizationStrategy> {
        self.anonymizers.keys().copied().collect()
    }
}

impl Default for AnonymizerRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn test_registry_new() {
        let registry = AnonymizerRegistry::new();
        assert!(registry.get(&AnonymizationStrategy::Replace).is_some());
        assert!(registry.get(&AnonymizationStrategy::Mask).is_some());
        assert!(registry.get(&AnonymizationStrategy::Hash).is_some());
        assert!(registry.get(&AnonymizationStrategy::Encrypt).is_some());
    }

    #[test]
    fn test_registry_anonymize_replace() {
        let registry = AnonymizerRegistry::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig {
            strategy: AnonymizationStrategy::Replace,
            ..Default::default()
        };

        let result = registry.anonymize(text, entities, &config).unwrap();
        assert_eq!(result.text, "Email: [EMAIL_ADDRESS]");
    }

    #[test]
    fn test_registry_anonymize_mask() {
        let registry = AnonymizerRegistry::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig {
            strategy: AnonymizationStrategy::Mask,
            mask_char: '*',
            mask_start_chars: 2,
            mask_end_chars: 4,
            ..Default::default()
        };

        let result = registry.anonymize(text, entities, &config).unwrap();
        assert!(result.text.contains("**"));
    }

    #[test]
    fn test_registry_strategies() {
        let registry = AnonymizerRegistry::new();
        let strategies = registry.strategies();
        assert!(strategies.len() >= 4);
    }
}
