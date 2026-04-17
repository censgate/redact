// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::types::{EntityType, RecognizerResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Policy for PII detection and anonymization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub name: String,
    pub display_name: String,
    pub organization_id: String,
    pub status: PolicyStatus,
    pub priority: u32,
    pub description: String,
    pub conditions: Vec<PolicyCondition>,
    pub pattern_rules: Vec<PatternRule>,
    pub redaction_config: RedactionConfig,
    pub actions: PolicyActions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyStatus {
    Active,
    Inactive,
    Draft,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyCondition {
    pub field: String,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    Regex,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternRule {
    pub pattern_id: String,
    pub name: String,
    pub enabled: bool,
    pub mode: String,
    pub strategy: String,
    pub confidence: f32,
    pub replacement: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionConfig {
    pub default_mode: String,
    pub enabled_categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyActions {
    pub action: String,
    pub redact_fields: Vec<String>,
}

impl Policy {
    /// Apply policy to filter and modify recognizer results
    pub fn apply(&self, results: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
        if self.status != PolicyStatus::Active {
            return results;
        }

        // Create a lookup map for pattern rules
        let mut rule_map: HashMap<String, &PatternRule> = HashMap::new();
        for rule in &self.pattern_rules {
            if rule.enabled {
                rule_map.insert(rule.pattern_id.clone(), rule);
            }
        }

        // Filter and adjust results based on policy
        results
            .into_iter()
            .filter_map(|mut result| {
                let entity_id = result.entity_type.as_str();

                // Check if this entity type has a rule
                if let Some(rule) = rule_map.get(entity_id) {
                    // Apply confidence threshold
                    if result.score >= rule.confidence {
                        // Update score based on policy
                        result.score = result.score.max(rule.confidence);
                        Some(result)
                    } else {
                        None
                    }
                } else {
                    // No specific rule, keep result if above general threshold
                    Some(result)
                }
            })
            .collect()
    }

    /// Get entity types that should be detected based on policy
    pub fn enabled_entity_types(&self) -> Vec<EntityType> {
        self.pattern_rules
            .iter()
            .filter(|rule| rule.enabled)
            .map(|rule| {
                // Parse entity type from pattern_id
                EntityType::from(rule.pattern_id.clone())
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_apply() {
        let policy = Policy {
            id: "test".to_string(),
            name: "test".to_string(),
            display_name: "Test Policy".to_string(),
            organization_id: "org1".to_string(),
            status: PolicyStatus::Active,
            priority: 100,
            description: "Test policy".to_string(),
            conditions: vec![],
            pattern_rules: vec![PatternRule {
                pattern_id: "EMAIL_ADDRESS".to_string(),
                name: "email".to_string(),
                enabled: true,
                mode: "replace".to_string(),
                strategy: "semantic".to_string(),
                confidence: 0.8,
                replacement: "[EMAIL]".to_string(),
            }],
            redaction_config: RedactionConfig {
                default_mode: "replace".to_string(),
                enabled_categories: vec!["contact_info".to_string()],
            },
            actions: PolicyActions {
                action: "redact".to_string(),
                redact_fields: vec!["content".to_string()],
            },
        };

        let results = vec![
            RecognizerResult::new(EntityType::EmailAddress, 0, 10, 0.9, "test"),
            RecognizerResult::new(EntityType::EmailAddress, 10, 20, 0.7, "test"),
        ];

        let filtered = policy.apply(results);

        // Only the result with score >= 0.8 should remain
        assert_eq!(filtered.len(), 1);
        assert!(filtered[0].score >= 0.8);
    }

    #[test]
    fn test_inactive_policy() {
        let policy = Policy {
            id: "test".to_string(),
            name: "test".to_string(),
            display_name: "Test Policy".to_string(),
            organization_id: "org1".to_string(),
            status: PolicyStatus::Inactive,
            priority: 100,
            description: "Test policy".to_string(),
            conditions: vec![],
            pattern_rules: vec![],
            redaction_config: RedactionConfig {
                default_mode: "replace".to_string(),
                enabled_categories: vec![],
            },
            actions: PolicyActions {
                action: "redact".to_string(),
                redact_fields: vec![],
            },
        };

        let results = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            0,
            10,
            0.9,
            "test",
        )];

        let filtered = policy.apply(results.clone());

        // Inactive policy should not filter
        assert_eq!(filtered.len(), results.len());
    }
}
