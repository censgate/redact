// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

use super::entity::EntityType;

/// A detected PII entity in text
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecognizerResult {
    /// The type of entity detected
    pub entity_type: EntityType,

    /// Start position in the text (inclusive)
    pub start: usize,

    /// End position in the text (exclusive)
    pub end: usize,

    /// Confidence score (0.0 to 1.0)
    pub score: f32,

    /// Name of the recognizer that detected this entity
    pub recognizer_name: String,

    /// The actual text that was recognized
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Additional context or metadata
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<serde_json::Value>,
}

impl RecognizerResult {
    pub fn new(
        entity_type: EntityType,
        start: usize,
        end: usize,
        score: f32,
        recognizer_name: impl Into<String>,
    ) -> Self {
        Self {
            entity_type,
            start,
            end,
            score,
            recognizer_name: recognizer_name.into(),
            text: None,
            context: None,
        }
    }

    /// Check if this result overlaps with another
    pub fn overlaps_with(&self, other: &RecognizerResult) -> bool {
        self.start < other.end && other.start < self.end
    }

    /// Get the length of the detected entity
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Check if the result is empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Check if this result contains another result
    pub fn contains(&self, other: &RecognizerResult) -> bool {
        self.start <= other.start && self.end >= other.end
    }

    /// Extract text from the source if not already set
    pub fn with_text(mut self, source: &str) -> Self {
        if self.text.is_none() && self.start < source.len() {
            let end = self.end.min(source.len());
            self.text = Some(source[self.start..end].to_string());
        }
        self
    }

    /// Add context metadata
    pub fn with_context(mut self, context: serde_json::Value) -> Self {
        self.context = Some(context);
        self
    }
}

impl Eq for RecognizerResult {}

impl Ord for RecognizerResult {
    fn cmp(&self, other: &Self) -> Ordering {
        // Primary sort by start position
        match self.start.cmp(&other.start) {
            Ordering::Equal => {
                // Secondary sort by length (longer first for overlap resolution)
                match other.len().cmp(&self.len()) {
                    Ordering::Equal => {
                        // Tertiary sort by confidence score (higher first)
                        other
                            .score
                            .partial_cmp(&self.score)
                            .unwrap_or(Ordering::Equal)
                    }
                    ord => ord,
                }
            }
            ord => ord,
        }
    }
}

impl PartialOrd for RecognizerResult {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Result of anonymization operation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnonymizedResult {
    /// The anonymized text
    pub text: String,

    /// List of entities that were anonymized
    pub entities: Vec<RecognizerResult>,

    /// Mapping of tokens to original values (for reversible anonymization)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<Token>>,
}

/// A reversible anonymization token
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Token {
    /// Unique token identifier
    pub token_id: String,

    /// Original value (encrypted or hashed)
    pub original_value: String,

    /// Entity type
    pub entity_type: EntityType,

    /// Start position in anonymized text
    pub start: usize,

    /// End position in anonymized text
    pub end: usize,

    /// Expiration timestamp (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Analysis result combining detection and anonymization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisResult {
    /// Original text (if requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_text: Option<String>,

    /// Detected entities before anonymization
    pub detected_entities: Vec<RecognizerResult>,

    /// Anonymized result
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anonymized: Option<AnonymizedResult>,

    /// Processing metadata
    pub metadata: AnalysisMetadata,
}

/// Metadata about the analysis process
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// Number of recognizers used
    pub recognizers_used: usize,

    /// Processing time in milliseconds
    pub processing_time_ms: u64,

    /// Language detected
    pub language: String,

    /// Model version (for NER)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_recognizer_result_overlap() {
        let r1 = RecognizerResult::new(EntityType::Person, 0, 10, 0.9, "test");
        let r2 = RecognizerResult::new(EntityType::EmailAddress, 5, 15, 0.8, "test");
        let r3 = RecognizerResult::new(EntityType::PhoneNumber, 20, 30, 0.7, "test");

        assert!(r1.overlaps_with(&r2));
        assert!(r2.overlaps_with(&r1));
        assert!(!r1.overlaps_with(&r3));
    }

    #[test]
    fn test_recognizer_result_contains() {
        let r1 = RecognizerResult::new(EntityType::Person, 0, 20, 0.9, "test");
        let r2 = RecognizerResult::new(EntityType::EmailAddress, 5, 15, 0.8, "test");

        assert!(r1.contains(&r2));
        assert!(!r2.contains(&r1));
    }

    #[test]
    fn test_recognizer_result_ordering() {
        let r1 = RecognizerResult::new(EntityType::Person, 0, 10, 0.9, "test");
        let r2 = RecognizerResult::new(EntityType::EmailAddress, 0, 20, 0.8, "test");
        let r3 = RecognizerResult::new(EntityType::PhoneNumber, 5, 15, 0.7, "test");

        assert!(r2 < r1); // r2 starts at same position but is longer
        assert!(r1 < r3); // r1 starts before r3
    }

    #[test]
    fn test_with_text() {
        let source = "John Doe lives in New York";
        let result = RecognizerResult::new(EntityType::Person, 0, 8, 0.9, "test").with_text(source);

        assert_eq!(result.text, Some("John Doe".to_string()));
    }
}
