// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use redact_core::AnonymizationStrategy;
use serde::{Deserialize, Serialize};

/// Request to analyze text for PII entities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeRequest {
    /// Text to analyze
    pub text: String,

    /// Language code (e.g., "en", "es")
    #[serde(default = "default_language")]
    pub language: String,

    /// Specific entity types to detect (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<String>>,

    /// Minimum confidence threshold
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_score: Option<f32>,
}

fn default_language() -> String {
    "en".to_string()
}

/// Response from analyze endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalyzeResponse {
    /// Original text (if requested)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_text: Option<String>,

    /// Detected entities
    pub results: Vec<EntityResult>,

    /// Metadata about the analysis
    pub metadata: AnalysisMetadata,
}

/// A detected entity in the text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityResult {
    /// Type of entity
    pub entity_type: String,

    /// Start position
    pub start: usize,

    /// End position
    pub end: usize,

    /// Confidence score (0.0 to 1.0)
    pub score: f32,

    /// The detected text
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,

    /// Recognizer that detected this entity
    pub recognizer_name: String,
}

/// Metadata about the analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisMetadata {
    /// Number of recognizers used
    pub recognizers_used: usize,

    /// Processing time in milliseconds
    pub processing_time_ms: u64,

    /// Language analyzed
    pub language: String,

    /// Model version (if NER was used)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
}

/// Request to anonymize text
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizeRequest {
    /// Text to anonymize
    pub text: String,

    /// Language code
    #[serde(default = "default_language")]
    pub language: String,

    /// Anonymization configuration
    #[serde(default)]
    pub config: AnonymizationConfig,

    /// Specific entity types to anonymize (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entities: Option<Vec<String>>,
}

/// Anonymization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizationConfig {
    /// Strategy to use
    #[serde(default)]
    pub strategy: AnonymizationStrategy,

    /// Masking character (for mask strategy)
    #[serde(default = "default_mask_char")]
    pub mask_char: String,

    /// Characters to show at start (for mask strategy)
    #[serde(default)]
    pub mask_start_chars: usize,

    /// Characters to show at end (for mask strategy)
    #[serde(default)]
    pub mask_end_chars: usize,

    /// Preserve format (for mask strategy)
    #[serde(default)]
    pub preserve_format: bool,

    /// Encryption key (for encrypt strategy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<String>,

    /// Hash salt (for hash strategy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash_salt: Option<String>,
}

impl Default for AnonymizationConfig {
    fn default() -> Self {
        Self {
            strategy: AnonymizationStrategy::Replace,
            mask_char: default_mask_char(),
            mask_start_chars: 0,
            mask_end_chars: 0,
            preserve_format: false,
            encryption_key: None,
            hash_salt: None,
        }
    }
}

fn default_mask_char() -> String {
    "*".to_string()
}

/// Response from anonymize endpoint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymizeResponse {
    /// Anonymized text
    pub text: String,

    /// Entities that were anonymized
    pub results: Vec<EntityResult>,

    /// Tokens for reversible anonymization
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens: Option<Vec<TokenInfo>>,

    /// Metadata
    pub metadata: AnalysisMetadata,
}

/// Token information for reversible anonymization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenInfo {
    /// Token identifier
    pub token_id: String,

    /// Entity type
    pub entity_type: String,

    /// Start position in anonymized text
    pub start: usize,

    /// End position in anonymized text
    pub end: usize,

    /// Expiration timestamp (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Health check response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    /// Number of recognizer instances (e.g. pattern, NER)
    pub recognizers: usize,
    /// Number of entity types supported across all recognizers (e.g. 36+)
    pub entity_types: usize,
}

/// Error response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub error: String,
    pub message: String,
}

impl ErrorResponse {
    pub fn new(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            message: message.into(),
        }
    }
}

// Conversion helpers
impl From<redact_core::RecognizerResult> for EntityResult {
    fn from(result: redact_core::RecognizerResult) -> Self {
        Self {
            entity_type: result.entity_type.as_str().to_string(),
            start: result.start,
            end: result.end,
            score: result.score,
            text: result.text,
            recognizer_name: result.recognizer_name,
        }
    }
}

impl From<redact_core::AnalysisMetadata> for AnalysisMetadata {
    fn from(metadata: redact_core::AnalysisMetadata) -> Self {
        Self {
            recognizers_used: metadata.recognizers_used,
            processing_time_ms: metadata.processing_time_ms,
            language: metadata.language,
            model_version: metadata.model_version,
        }
    }
}

impl From<redact_core::Token> for TokenInfo {
    fn from(token: redact_core::Token) -> Self {
        Self {
            token_id: token.token_id,
            entity_type: token.entity_type.as_str().to_string(),
            start: token.start,
            end: token.end,
            expires_at: token.expires_at.map(|dt| dt.to_rfc3339()),
        }
    }
}
