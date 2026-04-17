// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::models::{
    AnalyzeRequest, AnalyzeResponse, AnonymizeRequest, AnonymizeResponse, EntityResult,
    ErrorResponse, HealthResponse, TokenInfo,
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use redact_core::{AnalyzerEngine, AnonymizerConfig, EntityType};
use std::sync::Arc;

/// Application state
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<AnalyzerEngine>,
}

/// Custom error type
#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    pub fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, message)
    }

    pub fn internal_error(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = Json(ErrorResponse::new("error", self.message));
        (self.status, body).into_response()
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        ApiError::internal_error(err.to_string())
    }
}

/// Health check endpoint
pub async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let stats = state.engine.recognizer_registry().stats();
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: redact_core::VERSION.to_string(),
        recognizers: stats.recognizer_count,
        entity_types: stats.entity_coverage.len(),
    })
}

/// Analyze endpoint - detect PII entities
pub async fn analyze(
    State(state): State<AppState>,
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, ApiError> {
    // Validate input
    if request.text.is_empty() {
        return Err(ApiError::bad_request("Text cannot be empty"));
    }

    // Parse entity types if provided
    let entity_types: Option<Vec<EntityType>> = request.entities.as_ref().map(|entities| {
        entities
            .iter()
            .map(|e| EntityType::from(e.clone()))
            .collect()
    });

    // Analyze text
    let result = if let Some(entities) = entity_types.as_ref() {
        state
            .engine
            .analyze_with_entities(&request.text, entities, Some(&request.language))
            .map_err(ApiError::from)?
    } else {
        state
            .engine
            .analyze(&request.text, Some(&request.language))
            .map_err(ApiError::from)?
    };

    // Filter by min_score if provided
    let mut results: Vec<EntityResult> = result
        .detected_entities
        .into_iter()
        .filter(|e| {
            if let Some(min_score) = request.min_score {
                e.score >= min_score
            } else {
                true
            }
        })
        .map(EntityResult::from)
        .collect();

    // Sort by start position
    results.sort_by_key(|r| r.start);

    Ok(Json(AnalyzeResponse {
        original_text: None,
        results,
        metadata: result.metadata.into(),
    }))
}

/// Anonymize endpoint - detect and anonymize PII
pub async fn anonymize(
    State(state): State<AppState>,
    Json(request): Json<AnonymizeRequest>,
) -> Result<Json<AnonymizeResponse>, ApiError> {
    // Validate input
    if request.text.is_empty() {
        return Err(ApiError::bad_request("Text cannot be empty"));
    }

    // Validate encryption key if needed
    if request.config.strategy == redact_core::AnonymizationStrategy::Encrypt
        && request.config.encryption_key.is_none()
    {
        return Err(ApiError::bad_request(
            "Encryption key required for encrypt strategy",
        ));
    }

    // Convert API config to core config
    let mask_char = request.config.mask_char.chars().next().unwrap_or('*');

    let core_config = AnonymizerConfig {
        strategy: request.config.strategy,
        mask_char,
        mask_start_chars: request.config.mask_start_chars,
        mask_end_chars: request.config.mask_end_chars,
        preserve_format: request.config.preserve_format,
        encryption_key: request.config.encryption_key,
        hash_salt: request.config.hash_salt,
    };

    // Parse entity types if provided
    let entity_types: Option<Vec<EntityType>> = request.entities.as_ref().map(|entities| {
        entities
            .iter()
            .map(|e| EntityType::from(e.clone()))
            .collect()
    });

    // Analyze and anonymize
    let result = if let Some(entities) = entity_types.as_ref() {
        // First analyze with specific entities
        let analysis = state
            .engine
            .analyze_with_entities(&request.text, entities, Some(&request.language))
            .map_err(ApiError::from)?;

        // Then anonymize
        let anonymized = state
            .engine
            .anonymizer_registry()
            .anonymize(
                &request.text,
                analysis.detected_entities.clone(),
                &core_config,
            )
            .map_err(ApiError::from)?;

        (analysis.detected_entities, anonymized, analysis.metadata)
    } else {
        let analysis = state
            .engine
            .analyze_and_anonymize(&request.text, Some(&request.language), &core_config)
            .map_err(ApiError::from)?;

        let anonymized = analysis
            .anonymized
            .ok_or_else(|| ApiError::internal_error("Anonymization failed"))?;

        (analysis.detected_entities, anonymized, analysis.metadata)
    };

    let (detected_entities, anonymized, metadata) = result;

    // Convert results
    let results: Vec<EntityResult> = detected_entities
        .into_iter()
        .map(EntityResult::from)
        .collect();

    let tokens: Option<Vec<TokenInfo>> = anonymized
        .tokens
        .map(|tokens| tokens.into_iter().map(TokenInfo::from).collect());

    Ok(Json(AnonymizeResponse {
        text: anonymized.text,
        results,
        tokens,
        metadata: metadata.into(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AnonymizationConfig;

    fn create_test_state() -> AppState {
        AppState {
            engine: Arc::new(AnalyzerEngine::new()),
        }
    }

    #[tokio::test]
    async fn test_health() {
        let state = create_test_state();
        let response = health(State(state)).await;

        assert_eq!(response.status, "healthy");
        assert!(!response.version.is_empty());
    }

    #[tokio::test]
    async fn test_analyze() {
        let state = create_test_state();
        let request = AnalyzeRequest {
            text: "Email: john@example.com".to_string(),
            language: "en".to_string(),
            entities: None,
            min_score: None,
        };

        let response = analyze(State(state), Json(request)).await.unwrap();

        assert!(!response.results.is_empty());
        assert_eq!(response.results[0].entity_type, "EMAIL_ADDRESS");
    }

    #[tokio::test]
    async fn test_anonymize() {
        let state = create_test_state();
        let request = AnonymizeRequest {
            text: "Email: john@example.com".to_string(),
            language: "en".to_string(),
            config: AnonymizationConfig::default(),
            entities: None,
        };

        let response = anonymize(State(state), Json(request)).await.unwrap();

        assert!(response.text.contains("[EMAIL_ADDRESS]"));
        assert!(!response.results.is_empty());
    }
}
