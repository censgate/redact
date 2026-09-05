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
use serde::Deserialize;
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

/// Run CPU/ONNX work off the multi-thread tokio worker.
///
/// `block_in_place` parks the current worker in blocking mode; Tokio may
/// spawn a replacement worker. It is not the `spawn_blocking` thread pool.
/// Current-thread tests stay in-place (block_in_place panics there).
fn run_off_async_worker<T>(run: impl FnOnce() -> Result<T, ApiError>) -> Result<T, ApiError> {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(run)
        }
        _ => run(),
    }
}

fn analyze_off_async_worker(
    engine: &AnalyzerEngine,
    request: &AnalyzeRequest,
    entity_types: Option<&Vec<EntityType>>,
) -> Result<redact_core::AnalysisResult, ApiError> {
    run_off_async_worker(|| {
        if let Some(entities) = entity_types {
            engine.analyze_with_entities(&request.text, entities, Some(&request.language))
        } else {
            engine.analyze(&request.text, Some(&request.language))
        }
        .map_err(ApiError::from)
    })
}

/// Analyze endpoint - detect PII entities
pub async fn analyze(
    State(state): State<AppState>,
    Json(request): Json<AnalyzeRequest>,
) -> Result<Json<AnalyzeResponse>, ApiError> {
    analyze_request(state, request, true).await
}

pub(crate) async fn analyze_api(
    State(state): State<AppState>,
    Json(request): Json<AnalyzeApiRequest>,
) -> Result<Json<AnalyzeResponse>, ApiError> {
    analyze_request(state, request.request, request.include_text).await
}

async fn analyze_request(
    state: AppState,
    request: AnalyzeRequest,
    include_text: bool,
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

    // Analyze text off the multi-thread tokio worker.
    let result = analyze_off_async_worker(&state.engine, &request, entity_types.as_ref())?;

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
        .map(|entity| entity_result(entity, include_text))
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
    anonymize_request(state, request, true).await
}

pub(crate) async fn anonymize_api(
    State(state): State<AppState>,
    Json(request): Json<AnonymizeApiRequest>,
) -> Result<Json<AnonymizeResponse>, ApiError> {
    anonymize_request(state, request.request, request.include_text).await
}

async fn anonymize_request(
    state: AppState,
    request: AnonymizeRequest,
    include_text: bool,
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

    // Analyze and anonymize off the tokio worker (NER is synchronous).
    let result = run_off_async_worker(|| {
        if let Some(entities) = entity_types.as_ref() {
            let analysis = state
                .engine
                .analyze_with_entities(&request.text, entities, Some(&request.language))
                .map_err(ApiError::from)?;
            let anonymized = state
                .engine
                .anonymizer_registry()
                .anonymize(
                    &request.text,
                    analysis.detected_entities.clone(),
                    &core_config,
                )
                .map_err(ApiError::from)?;
            Ok((analysis.detected_entities, anonymized, analysis.metadata))
        } else {
            let analysis = state
                .engine
                .analyze_and_anonymize(&request.text, Some(&request.language), &core_config)
                .map_err(ApiError::from)?;
            let anonymized = analysis
                .anonymized
                .ok_or_else(|| ApiError::internal_error("Anonymization failed"))?;
            Ok((analysis.detected_entities, anonymized, analysis.metadata))
        }
    })?;

    let (detected_entities, anonymized, metadata) = result;

    // Convert results
    let results: Vec<EntityResult> = detected_entities
        .into_iter()
        .map(|entity| entity_result(entity, include_text))
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

#[derive(Debug, Deserialize)]
pub(crate) struct AnalyzeApiRequest {
    #[serde(flatten)]
    request: AnalyzeRequest,

    /// Include detected entity literal text in results
    #[serde(default = "default_include_text")]
    include_text: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AnonymizeApiRequest {
    #[serde(flatten)]
    request: AnonymizeRequest,

    /// Include detected entity literal text in results
    #[serde(default = "default_include_text")]
    include_text: bool,
}

fn default_include_text() -> bool {
    true
}

fn entity_result(entity: redact_core::RecognizerResult, include_text: bool) -> EntityResult {
    let mut result = EntityResult::from(entity);
    if !include_text {
        result.text = None;
    }
    result
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
