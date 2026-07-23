// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::openai::{ChatCompletionRequest, ErrorBody};
use crate::proxy::HttpChatUpstream;
use crate::redact::redact_chat_request;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use redact_core::{AnalyzerEngine, AnonymizerConfig};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub engine: Arc<AnalyzerEngine>,
    pub anonymizer: AnonymizerConfig,
    pub upstream: HttpChatUpstream,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/livez", get(health))
        .route("/readyz", get(health))
        .route("/v1/chat/completions", post(chat_completions))
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "gateway",
    }))
}

async fn chat_completions(
    State(state): State<AppState>,
    Json(mut request): Json<ChatCompletionRequest>,
) -> Response {
    if request.stream.unwrap_or(false) {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(ErrorBody::new(
                "streaming chat completions are not implemented yet",
                "not_implemented",
            )),
        )
            .into_response();
    }

    let outcome = match redact_chat_request(&state.engine, &mut request, &state.anonymizer) {
        Ok(o) => o,
        Err(err) => {
            warn!(error = %err, "redaction failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(
                    format!("redaction failed: {err}"),
                    "redaction_error",
                )),
            )
                .into_response();
        }
    };

    info!(
        redactions = outcome.redactions_applied,
        entities = ?outcome.entity_types,
        "request redacted"
    );

    let body = match serde_json::to_value(&request) {
        Ok(v) => v,
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(
                    format!("failed to serialize request: {err}"),
                    "internal_error",
                )),
            )
                .into_response();
        }
    };

    match state.upstream.chat_completions(&body).await {
        Ok(upstream) => {
            let mut headers = HeaderMap::new();
            if let Ok(v) = HeaderValue::from_str(&outcome.redactions_applied.to_string()) {
                headers.insert(HeaderName::from_static("x-censgate-redactions-applied"), v);
            }
            if !outcome.entity_types.is_empty() {
                if let Ok(v) = HeaderValue::from_str(&outcome.entity_types.join(",")) {
                    headers.insert(HeaderName::from_static("x-censgate-redaction-types"), v);
                }
            }
            (
                StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY),
                headers,
                Json(upstream.body),
            )
                .into_response()
        }
        Err(err) => {
            warn!(error = %err, "upstream request failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody::new(
                    format!("upstream request failed: {err}"),
                    "upstream_error",
                )),
            )
                .into_response()
        }
    }
}
