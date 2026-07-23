// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::openai::{ChatCompletionRequest, ErrorBody};
use crate::proxy::HttpChatUpstream;
use crate::redact::{
    redact_chat_request, redact_chat_response_json, redact_text, RedactionOutcome,
};
use crate::stream::{build_redacted_sse, extract_sse_model, extract_sse_text_content};
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use redact_core::{AnalyzerEngine, AnonymizerConfig};
use serde_json::json;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

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
        "service": "redact-gateway",
    }))
}

async fn chat_completions(
    State(state): State<AppState>,
    Json(mut request): Json<ChatCompletionRequest>,
) -> Response {
    let streaming = request.stream.unwrap_or(false);

    let request_outcome = match redact_chat_request(&state.engine, &mut request, &state.anonymizer)
    {
        Ok(o) => o,
        Err(err) => {
            warn!(error = %err, "request redaction failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorBody::new(
                    format!("request redaction failed: {err}"),
                    "redaction_error",
                )),
            )
                .into_response();
        }
    };

    info!(
        redactions = request_outcome.redactions_applied,
        entities = ?request_outcome.entity_types,
        streaming,
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

    if streaming {
        return stream_chat_completions(&state, &body, &request.model, request_outcome).await;
    }

    match state.upstream.chat_completions(&body).await {
        Ok(mut upstream) => {
            let response_outcome = match redact_chat_response_json(
                &state.engine,
                &mut upstream.body,
                &state.anonymizer,
            ) {
                Ok(o) => o,
                Err(err) => {
                    warn!(error = %err, "response redaction failed");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorBody::new(
                            format!("response redaction failed: {err}"),
                            "redaction_error",
                        )),
                    )
                        .into_response();
                }
            };

            info!(
                redactions = response_outcome.redactions_applied,
                entities = ?response_outcome.entity_types,
                "response redacted"
            );

            let headers = compliance_headers(&request_outcome, &response_outcome);
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

async fn stream_chat_completions(
    state: &AppState,
    body: &serde_json::Value,
    model: &str,
    request_outcome: RedactionOutcome,
) -> Response {
    match state.upstream.chat_completions_stream(body).await {
        Ok(upstream) => {
            if upstream.status >= 400 {
                // Upstream error payloads are usually JSON, not SSE.
                let err_body = serde_json::from_str::<serde_json::Value>(&upstream.body)
                    .unwrap_or_else(|_| {
                        json!({
                            "error": {
                                "message": upstream.body,
                                "type": "upstream_error"
                            }
                        })
                    });
                return (
                    StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY),
                    Json(err_body),
                )
                    .into_response();
            }

            let raw_content = extract_sse_text_content(&upstream.body);
            let (redacted_content, response_outcome) =
                match redact_text(&state.engine, &raw_content, &state.anonymizer) {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(error = %err, "stream response redaction failed");
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(ErrorBody::new(
                                format!("response redaction failed: {err}"),
                                "redaction_error",
                            )),
                        )
                            .into_response();
                    }
                };

            info!(
                redactions = response_outcome.redactions_applied,
                entities = ?response_outcome.entity_types,
                "stream response redacted"
            );

            let id = format!("chatcmpl-{}", Uuid::new_v4());
            let model_name = extract_sse_model(&upstream.body, model);
            let sse = build_redacted_sse(&id, &model_name, &redacted_content);

            let mut headers = compliance_headers(&request_outcome, &response_outcome);
            headers.insert(
                HeaderName::from_static("content-type"),
                HeaderValue::from_static("text/event-stream; charset=utf-8"),
            );
            headers.insert(
                HeaderName::from_static("cache-control"),
                HeaderValue::from_static("no-cache"),
            );

            (StatusCode::OK, headers, sse).into_response()
        }
        Err(err) => {
            warn!(error = %err, "upstream stream failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(ErrorBody::new(
                    format!("upstream stream failed: {err}"),
                    "upstream_error",
                )),
            )
                .into_response()
        }
    }
}

fn compliance_headers(request: &RedactionOutcome, response: &RedactionOutcome) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut total = request.clone();
    total.merge(response);

    if let Ok(v) = HeaderValue::from_str(&total.redactions_applied.to_string()) {
        headers.insert(HeaderName::from_static("x-censgate-redactions-applied"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&request.redactions_applied.to_string()) {
        headers.insert(HeaderName::from_static("x-censgate-request-redactions"), v);
    }
    if let Ok(v) = HeaderValue::from_str(&response.redactions_applied.to_string()) {
        headers.insert(HeaderName::from_static("x-censgate-response-redactions"), v);
    }
    if !total.entity_types.is_empty() {
        if let Ok(v) = HeaderValue::from_str(&total.entity_types.join(",")) {
            headers.insert(HeaderName::from_static("x-censgate-redaction-types"), v);
        }
    }
    headers
}
