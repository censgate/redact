// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! HTTP surface: OpenAI-compatible endpoints plus gateway utilities.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use redact_core::AnalyzerEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;

use crate::config::{ConfigHandle, ResolvedConfig};
use crate::error::GatewayError;
use crate::policy::Profile;
use crate::proxy::UpstreamClient;
use crate::redact::json as payload;
use crate::redact::token::{Dek, RestoreOutcome, TokenSession};
use crate::redact::{content_digest, RedactError, RedactionContext, RedactionOutcome};
use crate::stream::{build_redacted_sse, extract_sse};

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// Atomically swappable configuration snapshot.
    pub config: ConfigHandle,
    /// Detection engine shared by every request.
    pub engine: Arc<AnalyzerEngine>,
    /// Upstream provider client.
    pub upstream: UpstreamClient,
    /// Key used to seal reversible token mappings.
    pub dek: Arc<Dek>,
}

impl AppState {
    /// Current configuration snapshot.
    pub fn config(&self) -> Arc<ResolvedConfig> {
        self.config.load()
    }
}

/// Build the gateway router.
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/livez", get(live))
        .route("/readyz", get(ready))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/completions", post(completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/models", get(models))
        .route("/v1/redact", post(redact_endpoint))
        .route("/v1/compliance/status", get(compliance_status))
        .route("/v1/compliance/check", post(compliance_check))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();
    Json(json!({
        "status": "ok",
        "service": "redact-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "recognizers": state.engine.recognizer_registry().recognizers().len(),
        "profiles": config.policy.profile_names(),
        "default_profile": config.policy.default_profile,
    }))
}

async fn live() -> impl IntoResponse {
    Json(json!({"status": "ok"}))
}

async fn ready(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();
    Json(json!({
        "status": "ok",
        "upstream": config.upstream.base_url,
        "token_map": config.vault.backend.as_str(),
        "auth": config.auth.mode.as_str(),
    }))
}

/// Everything a request-scoped pipeline needs after policy selection.
struct RequestScope {
    profile: Arc<Profile>,
    session: TokenSession,
    forwarded_auth: Option<String>,
    upstream_headers: HeaderMap,
}

impl RequestScope {
    fn build(state: &AppState, headers: &HeaderMap) -> Result<Self, GatewayError> {
        let config = state.config();

        let requested_profile = if config.redaction.allow_profile_header {
            header_value(headers, &config.redaction.profile_header)
        } else {
            None
        };
        let profile = config
            .policy
            .profile(requested_profile.as_deref())
            .map_err(|e| GatewayError::InvalidRequest(e.to_string()))?;

        let session_id = header_value(headers, &config.redaction.session_header)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let session = TokenSession::new(session_id, "default", state.dek.clone());

        let forwarded_auth = if config.upstream.forward_client_authorization {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        } else {
            None
        };

        Ok(Self {
            profile,
            session,
            forwarded_auth,
            upstream_headers: HeaderMap::new(),
        })
    }

    /// Token lookup for restoring values in a response.
    fn restore_lookup(&self, dek: &Dek) -> HashMap<String, String> {
        if !self.profile.restore_responses {
            return HashMap::new();
        }
        self.session
            .new_mappings()
            .iter()
            .filter_map(|mapping| {
                dek.open(&mapping.sealed_value)
                    .ok()
                    .map(|plaintext| (mapping.token.clone(), plaintext))
            })
            .collect()
    }
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn redaction_error(err: RedactError) -> GatewayError {
    match err {
        RedactError::TokenizationUnavailable => GatewayError::DependencyUnavailable(
            "policy requires tokenization but no token map backend is available".to_string(),
        ),
        other => GatewayError::Redaction(other.to_string()),
    }
}

fn blocked_error(outcome: &RedactionOutcome) -> GatewayError {
    GatewayError::PolicyBlocked(format!(
        "request contains disallowed content: {}",
        outcome.blocked_entities.join(", ")
    ))
}

async fn chat_completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    match chat_completions_inner(state, headers, &mut body).await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn chat_completions_inner(
    state: AppState,
    headers: HeaderMap,
    body: &mut Value,
) -> Result<Response, GatewayError> {
    let mut scope = RequestScope::build(&state, &headers)?;
    let streaming = body.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let request_outcome = {
        let mut ctx =
            RedactionContext::with_session(&state.engine, &scope.profile, &mut scope.session);
        payload::redact_chat_request(&mut ctx, body).map_err(redaction_error)?;
        ctx.finish()
    };
    if request_outcome.is_blocked() {
        return Err(blocked_error(&request_outcome));
    }

    let lookup = scope.restore_lookup(&state.dek);

    if streaming {
        return stream_chat(&state, &scope, body, &request_outcome, &lookup).await;
    }

    let mut upstream = state
        .upstream
        .post_json(
            "/v1/chat/completions",
            body,
            scope.forwarded_auth.as_deref(),
            &scope.upstream_headers,
        )
        .await
        .map_err(|e| GatewayError::Upstream(e.to_string()))?;

    let response_outcome = {
        let mut ctx = RedactionContext::new(&state.engine, &scope.profile);
        payload::redact_chat_response(&mut ctx, &mut upstream.body).map_err(redaction_error)?;
        ctx.finish()
    };

    let restore = payload::restore_chat_response(&mut upstream.body, &lookup);

    let headers = compliance_headers(&request_outcome, &response_outcome, &restore);
    Ok((
        StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY),
        headers,
        Json(upstream.body),
    )
        .into_response())
}

async fn stream_chat(
    state: &AppState,
    scope: &RequestScope,
    body: &Value,
    request_outcome: &RedactionOutcome,
    lookup: &HashMap<String, String>,
) -> Result<Response, GatewayError> {
    let upstream = state
        .upstream
        .post_sse(
            "/v1/chat/completions",
            body,
            scope.forwarded_auth.as_deref(),
            &scope.upstream_headers,
        )
        .await
        .map_err(|e| GatewayError::Upstream(e.to_string()))?;

    if upstream.status >= 400 {
        // Provider errors arrive as JSON even when the request asked for SSE.
        let error_body = serde_json::from_str::<Value>(&upstream.body).unwrap_or_else(
            |_| json!({"error": {"message": upstream.body, "type": "upstream_error"}}),
        );
        return Ok((
            StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(error_body),
        )
            .into_response());
    }

    let extracted = extract_sse(&upstream.body);
    let (redacted, response_outcome) = {
        let mut ctx = RedactionContext::new(&state.engine, &scope.profile);
        let redacted = ctx.redact(&extracted.content).map_err(redaction_error)?;
        (redacted, ctx.finish())
    };

    let (restored, restore) = crate::redact::token::restore_text(&redacted, lookup);

    let id = format!("chatcmpl-{}", Uuid::new_v4());
    let model = extracted
        .model
        .as_deref()
        .or_else(|| body.get("model").and_then(Value::as_str))
        .unwrap_or("unknown");
    let sse = build_redacted_sse(
        &id,
        model,
        &restored,
        extracted.finish_reason.as_deref(),
        extracted.created,
    );

    let mut headers = compliance_headers(request_outcome, &response_outcome, &restore);
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-cache"),
    );
    Ok((StatusCode::OK, headers, sse).into_response())
}

async fn completions(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    match proxy_json_surface(state, headers, &mut body, "/v1/completions").await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn embeddings(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    match proxy_json_surface(state, headers, &mut body, "/v1/embeddings").await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

/// Shared pipeline for non-streaming JSON surfaces.
async fn proxy_json_surface(
    state: AppState,
    headers: HeaderMap,
    body: &mut Value,
    path: &str,
) -> Result<Response, GatewayError> {
    let mut scope = RequestScope::build(&state, &headers)?;

    let request_outcome = {
        let mut ctx =
            RedactionContext::with_session(&state.engine, &scope.profile, &mut scope.session);
        if path == "/v1/embeddings" {
            payload::redact_embeddings_request(&mut ctx, body).map_err(redaction_error)?;
        } else {
            payload::redact_chat_request(&mut ctx, body).map_err(redaction_error)?;
        }
        ctx.finish()
    };
    if request_outcome.is_blocked() {
        return Err(blocked_error(&request_outcome));
    }

    let mut upstream = state
        .upstream
        .post_json(
            path,
            body,
            scope.forwarded_auth.as_deref(),
            &scope.upstream_headers,
        )
        .await
        .map_err(|e| GatewayError::Upstream(e.to_string()))?;

    // Embedding vectors carry no text, so only completion-style bodies are
    // scanned on the way back.
    let response_outcome = if path == "/v1/embeddings" {
        RedactionOutcome::default()
    } else {
        let mut ctx = RedactionContext::new(&state.engine, &scope.profile);
        payload::redact_chat_response(&mut ctx, &mut upstream.body).map_err(redaction_error)?;
        ctx.finish()
    };

    let lookup = scope.restore_lookup(&state.dek);
    let restore = payload::restore_chat_response(&mut upstream.body, &lookup);

    let headers = compliance_headers(&request_outcome, &response_outcome, &restore);
    Ok((
        StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY),
        headers,
        Json(upstream.body),
    )
        .into_response())
}

async fn models(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let config = state.config();
    let forwarded_auth = if config.upstream.forward_client_authorization {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    } else {
        None
    };

    match state
        .upstream
        .get_json("/v1/models", forwarded_auth.as_deref(), &HeaderMap::new())
        .await
    {
        Ok(upstream) => (
            StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(upstream.body),
        )
            .into_response(),
        Err(err) => GatewayError::Upstream(err.to_string()).into_response(),
    }
}

/// Request body for `/v1/redact` and `/v1/compliance/check`.
#[derive(Debug, Clone, Deserialize)]
pub struct RedactRequest {
    /// Text to analyze.
    pub text: String,
    /// Policy profile to apply. Defaults to the configured default profile.
    #[serde(default)]
    pub profile: Option<String>,
}

/// Response body for `/v1/redact`.
#[derive(Debug, Clone, Serialize)]
pub struct RedactResponse {
    /// Text after the policy was applied.
    pub text: String,
    /// Profile that was applied.
    pub profile: String,
    /// Whether policy would refuse this content.
    pub blocked: bool,
    /// What the pass did.
    pub outcome: RedactionOutcome,
    /// Digest of the redacted text, for correlation without content.
    pub content_sha256: String,
}

async fn redact_endpoint(
    State(state): State<AppState>,
    Json(request): Json<RedactRequest>,
) -> Response {
    let config = state.config();
    let profile = match config.policy.profile(request.profile.as_deref()) {
        Ok(profile) => profile,
        Err(err) => return GatewayError::InvalidRequest(err.to_string()).into_response(),
    };

    let mut session = TokenSession::new(Uuid::new_v4().to_string(), "default", state.dek.clone());
    let mut ctx = RedactionContext::with_session(&state.engine, &profile, &mut session);
    let text = match ctx.redact(&request.text) {
        Ok(text) => text,
        Err(err) => return redaction_error(err).into_response(),
    };
    let outcome = ctx.finish();

    Json(RedactResponse {
        content_sha256: content_digest(&text),
        text,
        profile: profile.name.clone(),
        blocked: outcome.is_blocked(),
        outcome,
    })
    .into_response()
}

async fn compliance_check(
    State(state): State<AppState>,
    Json(request): Json<RedactRequest>,
) -> Response {
    let config = state.config();
    let profile = match config.policy.profile(request.profile.as_deref()) {
        Ok(profile) => profile,
        Err(err) => return GatewayError::InvalidRequest(err.to_string()).into_response(),
    };

    let mut ctx = RedactionContext::new(&state.engine, &profile);
    // A check reports what policy would do without minting tokens, so a
    // caller can pre-flight content without touching the token map.
    let would_tokenize = profile.uses_tokenization();
    let outcome = match ctx.redact(&request.text) {
        Ok(_) => ctx.finish(),
        Err(RedactError::TokenizationUnavailable) => {
            let mut session =
                TokenSession::new(Uuid::new_v4().to_string(), "check", state.dek.clone());
            let mut ctx = RedactionContext::with_session(&state.engine, &profile, &mut session);
            match ctx.redact(&request.text) {
                Ok(_) => ctx.finish(),
                Err(err) => return redaction_error(err).into_response(),
            }
        }
        Err(err) => return redaction_error(err).into_response(),
    };

    Json(json!({
        "profile": profile.name,
        "allowed": !outcome.is_blocked(),
        "blocked_entities": outcome.blocked_entities,
        "entity_counts": outcome.entity_counts,
        "action_counts": outcome.action_counts,
        "would_tokenize": would_tokenize,
    }))
    .into_response()
}

async fn compliance_status(State(state): State<AppState>) -> impl IntoResponse {
    let config = state.config();
    let profiles: Vec<Value> = config
        .policy
        .profiles
        .values()
        .map(|profile| {
            json!({
                "name": profile.name,
                "description": profile.description,
                "default_action": profile.default_action.as_str(),
                "min_confidence": profile.min_confidence,
                "rules": profile.entities.len(),
                "fail_closed": profile.fail_closed,
                "restore_responses": profile.restore_responses,
                "can_block": profile.can_block(),
                "uses_tokenization": profile.uses_tokenization(),
            })
        })
        .collect();

    Json(json!({
        "service": "redact-gateway",
        "version": env!("CARGO_PKG_VERSION"),
        "config_source": config.source.as_str(),
        "default_profile": config.policy.default_profile,
        "profiles": profiles,
        "recognizers": state.engine.recognizer_registry().recognizers().len(),
        "token_map_backend": config.vault.backend.as_str(),
        "auth_mode": config.auth.mode.as_str(),
        "audit_export": config.audit.export.as_str(),
    }))
}

/// Response headers describing what the gateway did.
pub fn compliance_headers(
    request: &RedactionOutcome,
    response: &RedactionOutcome,
    restore: &RestoreOutcome,
) -> HeaderMap {
    let mut headers = HeaderMap::new();
    let mut total = request.clone();
    total.merge(response);

    insert_number(
        &mut headers,
        "x-censgate-redactions-applied",
        total.redactions_applied,
    );
    insert_number(
        &mut headers,
        "x-censgate-request-redactions",
        request.redactions_applied,
    );
    insert_number(
        &mut headers,
        "x-censgate-response-redactions",
        response.redactions_applied,
    );
    if total.tokens_issued > 0 {
        insert_number(
            &mut headers,
            "x-censgate-tokens-issued",
            total.tokens_issued,
        );
    }
    if restore.restored > 0 {
        insert_number(&mut headers, "x-censgate-tokens-restored", restore.restored);
    }

    let types = total.entity_types();
    if !types.is_empty() {
        if let Ok(value) = HeaderValue::from_str(&types.join(",")) {
            headers.insert(HeaderName::from_static("x-censgate-redaction-types"), value);
        }
    }
    headers
}

fn insert_number(headers: &mut HeaderMap, name: &'static str, value: usize) {
    if let Ok(value) = HeaderValue::from_str(&value.to_string()) {
        headers.insert(HeaderName::from_static(name), value);
    }
}
