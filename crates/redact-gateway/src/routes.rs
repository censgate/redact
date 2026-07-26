// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! HTTP surface: OpenAI-compatible endpoints plus gateway utilities.
//!
//! Middleware order on the model surfaces is authenticate, then evaluate
//! policy, redact, forward, restore, and finally emit an audit record. Health
//! and metrics endpoints are deliberately outside the authentication layer so
//! orchestrators can probe a gateway that rejects unauthenticated traffic.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::{MatchedPath, Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Extension, Json, Router};
use redact_core::AnalyzerEngine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{warn, Instrument};
use uuid::Uuid;

use crate::audit::{AuditContext, AuditDispatcher, AuditEvent, AuditOutcome};
use crate::auth::{AuthContext, Authenticator};
use crate::config::{ConfigHandle, ResolvedConfig, StreamMode};
use crate::error::GatewayError;
use crate::policy::Profile;
use crate::proxy::ProviderClient;
use crate::redact::json as payload;
use crate::redact::token::{
    subject_bound_session_key, Dek, RestoreOutcome, TokenMapping, TokenSession,
};
use crate::redact::{content_digest, RedactError, RedactionContext, RedactionOutcome};
use crate::stream::transform_buffered_sse;
use crate::telemetry::{semconv, spans, Telemetry};
use crate::vault::TokenMapStore;

/// Shared handler state.
#[derive(Clone)]
pub struct AppState {
    /// Atomically swappable configuration snapshot.
    pub config: ConfigHandle,
    /// Detection engine shared by every request.
    pub engine: Arc<AnalyzerEngine>,
    /// Inference provider client.
    pub provider: ProviderClient,
    /// Key used to seal reversible token mappings.
    pub dek: Arc<Dek>,
    /// Token map backend.
    pub tokens: Arc<dyn TokenMapStore>,
    /// Inbound authenticator.
    pub auth: Arc<dyn Authenticator>,
    /// Audit record dispatcher.
    pub audit: Arc<AuditDispatcher>,
    /// Telemetry handles.
    pub telemetry: Arc<Telemetry>,
}

impl AppState {
    /// Current configuration snapshot.
    pub fn config(&self) -> Arc<ResolvedConfig> {
        self.config.load()
    }
}

/// Build the gateway router.
pub fn create_router(state: AppState) -> Router {
    let public = Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/livez", get(live))
        .route("/readyz", get(ready))
        .route("/metrics", get(metrics))
        .with_state(state.clone());

    let protected = Router::new()
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/completions", post(completions))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/models", get(models))
        .route("/v1/redact", post(redact_endpoint))
        .route("/v1/restore", post(restore_endpoint))
        .route("/v1/compliance/status", get(compliance_status))
        .route("/v1/compliance/check", post(compliance_check))
        .layer(from_fn_with_state(state.clone(), authenticate))
        .with_state(state.clone());

    public
        .merge(protected)
        .layer(from_fn_with_state(state, observe))
}

/// Record OpenTelemetry server spans and metrics for every request.
async fn observe(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let method = request.method().as_str().to_string();
    let route = request
        .extensions()
        .get::<MatchedPath>()
        .map(|matched| matched.as_str().to_string())
        .unwrap_or_else(|| "/{unmatched}".to_string());
    let scheme = request.uri().scheme_str().unwrap_or("http").to_string();

    let span = spans::http_server(&method, &route, &scheme);
    // Join the caller's trace when they propagated one.
    spans::adopt_remote_parent(&span, request.headers());

    let metrics = state.telemetry.metrics();
    metrics.http_server_active_add(1, &method, &scheme);
    let started = Instant::now();

    let response = next.run(request).instrument(span.clone()).await;

    let status = response.status();
    let error_type = if status.is_client_error() || status.is_server_error() {
        Some(status.as_str().to_string())
    } else {
        None
    };
    spans::finish_http_server(&span, status.as_u16(), error_type.as_deref());
    metrics.record_http_server(
        started.elapsed().as_secs_f64(),
        &method,
        &scheme,
        &route,
        status.as_u16(),
        error_type.as_deref(),
    );
    metrics.http_server_active_add(-1, &method, &scheme);

    let dropped = state.audit.dropped();
    if dropped > 0 {
        metrics.record_audit_dropped(dropped);
    }

    response
}

/// Authenticate the caller and attach an [`AuthContext`] to the request.
async fn authenticate(State(state): State<AppState>, mut request: Request, next: Next) -> Response {
    let config = state.config();
    let level = config.telemetry.operations;
    let span = spans::authenticate(level, state.auth.mode());

    match state.auth.authenticate(request.headers()).await {
        Ok(context) => {
            if let Some(span) = &span {
                spans::finish_authenticate(span, "allowed", None);
            }
            request.extensions_mut().insert(context);
            next.run(request).await
        }
        Err(err) => {
            let error: GatewayError = err.into();
            if let Some(span) = &span {
                spans::finish_authenticate(span, "denied", Some(error.telemetry_error_type()));
            }
            state.audit.emit(AuditEvent::from_outcome(
                &RedactionOutcome::default(),
                AuditContext {
                    event_name: semconv::event::AUTH_DENIED,
                    action: request.uri().path().to_string(),
                    outcome: Some(AuditOutcome::Denied),
                    profile: config.policy.default_profile.clone(),
                    tenant: "unknown".to_string(),
                    error_type: Some(error.telemetry_error_type().to_string()),
                    include_entity_types: config.audit.include_entity_types,
                    ..AuditContext::default()
                },
            ));
            error.into_response()
        }
    }
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

async fn ready(State(state): State<AppState>) -> Response {
    let config = state.config();
    let token_map_ready = state.tokens.health().await.is_ok();
    let auth_ready = state.auth.ready().await;
    let ready = token_map_ready && auth_ready;

    let body = json!({
        "status": if ready { "ok" } else { "degraded" },
        "provider": config.provider.base_url,
        "token_map": {"backend": config.vault.backend.as_str(), "ready": token_map_ready},
        "auth": {"mode": state.auth.mode(), "ready": auth_ready},
        "audit": config.audit.export.as_str(),
    });

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body)).into_response()
}

async fn metrics(State(state): State<AppState>) -> Response {
    let config = state.config();
    if !config.server.metrics_endpoint {
        return (StatusCode::NOT_FOUND, "metrics endpoint is disabled").into_response();
    }

    match state.telemetry.prometheus_metrics() {
        Some(rendered) => (
            StatusCode::OK,
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )],
            rendered,
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            "no pull-based metrics exporter is active; either the OpenTelemetry SDK is \
             disabled or this build was compiled without the `prometheus` feature",
        )
            .into_response(),
    }
}

/// Everything a request-scoped pipeline needs after policy selection.
struct RequestScope {
    config: Arc<ResolvedConfig>,
    profile: Arc<Profile>,
    session: TokenSession,
    /// Caller-facing session id (header / generated UUID). Used in audit and
    /// responses — never rewritten to the subject-bound storage key.
    session_id: String,
    /// Token-map partition key: subject-bound when authenticated, otherwise the
    /// caller-facing id (auth.mode = none residual trust model).
    token_map_session: String,
    tenant: String,
    subject: Option<String>,
    known_mappings: Vec<TokenMapping>,
    forwarded_auth: Option<String>,
    provider_headers: reqwest::header::HeaderMap,
}

impl RequestScope {
    async fn build(
        state: &AppState,
        headers: &HeaderMap,
        auth: &AuthContext,
    ) -> Result<Self, GatewayError> {
        let config = state.config();

        // A credential-supplied profile wins over the request header so a
        // caller cannot widen the policy their credential was issued for.
        let requested_profile = auth.profile.clone().or_else(|| {
            if config.redaction.allow_profile_header {
                header_value(headers, &config.redaction.profile_header)
            } else {
                None
            }
        });
        let profile = config
            .policy
            .profile(requested_profile.as_deref())
            .map_err(|e| GatewayError::InvalidRequest(e.to_string()))?;

        let caller_session = header_value(headers, &config.redaction.session_header);
        let session_id = caller_session
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        let tenant = auth.tenant.clone();
        // Bind persisted mappings to the authenticated subject so a second
        // caller in the same tenant cannot resume another subject's session by
        // replaying the caller-chosen session id. When auth.mode = none there
        // is no subject; the partition falls back to the caller id alone and
        // /v1/restore is rejected separately.
        let token_map_session = match auth.subject.as_deref() {
            Some(subject) => subject_bound_session_key(&session_id, subject),
            None => session_id.clone(),
        };

        // Resume prior tokens only when the caller identified a session, so
        // unrelated requests never share a token namespace.
        let known_mappings = if caller_session.is_some() && state.tokens.backend_name() != "off" {
            let span = spans::tokenmap_get(
                config.telemetry.operations,
                state.tokens.backend_name(),
                0,
                config.vault.address.as_deref(),
                None,
            );
            match state.tokens.get(&tenant, &token_map_session).await {
                Ok(mappings) => {
                    if let Some(span) = &span {
                        spans::finish_tokenmap(span, mappings.len(), None);
                    }
                    state.telemetry.metrics().record_tokenmap_operation(
                        state.tokens.backend_name(),
                        "get",
                        0.0,
                        None,
                    );
                    mappings
                }
                Err(err) => {
                    if let Some(span) = &span {
                        spans::finish_tokenmap(span, 0, Some("token_map_error"));
                    }
                    state.telemetry.metrics().record_tokenmap_operation(
                        state.tokens.backend_name(),
                        "get",
                        0.0,
                        Some("token_map_error"),
                    );
                    if profile.fail_closed {
                        return Err(GatewayError::DependencyUnavailable(format!(
                            "token map is unavailable: {err}"
                        )));
                    }
                    warn!(error = %err, "token map read failed; continuing without prior tokens");
                    Vec::new()
                }
            }
        } else {
            Vec::new()
        };

        let session = TokenSession::resume(
            session_id.clone(),
            tenant.clone(),
            state.dek.clone(),
            known_mappings.clone(),
        );

        let forwarded_auth = if config.provider.forward_client_authorization {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string)
        } else {
            None
        };

        let mut provider_headers = reqwest::header::HeaderMap::new();
        crate::telemetry::inject_context(&mut provider_headers);

        Ok(Self {
            config,
            profile,
            session,
            session_id,
            token_map_session,
            tenant,
            subject: auth.subject.clone(),
            known_mappings,
            forwarded_auth,
            provider_headers,
        })
    }

    /// Persist newly minted mappings so a later request can restore them.
    async fn persist_tokens(&mut self, state: &AppState) -> Result<(), GatewayError> {
        let minted = self.session.take_new_mappings();
        if minted.is_empty() || state.tokens.backend_name() == "off" {
            self.known_mappings.extend(minted);
            return Ok(());
        }

        let span = spans::tokenmap_put(
            self.config.telemetry.operations,
            state.tokens.backend_name(),
            minted.len(),
            self.config.vault.address.as_deref(),
            None,
        );
        let started = Instant::now();
        let result = state
            .tokens
            .put(&self.tenant, &self.token_map_session, &minted)
            .await;
        let elapsed = started.elapsed().as_secs_f64();

        match result {
            Ok(()) => {
                if let Some(span) = &span {
                    spans::finish_tokenmap(span, minted.len(), None);
                }
                state.telemetry.metrics().record_tokenmap_operation(
                    state.tokens.backend_name(),
                    "put",
                    elapsed,
                    None,
                );
                self.known_mappings.extend(minted);
                Ok(())
            }
            Err(err) => {
                if let Some(span) = &span {
                    spans::finish_tokenmap(span, 0, Some("token_map_error"));
                }
                state.telemetry.metrics().record_tokenmap_operation(
                    state.tokens.backend_name(),
                    "put",
                    elapsed,
                    Some("token_map_error"),
                );
                // Token-label collisions are integrity failures: never keep the
                // local mapping for restore when persistence rejected it.
                if matches!(err, crate::vault::TokenMapError::Conflict(_))
                    || self.profile.fail_closed
                {
                    return Err(GatewayError::DependencyUnavailable(format!(
                        "token map write failed: {err}"
                    )));
                }
                warn!(error = %err, "token map write failed; tokens will not survive this request");
                self.known_mappings.extend(minted);
                Ok(())
            }
        }
    }

    /// Token lookup for restoring values in a response.
    fn restore_lookup(&self, dek: &Dek) -> HashMap<String, String> {
        if !self.profile.restore_responses {
            return HashMap::new();
        }
        self.known_mappings
            .iter()
            .chain(self.session.new_mappings())
            .filter_map(|mapping| {
                dek.open(&mapping.sealed_value)
                    .ok()
                    .map(|plaintext| (mapping.token.clone(), plaintext))
            })
            .collect()
    }

    fn audit_context(&self, event_name: &'static str, action: &str) -> AuditContext {
        AuditContext {
            event_name,
            action: action.to_string(),
            outcome: None,
            profile: self.profile.name.clone(),
            tenant: self.tenant.clone(),
            session_id: Some(self.session_id.clone()),
            subject: self.subject.clone(),
            include_entity_types: self.config.audit.include_entity_types,
            ..AuditContext::default()
        }
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

/// Run detection and policy over a request payload, recording telemetry.
fn redact_request_payload(
    state: &AppState,
    scope: &mut RequestScope,
    body: &mut Value,
    embeddings: bool,
) -> Result<RedactionOutcome, GatewayError> {
    let level = scope.config.telemetry.operations;
    let policy_span = spans::policy_evaluate(level, &scope.profile.name);
    let detect_span = spans::detect(level, body.to_string().len());

    let mut ctx = RedactionContext::with_session(&state.engine, &scope.profile, &mut scope.session);
    let result = if embeddings {
        payload::redact_embeddings_request(&mut ctx, body)
    } else {
        payload::redact_chat_request(&mut ctx, body)
    };
    let outcome = ctx.finish();

    if let Some(span) = &detect_span {
        spans::finish_detect(
            span,
            outcome.redactions_applied + outcome.allowed,
            level,
            result.as_ref().err().map(|_| "redaction_error"),
        );
    }
    let decision = if outcome.is_blocked() {
        "blocked"
    } else if outcome.redactions_applied > 0 {
        "redacted"
    } else {
        "allowed"
    };
    if let Some(span) = &policy_span {
        spans::finish_policy_evaluate(span, decision, None);
    }

    let metrics = state.telemetry.metrics();
    metrics.record_redaction_outcome(&outcome, &scope.profile.name);
    metrics.record_policy_decision(&scope.profile.name, decision);

    result.map_err(redaction_error)?;
    Ok(outcome)
}

/// Run detection and policy over a response payload.
fn redact_response_payload(
    state: &AppState,
    scope: &RequestScope,
    body: &mut Value,
) -> Result<RedactionOutcome, GatewayError> {
    let mut ctx = RedactionContext::for_response(&state.engine, &scope.profile);
    let result = payload::redact_chat_response(&mut ctx, body);
    let outcome = ctx.finish();
    state
        .telemetry
        .metrics()
        .record_redaction_outcome(&outcome, &scope.profile.name);
    result.map_err(redaction_error)?;
    Ok(outcome)
}

fn restore_response_payload(
    state: &AppState,
    scope: &RequestScope,
    body: &mut Value,
    lookup: &HashMap<String, String>,
) -> RestoreOutcome {
    if lookup.is_empty() {
        return RestoreOutcome::default();
    }
    let span = spans::restore(scope.config.telemetry.operations);
    let outcome = payload::restore_chat_response(body, lookup);
    if let Some(span) = &span {
        spans::finish_restore(span, outcome.restored, outcome.missing, None);
    }
    let _ = state;
    outcome
}

async fn chat_completions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    match chat_completions_inner(state, auth, headers, &mut body).await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn chat_completions_inner(
    state: AppState,
    auth: AuthContext,
    headers: HeaderMap,
    body: &mut Value,
) -> Result<Response, GatewayError> {
    let mut scope = RequestScope::build(&state, &headers, &auth).await?;
    let streaming = body.get("stream").and_then(Value::as_bool).unwrap_or(false);

    let request_outcome = redact_request_payload(&state, &mut scope, body, false)?;
    if request_outcome.is_blocked() {
        let error = blocked_error(&request_outcome);
        state.audit.emit(AuditEvent::from_outcome(
            &request_outcome,
            AuditContext {
                outcome: Some(AuditOutcome::Blocked),
                error_type: Some(error.telemetry_error_type().to_string()),
                ..scope.audit_context(semconv::event::POLICY_BLOCK, "chat.completions")
            },
        ));
        return Err(error);
    }

    scope.persist_tokens(&state).await?;
    let lookup = scope.restore_lookup(&state.dek);

    state.audit.emit(AuditEvent::from_outcome(
        &request_outcome,
        AuditContext {
            outcome: Some(AuditOutcome::Allowed),
            content_sha256: Some(content_digest(&body.to_string())),
            ..scope.audit_context(semconv::event::REQUEST, "chat.completions")
        },
    ));

    if streaming {
        return stream_chat(&state, &scope, body, &request_outcome, &lookup).await;
    }

    let mut response = call_provider(&state, &scope, "/v1/chat/completions", body).await?;
    let response_outcome = redact_response_payload(&state, &scope, &mut response.body)?;
    if response_outcome.is_blocked() {
        let error = blocked_error(&response_outcome);
        state.audit.emit(AuditEvent::from_outcome(
            &response_outcome,
            AuditContext {
                outcome: Some(AuditOutcome::Blocked),
                error_type: Some(error.telemetry_error_type().to_string()),
                provider_status: Some(response.status),
                ..scope.audit_context(semconv::event::POLICY_BLOCK, "chat.completions")
            },
        ));
        return Err(error);
    }
    let restore = restore_response_payload(&state, &scope, &mut response.body, &lookup);

    state.audit.emit(AuditEvent::from_outcome(
        &response_outcome,
        AuditContext {
            outcome: Some(AuditOutcome::Allowed),
            provider_status: Some(response.status),
            ..scope.audit_context(semconv::event::RESPONSE, "chat.completions")
        },
    ));

    let headers = compliance_headers(&request_outcome, &response_outcome, &restore);
    Ok((
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY),
        headers,
        Json(response.body),
    )
        .into_response())
}

/// Map a gateway path to a `gen_ai.operation.name` value.
///
/// The OpenTelemetry GenAI conventions define these names; a request that does
/// not match one of them reports no operation rather than inventing a value.
fn genai_operation(path: &str) -> &'static str {
    match path {
        "/v1/chat/completions" => "chat",
        "/v1/embeddings" => "embeddings",
        "/v1/completions" => "text_completion",
        _ => "chat",
    }
}

/// Split a base URL into the `server.address` and `server.port` attributes.
fn provider_endpoint(base_url: &str) -> (String, u16) {
    let without_scheme = base_url
        .strip_prefix("https://")
        .map(|rest| (rest, 443u16))
        .or_else(|| base_url.strip_prefix("http://").map(|rest| (rest, 80u16)));
    let (rest, default_port) = match without_scheme {
        Some(parts) => parts,
        None => (base_url, 0),
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.rsplit_once(':') {
        Some((host, port)) => (host.to_string(), port.parse().unwrap_or(default_port)),
        None => (authority.to_string(), default_port),
    }
}

/// Fill in GenAI response attributes from an upstream body.
fn genai_response(body: &Value, request: &spans::GenAiAttrs) -> spans::GenAiAttrs {
    spans::GenAiAttrs {
        response_model: body
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        input_tokens: body.pointer("/usage/prompt_tokens").and_then(Value::as_u64),
        output_tokens: body
            .pointer("/usage/completion_tokens")
            .and_then(Value::as_u64),
        finish_reasons: body
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
            .map(str::to_string),
        ..request.clone()
    }
}

async fn call_provider(
    state: &AppState,
    scope: &RequestScope,
    path: &str,
    body: &Value,
) -> Result<crate::proxy::ProviderResponse, GatewayError> {
    let level = scope.config.telemetry.operations;
    let genai = spans::GenAiAttrs {
        operation_name: Some(genai_operation(path)),
        provider_name: Some(scope.config.provider.name.clone()),
        request_model: body
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        request_stream: Some(false),
        ..spans::GenAiAttrs::default()
    };
    let (address, port) = provider_endpoint(state.provider.base_url());
    let span = spans::provider_chat(
        level,
        "POST",
        &address,
        port,
        scope.config.telemetry.genai_attributes,
        &genai,
    );
    let started = Instant::now();
    let result = state
        .provider
        .post_json(
            path,
            body,
            scope.forwarded_auth.as_deref(),
            &scope.provider_headers,
        )
        .await;
    let elapsed = started.elapsed().as_secs_f64();

    match result {
        Ok(response) => {
            if let Some(span) = &span {
                spans::finish_provider_chat(
                    span,
                    Some(response.status),
                    scope.config.telemetry.genai_attributes,
                    level,
                    &genai_response(&response.body, &genai),
                    None,
                );
            }
            state.telemetry.metrics().record_http_client(
                elapsed,
                "POST",
                Some(response.status),
                None,
            );
            Ok(response)
        }
        Err(err) => {
            if let Some(span) = &span {
                spans::finish_provider_chat(
                    span,
                    None,
                    scope.config.telemetry.genai_attributes,
                    level,
                    &genai,
                    Some("upstream_error"),
                );
            }
            state.telemetry.metrics().record_http_client(
                elapsed,
                "POST",
                None,
                Some("upstream_error"),
            );
            Err(GatewayError::Provider(err.to_string()))
        }
    }
}

/// Client span for a streamed provider call.
fn stream_provider_span(
    state: &AppState,
    scope: &RequestScope,
    body: &Value,
) -> Option<tracing::Span> {
    let genai = spans::GenAiAttrs {
        operation_name: Some("chat"),
        provider_name: Some(scope.config.provider.name.clone()),
        request_model: body
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_string),
        request_stream: Some(true),
        ..spans::GenAiAttrs::default()
    };
    let (address, port) = provider_endpoint(state.provider.base_url());
    spans::provider_chat(
        scope.config.telemetry.operations,
        "POST",
        &address,
        port,
        scope.config.telemetry.genai_attributes,
        &genai,
    )
}

async fn stream_chat(
    state: &AppState,
    scope: &RequestScope,
    body: &Value,
    request_outcome: &RedactionOutcome,
    lookup: &HashMap<String, String>,
) -> Result<Response, GatewayError> {
    let mode = scope.config.redaction.stream_mode;
    let span = spans::stream_redact(scope.config.telemetry.operations, mode.as_str());

    if mode == StreamMode::Incremental {
        return stream_chat_incremental(state, scope, body, request_outcome, lookup).await;
    }

    let provider_span = stream_provider_span(state, scope, body);
    let response = match state
        .provider
        .post_sse(
            "/v1/chat/completions",
            body,
            scope.forwarded_auth.as_deref(),
            &scope.provider_headers,
        )
        .await
    {
        Ok(response) => {
            if let Some(span) = &provider_span {
                spans::finish_provider_chat(
                    span,
                    Some(response.status),
                    scope.config.telemetry.genai_attributes,
                    scope.config.telemetry.operations,
                    &spans::GenAiAttrs::default(),
                    None,
                );
            }
            response
        }
        Err(err) => {
            if let Some(span) = &provider_span {
                spans::finish_provider_chat(
                    span,
                    None,
                    scope.config.telemetry.genai_attributes,
                    scope.config.telemetry.operations,
                    &spans::GenAiAttrs::default(),
                    Some("provider_error"),
                );
            }
            return Err(GatewayError::Provider(err.to_string()));
        }
    };

    if response.status >= 400 {
        // Provider errors arrive as JSON even when the request asked for SSE.
        let mut error_body = serde_json::from_str::<Value>(&response.body).unwrap_or_else(
            |_| json!({"error": {"message": response.body, "type": "provider_error"}}),
        );
        let response_outcome = redact_response_payload(state, scope, &mut error_body)?;
        if response_outcome.is_blocked() {
            let error = blocked_error(&response_outcome);
            state.audit.emit(AuditEvent::from_outcome(
                &response_outcome,
                AuditContext {
                    outcome: Some(AuditOutcome::Blocked),
                    error_type: Some(error.telemetry_error_type().to_string()),
                    provider_status: Some(response.status),
                    ..scope.audit_context(semconv::event::POLICY_BLOCK, "chat.completions.stream")
                },
            ));
            return Err(error);
        }
        return Ok((
            StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(error_body),
        )
            .into_response());
    }

    let mut ctx = RedactionContext::for_response(&state.engine, &scope.profile);
    let mut restore = RestoreOutcome::default();
    let transformed = transform_buffered_sse(&response.body, |text| {
        let redacted = ctx.redact(text)?;
        let (restored, outcome) = crate::redact::token::restore_text(&redacted, lookup);
        restore.restored += outcome.restored;
        restore.missing += outcome.missing;
        Ok(restored)
    })
    .map_err(redaction_error)?;
    let response_outcome = ctx.finish();
    state
        .telemetry
        .metrics()
        .record_redaction_outcome(&response_outcome, &scope.profile.name);

    if let Some(span) = &span {
        spans::finish_stream_redact(
            span,
            transformed.chunks,
            scope.config.telemetry.operations,
            None,
        );
    }

    if response_outcome.is_blocked() {
        let error = blocked_error(&response_outcome);
        state.audit.emit(AuditEvent::from_outcome(
            &response_outcome,
            AuditContext {
                outcome: Some(AuditOutcome::Blocked),
                error_type: Some(error.telemetry_error_type().to_string()),
                provider_status: Some(response.status),
                ..scope.audit_context(semconv::event::POLICY_BLOCK, "chat.completions.stream")
            },
        ));
        return Err(error);
    }

    state.audit.emit(AuditEvent::from_outcome(
        &response_outcome,
        AuditContext {
            outcome: Some(AuditOutcome::Allowed),
            provider_status: Some(response.status),
            ..scope.audit_context(semconv::event::RESPONSE, "chat.completions.stream")
        },
    ));

    let sse = transformed.sse;

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

/// Forward a stream while redacting text as it arrives.
///
/// Time to first token is preserved at the cost of a bounded detection window:
/// values longer than the configured hold-back can straddle the boundary, which
/// is why the buffered mode remains the default.
async fn stream_chat_incremental(
    state: &AppState,
    scope: &RequestScope,
    body: &Value,
    request_outcome: &RedactionOutcome,
    lookup: &HashMap<String, String>,
) -> Result<Response, GatewayError> {
    let provider_span = stream_provider_span(state, scope, body);
    let (status, body_stream) = match state
        .provider
        .post_stream(
            "/v1/chat/completions",
            body,
            scope.forwarded_auth.as_deref(),
            &scope.provider_headers,
        )
        .await
    {
        Ok(parts) => parts,
        Err(err) => {
            if let Some(span) = &provider_span {
                spans::finish_provider_chat(
                    span,
                    None,
                    scope.config.telemetry.genai_attributes,
                    scope.config.telemetry.operations,
                    &spans::GenAiAttrs::default(),
                    Some("provider_error"),
                );
            }
            return Err(GatewayError::Provider(err.to_string()));
        }
    };
    if let Some(span) = &provider_span {
        spans::finish_provider_chat(
            span,
            Some(status),
            scope.config.telemetry.genai_attributes,
            scope.config.telemetry.operations,
            &spans::GenAiAttrs::default(),
            None,
        );
    }

    if status >= 400 {
        return Err(GatewayError::Provider(format!(
            "provider returned status {status}"
        )));
    }

    let model = body
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let (stream_body, outcome) = crate::stream::incremental_response(
        body_stream,
        state.engine.clone(),
        scope.profile.clone(),
        lookup.clone(),
        scope.config.redaction.stream_holdback_bytes,
        format!("chatcmpl-{}", Uuid::new_v4()),
        model,
    );

    state.audit.emit(AuditEvent::from_outcome(
        request_outcome,
        AuditContext {
            outcome: Some(AuditOutcome::Allowed),
            provider_status: Some(status),
            ..scope.audit_context(semconv::event::RESPONSE, "chat.completions.stream")
        },
    ));
    // Response totals are only known once the stream drains, so the headers
    // report the request-side counts and the stream itself carries the rest.
    let _ = outcome;

    let mut headers = compliance_headers(
        request_outcome,
        &RedactionOutcome::default(),
        &RestoreOutcome::default(),
    );
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static("text/event-stream; charset=utf-8"),
    );
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-cache"),
    );
    headers.insert(
        HeaderName::from_static("x-censgate-stream-mode"),
        HeaderValue::from_static("incremental"),
    );

    Ok((StatusCode::OK, headers, stream_body).into_response())
}

async fn completions(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    match proxy_json_surface(state, auth, headers, &mut body, "/v1/completions").await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn embeddings(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
    Json(mut body): Json<Value>,
) -> Response {
    match proxy_json_surface(state, auth, headers, &mut body, "/v1/embeddings").await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

/// Shared pipeline for non-streaming JSON surfaces.
async fn proxy_json_surface(
    state: AppState,
    auth: AuthContext,
    headers: HeaderMap,
    body: &mut Value,
    path: &str,
) -> Result<Response, GatewayError> {
    let is_embeddings = path == "/v1/embeddings";
    let action = if is_embeddings {
        "embeddings"
    } else {
        "completions"
    };

    let mut scope = RequestScope::build(&state, &headers, &auth).await?;
    let request_outcome = redact_request_payload(&state, &mut scope, body, is_embeddings)?;
    if request_outcome.is_blocked() {
        let error = blocked_error(&request_outcome);
        state.audit.emit(AuditEvent::from_outcome(
            &request_outcome,
            AuditContext {
                outcome: Some(AuditOutcome::Blocked),
                error_type: Some(error.telemetry_error_type().to_string()),
                ..scope.audit_context(semconv::event::POLICY_BLOCK, action)
            },
        ));
        return Err(error);
    }

    scope.persist_tokens(&state).await?;
    let mut response = call_provider(&state, &scope, path, body).await?;

    // Embedding vectors carry no text, so only completion-style bodies are
    // scanned on the way back.
    let response_outcome = if is_embeddings {
        RedactionOutcome::default()
    } else {
        redact_response_payload(&state, &scope, &mut response.body)?
    };

    if response_outcome.is_blocked() {
        let error = blocked_error(&response_outcome);
        state.audit.emit(AuditEvent::from_outcome(
            &response_outcome,
            AuditContext {
                outcome: Some(AuditOutcome::Blocked),
                error_type: Some(error.telemetry_error_type().to_string()),
                provider_status: Some(response.status),
                ..scope.audit_context(semconv::event::POLICY_BLOCK, action)
            },
        ));
        return Err(error);
    }

    let lookup = scope.restore_lookup(&state.dek);
    let restore = restore_response_payload(&state, &scope, &mut response.body, &lookup);

    state.audit.emit(AuditEvent::from_outcome(
        &request_outcome,
        AuditContext {
            outcome: Some(AuditOutcome::Allowed),
            provider_status: Some(response.status),
            ..scope.audit_context(semconv::event::REQUEST, action)
        },
    ));

    let headers = compliance_headers(&request_outcome, &response_outcome, &restore);
    Ok((
        StatusCode::from_u16(response.status).unwrap_or(StatusCode::BAD_GATEWAY),
        headers,
        Json(response.body),
    )
        .into_response())
}

async fn models(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let config = state.config();
    let forwarded_auth = if config.provider.forward_client_authorization {
        headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    } else {
        None
    };

    let mut provider_headers = reqwest::header::HeaderMap::new();
    crate::telemetry::inject_context(&mut provider_headers);

    match state
        .provider
        .get_json("/v1/models", forwarded_auth.as_deref(), &provider_headers)
        .await
    {
        Ok(upstream) => (
            StatusCode::from_u16(upstream.status).unwrap_or(StatusCode::BAD_GATEWAY),
            Json(upstream.body),
        )
            .into_response(),
        Err(err) => GatewayError::Provider(err.to_string()).into_response(),
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
    /// Session used for token numbering and persistence.
    #[serde(default)]
    pub session_id: Option<String>,
}

/// Response body for `/v1/redact`.
#[derive(Debug, Clone, Serialize)]
pub struct RedactResponse {
    /// Text after the policy was applied.
    pub text: String,
    /// Profile that was applied.
    pub profile: String,
    /// Session that owns any minted tokens.
    pub session_id: String,
    /// Whether policy would refuse this content.
    pub blocked: bool,
    /// What the pass did.
    pub outcome: RedactionOutcome,
    /// Digest of the redacted text, for correlation without content.
    pub content_sha256: String,
}

/// Resolve the policy profile for a request.
///
/// A credential-supplied profile always wins so callers cannot widen the policy
/// their credential was issued for. Otherwise the request-selected name is used
/// (body field or, on proxy surfaces, the profile header when enabled).
fn resolve_profile(
    config: &ResolvedConfig,
    auth: &AuthContext,
    request_profile: Option<&str>,
) -> Result<Arc<Profile>, GatewayError> {
    let name = auth
        .profile
        .as_deref()
        .or(request_profile)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    config
        .policy
        .profile(name)
        .map_err(|e| GatewayError::InvalidRequest(e.to_string()))
}

async fn redact_endpoint(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<RedactRequest>,
) -> Response {
    let config = state.config();
    let profile = match resolve_profile(&config, &auth, request.profile.as_deref()) {
        Ok(profile) => profile,
        Err(err) => return err.into_response(),
    };

    let session_id = request
        .session_id
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let token_map_session = match auth.subject.as_deref() {
        Some(subject) => subject_bound_session_key(&session_id, subject),
        None => session_id.clone(),
    };
    // Resume prior mappings so sequential /v1/redact calls with one session
    // continue the counter instead of reminting `[ENTITY_1]` and clobbering.
    let mut session = if state.tokens.backend_name() != "off" {
        match state.tokens.get(&auth.tenant, &token_map_session).await {
            Ok(existing) => TokenSession::resume(
                session_id.clone(),
                &auth.tenant,
                state.dek.clone(),
                existing,
            ),
            Err(err) if profile.fail_closed => {
                return GatewayError::DependencyUnavailable(format!(
                    "token map read failed: {err}"
                ))
                .into_response();
            }
            Err(err) => {
                warn!(error = %err, "token map read failed; starting a fresh session");
                TokenSession::new(session_id.clone(), &auth.tenant, state.dek.clone())
            }
        }
    } else {
        TokenSession::new(session_id.clone(), &auth.tenant, state.dek.clone())
    };
    let mut ctx = RedactionContext::with_session(&state.engine, &profile, &mut session);
    let text = match ctx.redact(&request.text) {
        Ok(text) => text,
        Err(err) => return redaction_error(err).into_response(),
    };
    let outcome = ctx.finish();

    let minted = session.take_new_mappings();
    if !minted.is_empty() && state.tokens.backend_name() != "off" {
        if let Err(err) = state
            .tokens
            .put(&auth.tenant, &token_map_session, &minted)
            .await
        {
            if profile.fail_closed {
                return GatewayError::DependencyUnavailable(format!(
                    "token map write failed: {err}"
                ))
                .into_response();
            }
            warn!(error = %err, "token map write failed");
        }
    }

    state
        .telemetry
        .metrics()
        .record_redaction_outcome(&outcome, &profile.name);

    Json(RedactResponse {
        content_sha256: content_digest(&text),
        text,
        profile: profile.name.clone(),
        session_id,
        blocked: outcome.is_blocked(),
        outcome,
    })
    .into_response()
}

/// Request body for `/v1/restore`.
#[derive(Debug, Clone, Deserialize)]
pub struct RestoreRequest {
    /// Text containing tokens to restore.
    pub text: String,
    /// Session that minted the tokens.
    pub session_id: String,
}

async fn restore_endpoint(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<RestoreRequest>,
) -> Response {
    // Standalone restore has no in-request token scope to fall back on, so it
    // requires an authenticated subject. auth.mode = none has none — reject
    // rather than letting every caller share the default-tenant partition.
    let Some(subject) = auth.subject.as_deref().filter(|_| auth.mode != "none") else {
        return GatewayError::Forbidden(
            "restore requires authentication; set auth.mode to api_key or oidc".to_string(),
        )
        .into_response();
    };

    if state.tokens.backend_name() == "off" {
        return GatewayError::DependencyUnavailable(
            "restore requires a token map backend; configure CENSGATE_VAULT_BACKEND".to_string(),
        )
        .into_response();
    }

    let token_map_session = subject_bound_session_key(&request.session_id, subject);

    // Missing and foreign-subject sessions both yield an empty mapping list so
    // callers cannot probe whether a session id exists for another subject.
    let mappings = match state.tokens.get(&auth.tenant, &token_map_session).await {
        Ok(mappings) => mappings,
        Err(err) => {
            return GatewayError::DependencyUnavailable(format!("token map read failed: {err}"))
                .into_response()
        }
    };

    let lookup: HashMap<String, String> = mappings
        .iter()
        .filter_map(|mapping| {
            state
                .dek
                .open(&mapping.sealed_value)
                .ok()
                .map(|plaintext| (mapping.token.clone(), plaintext))
        })
        .collect();

    let (text, outcome) = crate::redact::token::restore_text(&request.text, &lookup);
    Json(json!({
        "text": text,
        // Echo the caller-facing id only — never the subject-bound storage key.
        "session_id": request.session_id,
        "restored": outcome.restored,
        "missing": outcome.missing,
    }))
    .into_response()
}

async fn compliance_check(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Json(request): Json<RedactRequest>,
) -> Response {
    let config = state.config();
    let profile = match resolve_profile(&config, &auth, request.profile.as_deref()) {
        Ok(profile) => profile,
        Err(err) => return err.into_response(),
    };

    // A check reports what policy would do. Tokens are minted into a throwaway
    // session and never persisted, so callers can pre-flight content without
    // touching the token map.
    let mut session = TokenSession::new(Uuid::new_v4().to_string(), "check", state.dek.clone());
    let mut ctx = RedactionContext::with_session(&state.engine, &profile, &mut session);
    let outcome = match ctx.redact(&request.text) {
        Ok(_) => ctx.finish(),
        Err(err) => return redaction_error(err).into_response(),
    };

    Json(json!({
        "profile": profile.name,
        "allowed": !outcome.is_blocked(),
        "blocked_entities": outcome.blocked_entities,
        "entity_counts": outcome.entity_counts,
        "action_counts": outcome.action_counts,
        "would_tokenize": profile.uses_tokenization(),
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
        "telemetry": state.telemetry.summary(),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::AuthContext;
    use crate::config::ResolvedConfig;

    #[test]
    fn credential_profile_wins_over_request_profile() {
        let config = ResolvedConfig::default();
        let mut auth = AuthContext::anonymous();
        auth.profile = Some("strict".into());
        let profile = resolve_profile(&config, &auth, Some("permissive")).unwrap();
        assert_eq!(profile.name, "strict");
    }

    #[test]
    fn request_profile_applies_when_credential_has_none() {
        let config = ResolvedConfig::default();
        let auth = AuthContext::anonymous();
        let profile = resolve_profile(&config, &auth, Some("secrets_only")).unwrap();
        assert_eq!(profile.name, "secrets_only");
    }
}
