// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Env-gated operation spans exported through `tracing-opentelemetry`.
//!
//! Spans are ordinary [`tracing`] spans so `RUST_LOG` / `EnvFilter` continue to
//! work. Constructors accept only counts, enums and identifiers — never prompt
//! text, completion text, or detected entity values.
//!
//! When [`TraceLevel::Off`](crate::config::TraceLevel::Off), operation-span
//! constructors return `None` without building a span (HTTP server/client
//! helpers still create spans). [`TraceLevel::Detailed`] adds optional
//! attributes.
//!
//! # GenAI attributes
//!
//! `gen_ai.*` fields are Development-stage upstream and are attached only when
//! `emit_genai` is `true` (see [`crate::config::TelemetrySettings::genai_attributes`]).

use tracing::Span;

use crate::config::TraceLevel;

use super::semconv;

/// Mark a span as failed with a low-cardinality `error.type`.
pub fn record_error(span: &Span, error_type: &str) {
    span.record(semconv::ERROR_TYPE, error_type);
    span.record("otel.status_code", "error");
    span.record("otel.status_description", error_type);
}

/// HTTP server span named `{method} {route}` (SpanKind Server).
///
/// Always constructed regardless of [`TraceLevel`] — only disabled when the
/// caller chooses not to invoke this helper. `route` must be the matched route
/// template.
pub fn http_server(method: &str, route: &str, scheme: &str) -> Span {
    let name = format!("{method} {route}");
    tracing::info_span!(
        target: semconv::target::HTTP,
        "http.server",
        otel.name = %name,
        otel.kind = "server",
        { semconv::HTTP_REQUEST_METHOD } = method,
        { semconv::HTTP_ROUTE } = route,
        { semconv::URL_SCHEME } = scheme,
        { semconv::HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    )
}

/// Record the response status on an HTTP server span.
pub fn finish_http_server(span: &Span, status_code: u16, error_type: Option<&str>) {
    span.record(semconv::HTTP_RESPONSE_STATUS_CODE, status_code);
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// HTTP client span for upstream calls (SpanKind Client).
pub fn http_client(method: &str, server_address: &str, server_port: u16) -> Span {
    tracing::info_span!(
        target: semconv::target::UPSTREAM,
        "http.client",
        otel.kind = "client",
        { semconv::HTTP_REQUEST_METHOD } = method,
        { semconv::SERVER_ADDRESS } = server_address,
        { semconv::SERVER_PORT } = server_port,
        { semconv::HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    )
}

/// `redact.gateway.authenticate`.
pub fn authenticate(level: TraceLevel, mode: &str) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    Some(tracing::info_span!(
        target: semconv::target::AUTH,
        { semconv::span_name::AUTHENTICATE },
        { semconv::REDACT_AUTH_MODE } = mode,
        { semconv::REDACT_AUTH_OUTCOME } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// Record the auth outcome on an authenticate span.
pub fn finish_authenticate(span: &Span, outcome: &str, error_type: Option<&str>) {
    span.record(semconv::REDACT_AUTH_OUTCOME, outcome);
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// `redact.gateway.policy.evaluate`.
pub fn policy_evaluate(level: TraceLevel, profile: &str) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    Some(tracing::info_span!(
        target: semconv::target::POLICY,
        { semconv::span_name::POLICY_EVALUATE },
        { semconv::REDACT_POLICY_PROFILE } = profile,
        { semconv::REDACT_POLICY_DECISION } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// Record the policy decision.
pub fn finish_policy_evaluate(span: &Span, decision: &str, error_type: Option<&str>) {
    span.record(semconv::REDACT_POLICY_DECISION, decision);
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// `redact.gateway.detect`.
pub fn detect(level: TraceLevel, text_bytes: usize) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    let span = tracing::info_span!(
        target: semconv::target::DETECT,
        { semconv::span_name::DETECT },
        { semconv::REDACT_TEXT_BYTES } = text_bytes,
        { semconv::REDACT_ENTITIES_COUNT } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    );
    Some(span)
}

/// Record detection counts. Detailed mode may attach additional count fields later.
pub fn finish_detect(
    span: &Span,
    entities_count: usize,
    _level: TraceLevel,
    error_type: Option<&str>,
) {
    span.record(semconv::REDACT_ENTITIES_COUNT, entities_count);
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// `redact.gateway.anonymize`.
pub fn anonymize(level: TraceLevel) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    Some(tracing::info_span!(
        target: semconv::target::ANONYMIZE,
        { semconv::span_name::ANONYMIZE },
        { semconv::REDACT_REDACTIONS_COUNT } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// Record anonymize counts.
pub fn finish_anonymize(span: &Span, redactions_count: usize, error_type: Option<&str>) {
    span.record(semconv::REDACT_REDACTIONS_COUNT, redactions_count);
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// `redact.gateway.tokenmap.put` (SpanKind Client for remote backends).
pub fn tokenmap_put(
    level: TraceLevel,
    backend: &str,
    entries: usize,
    server_address: Option<&str>,
    server_port: Option<u16>,
) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    let kind = if server_address.is_some() {
        "client"
    } else {
        "internal"
    };
    let address = server_address.unwrap_or("");
    let port = i64::from(server_port.unwrap_or(0));
    Some(tracing::info_span!(
        target: semconv::target::TOKENMAP,
        { semconv::span_name::TOKENMAP_PUT },
        otel.kind = kind,
        { semconv::REDACT_TOKENMAP_BACKEND } = backend,
        { semconv::REDACT_TOKENMAP_ENTRIES } = entries,
        { semconv::SERVER_ADDRESS } = address,
        { semconv::SERVER_PORT } = port,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// `redact.gateway.tokenmap.get` (SpanKind Client for remote backends).
pub fn tokenmap_get(
    level: TraceLevel,
    backend: &str,
    entries: usize,
    server_address: Option<&str>,
    server_port: Option<u16>,
) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    let kind = if server_address.is_some() {
        "client"
    } else {
        "internal"
    };
    let address = server_address.unwrap_or("");
    let port = i64::from(server_port.unwrap_or(0));
    Some(tracing::info_span!(
        target: semconv::target::TOKENMAP,
        { semconv::span_name::TOKENMAP_GET },
        otel.kind = kind,
        { semconv::REDACT_TOKENMAP_BACKEND } = backend,
        { semconv::REDACT_TOKENMAP_ENTRIES } = entries,
        { semconv::SERVER_ADDRESS } = address,
        { semconv::SERVER_PORT } = port,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// `redact.gateway.restore`.
pub fn restore(level: TraceLevel) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    Some(tracing::info_span!(
        target: semconv::target::RESTORE,
        { semconv::span_name::RESTORE },
        { semconv::REDACT_TOKENS_RESTORED } = tracing::field::Empty,
        { semconv::REDACT_TOKENS_MISSING } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// Record restore counts.
pub fn finish_restore(
    span: &Span,
    tokens_restored: usize,
    tokens_missing: usize,
    error_type: Option<&str>,
) {
    span.record(semconv::REDACT_TOKENS_RESTORED, tokens_restored);
    span.record(semconv::REDACT_TOKENS_MISSING, tokens_missing);
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// Optional GenAI attributes attached to upstream spans when enabled.
#[derive(Debug, Clone, Default)]
pub struct GenAiAttrs {
    /// `gen_ai.operation.name`
    pub operation_name: Option<&'static str>,
    /// `gen_ai.provider.name`
    pub provider_name: Option<&'static str>,
    /// `gen_ai.request.model`
    pub request_model: Option<String>,
    /// `gen_ai.response.model`
    pub response_model: Option<String>,
    /// `gen_ai.usage.input_tokens`
    pub input_tokens: Option<u64>,
    /// `gen_ai.usage.output_tokens`
    pub output_tokens: Option<u64>,
    /// `gen_ai.response.finish_reasons` (low-cardinality reason codes only).
    pub finish_reasons: Option<String>,
}

/// `redact.gateway.upstream.chat` (SpanKind Client).
///
/// GenAI attributes are attached only when `emit_genai` is `true`.
pub fn upstream_chat(
    level: TraceLevel,
    method: &str,
    server_address: &str,
    server_port: u16,
    emit_genai: bool,
    genai: &GenAiAttrs,
) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    let span = tracing::info_span!(
        target: semconv::target::UPSTREAM,
        { semconv::span_name::UPSTREAM_CHAT },
        otel.kind = "client",
        { semconv::HTTP_REQUEST_METHOD } = method,
        { semconv::SERVER_ADDRESS } = server_address,
        { semconv::SERVER_PORT } = server_port,
        { semconv::HTTP_RESPONSE_STATUS_CODE } = tracing::field::Empty,
        { semconv::GEN_AI_OPERATION_NAME } = tracing::field::Empty,
        { semconv::GEN_AI_PROVIDER_NAME } = tracing::field::Empty,
        { semconv::GEN_AI_REQUEST_MODEL } = tracing::field::Empty,
        { semconv::GEN_AI_RESPONSE_MODEL } = tracing::field::Empty,
        { semconv::GEN_AI_USAGE_INPUT_TOKENS } = tracing::field::Empty,
        { semconv::GEN_AI_USAGE_OUTPUT_TOKENS } = tracing::field::Empty,
        { semconv::GEN_AI_RESPONSE_FINISH_REASONS } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    );
    if emit_genai {
        if let Some(op) = genai.operation_name {
            span.record(semconv::GEN_AI_OPERATION_NAME, op);
        }
        if let Some(provider) = genai.provider_name {
            span.record(semconv::GEN_AI_PROVIDER_NAME, provider);
        }
        if let Some(model) = genai.request_model.as_deref() {
            span.record(semconv::GEN_AI_REQUEST_MODEL, model);
        }
        if level.is_detailed() {
            if let Some(model) = genai.response_model.as_deref() {
                span.record(semconv::GEN_AI_RESPONSE_MODEL, model);
            }
            if let Some(n) = genai.input_tokens {
                span.record(semconv::GEN_AI_USAGE_INPUT_TOKENS, n);
            }
            if let Some(n) = genai.output_tokens {
                span.record(semconv::GEN_AI_USAGE_OUTPUT_TOKENS, n);
            }
            if let Some(reasons) = genai.finish_reasons.as_deref() {
                span.record(semconv::GEN_AI_RESPONSE_FINISH_REASONS, reasons);
            }
        }
    }
    Some(span)
}

/// Record upstream response status / GenAI response fields.
pub fn finish_upstream_chat(
    span: &Span,
    status_code: Option<u16>,
    emit_genai: bool,
    level: TraceLevel,
    genai: &GenAiAttrs,
    error_type: Option<&str>,
) {
    if let Some(code) = status_code {
        span.record(semconv::HTTP_RESPONSE_STATUS_CODE, code);
    }
    if emit_genai && level.is_detailed() {
        if let Some(model) = genai.response_model.as_deref() {
            span.record(semconv::GEN_AI_RESPONSE_MODEL, model);
        }
        if let Some(n) = genai.input_tokens {
            span.record(semconv::GEN_AI_USAGE_INPUT_TOKENS, n);
        }
        if let Some(n) = genai.output_tokens {
            span.record(semconv::GEN_AI_USAGE_OUTPUT_TOKENS, n);
        }
        if let Some(reasons) = genai.finish_reasons.as_deref() {
            span.record(semconv::GEN_AI_RESPONSE_FINISH_REASONS, reasons);
        }
    }
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// `redact.gateway.stream.redact`.
pub fn stream_redact(level: TraceLevel, mode: &str) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    Some(tracing::info_span!(
        target: semconv::target::STREAM,
        { semconv::span_name::STREAM_REDACT },
        { semconv::REDACT_STREAM_MODE } = mode,
        { semconv::REDACT_STREAM_CHUNKS } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// Record stream chunk count (Detailed attaches the value; Basic may leave empty).
pub fn finish_stream_redact(
    span: &Span,
    chunks: usize,
    level: TraceLevel,
    error_type: Option<&str>,
) {
    if level.is_detailed() || level.records_operations() {
        span.record(semconv::REDACT_STREAM_CHUNKS, chunks);
    }
    if let Some(err) = error_type {
        record_error(span, err);
    }
}

/// `redact.gateway.config.reload`.
pub fn config_reload(level: TraceLevel, source: &str) -> Option<Span> {
    if !level.records_operations() {
        return None;
    }
    Some(tracing::info_span!(
        target: semconv::target::CONFIG,
        { semconv::span_name::CONFIG_RELOAD },
        { semconv::REDACT_CONFIG_SOURCE } = source,
        { semconv::REDACT_CONFIG_OUTCOME } = tracing::field::Empty,
        { semconv::ERROR_TYPE } = tracing::field::Empty,
        otel.status_code = tracing::field::Empty,
        otel.status_description = tracing::field::Empty,
    ))
}

/// Record config reload outcome.
pub fn finish_config_reload(span: &Span, outcome: &str, error_type: Option<&str>) {
    span.record(semconv::REDACT_CONFIG_OUTCOME, outcome);
    if let Some(err) = error_type {
        record_error(span, err);
    }
}
