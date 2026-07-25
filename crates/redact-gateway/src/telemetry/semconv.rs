// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Attribute and metric name constants used by the gateway.
//!
//! Prefer re-exports from [`opentelemetry_semantic_conventions`] where a key
//! already exists. Gateway-specific keys live under the `redact.*` namespace.
//!
//! # Stable HTTP conventions
//!
//! Keys such as [`HTTP_REQUEST_METHOD`], [`HTTP_ROUTE`], and
//! [`HTTP_SERVER_REQUEST_DURATION`] follow the stable HTTP semantic
//! conventions. Prefer these for production dashboards and alerts.
//!
//! # Development-stage GenAI conventions
//!
//! Keys under `gen_ai.*` (for example [`GEN_AI_REQUEST_MODEL`]) are still in
//! **Development** upstream and have moved to a separate specification
//! repository. They are emitted only when
//! [`crate::config::TelemetrySettings::genai_attributes`] is `true`, and their
//! names or value types may change without a gateway major version bump.

// --- Stable HTTP / URL / error / server attributes --------------------------

/// Low-cardinality error class.
pub use opentelemetry_semantic_conventions::attribute::ERROR_TYPE;
/// HTTP request method (`GET`, `POST`, …).
pub use opentelemetry_semantic_conventions::attribute::HTTP_REQUEST_METHOD;
/// HTTP response status code.
pub use opentelemetry_semantic_conventions::attribute::HTTP_RESPONSE_STATUS_CODE;
/// Matched route template (never a raw URL path).
pub use opentelemetry_semantic_conventions::attribute::HTTP_ROUTE;
/// Server address (host).
pub use opentelemetry_semantic_conventions::attribute::SERVER_ADDRESS;
/// Server port.
pub use opentelemetry_semantic_conventions::attribute::SERVER_PORT;
/// URL scheme (`http` / `https`).
pub use opentelemetry_semantic_conventions::attribute::URL_SCHEME;
// --- Development-stage GenAI attributes (opt-in) ----------------------------
//
// These names match the upstream Development-stage GenAI conventions. The
// `opentelemetry-semantic-conventions` crate marks the re-exports as
// deprecated because the definitions moved to a separate repository; we keep
// the string values locally so the gateway compiles cleanly while documenting
// the opt-in / may-change status.

/// GenAI operation name (Development).
pub const GEN_AI_OPERATION_NAME: &str = "gen_ai.operation.name";
/// GenAI provider name (Development).
pub const GEN_AI_PROVIDER_NAME: &str = "gen_ai.provider.name";
/// Requested model identifier (Development).
pub const GEN_AI_REQUEST_MODEL: &str = "gen_ai.request.model";
/// Whether the request asked for a streamed response.
pub const GEN_AI_REQUEST_STREAM: &str = "gen_ai.request.stream";
/// Response model identifier (Development).
pub const GEN_AI_RESPONSE_MODEL: &str = "gen_ai.response.model";
/// Input token usage (Development).
pub const GEN_AI_USAGE_INPUT_TOKENS: &str = "gen_ai.usage.input_tokens";
/// Output token usage (Development).
pub const GEN_AI_USAGE_OUTPUT_TOKENS: &str = "gen_ai.usage.output_tokens";
/// Finish reasons from the provider (Development).
pub const GEN_AI_RESPONSE_FINISH_REASONS: &str = "gen_ai.response.finish_reasons";

/// Log / event name attribute key (prefer LogRecord event_name field for OTel logs).
pub const EVENT_NAME: &str = "event.name";

// --- Stable HTTP metric names -----------------------------------------------

/// Histogram of outbound HTTP request duration in seconds.
pub use opentelemetry_semantic_conventions::metric::HTTP_CLIENT_REQUEST_DURATION;
/// UpDownCounter of in-flight inbound HTTP requests.
pub use opentelemetry_semantic_conventions::metric::HTTP_SERVER_ACTIVE_REQUESTS;
/// Histogram of inbound HTTP request duration in seconds.
pub use opentelemetry_semantic_conventions::metric::HTTP_SERVER_REQUEST_DURATION;

// --- Resource ---------------------------------------------------------------

/// Service name resource attribute.
pub use opentelemetry_semantic_conventions::resource::SERVICE_NAME;
/// Service version resource attribute.
pub use opentelemetry_semantic_conventions::resource::SERVICE_VERSION;

// --- Gateway-specific attribute keys ----------------------------------------

/// Authentication mode (`none`, `api_key`, `oidc`).
pub const REDACT_AUTH_MODE: &str = "redact.auth.mode";
/// Authentication outcome (`allowed`, `denied`, `error`).
pub const REDACT_AUTH_OUTCOME: &str = "redact.auth.outcome";

/// Active policy profile name.
pub const REDACT_POLICY_PROFILE: &str = "redact.policy.profile";
/// Policy decision (`allow`, `block`, …).
pub const REDACT_POLICY_DECISION: &str = "redact.policy.decision";

/// Detected / rewritten entity type (low cardinality enum name).
pub const REDACT_ENTITY_TYPE: &str = "redact.entity_type";
/// Redaction action applied (`mask`, `replace`, `hash`, `tokenize`, …).
pub const REDACT_ACTION: &str = "redact.action";
/// Number of text bytes inspected.
pub const REDACT_TEXT_BYTES: &str = "redact.text.bytes";
/// Number of entities detected in a pass.
pub const REDACT_ENTITIES_COUNT: &str = "redact.entities.count";
/// Number of redactions applied.
pub const REDACT_REDACTIONS_COUNT: &str = "redact.redactions.count";
/// Tokens restored on the response path.
pub const REDACT_TOKENS_RESTORED: &str = "redact.tokens.restored";
/// Tokens referenced but missing from the map.
pub const REDACT_TOKENS_MISSING: &str = "redact.tokens.missing";

/// Token map backend (`memory`, `vault_kv2`, …).
pub const REDACT_TOKENMAP_BACKEND: &str = "redact.tokenmap.backend";
/// Token map operation (`get`, `put`, …).
pub const REDACT_TOKENMAP_OPERATION: &str = "redact.tokenmap.operation";
/// Number of entries touched by a token map operation.
pub const REDACT_TOKENMAP_ENTRIES: &str = "redact.tokenmap.entries";

/// Streaming redaction mode (`buffered`, `incremental`).
pub const REDACT_STREAM_MODE: &str = "redact.stream.mode";
/// Number of stream chunks processed.
pub const REDACT_STREAM_CHUNKS: &str = "redact.stream.chunks";

/// Configuration source (`env`, `file`, `layered`).
pub const REDACT_CONFIG_SOURCE: &str = "redact.config.source";
/// Configuration reload outcome (`success`, `error`).
pub const REDACT_CONFIG_OUTCOME: &str = "redact.config.outcome";

// --- Gateway-specific metric names ------------------------------------------

/// Counter of redactions applied. Unit: `{redaction}`.
pub const REDACT_GATEWAY_REDACTIONS: &str = "redact.gateway.redactions";
/// Counter of policy decisions. Unit: `{decision}`.
pub const REDACT_GATEWAY_POLICY_DECISIONS: &str = "redact.gateway.policy.decisions";
/// Counter of token map operations. Unit: `{operation}`.
pub const REDACT_GATEWAY_TOKENMAP_OPERATIONS: &str = "redact.gateway.tokenmap.operations";
/// Histogram of token map operation duration. Unit: `s`.
pub const REDACT_GATEWAY_TOKENMAP_OPERATION_DURATION: &str =
    "redact.gateway.tokenmap.operation.duration";
/// Counter of audit records dropped because the queue was full. Unit: `{record}`.
pub const REDACT_GATEWAY_AUDIT_RECORDS_DROPPED: &str = "redact.gateway.audit.records_dropped";

/// Spec-advised explicit bucket boundaries for HTTP request duration histograms.
pub const HTTP_DURATION_BOUNDS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

/// Span / operation names emitted by the gateway.
pub mod span_name {
    /// Inbound authentication.
    pub const AUTHENTICATE: &str = "redact.gateway.authenticate";
    /// Policy evaluation.
    pub const POLICY_EVALUATE: &str = "redact.gateway.policy.evaluate";
    /// Detection pass.
    pub const DETECT: &str = "redact.gateway.detect";
    /// Anonymization pass.
    pub const ANONYMIZE: &str = "redact.gateway.anonymize";
    /// Token map put.
    pub const TOKENMAP_PUT: &str = "redact.gateway.tokenmap.put";
    /// Token map get.
    pub const TOKENMAP_GET: &str = "redact.gateway.tokenmap.get";
    /// Response-path token restore.
    pub const RESTORE: &str = "redact.gateway.restore";
    /// Upstream chat completions call.
    pub const PROVIDER_CHAT: &str = "redact.gateway.provider.chat";
    /// Streaming redaction.
    pub const STREAM_REDACT: &str = "redact.gateway.stream.redact";
    /// Configuration reload.
    pub const CONFIG_RELOAD: &str = "redact.gateway.config.reload";
}

/// `tracing` targets so operators can filter per subsystem.
pub mod target {
    /// Authentication spans.
    pub const AUTH: &str = "redact_gateway::auth";
    /// Policy spans.
    pub const POLICY: &str = "redact_gateway::policy";
    /// Detection spans.
    pub const DETECT: &str = "redact_gateway::detect";
    /// Anonymization spans.
    pub const ANONYMIZE: &str = "redact_gateway::anonymize";
    /// Token map spans.
    pub const TOKENMAP: &str = "redact_gateway::tokenmap";
    /// Restore spans.
    pub const RESTORE: &str = "redact_gateway::restore";
    /// Upstream client spans.
    pub const PROVIDER: &str = "redact_gateway::provider";
    /// Streaming spans.
    pub const STREAM: &str = "redact_gateway::stream";
    /// Config reload spans.
    pub const CONFIG: &str = "redact_gateway::config";
    /// HTTP server spans.
    pub const HTTP: &str = "redact_gateway::http";
}

/// Audit event name constants.
pub mod event {
    /// Inbound request accepted for processing.
    pub const REQUEST: &str = "redact.gateway.request";
    /// Response completed.
    pub const RESPONSE: &str = "redact.gateway.response";
    /// Policy blocked the payload.
    pub const POLICY_BLOCK: &str = "redact.gateway.policy_block";
    /// Authentication denied.
    pub const AUTH_DENIED: &str = "redact.gateway.auth_denied";
    /// Configuration reload.
    pub const CONFIG_RELOAD: &str = "redact.gateway.config_reload";
}
