// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Gateway error type rendered as OpenAI-compatible error payloads.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::openai::ErrorBody;

/// Errors surfaced to clients on the OpenAI-compatible surface.
///
/// Every variant maps to a stable HTTP status and an OpenAI-shaped
/// `{"error": {"message", "type", "code"}}` body so existing SDKs can parse
/// failures without special-casing the gateway.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    /// Typed storage outcomes; deterministic failures must not trigger retries.
    #[error(transparent)]
    TokenStore(#[from] redact_token_store::Error),
    /// The request body could not be understood.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Credentials were missing or rejected.
    #[error("unauthorized: {0}")]
    Unauthorized(String),

    /// Authenticated, but not permitted to use the requested resource.
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Policy blocked the request because of detected content.
    #[error("blocked by policy: {0}")]
    PolicyBlocked(String),

    /// A required subsystem is unavailable and the policy is fail-closed.
    #[error("dependency unavailable: {0}")]
    DependencyUnavailable(String),

    /// A texts[] request was rejected before detection or a token-map write.
    #[error("redact batch overloaded")]
    Overloaded,

    /// The caller deadline elapsed before detection or a token-map write finished.
    #[error("redact deadline exceeded")]
    Deadline,

    /// Detection or anonymization failed.
    #[error("redaction failed: {0}")]
    Redaction(String),

    /// The inference provider failed or was unreachable.
    #[error("provider error: {0}")]
    Provider(String),

    /// Any other unexpected failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl GatewayError {
    /// HTTP status for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::TokenStore(err) => match err {
                redact_token_store::Error::Invalid => StatusCode::BAD_REQUEST,
                redact_token_store::Error::Retired => StatusCode::GONE,
                redact_token_store::Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
                redact_token_store::Error::Busy => StatusCode::TOO_MANY_REQUESTS,
                redact_token_store::Error::Capacity => StatusCode::PAYLOAD_TOO_LARGE,
                redact_token_store::Error::Integrity => StatusCode::CONFLICT,
            },
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::PolicyBlocked(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::DependencyUnavailable(_) | Self::Overloaded => StatusCode::SERVICE_UNAVAILABLE,
            Self::Deadline => StatusCode::GATEWAY_TIMEOUT,
            Self::Redaction(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Provider(_) => StatusCode::BAD_GATEWAY,
        }
    }

    /// OpenAI-style error `type` discriminator.
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::TokenStore(err) => match err {
                redact_token_store::Error::Invalid => "token_store_invalid",
                redact_token_store::Error::Retired => "token_store_retired",
                redact_token_store::Error::Unavailable => "token_store_unavailable",
                redact_token_store::Error::Busy => "token_store_busy",
                redact_token_store::Error::Capacity => "token_store_capacity",
                redact_token_store::Error::Integrity => "token_store_integrity",
            },
            Self::InvalidRequest(_) => "invalid_request_error",
            Self::Unauthorized(_) => "authentication_error",
            Self::Forbidden(_) => "permission_error",
            Self::PolicyBlocked(_) => "policy_violation",
            Self::DependencyUnavailable(_) => "dependency_unavailable",
            Self::Overloaded => "overload",
            Self::Deadline => "deadline",
            Self::Redaction(_) => "redaction_error",
            Self::Provider(_) => "provider_error",
            Self::Internal(_) => "internal_error",
        }
    }

    /// Low-cardinality `error.type` value for telemetry attributes.
    pub fn telemetry_error_type(&self) -> &'static str {
        self.error_type()
    }
}

impl From<crate::vault::TokenMapError> for GatewayError {
    fn from(err: crate::vault::TokenMapError) -> Self {
        match err {
            crate::vault::TokenMapError::Indexed(err) => Self::TokenStore(err),
            err => Self::DependencyUnavailable(format!("token map operation failed: {err}")),
        }
    }
}

impl IntoResponse for GatewayError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = ErrorBody::new(self.to_string(), self.error_type());
        (status, Json(body)).into_response()
    }
}

impl From<anyhow::Error> for GatewayError {
    fn from(err: anyhow::Error) -> Self {
        Self::Internal(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_storage_errors_survive_gateway_boundary() {
        use redact_token_store::Error;
        for (error, status, kind) in [
            (Error::Invalid, 400, "token_store_invalid"),
            (Error::Retired, 410, "token_store_retired"),
            (Error::Integrity, 409, "token_store_integrity"),
            (Error::Capacity, 413, "token_store_capacity"),
            (Error::Busy, 429, "token_store_busy"),
            (Error::Unavailable, 503, "token_store_unavailable"),
        ] {
            let gateway = GatewayError::from(crate::vault::TokenMapError::from(error));
            assert_eq!(gateway.status().as_u16(), status);
            assert_eq!(gateway.error_type(), kind);
        }
    }

    #[test]
    fn statuses_are_stable() {
        assert_eq!(
            GatewayError::Unauthorized("nope".into()).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            GatewayError::PolicyBlocked("US_SSN".into()).status(),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            GatewayError::DependencyUnavailable("token map".into()).status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            GatewayError::Overloaded.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(GatewayError::Overloaded.error_type(), "overload");
        assert_eq!(GatewayError::Deadline.status(), StatusCode::GATEWAY_TIMEOUT);
        assert_eq!(GatewayError::Deadline.error_type(), "deadline");
    }

    #[test]
    fn error_types_are_openai_shaped() {
        assert_eq!(
            GatewayError::InvalidRequest("x".into()).error_type(),
            "invalid_request_error"
        );
        assert_eq!(
            GatewayError::Provider("x".into()).error_type(),
            "provider_error"
        );
    }
}
