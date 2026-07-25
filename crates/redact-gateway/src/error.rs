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

    /// Detection or anonymization failed.
    #[error("redaction failed: {0}")]
    Redaction(String),

    /// The upstream model provider failed or was unreachable.
    #[error("upstream error: {0}")]
    Upstream(String),

    /// Any other unexpected failure.
    #[error("internal error: {0}")]
    Internal(String),
}

impl GatewayError {
    /// HTTP status for this error.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::PolicyBlocked(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::DependencyUnavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Redaction(_) | Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
        }
    }

    /// OpenAI-style error `type` discriminator.
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::InvalidRequest(_) => "invalid_request_error",
            Self::Unauthorized(_) => "authentication_error",
            Self::Forbidden(_) => "permission_error",
            Self::PolicyBlocked(_) => "policy_violation",
            Self::DependencyUnavailable(_) => "dependency_unavailable",
            Self::Redaction(_) => "redaction_error",
            Self::Upstream(_) => "upstream_error",
            Self::Internal(_) => "internal_error",
        }
    }

    /// Low-cardinality `error.type` value for telemetry attributes.
    pub fn telemetry_error_type(&self) -> &'static str {
        self.error_type()
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
    }

    #[test]
    fn error_types_are_openai_shaped() {
        assert_eq!(
            GatewayError::InvalidRequest("x".into()).error_type(),
            "invalid_request_error"
        );
        assert_eq!(
            GatewayError::Upstream("x".into()).error_type(),
            "upstream_error"
        );
    }
}
