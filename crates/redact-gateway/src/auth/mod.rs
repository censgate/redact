// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Inbound authentication for the gateway.
//!
//! Callers are identified by an [`Authenticator`] selected from
//! [`AuthSettings`]. When authentication is enabled (`api_key` or `oidc`),
//! requests without valid credentials are rejected (fail closed).
//!
//! The [`crate::config::AuthMode::None`] / [`AllowAllAuthenticator`] path
//! disables inbound authentication and is **only appropriate on a trusted
//! network**. Never expose that mode on an untrusted edge.

mod api_key;
#[cfg(feature = "oidc")]
mod oidc;

use std::sync::Arc;

use axum::http::header::AUTHORIZATION;
use axum::http::HeaderMap;

use crate::config::{AuthMode, AuthSettings};
use crate::error::GatewayError;

pub use api_key::ApiKeyAuthenticator;
#[cfg(feature = "oidc")]
pub use oidc::OidcAuthenticator;

/// Identity and policy selection derived from a caller's credential.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// Stable caller identifier (JWT `sub`, or a non-secret key id).
    pub subject: Option<String>,
    /// Tenant the caller belongs to. Defaults to `"default"` when absent.
    pub tenant: String,
    /// Policy profile requested by the credential's claims, if any.
    pub profile: Option<String>,
    /// Scopes granted by the credential.
    pub scopes: Vec<String>,
    /// Authentication mode that produced this context: `"none"`, `"api_key"`, or `"oidc"`.
    pub mode: &'static str,
}

impl AuthContext {
    /// Anonymous context used when inbound authentication is disabled.
    pub fn anonymous() -> Self {
        Self {
            subject: None,
            tenant: "default".to_string(),
            profile: None,
            scopes: Vec::new(),
            mode: "none",
        }
    }
}

/// Failures raised while authenticating a request.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// No credential was presented.
    #[error("missing credentials")]
    Missing,
    /// A credential was presented but could not be validated.
    #[error("invalid credentials: {0}")]
    Invalid(String),
    /// The credential is valid but lacks a required scope.
    #[error("insufficient scope: requires {0}")]
    InsufficientScope(String),
    /// The authentication backend could not be reached or is misconfigured.
    #[error("authentication backend unavailable: {0}")]
    Unavailable(String),
}

impl From<AuthError> for GatewayError {
    fn from(err: AuthError) -> Self {
        match err {
            AuthError::Missing | AuthError::Invalid(_) => {
                GatewayError::Unauthorized(err.to_string())
            }
            AuthError::InsufficientScope(_) => GatewayError::Forbidden(err.to_string()),
            AuthError::Unavailable(msg) => GatewayError::DependencyUnavailable(msg),
        }
    }
}

/// Pluggable inbound authenticator.
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync + std::fmt::Debug {
    /// Stable mode name (`"none"`, `"api_key"`, or `"oidc"`).
    fn mode(&self) -> &'static str;

    /// Validate credentials from request headers and return an identity context.
    async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthContext, AuthError>;

    /// Readiness probe. For OIDC this reflects whether a JWKS document has been fetched.
    async fn ready(&self) -> bool {
        true
    }
}

/// Authenticator that accepts every request as anonymous.
///
/// Only appropriate when the operator explicitly selects [`AuthMode::None`]
/// on a trusted network.
#[derive(Debug, Default)]
pub struct AllowAllAuthenticator;

#[async_trait::async_trait]
impl Authenticator for AllowAllAuthenticator {
    fn mode(&self) -> &'static str {
        "none"
    }

    async fn authenticate(&self, _headers: &HeaderMap) -> Result<AuthContext, AuthError> {
        Ok(AuthContext::anonymous())
    }
}

/// Build the authenticator configured by `settings`.
///
/// Returns an error when the selected mode cannot be constructed (for example
/// OIDC requested without the `oidc` feature, or missing issuer).
pub async fn build_authenticator(
    settings: &AuthSettings,
) -> Result<Arc<dyn Authenticator>, AuthError> {
    match settings.mode {
        AuthMode::None => Ok(Arc::new(AllowAllAuthenticator)),
        AuthMode::ApiKey => Ok(Arc::new(ApiKeyAuthenticator::new(&settings.api_keys))),
        AuthMode::Oidc => {
            #[cfg(feature = "oidc")]
            {
                Ok(Arc::new(OidcAuthenticator::new(&settings.oidc)?))
            }
            #[cfg(not(feature = "oidc"))]
            {
                let _ = settings;
                Err(AuthError::Unavailable(
                    "oidc authentication requires the `oidc` cargo feature".to_string(),
                ))
            }
        }
    }
}

/// Extract a `Authorization: Bearer <token>` value.
///
/// The scheme comparison is case-insensitive. Returns `None` when the header
/// is absent or not a bearer credential.
pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let mut parts = value.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let token = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("bearer") && !token.is_empty() {
        Some(token)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn bearer_token_is_case_insensitive_on_scheme() {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer secret-token"),
        );
        assert_eq!(bearer_token(&headers), Some("secret-token"));

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("bearer secret-token"),
        );
        assert_eq!(bearer_token(&headers), Some("secret-token"));

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("BEARER secret-token"),
        );
        assert_eq!(bearer_token(&headers), Some("secret-token"));
    }

    #[test]
    fn bearer_token_rejects_non_bearer() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Basic abc"));
        assert!(bearer_token(&headers).is_none());
    }

    #[test]
    fn auth_error_maps_to_gateway_error() {
        assert!(matches!(
            GatewayError::from(AuthError::Missing),
            GatewayError::Unauthorized(_)
        ));
        assert!(matches!(
            GatewayError::from(AuthError::Invalid("x".into())),
            GatewayError::Unauthorized(_)
        ));
        assert!(matches!(
            GatewayError::from(AuthError::InsufficientScope("s".into())),
            GatewayError::Forbidden(_)
        ));
        assert!(matches!(
            GatewayError::from(AuthError::Unavailable("down".into())),
            GatewayError::DependencyUnavailable(_)
        ));
    }

    #[tokio::test]
    async fn allow_all_returns_anonymous() {
        let auth = AllowAllAuthenticator;
        let ctx = auth.authenticate(&HeaderMap::new()).await.unwrap();
        assert_eq!(ctx.mode, "none");
        assert_eq!(ctx.tenant, "default");
        assert!(ctx.subject.is_none());
    }
}
