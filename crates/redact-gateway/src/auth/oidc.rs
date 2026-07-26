// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! OIDC / OAuth 2.0 resource-server authentication via bearer JWTs.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use jsonwebtoken::jwk::{AlgorithmParameters, Jwk, JwkSet};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use crate::config::OidcSettings;

use super::{bearer_token, AuthContext, AuthError, Authenticator};

/// Algorithms accepted for inbound OIDC access tokens.
const SUPPORTED_ALGS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::ES256,
    Algorithm::ES384,
];

/// Cached JWKS document and discovery metadata.
#[derive(Default)]
struct JwksState {
    jwks: Option<JwkSet>,
    jwks_uri: Option<String>,
    fetched_at: Option<Instant>,
}

/// OAuth 2.0 / OIDC resource-server authenticator.
///
/// Validates bearer JWTs against a JWKS document. The JWKS is cached in memory
/// and refreshed after [`OidcSettings::jwks_refresh_secs`]. On a `kid` miss the
/// cache is force-refreshed once so key rotation does not require downtime.
pub struct OidcAuthenticator {
    issuer: String,
    audience: Option<String>,
    configured_jwks_url: Option<String>,
    required_scopes: Vec<String>,
    tenant_claim: Option<String>,
    profile_claim: Option<String>,
    jwks_refresh: Duration,
    leeway_secs: u64,
    http: reqwest::Client,
    state: RwLock<JwksState>,
}

impl std::fmt::Debug for OidcAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OidcAuthenticator")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .field("configured_jwks_url", &self.configured_jwks_url)
            .field("required_scopes", &self.required_scopes)
            .field("tenant_claim", &self.tenant_claim)
            .field("profile_claim", &self.profile_claim)
            .field("jwks_refresh_secs", &self.jwks_refresh.as_secs())
            .field("leeway_secs", &self.leeway_secs)
            .finish()
    }
}

impl OidcAuthenticator {
    /// Construct an authenticator from OIDC settings.
    ///
    /// Requires a configured issuer. Does not fetch JWKS until the first
    /// authentication attempt (or an explicit readiness probe that triggers
    /// refresh via [`Self::ensure_jwks`]).
    pub fn new(settings: &OidcSettings) -> Result<Self, AuthError> {
        let issuer = settings
            .issuer
            .as_ref()
            .map(|s| s.trim().trim_end_matches('/').to_string())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| AuthError::Unavailable("oidc issuer is not configured".to_string()))?;

        Ok(Self {
            issuer,
            audience: settings.audience.clone(),
            configured_jwks_url: settings.jwks_url.clone(),
            required_scopes: settings.required_scopes.clone(),
            tenant_claim: settings.tenant_claim.clone(),
            profile_claim: settings.profile_claim.clone(),
            jwks_refresh: Duration::from_secs(settings.jwks_refresh_secs.max(1)),
            leeway_secs: settings.leeway_secs,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .map_err(|e| AuthError::Unavailable(format!("http client: {e}")))?,
            state: RwLock::new(JwksState::default()),
        })
    }

    /// Ensure a JWKS document is present, refreshing when stale or forced.
    async fn ensure_jwks(&self, force: bool) -> Result<(), AuthError> {
        {
            let state = self.state.read().await;
            if !force {
                if let (Some(_), Some(fetched_at)) = (&state.jwks, state.fetched_at) {
                    if fetched_at.elapsed() < self.jwks_refresh {
                        return Ok(());
                    }
                }
            }
        }
        self.refresh_jwks().await
    }

    async fn refresh_jwks(&self) -> Result<(), AuthError> {
        let jwks_uri = self.resolve_jwks_uri().await?;
        debug!(%jwks_uri, "fetching JWKS");
        let jwks = self
            .http
            .get(&jwks_uri)
            .send()
            .await
            .map_err(|e| AuthError::Unavailable(format!("jwks fetch failed: {e}")))?
            .error_for_status()
            .map_err(|e| AuthError::Unavailable(format!("jwks fetch status: {e}")))?
            .json::<JwkSet>()
            .await
            .map_err(|e| AuthError::Unavailable(format!("jwks parse failed: {e}")))?;

        let mut state = self.state.write().await;
        state.jwks = Some(jwks);
        state.jwks_uri = Some(jwks_uri);
        state.fetched_at = Some(Instant::now());
        Ok(())
    }

    async fn resolve_jwks_uri(&self) -> Result<String, AuthError> {
        if let Some(url) = &self.configured_jwks_url {
            return Ok(url.clone());
        }

        {
            let state = self.state.read().await;
            if let Some(uri) = &state.jwks_uri {
                return Ok(uri.clone());
            }
        }

        let discovery_url = format!("{}/.well-known/openid-configuration", self.issuer);
        debug!(%discovery_url, "fetching OIDC discovery document");
        let doc: DiscoveryDocument = self
            .http
            .get(&discovery_url)
            .send()
            .await
            .map_err(|e| AuthError::Unavailable(format!("oidc discovery failed: {e}")))?
            .error_for_status()
            .map_err(|e| AuthError::Unavailable(format!("oidc discovery status: {e}")))?
            .json()
            .await
            .map_err(|e| AuthError::Unavailable(format!("oidc discovery parse failed: {e}")))?;

        let jwks_uri = doc.jwks_uri.ok_or_else(|| {
            AuthError::Unavailable("openid-configuration missing jwks_uri".to_string())
        })?;

        let mut state = self.state.write().await;
        state.jwks_uri = Some(jwks_uri.clone());
        Ok(jwks_uri)
    }

    async fn find_jwk(&self, kid: Option<&str>) -> Result<Jwk, AuthError> {
        self.ensure_jwks(false).await?;
        if let Some(jwk) = self.lookup_cached(kid).await {
            return Ok(jwk);
        }

        // Key rotation: force one refresh on kid miss before rejecting.
        self.ensure_jwks(true).await?;
        self.lookup_cached(kid).await.ok_or_else(|| {
            AuthError::Invalid(match kid {
                Some(k) => format!("no jwk for kid `{k}`"),
                None => "no matching jwk in set".to_string(),
            })
        })
    }

    async fn lookup_cached(&self, kid: Option<&str>) -> Option<Jwk> {
        let state = self.state.read().await;
        let jwks = state.jwks.as_ref()?;
        match kid {
            Some(kid) => jwks.find(kid).cloned(),
            None if jwks.keys.len() == 1 => jwks.keys.first().cloned(),
            None => None,
        }
    }

    fn validate_token(&self, token: &str, jwk: &Jwk) -> Result<TokenClaims, AuthError> {
        let header =
            decode_header(token).map_err(|e| AuthError::Invalid(format!("jwt header: {e}")))?;

        if !SUPPORTED_ALGS.contains(&header.alg) {
            return Err(AuthError::Invalid(format!(
                "unsupported jwt algorithm {:?}",
                header.alg
            )));
        }

        ensure_alg_matches_key(header.alg, jwk)?;

        let decoding_key = DecodingKey::from_jwk(jwk)
            .map_err(|e| AuthError::Invalid(format!("jwk to decoding key: {e}")))?;

        let mut validation = Validation::new(header.alg);
        validation.algorithms = vec![header.alg];
        validation.leeway = self.leeway_secs;
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.set_issuer(&[&self.issuer]);
        // `sub` is required so authenticated callers always receive a stable
        // subject for token-map partitioning.
        validation.set_required_spec_claims(&["exp", "iss", "sub"]);

        if let Some(aud) = &self.audience {
            validation.set_audience(&[aud]);
            validation.validate_aud = true;
            let mut required = validation.required_spec_claims.clone();
            required.insert("aud".to_string());
            validation.required_spec_claims = required;
        } else {
            // Only reachable when allow_missing_audience was explicitly set.
            validation.validate_aud = false;
        }

        let data = decode::<TokenClaims>(token, &decoding_key, &validation)
            .map_err(|e| AuthError::Invalid(format!("jwt validation failed: {e}")))?;

        Ok(data.claims)
    }

    fn build_context(&self, claims: TokenClaims) -> Result<AuthContext, AuthError> {
        let scopes = claims.scopes();
        for required in &self.required_scopes {
            if !scopes.iter().any(|s| s == required) {
                return Err(AuthError::InsufficientScope(required.clone()));
            }
        }

        let subject = claims
            .sub
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .ok_or_else(|| {
                AuthError::Invalid("token is missing a non-empty subject (sub) claim".to_string())
            })?;

        let tenant = self.resolve_tenant(&claims);
        let profile = self.resolve_profile(&claims);

        debug!(subject = %subject, tenant = %tenant, "oidc authentication succeeded");

        Ok(AuthContext {
            subject: Some(subject),
            tenant,
            profile,
            scopes,
            mode: "oidc",
        })
    }

    fn resolve_tenant(&self, claims: &TokenClaims) -> String {
        if let Some(name) = &self.tenant_claim {
            if let Some(value) = string_claim(&claims.extra, name) {
                return value;
            }
        }
        if let Some(value) = string_claim(&claims.extra, "tid") {
            return value;
        }
        if let Some(value) = string_claim(&claims.extra, "tenant") {
            return value;
        }
        "default".to_string()
    }

    fn resolve_profile(&self, claims: &TokenClaims) -> Option<String> {
        self.profile_claim
            .as_ref()
            .and_then(|name| string_claim(&claims.extra, name))
    }
}

#[async_trait::async_trait]
impl Authenticator for OidcAuthenticator {
    fn mode(&self) -> &'static str {
        "oidc"
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthContext, AuthError> {
        let token = bearer_token(headers).ok_or(AuthError::Missing)?;

        // Reject `alg: none` (and any other non-enumerable alg) before key lookup.
        let header =
            decode_header(token).map_err(|e| AuthError::Invalid(format!("jwt header: {e}")))?;
        if !SUPPORTED_ALGS.contains(&header.alg) {
            return Err(AuthError::Invalid(format!(
                "unsupported jwt algorithm {:?}",
                header.alg
            )));
        }

        let jwk = self.find_jwk(header.kid.as_deref()).await?;
        let claims = self.validate_token(token, &jwk)?;
        self.build_context(claims)
    }

    async fn ready(&self) -> bool {
        if self.ensure_jwks(false).await.is_err() {
            warn!("oidc readiness: JWKS not available");
            return false;
        }
        let state = self.state.read().await;
        state.jwks.as_ref().is_some_and(|j| !j.keys.is_empty())
    }
}

fn ensure_alg_matches_key(alg: Algorithm, jwk: &Jwk) -> Result<(), AuthError> {
    let key_family_ok = match &jwk.algorithm {
        AlgorithmParameters::RSA(_) => {
            matches!(alg, Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512)
        }
        AlgorithmParameters::EllipticCurve(_) => {
            matches!(alg, Algorithm::ES256 | Algorithm::ES384)
        }
        AlgorithmParameters::OctetKey(_)
        | AlgorithmParameters::OctetKeyPair(_)
        | AlgorithmParameters::Other(_)
        | _ => false,
    };

    if !key_family_ok {
        return Err(AuthError::Invalid(
            "jwt algorithm does not match jwk key type".to_string(),
        ));
    }

    if let Some(key_alg) = jwk.common.key_algorithm {
        if let Ok(expected) = Algorithm::try_from(key_alg) {
            if expected != alg {
                return Err(AuthError::Invalid(
                    "jwt algorithm does not match jwk alg".to_string(),
                ));
            }
        }
    }

    Ok(())
}

fn string_claim(extra: &serde_json::Map<String, Value>, name: &str) -> Option<String> {
    match extra.get(name)? {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    jwks_uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct TokenClaims {
    sub: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    scp: Option<ScpClaim>,
    #[serde(flatten)]
    extra: serde_json::Map<String, Value>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum ScpClaim {
    List(Vec<String>),
    One(String),
}

impl TokenClaims {
    fn scopes(&self) -> Vec<String> {
        let mut set = HashSet::new();
        if let Some(scope) = &self.scope {
            for part in scope.split_whitespace() {
                if !part.is_empty() {
                    set.insert(part.to_string());
                }
            }
        }
        match &self.scp {
            Some(ScpClaim::List(items)) => {
                for item in items {
                    if !item.is_empty() {
                        set.insert(item.clone());
                    }
                }
            }
            Some(ScpClaim::One(item)) => {
                for part in item.split_whitespace() {
                    if !part.is_empty() {
                        set.insert(part.to_string());
                    }
                }
            }
            None => {}
        }
        let mut scopes: Vec<String> = set.into_iter().collect();
        scopes.sort();
        scopes
    }
}
