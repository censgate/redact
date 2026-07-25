// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Static API-key authentication with constant-time comparison.

use axum::http::HeaderMap;
use axum::http::HeaderName;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use super::{bearer_token, AuthContext, AuthError, Authenticator};

/// Header accepted as an alternative to `Authorization: Bearer`.
static X_API_KEY: HeaderName = HeaderName::from_static("x-api-key");

/// One accepted key, stored only as a digest and a non-secret subject id.
#[derive(Clone)]
struct KeyRecord {
    digest: [u8; 32],
    /// First 8 hex chars of the digest, prefixed with `key:`.
    subject: String,
}

impl std::fmt::Debug for KeyRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyRecord")
            .field("subject", &self.subject)
            .field("digest", &"<redacted>")
            .finish()
    }
}

/// Authenticator that accepts configured static API keys.
///
/// Keys are hashed with SHA-256 at construction. Presented credentials are
/// hashed the same way and compared with [`ConstantTimeEq`] so neither the
/// key length nor the key bytes influence comparison time.
#[derive(Clone)]
pub struct ApiKeyAuthenticator {
    keys: Vec<KeyRecord>,
}

impl std::fmt::Debug for ApiKeyAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ApiKeyAuthenticator")
            .field("key_count", &self.keys.len())
            .field(
                "subjects",
                &self.keys.iter().map(|k| &k.subject).collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl ApiKeyAuthenticator {
    /// Build an authenticator from the configured plaintext keys.
    ///
    /// The plaintext keys are hashed immediately and never retained.
    pub fn new(api_keys: &[String]) -> Self {
        let keys = api_keys
            .iter()
            .map(|key| {
                let digest = Sha256::digest(key.as_bytes());
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&digest);
                let subject = format!("key:{}", hex_prefix(&arr));
                KeyRecord {
                    digest: arr,
                    subject,
                }
            })
            .collect();
        Self { keys }
    }

    fn presented_credential<'a>(&self, headers: &'a HeaderMap) -> Option<&'a str> {
        if let Some(token) = bearer_token(headers) {
            return Some(token);
        }
        headers
            .get(&X_API_KEY)
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    }
}

#[async_trait::async_trait]
impl Authenticator for ApiKeyAuthenticator {
    fn mode(&self) -> &'static str {
        "api_key"
    }

    async fn authenticate(&self, headers: &HeaderMap) -> Result<AuthContext, AuthError> {
        let presented = self
            .presented_credential(headers)
            .ok_or(AuthError::Missing)?;

        let presented_digest = Sha256::digest(presented.as_bytes());
        let mut matched_subject: Option<&str> = None;

        // Always scan every configured digest so match index does not leak via
        // early return timing.
        for record in &self.keys {
            let eq = record.digest.ct_eq(presented_digest.as_ref());
            if bool::from(eq) {
                matched_subject = Some(&record.subject);
            }
        }

        match matched_subject {
            Some(subject) => Ok(AuthContext {
                subject: Some(subject.to_string()),
                tenant: "default".to_string(),
                profile: None,
                scopes: Vec::new(),
                mode: "api_key",
            }),
            None => Err(AuthError::Invalid("api key not recognized".to_string())),
        }
    }
}

fn hex_prefix(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(8);
    for &byte in digest.iter().take(4) {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0xf) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;
    use axum::http::HeaderValue;

    fn headers_bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    #[tokio::test]
    async fn accepts_configured_key() {
        let auth = ApiKeyAuthenticator::new(&[String::from("super-secret-key")]);
        let ctx = auth
            .authenticate(&headers_bearer("super-secret-key"))
            .await
            .unwrap();
        assert_eq!(ctx.mode, "api_key");
        assert!(ctx.subject.as_ref().unwrap().starts_with("key:"));
        assert_eq!(ctx.subject.as_ref().unwrap().len(), 12); // "key:" + 8 hex
    }

    #[tokio::test]
    async fn rejects_unknown_key() {
        let auth = ApiKeyAuthenticator::new(&[String::from("super-secret-key")]);
        let err = auth
            .authenticate(&headers_bearer("wrong-key"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn missing_credential() {
        let auth = ApiKeyAuthenticator::new(&[String::from("super-secret-key")]);
        let err = auth.authenticate(&HeaderMap::new()).await.unwrap_err();
        assert!(matches!(err, AuthError::Missing));
    }

    #[tokio::test]
    async fn accepts_x_api_key_header() {
        let auth = ApiKeyAuthenticator::new(&[String::from("super-secret-key")]);
        let mut headers = HeaderMap::new();
        headers.insert(&X_API_KEY, HeaderValue::from_static("super-secret-key"));
        let ctx = auth.authenticate(&headers).await.unwrap();
        assert_eq!(ctx.mode, "api_key");
    }

    #[tokio::test]
    async fn differing_lengths_do_not_panic() {
        let auth = ApiKeyAuthenticator::new(&[String::from("short")]);
        let err = auth
            .authenticate(&headers_bearer("a-much-longer-candidate-key"))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Invalid(_)));
    }

    #[tokio::test]
    async fn secret_never_appears_in_context_or_debug() {
        let secret = "literally-the-raw-api-key-value";
        let auth = ApiKeyAuthenticator::new(&[String::from(secret)]);
        let ctx = auth.authenticate(&headers_bearer(secret)).await.unwrap();
        let debug_auth = format!("{auth:?}");
        let debug_ctx = format!("{ctx:?}");
        assert!(!debug_auth.contains(secret));
        assert!(!debug_ctx.contains(secret));
        assert!(!ctx.subject.as_ref().unwrap().contains(secret));
    }
}
