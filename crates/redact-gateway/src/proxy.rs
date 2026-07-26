// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! HTTP client for the OpenAI-compatible inference provider.
//!
//! This is a thin `reqwest` wrapper over `serde_json::Value` rather than a
//! typed LLM client crate, and deliberately so. A gateway must return the
//! provider's response with only the spans it redacted changed; a client that
//! deserializes into fixed structs silently drops fields it does not model,
//! which would quietly discard provider extensions and anything the wire
//! format gains next. Working on `Value` keeps unknown fields intact, and
//! owning the transport keeps raw byte access for incremental streaming,
//! response size caps, and verbatim upstream error bodies.

use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use bytes::Bytes;
use futures_util::{Stream, StreamExt};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;

use crate::config::ProviderSettings;

/// A buffered JSON response from the provider.
#[derive(Debug, Clone)]
pub struct ProviderResponse {
    /// HTTP status returned by the provider.
    pub status: u16,
    /// Parsed JSON body.
    pub body: Value,
}

/// A buffered `text/event-stream` response from the provider.
#[derive(Debug, Clone)]
pub struct ProviderStreamResponse {
    /// HTTP status returned by the provider.
    pub status: u16,
    /// Raw SSE body.
    pub body: String,
}

/// Client tuning independent of the resolved configuration.
#[derive(Debug, Clone)]
pub struct ProviderClientOptions {
    /// TCP connect timeout.
    pub connect_timeout: Duration,
    /// Overall request timeout, including streamed bodies.
    pub request_timeout: Duration,
    /// Cap on buffered response bodies.
    pub max_body_bytes: usize,
}

impl Default for ProviderClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(600),
            max_body_bytes: 32 * 1024 * 1024,
        }
    }
}

/// Inference provider client.
///
/// The client is path-agnostic so every OpenAI-compatible surface the gateway
/// exposes is proxied through one configuration, one timeout policy, and one
/// body-size cap.
#[derive(Clone)]
pub struct ProviderClient {
    client: reqwest::Client,
    base_url: String,
    api_key: Option<String>,
    max_body_bytes: usize,
}

impl std::fmt::Debug for ProviderClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProviderClient")
            .field("base_url", &self.base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<set>"))
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

impl ProviderClient {
    /// Build a client with default options.
    pub fn new(base_url: impl AsRef<str>, api_key: Option<String>) -> Result<Self> {
        Self::with_options(base_url, api_key, ProviderClientOptions::default())
    }

    /// Build a client with explicit options.
    pub fn with_options(
        base_url: impl AsRef<str>,
        api_key: Option<String>,
        options: ProviderClientOptions,
    ) -> Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout)
            .build()?;
        Ok(Self {
            client,
            base_url: base_url.as_ref().trim_end_matches('/').to_string(),
            api_key,
            max_body_bytes: options.max_body_bytes,
        })
    }

    /// Build a client from resolved provider settings.
    pub fn from_settings(settings: &ProviderSettings) -> Result<Self> {
        Self::with_options(
            &settings.base_url,
            settings.api_key.clone(),
            ProviderClientOptions {
                connect_timeout: Duration::from_secs(settings.connect_timeout_secs),
                request_timeout: Duration::from_secs(settings.request_timeout_secs),
                max_body_bytes: settings.max_body_bytes,
            },
        )
    }

    /// Configured base URL.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Absolute URL for a gateway-relative path such as `/v1/models`.
    pub fn url_for(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    fn headers(&self, forwarded_auth: Option<&str>, extra: &HeaderMap) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

        // A caller-supplied credential wins so operators can run the gateway
        // as a pass-through in front of per-user provider keys.
        let credential = forwarded_auth
            .map(str::to_string)
            .or_else(|| self.api_key.as_ref().map(|key| format!("Bearer {key}")));
        if let Some(value) = credential {
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&value)
                    .map_err(|e| anyhow!("invalid authorization header: {e}"))?,
            );
        }

        for (name, value) in extra.iter() {
            headers.insert(name.clone(), value.clone());
        }
        Ok(headers)
    }

    async fn read_body_limited(&self, response: reqwest::Response) -> Result<(u16, Vec<u8>)> {
        let status = response.status().as_u16();
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk?;
            if body.len().saturating_add(chunk.len()) > self.max_body_bytes {
                bail!(
                    "provider response exceeded max body size of {} bytes",
                    self.max_body_bytes
                );
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, body))
    }

    /// POST a JSON body and buffer the JSON response.
    pub async fn post_json(
        &self,
        path: &str,
        body: &Value,
        forwarded_auth: Option<&str>,
        extra_headers: &HeaderMap,
    ) -> Result<ProviderResponse> {
        let response = self
            .client
            .post(self.url_for(path))
            .headers(self.headers(forwarded_auth, extra_headers)?)
            .json(body)
            .send()
            .await?;

        let (status, bytes) = self.read_body_limited(response).await?;
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::json!({
                "error": {
                    "message": "the provider returned a non-JSON body",
                    "type": "provider_error"
                }
            })
        });
        Ok(ProviderResponse { status, body })
    }

    /// GET a JSON response, used for pass-through surfaces such as `/v1/models`.
    pub async fn get_json(
        &self,
        path: &str,
        forwarded_auth: Option<&str>,
        extra_headers: &HeaderMap,
    ) -> Result<ProviderResponse> {
        let response = self
            .client
            .get(self.url_for(path))
            .headers(self.headers(forwarded_auth, extra_headers)?)
            .send()
            .await?;

        let (status, bytes) = self.read_body_limited(response).await?;
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::json!({
                "error": {
                    "message": "the provider returned a non-JSON body",
                    "type": "provider_error"
                }
            })
        });
        Ok(ProviderResponse { status, body })
    }

    /// POST a JSON body and buffer the whole `text/event-stream` response.
    ///
    /// Buffering trades time to first token for detection accuracy: entities
    /// that straddle token deltas are only visible once the stream is whole.
    pub async fn post_sse(
        &self,
        path: &str,
        body: &Value,
        forwarded_auth: Option<&str>,
        extra_headers: &HeaderMap,
    ) -> Result<ProviderStreamResponse> {
        let response = self
            .client
            .post(self.url_for(path))
            .headers(self.headers(forwarded_auth, extra_headers)?)
            .json(body)
            .send()
            .await?;

        let (status, bytes) = self.read_body_limited(response).await?;
        let body = String::from_utf8(bytes)
            .map_err(|e| anyhow!("provider stream was not valid UTF-8: {e}"))?;
        Ok(ProviderStreamResponse { status, body })
    }

    /// POST a JSON body and return the response as a byte stream.
    ///
    /// Used by incremental streaming, where the gateway redacts and forwards
    /// chunks as they arrive instead of waiting for the whole body.
    pub async fn post_stream(
        &self,
        path: &str,
        body: &Value,
        forwarded_auth: Option<&str>,
        extra_headers: &HeaderMap,
    ) -> Result<(u16, ProviderByteStream)> {
        let response = self
            .client
            .post(self.url_for(path))
            .headers(self.headers(forwarded_auth, extra_headers)?)
            .json(body)
            .send()
            .await?;

        let status = response.status().as_u16();
        let stream = response
            .bytes_stream()
            .map(|chunk| chunk.map_err(|e| anyhow!("provider stream failed: {e}")));
        Ok((status, Box::pin(stream)))
    }
}

/// Byte stream of a provider response body.
pub type ProviderByteStream = std::pin::Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

/// Header names that must never be copied from a client request to the
/// provider or from the provider back to the client.
pub const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
    "content-length",
    "authorization",
];

/// Whether a header may be forwarded to the provider.
pub fn is_forwardable_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    !HOP_BY_HOP_HEADERS
        .iter()
        .any(|blocked| blocked.eq_ignore_ascii_case(name))
        && !name.starts_with("x-censgate-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_building_normalizes_the_base() {
        let client = ProviderClient::new("http://example.com/", None).unwrap();
        assert_eq!(client.base_url(), "http://example.com");
        assert_eq!(
            client.url_for("/v1/chat/completions"),
            "http://example.com/v1/chat/completions"
        );
    }

    #[test]
    fn configured_key_is_used_when_no_client_credential_is_forwarded() {
        let client = ProviderClient::new("http://example.com", Some("sk-test".into())).unwrap();
        let headers = client.headers(None, &HeaderMap::new()).unwrap();
        assert_eq!(headers[AUTHORIZATION], "Bearer sk-test");
    }

    #[test]
    fn forwarded_credential_takes_precedence() {
        let client = ProviderClient::new("http://example.com", Some("sk-config".into())).unwrap();
        let headers = client
            .headers(Some("Bearer sk-caller"), &HeaderMap::new())
            .unwrap();
        assert_eq!(headers[AUTHORIZATION], "Bearer sk-caller");
    }

    #[test]
    fn extra_headers_are_merged() {
        let client = ProviderClient::new("http://example.com", None).unwrap();
        let mut extra = HeaderMap::new();
        extra.insert("traceparent", HeaderValue::from_static("00-abc-def-01"));
        let headers = client.headers(None, &extra).unwrap();
        assert_eq!(headers["traceparent"], "00-abc-def-01");
        assert_eq!(headers[CONTENT_TYPE], "application/json");
    }

    #[test]
    fn hop_by_hop_and_gateway_headers_are_not_forwarded() {
        assert!(!is_forwardable_header(&HeaderName::from_static(
            "transfer-encoding"
        )));
        assert!(!is_forwardable_header(&HeaderName::from_static(
            "authorization"
        )));
        assert!(!is_forwardable_header(&HeaderName::from_static(
            "x-censgate-profile"
        )));
        assert!(is_forwardable_header(&HeaderName::from_static(
            "x-request-id"
        )));
    }

    #[test]
    fn debug_output_hides_the_api_key() {
        let client = ProviderClient::new("http://example.com", Some("sk-secret".into())).unwrap();
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("sk-secret"));
        assert!(rendered.contains("<set>"));
    }
}
