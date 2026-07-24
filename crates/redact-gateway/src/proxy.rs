// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use anyhow::{anyhow, bail, Result};
use futures_util::StreamExt;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;
use std::time::Duration;

/// Upstream OpenAI-compatible chat completions HTTP client.
#[derive(Clone)]
pub struct HttpChatUpstream {
    client: reqwest::Client,
    chat_url: String,
    api_key: Option<String>,
    max_body_bytes: usize,
}

#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub body: Value,
}

#[derive(Debug, Clone)]
pub struct UpstreamStreamResponse {
    pub status: u16,
    pub body: String,
}

#[derive(Debug, Clone)]
pub struct UpstreamClientOptions {
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub max_body_bytes: usize,
}

impl Default for UpstreamClientOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(600),
            max_body_bytes: 32 * 1024 * 1024,
        }
    }
}

impl HttpChatUpstream {
    pub fn new(backend_url: impl AsRef<str>, api_key: Option<String>) -> Result<Self> {
        Self::with_options(backend_url, api_key, UpstreamClientOptions::default())
    }

    pub fn with_options(
        backend_url: impl AsRef<str>,
        api_key: Option<String>,
        options: UpstreamClientOptions,
    ) -> Result<Self> {
        let base = backend_url.as_ref().trim_end_matches('/');
        let client = reqwest::Client::builder()
            .connect_timeout(options.connect_timeout)
            .timeout(options.request_timeout)
            .build()?;
        Ok(Self {
            client,
            chat_url: format!("{base}/v1/chat/completions"),
            api_key,
            max_body_bytes: options.max_body_bytes,
        })
    }

    fn auth_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        if let Some(key) = &self.api_key {
            let value = format!("Bearer {key}");
            headers.insert(
                AUTHORIZATION,
                HeaderValue::from_str(&value)
                    .map_err(|e| anyhow!("invalid api key header: {e}"))?,
            );
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
                    "upstream response exceeded max body size of {} bytes",
                    self.max_body_bytes
                );
            }
            body.extend_from_slice(&chunk);
        }
        Ok((status, body))
    }

    pub async fn chat_completions(&self, body: &Value) -> Result<UpstreamResponse> {
        let response = self
            .client
            .post(&self.chat_url)
            .headers(self.auth_headers()?)
            .json(body)
            .send()
            .await?;

        let (status, bytes) = self.read_body_limited(response).await?;
        let body = serde_json::from_slice(&bytes).unwrap_or_else(|_| {
            serde_json::json!({
                "error": {
                    "message": "upstream returned non-JSON body",
                    "type": "upstream_error"
                }
            })
        });

        Ok(UpstreamResponse { status, body })
    }

    /// Request a streaming chat completion and buffer the full SSE body.
    ///
    /// Buffering is intentional: response redaction requires complete content so
    /// entities split across token deltas are not missed. Size is capped by
    /// `max_body_bytes`.
    pub async fn chat_completions_stream(&self, body: &Value) -> Result<UpstreamStreamResponse> {
        let response = self
            .client
            .post(&self.chat_url)
            .headers(self.auth_headers()?)
            .json(body)
            .send()
            .await?;

        let (status, bytes) = self.read_body_limited(response).await?;
        let body = String::from_utf8(bytes)
            .map_err(|e| anyhow!("upstream stream was not valid UTF-8: {e}"))?;
        Ok(UpstreamStreamResponse { status, body })
    }
}
