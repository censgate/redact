// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use anyhow::{anyhow, Result};
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use serde_json::Value;

/// Upstream OpenAI-compatible chat completions HTTP client.
#[derive(Clone)]
pub struct HttpChatUpstream {
    client: reqwest::Client,
    chat_url: String,
    api_key: Option<String>,
}

#[derive(Debug, Clone)]
pub struct UpstreamResponse {
    pub status: u16,
    pub body: Value,
}

impl HttpChatUpstream {
    pub fn new(backend_url: impl AsRef<str>, api_key: Option<String>) -> Result<Self> {
        let base = backend_url.as_ref().trim_end_matches('/');
        Ok(Self {
            client: reqwest::Client::new(),
            chat_url: format!("{base}/v1/chat/completions"),
            api_key,
        })
    }

    pub async fn chat_completions(&self, body: &Value) -> Result<UpstreamResponse> {
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

        let response = self
            .client
            .post(&self.chat_url)
            .headers(headers)
            .json(body)
            .send()
            .await?;

        let status = response.status().as_u16();
        let body = response.json::<Value>().await.unwrap_or_else(|_| {
            serde_json::json!({
                "error": {
                    "message": "upstream returned non-JSON body",
                    "type": "upstream_error"
                }
            })
        });

        Ok(UpstreamResponse { status, body })
    }
}
