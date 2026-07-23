// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use redact_core::{AnonymizationStrategy, AnonymizerConfig};

/// Runtime configuration for the gateway binary / server.
#[derive(Debug, Clone)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
    /// Upstream OpenAI-compatible base URL (e.g. `https://api.openai.com` or Ollama).
    pub backend_url: String,
    /// Optional bearer token forwarded as `Authorization: Bearer …`.
    pub backend_api_key: Option<String>,
    pub anonymizer: AnonymizerConfig,
    pub enable_tracing: bool,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            backend_url: "http://127.0.0.1:11434".to_string(),
            backend_api_key: None,
            anonymizer: AnonymizerConfig {
                strategy: AnonymizationStrategy::Replace,
                ..Default::default()
            },
            enable_tracing: true,
        }
    }
}

impl GatewayConfig {
    /// Load from environment variables.
    ///
    /// - `HOST` (default `0.0.0.0`)
    /// - `PORT` (default `8080`)
    /// - `BACKEND_URL` (default `http://127.0.0.1:11434`)
    /// - `BACKEND_API_KEY` / `OPENAI_API_KEY`
    /// - `REDACTION_STRATEGY` (`replace`|`mask`|`hash`, default `replace`)
    /// - `ENABLE_TRACING` (default `true`)
    pub fn from_env() -> Self {
        let mut config = Self::default();

        if let Ok(host) = std::env::var("HOST") {
            if !host.is_empty() {
                config.host = host;
            }
        }
        if let Ok(port) = std::env::var("PORT") {
            if let Ok(p) = port.parse() {
                config.port = p;
            }
        }
        if let Ok(url) = std::env::var("BACKEND_URL") {
            if !url.is_empty() {
                config.backend_url = url.trim_end_matches('/').to_string();
            }
        }
        config.backend_api_key = std::env::var("BACKEND_API_KEY")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::env::var("OPENAI_API_KEY")
                    .ok()
                    .filter(|s| !s.is_empty())
            });

        if let Ok(strategy) = std::env::var("REDACTION_STRATEGY") {
            config.anonymizer.strategy = match strategy.to_ascii_lowercase().as_str() {
                "mask" => AnonymizationStrategy::Mask,
                "hash" => AnonymizationStrategy::Hash,
                _ => AnonymizationStrategy::Replace,
            };
        }

        if let Ok(tracing) = std::env::var("ENABLE_TRACING") {
            if let Ok(v) = tracing.parse() {
                config.enable_tracing = v;
            }
        }

        config
    }
}
