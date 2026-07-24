// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use redact_core::{AnonymizationStrategy, AnonymizerConfig};
use thiserror::Error;

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
    /// TCP connect timeout for upstream requests.
    pub connect_timeout_secs: u64,
    /// Overall upstream request timeout (streams may run for minutes).
    pub request_timeout_secs: u64,
    /// Max buffered upstream response body bytes (JSON or SSE).
    pub max_upstream_body_bytes: usize,
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
            connect_timeout_secs: 10,
            request_timeout_secs: 600,
            max_upstream_body_bytes: 32 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid PORT value {0:?}: {1}")]
    InvalidPort(String, String),
    #[error("invalid REDACTION_STRATEGY {0:?}: expected one of replace, mask, hash")]
    InvalidStrategy(String),
    #[error("invalid ENABLE_TRACING value {0:?}: {1}")]
    InvalidTracing(String, String),
    #[error("invalid {0} value {1:?}: {2}")]
    InvalidNumber(&'static str, String, String),
}

impl GatewayConfig {
    /// Load from environment variables. Returns an error on invalid values
    /// instead of silently falling back.
    ///
    /// - `HOST` (default `0.0.0.0`)
    /// - `PORT` (default `8080`)
    /// - `BACKEND_URL` (default `http://127.0.0.1:11434`)
    /// - `BACKEND_API_KEY` / `OPENAI_API_KEY`
    /// - `REDACTION_STRATEGY` (`replace`|`mask`|`hash`, default `replace`)
    /// - `ENABLE_TRACING` (default `true`)
    /// - `CONNECT_TIMEOUT_SECS` (default `10`)
    /// - `REQUEST_TIMEOUT_SECS` (default `600`)
    /// - `MAX_UPSTREAM_BODY_BYTES` (default `33554432`)
    pub fn try_from_env() -> Result<Self, ConfigError> {
        let mut config = Self::default();

        if let Ok(host) = std::env::var("HOST") {
            if !host.is_empty() {
                config.host = host;
            }
        }
        if let Ok(port) = std::env::var("PORT") {
            if !port.is_empty() {
                config.port = port
                    .parse::<u16>()
                    .map_err(|e| ConfigError::InvalidPort(port.clone(), e.to_string()))?;
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
            if !strategy.is_empty() {
                config.anonymizer.strategy = parse_strategy(&strategy)?;
            }
        }

        if let Ok(tracing) = std::env::var("ENABLE_TRACING") {
            if !tracing.is_empty() {
                config.enable_tracing = tracing
                    .parse::<bool>()
                    .map_err(|e| ConfigError::InvalidTracing(tracing.clone(), e.to_string()))?;
            }
        }

        if let Ok(v) = std::env::var("CONNECT_TIMEOUT_SECS") {
            if !v.is_empty() {
                config.connect_timeout_secs = parse_u64("CONNECT_TIMEOUT_SECS", &v)?;
            }
        }
        if let Ok(v) = std::env::var("REQUEST_TIMEOUT_SECS") {
            if !v.is_empty() {
                config.request_timeout_secs = parse_u64("REQUEST_TIMEOUT_SECS", &v)?;
            }
        }
        if let Ok(v) = std::env::var("MAX_UPSTREAM_BODY_BYTES") {
            if !v.is_empty() {
                config.max_upstream_body_bytes = parse_u64("MAX_UPSTREAM_BODY_BYTES", &v)? as usize;
            }
        }

        Ok(config)
    }

    /// Load from environment, panicking on invalid values.
    /// Prefer [`Self::try_from_env`] when you want to handle errors.
    pub fn from_env() -> Self {
        Self::try_from_env()
            .unwrap_or_else(|err| panic!("invalid gateway configuration from environment: {err}"))
    }
}

pub fn parse_strategy(strategy: &str) -> Result<AnonymizationStrategy, ConfigError> {
    match strategy.to_ascii_lowercase().as_str() {
        "replace" => Ok(AnonymizationStrategy::Replace),
        "mask" => Ok(AnonymizationStrategy::Mask),
        "hash" => Ok(AnonymizationStrategy::Hash),
        other => Err(ConfigError::InvalidStrategy(other.to_string())),
    }
}

fn parse_u64(name: &'static str, raw: &str) -> Result<u64, ConfigError> {
    raw.parse::<u64>()
        .map_err(|e| ConfigError::InvalidNumber(name, raw.to_string(), e.to_string()))
}
