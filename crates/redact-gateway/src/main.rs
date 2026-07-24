// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use clap::Parser;
use redact_gateway::config::{parse_strategy, GatewayConfig};
use redact_gateway::GatewayServer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// CLI is the single config owner for the binary (flags + env via clap).
#[derive(Debug, Parser)]
#[command(
    name = "redact-gateway",
    about = "Censgate AI privacy gateway (OpenAI-compatible, embeds redact-core)"
)]
struct Cli {
    /// Bind host
    #[arg(long, env = "HOST", default_value = "0.0.0.0")]
    host: String,

    /// Bind port
    #[arg(long, env = "PORT", default_value_t = 8080)]
    port: u16,

    /// Upstream OpenAI-compatible base URL
    #[arg(long, env = "BACKEND_URL", default_value = "http://127.0.0.1:11434")]
    backend_url: String,

    /// Upstream API key (falls back to OPENAI_API_KEY)
    #[arg(long, env = "BACKEND_API_KEY")]
    backend_api_key: Option<String>,

    /// Redaction strategy: replace | mask | hash
    #[arg(long, env = "REDACTION_STRATEGY", default_value = "replace")]
    redaction_strategy: String,

    /// Enable HTTP request tracing
    #[arg(long, env = "ENABLE_TRACING", default_value_t = true)]
    enable_tracing: bool,

    /// Upstream TCP connect timeout (seconds)
    #[arg(long, env = "CONNECT_TIMEOUT_SECS", default_value_t = 10)]
    connect_timeout_secs: u64,

    /// Upstream request timeout (seconds); streams may run for minutes
    #[arg(long, env = "REQUEST_TIMEOUT_SECS", default_value_t = 600)]
    request_timeout_secs: u64,

    /// Max buffered upstream response body bytes (JSON or SSE)
    #[arg(long, env = "MAX_UPSTREAM_BODY_BYTES", default_value_t = 33_554_432)]
    max_upstream_body_bytes: usize,
}

impl Cli {
    fn into_config(self) -> anyhow::Result<GatewayConfig> {
        let strategy = parse_strategy(&self.redaction_strategy)?;
        let backend_api_key = self.backend_api_key.filter(|s| !s.is_empty()).or_else(|| {
            std::env::var("OPENAI_API_KEY")
                .ok()
                .filter(|s| !s.is_empty())
        });

        Ok(GatewayConfig {
            host: self.host,
            port: self.port,
            backend_url: self.backend_url.trim_end_matches('/').to_string(),
            backend_api_key,
            anonymizer: redact_core::AnonymizerConfig {
                strategy,
                ..Default::default()
            },
            enable_tracing: self.enable_tracing,
            connect_timeout_secs: self.connect_timeout_secs,
            request_timeout_secs: self.request_timeout_secs,
            max_upstream_body_bytes: self.max_upstream_body_bytes,
        })
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redact_gateway=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = Cli::parse().into_config()?;
    GatewayServer::new(config).run().await
}
