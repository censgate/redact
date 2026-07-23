// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use clap::Parser;
use redact_gateway::{GatewayConfig, GatewayServer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

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

    /// Upstream API key (also reads OPENAI_API_KEY)
    #[arg(long, env = "BACKEND_API_KEY")]
    backend_api_key: Option<String>,
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

    let cli = Cli::parse();
    let mut config = GatewayConfig::from_env();
    config.host = cli.host;
    config.port = cli.port;
    config.backend_url = cli.backend_url.trim_end_matches('/').to_string();
    if cli.backend_api_key.is_some() {
        config.backend_api_key = cli.backend_api_key;
    }

    GatewayServer::new(config).run().await
}
