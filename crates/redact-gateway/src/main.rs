// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! `redact-gateway` binary entry point.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use redact_gateway::config::{env as config_env, ConfigSourceKind, ResolvedConfig};
use redact_gateway::GatewayServer;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// OpenAI-compatible privacy gateway.
#[derive(Debug, Parser)]
#[command(name = "redact-gateway", version, about, long_about = None)]
struct Cli {
    /// Configuration file to load.
    #[arg(long, env = config_env::CONFIG_FILE, global = true)]
    config: Option<PathBuf>,

    /// Configuration source: env, file or layered.
    #[arg(long, env = config_env::CONFIG_SOURCE, global = true)]
    config_source: Option<ConfigSourceKind>,

    /// Bind address.
    #[arg(long, env = config_env::HOST)]
    host: Option<String>,

    /// Bind port.
    #[arg(long, env = config_env::PORT)]
    port: Option<u16>,

    /// Upstream OpenAI-compatible base URL.
    #[arg(long, env = config_env::BACKEND_URL)]
    backend_url: Option<String>,

    /// Bearer token sent to the upstream provider.
    #[arg(long, env = config_env::BACKEND_API_KEY, hide_env_values = true)]
    backend_api_key: Option<String>,

    /// Policy profile applied when a request does not select one.
    #[arg(long, env = config_env::DEFAULT_PROFILE)]
    profile: Option<String>,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Serve traffic. This is the default when no subcommand is given.
    Serve,
    /// Load the configuration and report any problems without serving.
    ValidateConfig,
    /// Print the resolved configuration with secrets redacted.
    PrintConfig,
}

impl Cli {
    fn resolve(&self) -> Result<ResolvedConfig> {
        // Flags are applied through the same environment overlay the library
        // uses, so precedence is identical however the gateway is launched.
        if let Some(path) = &self.config {
            // SAFETY: configuration resolution happens before any worker
            // threads are spawned, so no other thread can read the environment.
            unsafe { std::env::set_var(config_env::CONFIG_FILE, path) };
        }
        if let Some(source) = &self.config_source {
            unsafe { std::env::set_var(config_env::CONFIG_SOURCE, source.as_str()) };
        }
        if let Some(host) = &self.host {
            unsafe { std::env::set_var(config_env::HOST, host) };
        }
        if let Some(port) = self.port {
            unsafe { std::env::set_var(config_env::PORT, port.to_string()) };
        }
        if let Some(url) = &self.backend_url {
            unsafe { std::env::set_var(config_env::BACKEND_URL, url) };
        }
        if let Some(key) = &self.backend_api_key {
            unsafe { std::env::set_var(config_env::BACKEND_API_KEY, key) };
        }
        if let Some(profile) = &self.profile {
            unsafe { std::env::set_var(config_env::DEFAULT_PROFILE, profile) };
        }

        ResolvedConfig::load().context("could not resolve configuration")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    init_logging();

    let config = cli.resolve()?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => GatewayServer::new(config).await?.run().await,
        Command::ValidateConfig => {
            config.validate()?;
            println!(
                "configuration is valid ({} profiles, default `{}`)",
                config.policy.profiles.len(),
                config.policy.default_profile
            );
            Ok(())
        }
        Command::PrintConfig => {
            println!("{}", serde_json::to_string_pretty(&config.summary())?);
            Ok(())
        }
    }
}

fn init_logging() {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("redact_gateway=info,tower_http=info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
