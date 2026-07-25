// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! `redact-gateway` binary entry point.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use redact_gateway::config::{env as config_env, ConfigSourceKind, ResolvedConfig};
use redact_gateway::server::reload_config;
use redact_gateway::GatewayServer;
use tracing::{info, warn};

/// OpenAI-compatible privacy gateway.
///
/// Telemetry is configured with the standard OpenTelemetry environment
/// variables (`OTEL_SERVICE_NAME`, `OTEL_EXPORTER_OTLP_ENDPOINT`, and so on)
/// rather than gateway-specific flags.
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

    /// Base URL of the OpenAI-compatible inference provider.
    #[arg(long, alias = "backend-url", env = config_env::PROVIDER_BASE_URL)]
    provider_base_url: Option<String>,

    /// Bearer token sent to the provider.
    #[arg(
        long,
        alias = "backend-api-key",
        env = config_env::PROVIDER_API_KEY,
        hide_env_values = true
    )]
    provider_api_key: Option<String>,

    /// Policy profile applied when a request does not select one.
    #[arg(long, env = config_env::DEFAULT_PROFILE)]
    profile: Option<String>,

    /// Policy document to load.
    #[arg(long, env = config_env::POLICY_FILE)]
    policy: Option<PathBuf>,

    /// Directory or file of additional pattern packs. Repeatable.
    #[arg(long = "pattern-pack", value_delimiter = ',')]
    pattern_packs: Vec<PathBuf>,

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
    /// Print the effective policy as YAML.
    PrintPolicy,
}

impl Cli {
    fn resolve(&self) -> Result<ResolvedConfig> {
        // Flags are applied through the same environment overlay the library
        // uses, so precedence is identical however the gateway is launched.
        let mut overrides: Vec<(&str, String)> = Vec::new();
        if let Some(path) = &self.config {
            overrides.push((config_env::CONFIG_FILE, path.display().to_string()));
        }
        if let Some(source) = &self.config_source {
            overrides.push((config_env::CONFIG_SOURCE, source.as_str().to_string()));
        }
        if let Some(host) = &self.host {
            overrides.push((config_env::HOST, host.clone()));
        }
        if let Some(port) = self.port {
            overrides.push((config_env::PORT, port.to_string()));
        }
        if let Some(url) = &self.provider_base_url {
            overrides.push((config_env::PROVIDER_BASE_URL, url.clone()));
        }
        if let Some(key) = &self.provider_api_key {
            overrides.push((config_env::PROVIDER_API_KEY, key.clone()));
        }
        if let Some(profile) = &self.profile {
            overrides.push((config_env::DEFAULT_PROFILE, profile.clone()));
        }
        if let Some(policy) = &self.policy {
            overrides.push((config_env::POLICY_FILE, policy.display().to_string()));
        }
        if !self.pattern_packs.is_empty() {
            let joined = self
                .pattern_packs
                .iter()
                .map(|path| path.display().to_string())
                .collect::<Vec<_>>()
                .join(",");
            overrides.push((config_env::PATTERN_PACKS, joined));
        }

        for (key, value) in overrides {
            // SAFETY: configuration is resolved before any worker thread is
            // spawned, so no other thread can be reading the environment.
            unsafe { std::env::set_var(key, value) };
        }

        ResolvedConfig::load().context("could not resolve configuration")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config = match cli.resolve() {
        Ok(config) => config,
        Err(err) => {
            // Telemetry is not up yet, so report the failure plainly.
            eprintln!("error: {err:#}");
            std::process::exit(2);
        }
    };

    let telemetry = Arc::new(
        redact_gateway::telemetry::init(&config.telemetry)
            .context("could not initialize telemetry")?,
    );
    telemetry
        .init_tracing_subscriber()
        .context("could not install the tracing subscriber")?;

    match cli.command.unwrap_or(Command::Serve) {
        Command::Serve => serve(config, telemetry).await,
        Command::ValidateConfig => {
            config.validate()?;
            println!(
                "configuration is valid: {} profiles, default `{}`, source `{}`",
                config.policy.profiles.len(),
                config.policy.default_profile,
                config.source.as_str()
            );
            Ok(())
        }
        Command::PrintConfig => {
            println!("{}", serde_json::to_string_pretty(&config.summary())?);
            Ok(())
        }
        Command::PrintPolicy => {
            println!("{}", serde_norway::to_string(config.policy.as_ref())?);
            Ok(())
        }
    }
}

async fn serve(
    config: ResolvedConfig,
    telemetry: Arc<redact_gateway::telemetry::Telemetry>,
) -> Result<()> {
    info!(telemetry = %telemetry.summary(), "telemetry configured");

    let server = GatewayServer::with_telemetry(config, telemetry).await?;
    spawn_reload_watcher(server.config_handle());
    server.run().await
}

/// Reload configuration when the process receives `SIGHUP`.
#[cfg(unix)]
fn spawn_reload_watcher(handle: redact_gateway::ConfigHandle) {
    tokio::spawn(async move {
        let mut hangup = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())
        {
            Ok(signal) => signal,
            Err(err) => {
                warn!(error = %err, "could not listen for SIGHUP; configuration reload is disabled");
                return;
            }
        };
        while hangup.recv().await.is_some() {
            if let Err(err) = reload_config(&handle) {
                warn!(error = %err, "configuration reload failed");
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_reload_watcher(_handle: redact_gateway::ConfigHandle) {}
