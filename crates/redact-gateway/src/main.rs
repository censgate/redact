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
    #[arg(long, env = config_env::PROVIDER_BASE_URL)]
    provider_base_url: Option<String>,

    /// Bearer token sent to the provider.
    #[arg(long, env = config_env::PROVIDER_API_KEY, hide_env_values = true)]
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
    /// Check indexed storage prerequisites without serving or migrating contexts.
    CheckTokenStore,
    /// Run one bounded expiry-maintenance slice over an authorized inventory.
    ///
    /// Clears expired ciphertext of already imported contexts only; identity
    /// reservations are kept and never-imported contexts are not migrated.
    /// Prints an identifier-free JSON summary. Exits 0 when the slice stopped
    /// cleanly (including budget/deadline stops that the next run resumes) and
    /// 1 when it failed closed.
    MaintainTokenStore(MaintainArgs),
    /// Print the resolved configuration with secrets redacted.
    PrintConfig,
    /// Print the effective policy as YAML.
    PrintPolicy,
}

#[derive(Debug, clap::Args)]
struct MaintainArgs {
    /// Authorized inventory: one `{"tenant":…,"context":…}` JSON object per line.
    #[arg(long)]
    inventory: PathBuf,
    /// Durable cursor file; `<path>.lock` is the single-worker lock.
    #[arg(long)]
    checkpoint: PathBuf,
    /// Expired entries cleared per batch (1..=256).
    #[arg(long, default_value_t = 256)]
    batch_limit: usize,
    /// Batches per context before stopping and resuming it next run.
    #[arg(long, default_value_t = 1024)]
    max_batches_per_context: u32,
    /// Contexts visited per run.
    #[arg(long, default_value_t = 10_000)]
    max_contexts: usize,
    /// Attempts per operation for transient failures (1..=10).
    #[arg(long, default_value_t = 5)]
    max_attempts: u32,
    /// Wall-clock budget for this run, in seconds.
    #[arg(long, default_value_t = 3300)]
    deadline_secs: u64,
    /// Discard an unfinished cursor bound to a different inventory.
    #[arg(long)]
    restart_pass: bool,
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
        Command::CheckTokenStore => {
            let backend = redact_gateway::server::check_token_store(&config).await?;
            println!("token-store preflight passed: {backend}; writer drain and restore rehearsal remain operator gates");
            Ok(())
        }
        Command::MaintainTokenStore(args) => {
            let limits = redact_gateway::vault::maintenance::Limits {
                batch_limit: args.batch_limit,
                max_batches_per_context: args.max_batches_per_context,
                max_contexts_per_run: args.max_contexts,
                max_attempts: args.max_attempts,
                run_deadline: std::time::Duration::from_secs(args.deadline_secs),
                ..Default::default()
            };
            let result = redact_gateway::server::maintain_token_store(
                &config,
                &telemetry,
                &args.inventory,
                &args.checkpoint,
                limits,
                args.restart_pass,
            )
            .await;
            // Flush RED metrics and spans before exiting.
            telemetry.shutdown();
            let summary = result?;
            println!("{}", serde_json::to_string(&summary)?);
            if summary.failed() {
                std::process::exit(1);
            }
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
