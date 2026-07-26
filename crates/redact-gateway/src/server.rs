// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Server assembly: engine, pattern packs, token map, auth, audit and router.

use std::sync::Arc;

use anyhow::{Context, Result};
use redact_core::AnalyzerEngine;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::audit::{build_dispatcher, AuditDispatcher};
use crate::auth::{build_authenticator, Authenticator};
use crate::config::{ConfigHandle, ResolvedConfig};
use crate::packs::load_packs;
use crate::proxy::ProviderClient;
use crate::redact::token::Dek;
use crate::routes::{create_router, AppState};
use crate::telemetry::Telemetry;
use crate::vault::{build_store, TokenMapStore};

/// A configured gateway ready to serve traffic.
pub struct GatewayServer {
    config: ConfigHandle,
    state: AppState,
}

impl GatewayServer {
    /// Build a server from resolved configuration.
    pub async fn new(config: ResolvedConfig) -> Result<Self> {
        Self::build(config, None, None).await
    }

    /// Build a server that reports through an already initialized telemetry stack.
    pub async fn with_telemetry(config: ResolvedConfig, telemetry: Arc<Telemetry>) -> Result<Self> {
        Self::build(config, None, Some(telemetry)).await
    }

    /// Build a server around a pre-configured detection engine.
    ///
    /// Useful for embedding, where callers register extra recognizers such as
    /// the ONNX named-entity recognizer before serving traffic.
    pub async fn with_engine(config: ResolvedConfig, engine: Arc<AnalyzerEngine>) -> Result<Self> {
        Self::build(config, Some(engine), None).await
    }

    async fn build(
        config: ResolvedConfig,
        engine: Option<Arc<AnalyzerEngine>>,
        telemetry: Option<Arc<Telemetry>>,
    ) -> Result<Self> {
        config.validate()?;

        let engine = match engine {
            Some(engine) => engine,
            None => Arc::new(build_engine(&config)?),
        };

        let dek = build_dek(&config)?;

        let tokens = build_store(&config.vault)
            .await
            .context("could not initialize the token map backend")?;
        if tokens.backend_name() != "off" {
            if let Err(err) = tokens.health().await {
                // Startup continues so a transient outage does not prevent the
                // gateway from booting; fail-closed profiles reject at request
                // time instead.
                warn!(error = %err, backend = tokens.backend_name(), "token map backend is not reachable");
            }
        }

        let authenticator = build_authenticator(&config.auth)
            .await
            .context("could not initialize inbound authentication")?;

        let telemetry = match telemetry {
            Some(telemetry) => telemetry,
            None => Arc::new(
                crate::telemetry::init(&config.telemetry)
                    .context("could not initialize telemetry")?,
            ),
        };

        let audit = Arc::new(
            build_dispatcher(&config.audit, telemetry.logger_provider())
                .context("could not initialize audit emission")?,
        );

        let provider = ProviderClient::from_settings(&config.provider)
            .context("could not build the provider client")?;

        let handle = ConfigHandle::new(config);
        let state = AppState {
            config: handle.clone(),
            engine,
            provider,
            dek,
            tokens,
            auth: authenticator,
            audit,
            telemetry,
        };

        Ok(Self {
            config: handle,
            state,
        })
    }

    /// Current configuration snapshot.
    pub fn config(&self) -> Arc<ResolvedConfig> {
        self.config.load()
    }

    /// Handle used to swap configuration at runtime.
    pub fn config_handle(&self) -> ConfigHandle {
        self.config.clone()
    }

    /// Handler state, exposed for tests and embedding.
    pub fn state(&self) -> AppState {
        self.state.clone()
    }

    /// Token map backend in use.
    pub fn token_store(&self) -> Arc<dyn TokenMapStore> {
        self.state.tokens.clone()
    }

    /// Inbound authenticator in use.
    pub fn authenticator(&self) -> Arc<dyn Authenticator> {
        self.state.auth.clone()
    }

    /// Audit dispatcher in use.
    pub fn audit(&self) -> Arc<AuditDispatcher> {
        self.state.audit.clone()
    }

    /// Bind address in `host:port` form.
    pub fn bind_address(&self) -> String {
        self.config.load().bind_address()
    }

    /// Build the router for this server.
    pub fn router(&self) -> axum::Router {
        let config = self.config.load();
        let router = create_router(self.state.clone());
        if config.server.enable_http_trace {
            router.layer(TraceLayer::new_for_http())
        } else {
            router
        }
    }

    /// Serve until the process is asked to shut down.
    pub async fn run(self) -> Result<()> {
        let config = self.config.load();
        let address = config.bind_address();
        let router = self.router();
        let audit = self.state.audit.clone();

        let listener = tokio::net::TcpListener::bind(&address)
            .await
            .with_context(|| format!("could not bind {address}"))?;

        info!(
            address = %address,
            upstream = %config.provider.base_url,
            profile = %config.policy.default_profile,
            auth = config.auth.mode.as_str(),
            token_map = config.vault.backend.as_str(),
            audit = config.audit.export.as_str(),
            trace_operations = config.telemetry.operations.as_str(),
            "redact-gateway listening"
        );

        let result = axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("server error");

        if let Err(err) = audit.shutdown().await {
            warn!(error = %err, "audit dispatcher did not shut down cleanly");
        }
        self.state.telemetry.shutdown();
        result
    }
}

/// Build the detection engine, registering any configured pattern packs.
fn build_engine(config: &ResolvedConfig) -> Result<AnalyzerEngine> {
    let mut engine = if config.packs.disable_builtin {
        AnalyzerEngine::builder().build()
    } else {
        AnalyzerEngine::new()
    };

    if !config.packs.paths.is_empty() {
        let (recognizer, report) =
            load_packs(&config.packs.paths).context("could not load pattern packs")?;
        match recognizer {
            Some(recognizer) => {
                info!(
                    packs = report.packs_loaded,
                    patterns = report.patterns_loaded,
                    skipped = report.patterns_skipped,
                    "loaded pattern packs"
                );
                engine
                    .recognizer_registry_mut()
                    .add_recognizer(Arc::new(recognizer));
            }
            None => warn!(
                paths = ?config.packs.paths,
                "pattern pack paths matched no usable patterns"
            ),
        }
        for error in &report.errors {
            warn!(error = %error, "pattern pack problem");
        }
    }

    if config.packs.disable_builtin && engine.recognizer_registry().recognizers().is_empty() {
        anyhow::bail!(
            "built-in patterns are disabled and no pattern packs were loaded, so nothing would be detected"
        );
    }

    Ok(engine)
}

/// Resolve the key used to seal reversible token mappings.
fn build_dek(config: &ResolvedConfig) -> Result<Arc<Dek>> {
    match config.vault.data_encryption_key.as_deref() {
        Some(encoded) => Ok(Arc::new(
            Dek::from_base64(encoded)
                .context("CENSGATE_TOKEN_DEK must be a base64 encoded 32-byte key")?,
        )),
        None => {
            let generated = Dek::generate().context("could not generate a token sealing key")?;
            let tokenizing = config
                .policy
                .profiles
                .values()
                .any(|profile| profile.uses_tokenization());
            if tokenizing {
                warn!(
                    "no token sealing key is configured; an ephemeral key was generated, so \
                     tokens cannot be restored after a restart or by another replica"
                );
            }
            Ok(Arc::new(generated))
        }
    }
}

/// Resolve when the process receives an interrupt or termination signal.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {}
        _ = terminate => {}
    }
    info!("shutdown signal received");
}

/// Reload configuration from its original source and swap the snapshot.
///
/// Only settings the request path reads from the snapshot take effect:
/// policy profiles, redaction behavior, and telemetry detail. Anything
/// consumed once at startup to build a listener, the provider client, the
/// detection engine, the token map, the authenticator or the audit sink keeps
/// its original value, and the changed field names are logged so an operator
/// knows a restart is needed. [`ResolvedConfig::restart_required_changes`]
/// defines that list.
///
/// A failed reload keeps the last known good configuration: a typo in a policy
/// file must not take a running gateway offline.
pub fn reload_config(handle: &ConfigHandle) -> Result<Arc<ResolvedConfig>> {
    let current = handle.load();
    let span = crate::telemetry::spans::config_reload(
        current.telemetry.operations,
        current.source.as_str(),
    );

    match ResolvedConfig::load() {
        Ok(next) => {
            let restart_required = current.restart_required_changes(&next);
            if !restart_required.is_empty() {
                warn!(
                    fields = ?restart_required,
                    "these settings changed but are only read at startup; the running gateway \
                     keeps its current values until it is restarted"
                );
            }
            // Install the effective snapshot so hot-path readers (forward flag,
            // /readyz auth mode) cannot disagree with frozen subsystems.
            let effective = current.effective_for_reload(next);
            if let Err(err) = effective.validate() {
                warn!(
                    error = %err,
                    "effective reloaded configuration failed validation; keeping the last good configuration"
                );
                if let Some(span) = &span {
                    crate::telemetry::spans::finish_config_reload(
                        span,
                        "failed",
                        Some("config_error"),
                    );
                }
                return Err(err.into());
            }
            info!(
                source = effective.source.as_str(),
                profiles = effective.policy.profiles.len(),
                "configuration reloaded"
            );
            handle.store(effective);
            if let Some(span) = &span {
                crate::telemetry::spans::finish_config_reload(span, "reloaded", None);
            }
            Ok(handle.load())
        }
        Err(err) => {
            warn!(error = %err, "configuration reload failed; keeping the last good configuration");
            if let Some(span) = &span {
                crate::telemetry::spans::finish_config_reload(span, "failed", Some("config_error"));
            }
            Err(err.into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_builds_from_defaults() {
        let server = GatewayServer::new(ResolvedConfig::default()).await.unwrap();
        assert_eq!(server.bind_address(), "0.0.0.0:8080");
        assert_eq!(server.token_store().backend_name(), "off");
        assert_eq!(server.authenticator().mode(), "none");
    }

    #[tokio::test]
    async fn invalid_configuration_is_rejected() {
        let mut config = ResolvedConfig::default();
        config.provider.base_url = "not-a-url".to_string();
        assert!(GatewayServer::new(config).await.is_err());
    }

    #[tokio::test]
    async fn a_bad_sealing_key_fails_startup() {
        let mut config = ResolvedConfig::default();
        config.vault.data_encryption_key = Some("too-short".to_string());
        assert!(GatewayServer::new(config).await.is_err());
    }

    #[tokio::test]
    async fn disabling_builtin_patterns_without_packs_fails_startup() {
        let mut config = ResolvedConfig::default();
        config.packs.disable_builtin = true;
        let err = match GatewayServer::new(config).await {
            Ok(_) => panic!("expected startup to fail"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("nothing would be detected"));
    }

    #[tokio::test]
    async fn missing_pattern_pack_paths_fail_startup() {
        let mut config = ResolvedConfig::default();
        config.packs.paths = vec![std::path::PathBuf::from("/nonexistent/packs")];
        assert!(GatewayServer::new(config).await.is_err());
    }

    #[tokio::test]
    async fn repository_pattern_packs_load() {
        let packs = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../patterns");
        let mut config = ResolvedConfig::default();
        config.packs.paths = vec![packs];
        let server = GatewayServer::new(config).await.unwrap();
        assert!(
            server
                .state()
                .engine
                .recognizer_registry()
                .recognizers()
                .len()
                >= 2
        );
    }

    #[tokio::test]
    async fn memory_token_store_is_selected_by_configuration() {
        let mut config = ResolvedConfig::default();
        config.vault.backend = crate::config::VaultBackend::Memory;
        let server = GatewayServer::new(config).await.unwrap();
        assert_eq!(server.token_store().backend_name(), "memory");
    }
}
