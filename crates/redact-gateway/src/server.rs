// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Server assembly: engine, upstream client, router and listener.

use std::sync::Arc;

use anyhow::{Context, Result};
use redact_core::AnalyzerEngine;
use tower_http::trace::TraceLayer;
use tracing::info;

use crate::config::{ConfigHandle, ResolvedConfig};
use crate::proxy::UpstreamClient;
use crate::redact::token::Dek;
use crate::routes::{create_router, AppState};

/// A configured gateway ready to serve traffic.
pub struct GatewayServer {
    config: ConfigHandle,
    state: AppState,
}

impl GatewayServer {
    /// Build a server from resolved configuration.
    pub async fn new(config: ResolvedConfig) -> Result<Self> {
        let engine = Arc::new(AnalyzerEngine::new());
        Self::with_engine(config, engine).await
    }

    /// Build a server around a pre-configured detection engine.
    ///
    /// Useful for embedding, where callers register extra recognizers such as
    /// the ONNX named-entity recognizer before serving traffic.
    pub async fn with_engine(config: ResolvedConfig, engine: Arc<AnalyzerEngine>) -> Result<Self> {
        config.validate()?;

        let dek = match config.vault.data_encryption_key.as_deref() {
            Some(encoded) => Dek::from_base64(encoded)
                .context("CENSGATE_TOKEN_DEK must be a base64 encoded 32-byte key")?,
            None => {
                let generated =
                    Dek::generate().context("could not generate a token sealing key")?;
                if config
                    .policy
                    .profiles
                    .values()
                    .any(|profile| profile.uses_tokenization())
                {
                    info!(
                        "no token sealing key configured; generated an ephemeral key, so tokens \
                         cannot be restored after a restart or by another replica"
                    );
                }
                generated
            }
        };

        let upstream = UpstreamClient::from_settings(&config.upstream)
            .context("could not build the upstream client")?;

        let handle = ConfigHandle::new(config);
        let state = AppState {
            config: handle.clone(),
            engine,
            upstream,
            dek: Arc::new(dek),
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

        let listener = tokio::net::TcpListener::bind(&address)
            .await
            .with_context(|| format!("could not bind {address}"))?;

        info!(
            address = %address,
            upstream = %config.upstream.base_url,
            profile = %config.policy.default_profile,
            auth = config.auth.mode.as_str(),
            token_map = config.vault.backend.as_str(),
            audit = config.audit.export.as_str(),
            "redact-gateway listening"
        );

        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown_signal())
            .await
            .context("server error")
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn server_builds_from_defaults() {
        let server = GatewayServer::new(ResolvedConfig::default()).await.unwrap();
        assert_eq!(server.bind_address(), "0.0.0.0:8080");
    }

    #[tokio::test]
    async fn invalid_configuration_is_rejected() {
        let mut config = ResolvedConfig::default();
        config.upstream.base_url = "not-a-url".to_string();
        assert!(GatewayServer::new(config).await.is_err());
    }

    #[tokio::test]
    async fn a_bad_sealing_key_fails_startup() {
        let mut config = ResolvedConfig::default();
        config.vault.data_encryption_key = Some("too-short".to_string());
        assert!(GatewayServer::new(config).await.is_err());
    }
}
