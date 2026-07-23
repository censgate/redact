// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::config::GatewayConfig;
use crate::proxy::HttpChatUpstream;
use crate::routes::{create_router, AppState};
use axum::serve;
use redact_core::AnalyzerEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

/// Gateway HTTP server.
pub struct GatewayServer {
    config: GatewayConfig,
    engine: Arc<AnalyzerEngine>,
}

impl GatewayServer {
    pub fn new(config: GatewayConfig) -> Self {
        Self {
            config,
            engine: Arc::new(AnalyzerEngine::new()),
        }
    }

    pub fn with_engine(config: GatewayConfig, engine: AnalyzerEngine) -> Self {
        Self {
            config,
            engine: Arc::new(engine),
        }
    }

    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let bind_addr = self.bind_address();
        let enable_tracing = self.config.enable_tracing;
        let upstream = HttpChatUpstream::new(
            &self.config.backend_url,
            self.config.backend_api_key.clone(),
        )?;

        let state = AppState {
            engine: self.engine,
            anonymizer: self.config.anonymizer,
            upstream,
        };

        let mut app = create_router(state);
        if enable_tracing {
            app = app.layer(TraceLayer::new_for_http());
        }

        let addr: SocketAddr = bind_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;

        info!("Censgate gateway listening on {}", addr);
        info!("Upstream backend: {}", self.config.backend_url);
        info!("Endpoints:");
        info!("  GET  /health                 - Health check");
        info!("  POST /v1/chat/completions    - Redacting OpenAI-compatible proxy");

        serve(listener, app).await?;
        Ok(())
    }
}
