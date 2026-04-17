// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::handlers::AppState;
use crate::routes::create_router;
use axum::serve;
use redact_core::AnalyzerEngine;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::info;

/// API Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Host to bind to
    pub host: String,

    /// Port to bind to
    pub port: u16,

    /// Enable request tracing
    pub enable_tracing: bool,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 8080,
            enable_tracing: true,
        }
    }
}

/// API Server
pub struct ApiServer {
    config: ServerConfig,
    engine: Arc<AnalyzerEngine>,
}

impl ApiServer {
    /// Create a new API server
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            engine: Arc::new(AnalyzerEngine::new()),
        }
    }

    /// Create a new API server with a custom engine
    pub fn with_engine(config: ServerConfig, engine: AnalyzerEngine) -> Self {
        Self {
            config,
            engine: Arc::new(engine),
        }
    }

    /// Get the bind address
    pub fn bind_address(&self) -> String {
        format!("{}:{}", self.config.host, self.config.port)
    }

    /// Run the server
    pub async fn run(self) -> anyhow::Result<()> {
        // Get bind address before moving self
        let bind_addr = self.bind_address();
        let enable_tracing = self.config.enable_tracing;

        // Create application state
        let state = AppState {
            engine: self.engine,
        };

        // Create router
        let mut app = create_router(state);

        // Add tracing middleware
        if enable_tracing {
            app = app.layer(TraceLayer::new_for_http());
        }

        // Bind to address
        let addr: SocketAddr = bind_addr.parse()?;
        let listener = TcpListener::bind(addr).await?;

        info!("Redact API server listening on {}", addr);
        info!("Endpoints:");
        info!("  GET  /health           - Health check");
        info!("  POST /api/v1/analyze   - Analyze text for PII");
        info!("  POST /api/v1/anonymize - Anonymize detected PII");

        // Run server
        serve(listener, app).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config() {
        let config = ServerConfig::default();
        assert_eq!(config.host, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert!(config.enable_tracing);
    }

    #[test]
    fn test_bind_address() {
        let config = ServerConfig {
            host: "127.0.0.1".to_string(),
            port: 3000,
            enable_tracing: false,
        };
        let server = ApiServer::new(config);
        assert_eq!(server.bind_address(), "127.0.0.1:3000");
    }
}
