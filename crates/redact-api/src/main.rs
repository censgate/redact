// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use redact_api::server::{ApiServer, ServerConfig};
use redact_core::{
    recognizers::{pattern::PatternRecognizer, RecognizerRegistry},
    AnalyzerEngine,
};
use redact_ner::NerRecognizer;
use std::sync::Arc;
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Build analyzer engine with pattern recognizer and optional NER when NER_MODEL_PATH is set.
fn build_engine() -> AnalyzerEngine {
    let mut registry = RecognizerRegistry::new();

    // Always add pattern-based recognizer (36+ entity types)
    registry.add_recognizer(Arc::new(PatternRecognizer::new()));

    // Add NER recognizer when ONNX model path is set
    if let Ok(path) = std::env::var("NER_MODEL_PATH") {
        if !path.is_empty() {
            match NerRecognizer::from_file(&path) {
                Ok(ner) => {
                    registry.add_recognizer(Arc::new(ner));
                    info!("NER recognizer loaded from {}", path);
                }
                Err(e) => {
                    warn!(
                        "NER model path set but load failed: {}. Running with pattern-only.",
                        e
                    );
                }
            }
        }
    }

    let mut engine = AnalyzerEngine::builder()
        .with_recognizer_registry(registry)
        .build();

    if std::env::var("NER_MODEL_PATH").is_ok_and(|p| !p.is_empty()) {
        engine = engine.with_model_version("onnx-v1");
    }

    engine
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "redact_api=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse configuration from environment
    let config = ServerConfig {
        host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
        port: std::env::var("PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8080),
        enable_tracing: std::env::var("ENABLE_TRACING")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true),
    };

    let engine = build_engine();
    let server = ApiServer::with_engine(config, engine);
    server.run().await?;

    Ok(())
}
