// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::handlers::{analyze, anonymize, health, AppState};
use axum::{
    routing::{get, post},
    Router,
};

/// Create the application router with all routes
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/v1/analyze", post(analyze))
        .route("/api/v1/anonymize", post(anonymize))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use redact_core::AnalyzerEngine;
    use std::sync::Arc;
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn test_health_route() {
        let state = AppState {
            engine: Arc::new(AnalyzerEngine::new()),
        };
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_analyze_route() {
        let state = AppState {
            engine: Arc::new(AnalyzerEngine::new()),
        };
        let app = create_router(state);

        let body = r#"{"text":"john@example.com","language":"en"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/analyze")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}
