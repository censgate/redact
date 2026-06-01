// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::handlers::{analyze_api, anonymize_api, health, AppState};
use axum::{
    routing::{get, post},
    Router,
};

/// Create the application router with all routes
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/healthz", get(health))
        .route("/api/v1/analyze", post(analyze_api))
        .route("/api/v1/anonymize", post(anonymize_api))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::{Request, StatusCode},
    };
    use redact_core::AnalyzerEngine;
    use serde_json::Value;
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
    async fn test_healthz_route() {
        let state = AppState {
            engine: Arc::new(AnalyzerEngine::new()),
        };
        let app = create_router(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/healthz")
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["results"][0]["text"], "john@example.com");
    }

    #[tokio::test]
    async fn test_analyze_route_omits_entity_text_when_include_text_false() {
        let state = AppState {
            engine: Arc::new(AnalyzerEngine::new()),
        };
        let app = create_router(state);

        let body = r#"{"text":"Email: john@example.com","language":"en","include_text":false}"#;

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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let result = &json["results"][0];

        assert_eq!(result["entity_type"], "EMAIL_ADDRESS");
        assert!(result["start"].is_number());
        assert!(result["end"].is_number());
        assert!(result["score"].is_number());
        assert!(result["recognizer_name"].is_string());
        assert!(result.get("text").is_none());
    }

    #[tokio::test]
    async fn test_anonymize_route_omits_entity_text_when_include_text_false() {
        let state = AppState {
            engine: Arc::new(AnalyzerEngine::new()),
        };
        let app = create_router(state);

        let body = r#"{"text":"Email: john@example.com","language":"en","include_text":false}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();
        let result = &json["results"][0];

        assert!(json["text"].as_str().unwrap().contains("[EMAIL_ADDRESS]"));
        assert_eq!(result["entity_type"], "EMAIL_ADDRESS");
        assert!(result["start"].is_number());
        assert!(result["end"].is_number());
        assert!(result["score"].is_number());
        assert!(result["recognizer_name"].is_string());
        assert!(result.get("text").is_none());
    }

    #[tokio::test]
    async fn test_anonymize_route_includes_entity_text_when_include_text_omitted() {
        let state = AppState {
            engine: Arc::new(AnalyzerEngine::new()),
        };
        let app = create_router(state);

        let body = r#"{"text":"Email: john@example.com","language":"en"}"#;

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/anonymize")
                    .header("content-type", "application/json")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert!(json["text"].as_str().unwrap().contains("[EMAIL_ADDRESS]"));
        assert_eq!(json["results"][0]["text"], "john@example.com");
    }

    fn ner_model_fixture_dir() -> std::path::PathBuf {
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../redact-ner/tests/fixtures/models/bert-base-ner")
    }

    fn ner_model_available(model_dir: &std::path::Path) -> bool {
        model_dir.join("model.onnx").exists() && model_dir.join("tokenizer.json").exists()
    }

    /// `/api/v1/analyze` returns NER entity spans when an ONNX model is loaded.
    #[tokio::test]
    #[ignore = "requires redact-ner/tests/fixtures/models/bert-base-ner (see ner_e2e.rs setup)"]
    async fn test_analyze_route_returns_ner_person_spans() {
        use redact_core::recognizers::RecognizerRegistry;
        use redact_ner::{NerConfig, NerRecognizer};

        let model_dir = ner_model_fixture_dir();
        if !ner_model_available(&model_dir) {
            eprintln!(
                "Skipping NER analyze route test: model fixture missing at {}",
                model_dir.display()
            );
            return;
        }

        let config = NerConfig {
            model_path: model_dir.join("model.onnx").to_string_lossy().into_owned(),
            tokenizer_path: Some(
                model_dir
                    .join("tokenizer.json")
                    .to_string_lossy()
                    .into_owned(),
            ),
            min_confidence: 0.7,
            ..Default::default()
        };

        let ner = NerRecognizer::from_config(config).expect("load NER model");
        let mut registry = RecognizerRegistry::new();
        registry.add_recognizer(Arc::new(ner));

        let state = AppState {
            engine: Arc::new(
                AnalyzerEngine::builder()
                    .with_recognizer_registry(registry)
                    .build(),
            ),
        };
        let app = create_router(state);

        let body = r#"{"text":"Contact John Doe at john@example.com","language":"en"}"#;
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        let person_spans: Vec<_> = json["results"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|r| r["entity_type"] == "PERSON")
            .collect();

        assert!(
            !person_spans.is_empty(),
            "expected PERSON spans from NER-enabled analyze response"
        );
        assert!(person_spans[0]["start"].is_number());
        assert!(person_spans[0]["end"].is_number());
        assert!(person_spans[0]["score"].as_f64().unwrap() > 0.0);
    }
}
