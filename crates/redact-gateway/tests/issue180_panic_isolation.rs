//! A recognizer panic must become an HTTP error plus an audit record.

mod support;

use std::sync::Arc;

use redact_core::{AnalyzerEngine, EntityType, Recognizer, RecognizerResult};
use redact_gateway::config::AuditExport;
use redact_gateway::routes::create_router;
use redact_gateway::GatewayServer;
use serde_json::Value;
use support::*;

#[derive(Debug)]
struct Panicky;

impl Recognizer for Panicky {
    fn name(&self) -> &str {
        "panicky"
    }

    fn supported_entities(&self) -> &[EntityType] {
        &[EntityType::Person]
    }

    fn analyze(&self, _text: &str, _language: &str) -> anyhow::Result<Vec<RecognizerResult>> {
        panic!("injected recognizer failure");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recognizer_panic_returns_500_and_writes_error_audit() {
    let upstream = mock_json_upstream(chat_response("xin chào")).await;
    let dir = tempfile::tempdir().unwrap();
    let audit = dir.path().join("audit.jsonl");
    let mut config = config_for(&upstream);
    config.audit.export = AuditExport::File;
    config.audit.file_path = Some(audit.clone());

    let mut engine = AnalyzerEngine::new();
    engine
        .recognizer_registry_mut()
        .add_recognizer(Arc::new(Panicky));
    let state = GatewayServer::with_engine(config, Arc::new(engine))
        .await
        .unwrap()
        .state();
    let addr = spawn(create_router(state)).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!("http://{addr}/v1/chat/completions"))
        .json(&chat_request("Xin chào, tôi là Ánh"))
        .send()
        .await
        .expect("gateway must answer, not drop the connection");
    assert_eq!(response.status().as_u16(), 500);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["type"], "redaction_error");
    assert!(
        !body.to_string().contains("injected"),
        "panic payload leaked: {body}"
    );

    let contents = wait_for_audit_containing(&audit, "\"outcome\":\"error\"").await;
    assert!(
        contents.contains("\"error_type\":\"redaction_error\""),
        "{contents}"
    );
    assert!(
        !contents.contains("Ánh"),
        "audit leaked content: {contents}"
    );
    assert!(upstream.received_nothing(), "provider must not be called");

    let health = client
        .get(format!("http://{addr}/healthz"))
        .send()
        .await
        .unwrap();
    assert_eq!(health.status().as_u16(), 200);
}
