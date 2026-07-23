// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use redact_core::{AnalyzerEngine, AnonymizationStrategy, AnonymizerConfig};
use redact_gateway::openai::{ChatCompletionRequest, ChatMessage};
use redact_gateway::redact::{redact_chat_request, RedactionOutcome};

#[test]
fn redact_chat_request_replaces_email_in_user_message() {
    let engine = AnalyzerEngine::new();
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };

    let mut request = ChatCompletionRequest {
        model: "gpt-4o-mini".to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: Some("Email me at alice@example.com please".to_string()),
        }],
        stream: None,
        extra: Default::default(),
    };

    let outcome = redact_chat_request(&engine, &mut request, &config).expect("redact");

    assert!(
        matches!(outcome, RedactionOutcome { redactions_applied, .. } if redactions_applied >= 1)
    );
    let content = request.messages[0].content.as_deref().unwrap();
    assert!(
        !content.contains("alice@example.com"),
        "PII must not remain in forwarded content: {content}"
    );
    assert!(
        content.contains("[EMAIL_ADDRESS]") || content.contains("EMAIL"),
        "expected replace placeholder, got: {content}"
    );
}

#[test]
fn redact_chat_request_leaves_clean_message_unchanged() {
    let engine = AnalyzerEngine::new();
    let config = AnonymizerConfig::default();

    let original = "Explain how TLS handshakes work".to_string();
    let mut request = ChatCompletionRequest {
        model: "gpt-4o-mini".to_string(),
        messages: vec![ChatMessage {
            role: "user".to_string(),
            content: Some(original.clone()),
        }],
        stream: None,
        extra: Default::default(),
    };

    let outcome = redact_chat_request(&engine, &mut request, &config).expect("redact");
    assert_eq!(outcome.redactions_applied, 0);
    assert_eq!(
        request.messages[0].content.as_deref(),
        Some(original.as_str())
    );
}
