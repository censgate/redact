// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use redact_core::{AnalyzerEngine, AnonymizationStrategy, AnonymizerConfig};
use redact_gateway::openai::{ChatCompletionRequest, ChatMessage, MessageContent};
use redact_gateway::redact::{redact_chat_request, RedactionOutcome};
use serde_json::json;

#[test]
fn redact_chat_request_replaces_email_in_user_message() {
    let engine = AnalyzerEngine::new();
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };

    let mut request = ChatCompletionRequest {
        model: "gpt-4o-mini".to_string(),
        messages: vec![ChatMessage::text(
            "user",
            "Email me at alice@example.com please",
        )],
        stream: None,
        extra: Default::default(),
    };

    let outcome = redact_chat_request(&engine, &mut request, &config).expect("redact");

    assert!(
        matches!(outcome, RedactionOutcome { redactions_applied, .. } if redactions_applied >= 1)
    );
    let content = request.messages[0]
        .content
        .as_ref()
        .and_then(MessageContent::as_text)
        .unwrap();
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
        messages: vec![ChatMessage::text("user", original.clone())],
        stream: None,
        extra: Default::default(),
    };

    let outcome = redact_chat_request(&engine, &mut request, &config).expect("redact");
    assert_eq!(outcome.redactions_applied, 0);
    assert_eq!(
        request.messages[0]
            .content
            .as_ref()
            .and_then(MessageContent::as_text),
        Some(original.as_str())
    );
}

#[test]
fn redact_chat_request_redacts_text_content_parts() {
    let engine = AnalyzerEngine::new();
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };

    let mut request: ChatCompletionRequest = serde_json::from_value(json!({
        "model": "gpt-4o-mini",
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": "Email alice@example.com"},
                {"type": "image_url", "image_url": {"url": "https://example.com/a.png"}}
            ]
        }]
    }))
    .unwrap();

    let outcome = redact_chat_request(&engine, &mut request, &config).expect("redact");
    assert!(outcome.redactions_applied >= 1);

    let MessageContent::Parts(parts) = request.messages[0].content.as_ref().unwrap() else {
        panic!("expected parts content");
    };
    let text = parts[0].text.as_deref().unwrap();
    assert!(
        !text.contains("alice@example.com") && text.contains("[EMAIL_ADDRESS]"),
        "expected redacted text part, got {text}"
    );
    assert_eq!(parts[1].kind, "image_url");
}

#[test]
fn chat_message_round_trip_keeps_tool_call_id() {
    let mut request: ChatCompletionRequest = serde_json::from_value(json!({
        "model": "gpt-4o-mini",
        "messages": [
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "lookup", "arguments": "{}"}
                }]
            },
            {
                "role": "tool",
                "tool_call_id": "call_1",
                "content": "ok"
            }
        ]
    }))
    .unwrap();

    // Ensure extra fields survive serialize after a no-op redaction pass.
    let engine = AnalyzerEngine::new();
    let config = AnonymizerConfig::default();
    redact_chat_request(&engine, &mut request, &config).unwrap();

    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value["messages"][0]["tool_calls"][0]["id"], "call_1");
    assert_eq!(value["messages"][1]["tool_call_id"], "call_1");
    assert_eq!(value["messages"][1]["content"], "ok");
}
