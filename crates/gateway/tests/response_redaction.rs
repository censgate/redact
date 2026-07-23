// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use gateway::redact::redact_chat_response_json;
use redact_core::{AnalyzerEngine, AnonymizationStrategy, AnonymizerConfig};
use serde_json::json;

#[test]
fn redact_chat_response_json_replaces_email_in_assistant_message() {
    let engine = AnalyzerEngine::new();
    let config = AnonymizerConfig {
        strategy: AnonymizationStrategy::Replace,
        ..Default::default()
    };

    let mut body = json!({
        "id": "chatcmpl-1",
        "object": "chat.completion",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": "You can reach me at leak@example.com"
            },
            "finish_reason": "stop"
        }]
    });

    let outcome = redact_chat_response_json(&engine, &mut body, &config).expect("redact");
    assert!(outcome.redactions_applied >= 1);

    let content = body["choices"][0]["message"]["content"].as_str().unwrap();
    assert!(
        !content.contains("leak@example.com"),
        "response must not leak email: {content}"
    );
    assert!(
        content.contains("[EMAIL_ADDRESS]"),
        "expected placeholder: {content}"
    );
}
