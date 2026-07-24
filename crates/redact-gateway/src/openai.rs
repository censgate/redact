// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

/// OpenAI-compatible chat completion request (subset used by the gateway).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatCompletionRequest {
    pub model: String,
    pub messages: Vec<ChatMessage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    /// Pass-through fields (temperature, tools, etc.) preserved on forward.
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Chat message. Unknown fields (`tool_calls`, `tool_call_id`, `name`, …) are
/// preserved via `extra` so tool-use loops survive the round-trip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<MessageContent>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

impl ChatMessage {
    pub fn text(role: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: role.into(),
            content: Some(MessageContent::Text(content.into())),
            extra: HashMap::new(),
        }
    }
}

/// OpenAI `content` may be a string or an array of content parts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

impl MessageContent {
    /// Plain-text view when content is a single string (not multimodal parts).
    pub fn as_text(&self) -> Option<&str> {
        match self {
            Self::Text(text) => Some(text.as_str()),
            Self::Parts(_) => None,
        }
    }
}

/// One multimodal / typed content part. Unknown keys are preserved in `extra`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContentPart {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(flatten)]
    pub extra: HashMap<String, Value>,
}

/// Minimal OpenAI-compatible error body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: ErrorDetail,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorDetail {
    pub message: String,
    #[serde(rename = "type")]
    pub error_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl ErrorBody {
    pub fn new(message: impl Into<String>, error_type: impl Into<String>) -> Self {
        Self {
            error: ErrorDetail {
                message: message.into(),
                error_type: error_type.into(),
                code: None,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn chat_message_preserves_tool_fields() {
        let raw = json!({
            "role": "assistant",
            "content": null,
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "lookup", "arguments": "{}"}
            }]
        });
        let msg: ChatMessage = serde_json::from_value(raw).unwrap();
        let back = serde_json::to_value(&msg).unwrap();
        assert_eq!(back["tool_calls"][0]["id"], "call_1");
        assert!(back.get("content").is_none() || back["content"].is_null());
    }

    #[test]
    fn message_content_accepts_text_parts_array() {
        let raw = json!([{"type": "text", "text": "hello"}]);
        let content: MessageContent = serde_json::from_value(raw).unwrap();
        match content {
            MessageContent::Parts(parts) => {
                assert_eq!(parts.len(), 1);
                assert_eq!(parts[0].text.as_deref(), Some("hello"));
            }
            MessageContent::Text(_) => panic!("expected parts"),
        }
    }
}
