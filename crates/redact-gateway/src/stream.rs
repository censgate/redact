// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! SSE helpers for OpenAI-compatible streaming chat completions.
//!
//! Upstream streams are fully consumed so response content can be redacted with
//! complete-context detection (PII often spans token deltas). The gateway then
//! re-emits a standards-shaped `text/event-stream` with redacted content.

use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Fields extracted from an upstream chat-completion SSE body.
#[derive(Debug, Clone, Default)]
pub struct SseExtraction {
    pub content: String,
    pub model: Option<String>,
    pub finish_reason: Option<String>,
    pub created: Option<u64>,
}

/// Parse upstream SSE into content + metadata used to rebuild a redacted stream.
pub fn extract_sse(sse: &str) -> SseExtraction {
    let mut out = SseExtraction::default();
    for data in iter_sse_data_payloads(sse) {
        if data == "[DONE]" {
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        if out.model.is_none() {
            if let Some(model) = value.get("model").and_then(|v| v.as_str()) {
                out.model = Some(model.to_string());
            }
        }
        if out.created.is_none() {
            if let Some(created) = value.get("created").and_then(|v| v.as_u64()) {
                out.created = Some(created);
            }
        }
        if let Some(piece) = value
            .pointer("/choices/0/delta/content")
            .and_then(|v| v.as_str())
        {
            out.content.push_str(piece);
        }
        if let Some(reason) = value
            .pointer("/choices/0/finish_reason")
            .and_then(|v| v.as_str())
        {
            out.finish_reason = Some(reason.to_string());
        }
    }
    out
}

/// Concatenate `choices[0].delta.content` fragments from an upstream SSE body.
pub fn extract_sse_text_content(sse: &str) -> String {
    extract_sse(sse).content
}

/// Best-effort model id from the first JSON chunk (fallback provided by caller).
pub fn extract_sse_model(sse: &str, fallback: &str) -> String {
    extract_sse(sse)
        .model
        .unwrap_or_else(|| fallback.to_string())
}

/// Build a minimal OpenAI-compatible SSE stream for redacted assistant content.
pub fn build_redacted_sse(
    id: &str,
    model: &str,
    redacted_content: &str,
    finish_reason: Option<&str>,
    created: Option<u64>,
) -> String {
    let mut out = String::new();
    let created = created.unwrap_or_else(unix_now);
    let finish_reason = finish_reason.unwrap_or("stop");

    let role_chunk = json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {"role": "assistant"},
            "finish_reason": null
        }]
    });
    push_sse_data(&mut out, &role_chunk.to_string());

    if !redacted_content.is_empty() {
        let content_chunk = json!({
            "id": id,
            "object": "chat.completion.chunk",
            "created": created,
            "model": model,
            "choices": [{
                "index": 0,
                "delta": {"content": redacted_content},
                "finish_reason": null
            }]
        });
        push_sse_data(&mut out, &content_chunk.to_string());
    }

    let stop_chunk = json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {},
            "finish_reason": finish_reason
        }]
    });
    push_sse_data(&mut out, &stop_chunk.to_string());
    push_sse_data(&mut out, "[DONE]");
    out
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn push_sse_data(out: &mut String, data: &str) {
    out.push_str("data: ");
    out.push_str(data);
    out.push_str("\n\n");
}

fn iter_sse_data_payloads(sse: &str) -> impl Iterator<Item = String> {
    let normalized = sse.replace("\r\n", "\n");
    let frames: Vec<String> = normalized.split("\n\n").map(str::to_string).collect();
    frames.into_iter().filter_map(|frame| {
        let mut data_lines = Vec::new();
        for line in frame.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start());
            }
        }
        if data_lines.is_empty() {
            None
        } else {
            // SSE: multiple data: lines in one event are joined with \n.
            let joined = data_lines.join("\n");
            if joined.is_empty() {
                None
            } else {
                Some(joined)
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_split_email_across_deltas() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"a@\"}}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"b.com\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        assert_eq!(extract_sse_text_content(sse), "a@b.com");
    }

    #[test]
    fn preserves_finish_reason_model_and_created() {
        let sse = concat!(
            "data: {\"created\":42,\"model\":\"m\",\"choices\":[{\"index\":0,",
            "\"delta\":{\"content\":\"x\"},\"finish_reason\":null}]}\n\n",
            "data: {\"created\":42,\"model\":\"m\",\"choices\":[{\"index\":0,",
            "\"delta\":{},\"finish_reason\":\"length\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let extracted = extract_sse(sse);
        assert_eq!(extracted.content, "x");
        assert_eq!(extracted.finish_reason.as_deref(), Some("length"));
        assert_eq!(extracted.created, Some(42));
        assert_eq!(extracted.model.as_deref(), Some("m"));
    }

    #[test]
    fn joins_multiple_data_lines_and_accepts_crlf() {
        let sse = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"ab\"},\n",
            "data: \"finish_reason\":null}]}\r\n\r\n",
        );
        assert_eq!(extract_sse_text_content(sse), "ab");
    }

    #[test]
    fn build_redacted_sse_preserves_finish_reason_and_created() {
        let out = build_redacted_sse(
            "chatcmpl-x",
            "m",
            "hi [EMAIL_ADDRESS]",
            Some("length"),
            Some(99),
        );
        assert!(out.contains("hi [EMAIL_ADDRESS]"));
        assert!(out.contains("data: [DONE]"));
        assert!(out.contains("\"finish_reason\":\"length\""));
        assert!(out.contains("\"created\":99"));
    }
}
