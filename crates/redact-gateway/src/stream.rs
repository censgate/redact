// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! SSE helpers for OpenAI-compatible streaming chat completions.
//!
//! Upstream streams are fully consumed so response content can be redacted with
//! complete-context detection (PII often spans token deltas). The gateway then
//! re-emits a standards-shaped `text/event-stream` with redacted content.

use serde_json::{json, Value};

/// Concatenate `choices[0].delta.content` fragments from an upstream SSE body.
pub fn extract_sse_text_content(sse: &str) -> String {
    let mut content = String::new();
    for data in iter_sse_data_payloads(sse) {
        if data == "[DONE]" {
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(data) else {
            continue;
        };
        if let Some(piece) = value
            .pointer("/choices/0/delta/content")
            .and_then(|v| v.as_str())
        {
            content.push_str(piece);
        }
    }
    content
}

/// Best-effort model id from the first JSON chunk (fallback provided by caller).
pub fn extract_sse_model(sse: &str, fallback: &str) -> String {
    for data in iter_sse_data_payloads(sse) {
        if data == "[DONE]" {
            break;
        }
        if let Ok(value) = serde_json::from_str::<Value>(data) {
            if let Some(model) = value.get("model").and_then(|v| v.as_str()) {
                return model.to_string();
            }
        }
    }
    fallback.to_string()
}

/// Build a minimal OpenAI-compatible SSE stream for redacted assistant content.
pub fn build_redacted_sse(id: &str, model: &str, redacted_content: &str) -> String {
    let mut out = String::new();

    let role_chunk = json!({
        "id": id,
        "object": "chat.completion.chunk",
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {"role": "assistant"},
            "finish_reason": null
        }]
    });
    push_sse_data(&mut out, &role_chunk.to_string());

    // Emit content as a single delta for correctness after full-buffer redaction.
    if !redacted_content.is_empty() {
        let content_chunk = json!({
            "id": id,
            "object": "chat.completion.chunk",
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
        "model": model,
        "choices": [{
            "index": 0,
            "delta": {},
            "finish_reason": "stop"
        }]
    });
    push_sse_data(&mut out, &stop_chunk.to_string());
    push_sse_data(&mut out, "[DONE]");
    out
}

fn push_sse_data(out: &mut String, data: &str) {
    out.push_str("data: ");
    out.push_str(data);
    out.push_str("\n\n");
}

fn iter_sse_data_payloads(sse: &str) -> impl Iterator<Item = &str> {
    sse.split("\n\n").filter_map(|frame| {
        let mut data_lines = Vec::new();
        for line in frame.lines() {
            if let Some(rest) = line.strip_prefix("data:") {
                data_lines.push(rest.trim_start());
            }
        }
        if data_lines.is_empty() {
            None
        } else {
            // OpenAI uses a single data line per event; join for robustness.
            Some(data_lines[0]).filter(|s| !s.is_empty())
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
    fn build_redacted_sse_includes_done() {
        let out = build_redacted_sse("chatcmpl-x", "m", "hi [EMAIL_ADDRESS]");
        assert!(out.contains("hi [EMAIL_ADDRESS]"));
        assert!(out.contains("data: [DONE]"));
        assert!(
            out.contains("\"finish_reason\":\"stop\"")
                || out.contains("\"finish_reason\": \"stop\"")
        );
    }
}
