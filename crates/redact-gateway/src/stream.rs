// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Server-sent event handling for streaming chat completions.
//!
//! Two modes are available, selected by configuration:
//!
//! * `buffered` (default) consumes the whole upstream stream before emitting.
//!   Detection sees complete context, so no entity can hide in a token split,
//!   at the cost of time to first token.
//! * `incremental` forwards redacted text as it arrives while retaining a
//!   trailing window. It never emits inside a detected entity, so detection is
//!   reliable for entities shorter than that window.

use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// Fields extracted from an upstream chat-completion SSE body.
#[derive(Debug, Clone, Default)]
pub struct SseExtraction {
    /// Concatenated assistant text across every content delta.
    pub content: String,
    /// Model reported by the upstream chunks.
    pub model: Option<String>,
    /// Terminal finish reason, when the stream reported one.
    pub finish_reason: Option<String>,
    /// Creation timestamp reported by the upstream chunks.
    pub created: Option<u64>,
    /// Completion id reported by the upstream chunks.
    pub id: Option<String>,
    /// Number of data frames consumed, excluding the terminator.
    pub chunks: usize,
    /// Chunks that carry no assistant text and are replayed verbatim, such as
    /// tool-call deltas, usage reports and choices beyond the first.
    pub passthrough: Vec<Value>,
}

/// Parse upstream SSE into content plus the metadata needed to rebuild a stream.
pub fn extract_sse(sse: &str) -> SseExtraction {
    let mut out = SseExtraction::default();
    for data in iter_sse_data_payloads(sse) {
        if data == "[DONE]" {
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        out.chunks += 1;

        if out.model.is_none() {
            if let Some(model) = value.get("model").and_then(Value::as_str) {
                out.model = Some(model.to_string());
            }
        }
        if out.created.is_none() {
            if let Some(created) = value.get("created").and_then(Value::as_u64) {
                out.created = Some(created);
            }
        }
        if out.id.is_none() {
            if let Some(id) = value.get("id").and_then(Value::as_str) {
                out.id = Some(id.to_string());
            }
        }
        if let Some(piece) = value
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
        {
            out.content.push_str(piece);
        }
        if let Some(reason) = value
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
        {
            out.finish_reason = Some(reason.to_string());
        }
        if carries_passthrough(&value) {
            out.passthrough.push(value);
        }
    }
    out
}

/// Whether a chunk carries information the rebuilt stream must not drop.
fn carries_passthrough(chunk: &Value) -> bool {
    if chunk.get("usage").map(|u| !u.is_null()).unwrap_or(false) {
        return true;
    }
    let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
        return false;
    };
    choices.iter().any(|choice| {
        let index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
        let has_tool_calls = choice
            .pointer("/delta/tool_calls")
            .map(|v| !v.is_null())
            .unwrap_or(false);
        index > 0 || has_tool_calls
    })
}

/// Concatenate `choices[0].delta.content` fragments from an upstream SSE body.
pub fn extract_sse_text_content(sse: &str) -> String {
    extract_sse(sse).content
}

/// Best-effort model id from the first JSON chunk, with a caller fallback.
pub fn extract_sse_model(sse: &str, fallback: &str) -> String {
    extract_sse(sse)
        .model
        .unwrap_or_else(|| fallback.to_string())
}

/// Build an OpenAI-compatible SSE stream for redacted assistant content.
pub fn build_redacted_sse(
    id: &str,
    model: &str,
    redacted_content: &str,
    finish_reason: Option<&str>,
    created: Option<u64>,
) -> String {
    build_redacted_sse_with_passthrough(id, model, redacted_content, finish_reason, created, &[])
}

/// Build a redacted SSE stream, replaying chunks that carry non-text payloads.
pub fn build_redacted_sse_with_passthrough(
    id: &str,
    model: &str,
    redacted_content: &str,
    finish_reason: Option<&str>,
    created: Option<u64>,
    passthrough: &[Value],
) -> String {
    let mut out = String::new();
    let created = created.unwrap_or_else(unix_now);
    let finish_reason = finish_reason.unwrap_or("stop");

    push_sse_data(&mut out, &role_chunk(id, model, created).to_string());

    if !redacted_content.is_empty() {
        push_sse_data(
            &mut out,
            &content_chunk(id, model, created, redacted_content).to_string(),
        );
    }

    for chunk in passthrough {
        push_sse_data(&mut out, &chunk.to_string());
    }

    push_sse_data(
        &mut out,
        &stop_chunk(id, model, created, finish_reason).to_string(),
    );
    push_sse_data(&mut out, "[DONE]");
    out
}

/// First chunk of a rebuilt stream, announcing the assistant role.
pub fn role_chunk(id: &str, model: &str, created: u64) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {"role": "assistant"}, "finish_reason": null}]
    })
}

/// A content delta of a rebuilt stream.
pub fn content_chunk(id: &str, model: &str, created: u64, content: &str) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {"content": content}, "finish_reason": null}]
    })
}

/// Terminal chunk of a rebuilt stream.
pub fn stop_chunk(id: &str, model: &str, created: u64, finish_reason: &str) -> Value {
    json!({
        "id": id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [{"index": 0, "delta": {}, "finish_reason": finish_reason}]
    })
}

/// Frame a JSON payload as one SSE `data:` event.
pub fn sse_frame(payload: &str) -> String {
    format!("data: {payload}\n\n")
}

/// Incremental SSE frame parser.
///
/// Upstream bytes arrive without regard for event boundaries, so bytes are
/// buffered until a complete `\n\n` (or `\r\n\r\n`) terminated frame is available.
#[derive(Debug, Default)]
pub struct SseParser {
    buffer: String,
}

impl SseParser {
    /// Create an empty parser.
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed raw bytes and return every complete data payload they completed.
    pub fn push(&mut self, bytes: &str) -> Vec<String> {
        self.buffer.push_str(bytes);
        let mut payloads = Vec::new();

        while let Some((end, skip)) = self
            .buffer
            .find("\r\n\r\n")
            .map(|index| (index, 4))
            .or_else(|| self.buffer.find("\n\n").map(|index| (index, 2)))
        {
            let frame: String = self.buffer.drain(..end + skip).collect();
            if let Some(payload) = frame_payload(&frame) {
                payloads.push(payload);
            }
        }
        payloads
    }

    /// Return any trailing frame that never received its terminator.
    pub fn flush(&mut self) -> Option<String> {
        if self.buffer.trim().is_empty() {
            self.buffer.clear();
            return None;
        }
        let frame = std::mem::take(&mut self.buffer);
        frame_payload(&frame)
    }
}

fn frame_payload(frame: &str) -> Option<String> {
    let mut payload = String::new();
    for line in frame.split('\n') {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("data:") {
            if !payload.is_empty() {
                payload.push('\n');
            }
            payload.push_str(rest.trim_start());
        }
    }
    if payload.is_empty() {
        None
    } else {
        Some(payload)
    }
}

/// Accumulates streamed text and releases the part that is safe to emit.
///
/// The retained window is what makes incremental redaction sound: a value that
/// is still being streamed always sits at the end of the buffer, so keeping the
/// last `holdback` bytes back means it is re-examined with its full context
/// before anything is released.
#[derive(Debug)]
pub struct HoldbackBuffer {
    holdback: usize,
    pending: String,
}

impl HoldbackBuffer {
    /// Create a buffer that retains `holdback` bytes.
    pub fn new(holdback: usize) -> Self {
        Self {
            holdback: holdback.max(1),
            pending: String::new(),
        }
    }

    /// Append newly streamed text.
    pub fn push(&mut self, text: &str) {
        self.pending.push_str(text);
    }

    /// Whether enough text has accumulated to consider releasing some.
    pub fn is_ready(&self) -> bool {
        self.pending.len() > self.holdback
    }

    /// Bytes retained so far.
    pub fn len(&self) -> usize {
        self.pending.len()
    }

    /// Whether nothing is buffered.
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Borrow the retained text.
    pub fn pending(&self) -> &str {
        &self.pending
    }

    /// Replace the retained text, typically with the tail a redactor kept back.
    pub fn set_pending(&mut self, pending: String) {
        self.pending = pending;
    }

    /// Take everything retained, leaving the buffer empty.
    pub fn take(&mut self) -> String {
        std::mem::take(&mut self.pending)
    }

    /// Size of the retained window.
    pub fn holdback(&self) -> usize {
        self.holdback
    }
}

/// State carried across polls of an incremental stream.
struct IncrementalState {
    upstream: crate::proxy::UpstreamByteStream,
    parser: SseParser,
    holdback: HoldbackBuffer,
    engine: std::sync::Arc<redact_core::AnalyzerEngine>,
    profile: std::sync::Arc<crate::policy::Profile>,
    lookup: std::collections::HashMap<String, String>,
    outcome: std::sync::Arc<std::sync::Mutex<crate::redact::RedactionOutcome>>,
    id: String,
    model: String,
    created: u64,
    finish_reason: Option<String>,
    ready: std::collections::VecDeque<String>,
    role_sent: bool,
    upstream_done: bool,
    completed: bool,
}

impl IncrementalState {
    /// Handle one decoded upstream frame.
    fn absorb(&mut self, payload: &str) {
        if payload == "[DONE]" {
            self.upstream_done = true;
            return;
        }
        let Ok(chunk) = serde_json::from_str::<Value>(payload) else {
            return;
        };

        if let Some(model) = chunk.get("model").and_then(Value::as_str) {
            self.model = model.to_string();
        }
        if let Some(created) = chunk.get("created").and_then(Value::as_u64) {
            self.created = created;
        }
        if let Some(reason) = chunk
            .pointer("/choices/0/finish_reason")
            .and_then(Value::as_str)
        {
            self.finish_reason = Some(reason.to_string());
        }
        if let Some(text) = chunk
            .pointer("/choices/0/delta/content")
            .and_then(Value::as_str)
        {
            self.holdback.push(text);
        }
        if carries_passthrough(&chunk) {
            // Tool calls, usage and extra choices are replayed untouched after
            // the text released so far, preserving client-side reassembly.
            self.flush_ready();
            self.ready.push_back(sse_frame(&chunk.to_string()));
        }
    }

    /// Release whatever text is currently safe to emit.
    fn flush_ready(&mut self) {
        if !self.holdback.is_ready() {
            return;
        }
        let pending = self.holdback.take();
        let mut ctx = crate::redact::RedactionContext::new(&self.engine, &self.profile);
        match ctx.redact_prefix(&pending, self.holdback.holdback()) {
            Ok((head, tail)) => {
                self.holdback.set_pending(tail);
                self.record(ctx.finish());
                self.emit_text(&head);
            }
            Err(_) => {
                // Detection failed for this window: keep the text buffered so
                // the final pass can try again rather than emitting it raw.
                self.holdback.set_pending(pending);
            }
        }
    }

    /// Release everything still buffered at the end of the stream.
    fn flush_final(&mut self) {
        let pending = self.holdback.take();
        if pending.is_empty() {
            return;
        }
        let mut ctx = crate::redact::RedactionContext::new(&self.engine, &self.profile);
        match ctx.redact(&pending) {
            Ok(text) => {
                self.record(ctx.finish());
                self.emit_text(&text);
            }
            Err(_) => self.emit_text("[REDACTION_FAILED]"),
        }
    }

    fn emit_text(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let (restored, _) = crate::redact::token::restore_text(text, &self.lookup);
        if !self.role_sent {
            self.ready.push_back(sse_frame(
                &role_chunk(&self.id, &self.model, self.created).to_string(),
            ));
            self.role_sent = true;
        }
        self.ready.push_back(sse_frame(
            &content_chunk(&self.id, &self.model, self.created, &restored).to_string(),
        ));
    }

    fn record(&self, outcome: crate::redact::RedactionOutcome) {
        if let Ok(mut total) = self.outcome.lock() {
            total.merge(&outcome);
        }
    }

    fn finish(&mut self) {
        self.flush_final();
        if !self.role_sent {
            self.ready.push_back(sse_frame(
                &role_chunk(&self.id, &self.model, self.created).to_string(),
            ));
            self.role_sent = true;
        }
        let reason = self.finish_reason.clone().unwrap_or_else(|| "stop".into());
        self.ready.push_back(sse_frame(
            &stop_chunk(&self.id, &self.model, self.created, &reason).to_string(),
        ));
        self.ready.push_back(sse_frame("[DONE]"));
        self.completed = true;
    }
}

/// Redact an upstream byte stream as it arrives.
///
/// Returns a body that emits OpenAI-compatible SSE frames plus a handle to the
/// redaction totals, which are only complete once the stream has finished.
#[allow(clippy::too_many_arguments)]
pub fn incremental_response(
    upstream: crate::proxy::UpstreamByteStream,
    engine: std::sync::Arc<redact_core::AnalyzerEngine>,
    profile: std::sync::Arc<crate::policy::Profile>,
    lookup: std::collections::HashMap<String, String>,
    holdback_bytes: usize,
    id: String,
    model: String,
) -> (
    axum::body::Body,
    std::sync::Arc<std::sync::Mutex<crate::redact::RedactionOutcome>>,
) {
    use futures_util::StreamExt;

    let outcome = std::sync::Arc::new(std::sync::Mutex::new(
        crate::redact::RedactionOutcome::default(),
    ));
    let state = IncrementalState {
        upstream,
        parser: SseParser::new(),
        holdback: HoldbackBuffer::new(holdback_bytes),
        engine,
        profile,
        lookup,
        outcome: outcome.clone(),
        id,
        model,
        created: unix_now(),
        finish_reason: None,
        ready: std::collections::VecDeque::new(),
        role_sent: false,
        upstream_done: false,
        completed: false,
    };

    let stream = futures_util::stream::unfold(state, |mut state| async move {
        loop {
            if let Some(frame) = state.ready.pop_front() {
                return Some((Ok::<_, std::convert::Infallible>(frame), state));
            }
            if state.completed {
                return None;
            }
            if state.upstream_done {
                state.finish();
                continue;
            }

            match state.upstream.next().await {
                Some(Ok(bytes)) => {
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    for payload in state.parser.push(&text) {
                        state.absorb(&payload);
                    }
                    state.flush_ready();
                }
                Some(Err(_)) | None => {
                    if let Some(payload) = state.parser.flush() {
                        state.absorb(&payload);
                    }
                    state.finish();
                }
            }
        }
    });

    (axum::body::Body::from_stream(stream), outcome)
}

/// Iterate `data:` payloads of a complete SSE body.
fn iter_sse_data_payloads(sse: &str) -> Vec<String> {
    let mut parser = SseParser::new();
    let mut payloads = parser.push(sse);
    if let Some(trailing) = parser.flush() {
        payloads.push(trailing);
    }
    payloads
}

fn push_sse_data(out: &mut String, payload: &str) {
    out.push_str(&sse_frame(payload));
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_is_concatenated_across_deltas() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"leak@exa\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"mple.com\"}}]}\n\n",
            "data: [DONE]\n\n",
        );
        let extracted = extract_sse(sse);
        assert_eq!(extracted.content, "leak@example.com");
        assert_eq!(extracted.chunks, 2);
    }

    #[test]
    fn metadata_is_captured_from_any_chunk() {
        let sse = concat!(
            "data: {\"id\":\"c1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"created\":42,\"model\":\"m\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let extracted = extract_sse(sse);
        assert_eq!(extracted.id.as_deref(), Some("c1"));
        assert_eq!(extracted.created, Some(42));
        assert_eq!(extracted.model.as_deref(), Some("m"));
        assert_eq!(extracted.finish_reason.as_deref(), Some("stop"));
    }

    #[test]
    fn crlf_framing_is_understood() {
        let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"a\"}}]}\r\n\r\ndata: [DONE]\r\n\r\n";
        assert_eq!(extract_sse(sse).content, "a");
    }

    #[test]
    fn tool_call_and_usage_chunks_are_kept_for_replay() {
        let sse = concat!(
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\n",
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"f\"}}]}}]}\n\n",
            "data: {\"choices\":[],\"usage\":{\"total_tokens\":7}}\n\n",
            "data: [DONE]\n\n",
        );
        let extracted = extract_sse(sse);
        assert_eq!(extracted.passthrough.len(), 2);
        assert_eq!(extracted.content, "hi");
    }

    #[test]
    fn rebuilt_stream_replays_passthrough_chunks() {
        let passthrough = vec![json!({"choices": [], "usage": {"total_tokens": 7}})];
        let sse = build_redacted_sse_with_passthrough(
            "id",
            "model",
            "text",
            Some("stop"),
            Some(1),
            &passthrough,
        );
        assert!(sse.contains("\"total_tokens\":7"));
        assert!(sse.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn parser_handles_frames_split_across_reads() {
        let mut parser = SseParser::new();
        assert!(parser.push("data: {\"a\":").is_empty());
        let payloads = parser.push("1}\n\ndata: [DONE]\n\n");
        assert_eq!(
            payloads,
            vec!["{\"a\":1}".to_string(), "[DONE]".to_string()]
        );
    }

    #[test]
    fn parser_joins_multi_line_data_payloads() {
        let mut parser = SseParser::new();
        let payloads = parser.push("data: line1\ndata: line2\n\n");
        assert_eq!(payloads, vec!["line1\nline2".to_string()]);
    }

    #[test]
    fn parser_ignores_comments_and_empty_frames() {
        let mut parser = SseParser::new();
        let payloads = parser.push(": keep-alive\n\ndata: {}\n\n");
        assert_eq!(payloads, vec!["{}".to_string()]);
    }

    #[test]
    fn parser_flushes_an_unterminated_trailing_frame() {
        let mut parser = SseParser::new();
        assert!(parser.push("data: {\"a\":1}").is_empty());
        assert_eq!(parser.flush(), Some("{\"a\":1}".to_string()));
        assert_eq!(parser.flush(), None);
    }

    #[test]
    fn holdback_reports_readiness_by_size() {
        let mut buffer = HoldbackBuffer::new(4);
        buffer.push("abc");
        assert!(!buffer.is_ready());
        buffer.push("de");
        assert!(buffer.is_ready());
        assert_eq!(buffer.take(), "abcde");
        assert!(buffer.is_empty());
    }
}
