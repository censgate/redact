// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Server-sent event handling for streaming chat completions.
//!
//! Two modes are available, selected by configuration:
//!
//! * `buffered` (default) consumes the whole upstream stream before emitting.
//!   Detection sees complete context, so no entity can hide in a token split,
//!   at the cost of time to first token. Chunks are rewritten in place so
//!   provider fields survive; see [`transform_buffered_sse`].
//! * `incremental` forwards redacted text as it arrives while retaining a
//!   trailing window. It never emits inside a detected entity, so detection is
//!   reliable for entities shorter than that window.

use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Result of rewriting a buffered upstream SSE body in place.
#[derive(Debug, Clone)]
pub struct BufferedSseTransform {
    /// Rewritten SSE body, including the trailing `[DONE]` terminator when present.
    pub sse: String,
    /// Number of JSON data frames consumed, excluding `[DONE]`.
    pub chunks: usize,
}

/// Rewrite redacted text into an upstream SSE body without rebuilding it.
///
/// # Fidelity guarantee
///
/// Buffered mode preserves the upstream chunk **sequence** and every JSON field
/// on every chunk. The only values rewritten are:
///
/// - `choices[i].delta.content`
/// - `choices[i].delta.tool_calls[j].function.arguments`
///
/// Chunks that do not carry those fields (role announcements, `finish_reason`,
/// `usage`, `system_fingerprint`, `logprobs`, `service_tier`, provider
/// extensions, and any other unknown fields) are emitted with all fields
/// intact. Re-serialization via `serde_json` may reorder object keys; field
/// **presence and values** are what this guarantee covers.
///
/// # Coalescing trade-off
///
/// Detection must see complete values, so content and tool-call argument
/// fragments are concatenated per stream before redaction. The redacted string
/// is placed on the **first** chunk that carried text for that stream; later
/// fragments become empty strings. Clients therefore receive fewer content
/// deltas than the provider sent. That is inherent to buffered mode (which
/// already waits for the whole upstream body) and is strictly preferable to
/// discarding unknown fields by rebuilding the stream from scratch.
pub fn transform_buffered_sse<E>(
    sse: &str,
    mut redact: impl FnMut(&str) -> Result<String, E>,
) -> Result<BufferedSseTransform, E> {
    let mut chunks: Vec<Value> = Vec::new();
    let mut saw_done = false;

    for data in iter_sse_data_payloads(sse) {
        if data == "[DONE]" {
            saw_done = true;
            break;
        }
        let Ok(value) = serde_json::from_str::<Value>(&data) else {
            continue;
        };
        chunks.push(value);
    }

    let mut content: BTreeMap<u64, String> = BTreeMap::new();
    let mut content_first: BTreeMap<u64, (usize, usize)> = BTreeMap::new();
    let mut arguments: BTreeMap<(u64, u64), String> = BTreeMap::new();
    let mut arguments_first: BTreeMap<(u64, u64), (usize, usize, usize)> = BTreeMap::new();

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let Some(choices) = chunk.get("choices").and_then(Value::as_array) else {
            continue;
        };
        for (choice_arr_idx, choice) in choices.iter().enumerate() {
            let choice_index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
            if let Some(piece) = choice.pointer("/delta/content").and_then(Value::as_str) {
                if !piece.is_empty() {
                    content_first
                        .entry(choice_index)
                        .or_insert((chunk_idx, choice_arr_idx));
                    content.entry(choice_index).or_default().push_str(piece);
                }
            }
            let Some(tool_calls) = choice
                .pointer("/delta/tool_calls")
                .and_then(Value::as_array)
            else {
                continue;
            };
            for (tool_arr_idx, call) in tool_calls.iter().enumerate() {
                let tool_index = call.get("index").and_then(Value::as_u64).unwrap_or(0);
                let Some(piece) = call.pointer("/function/arguments").and_then(Value::as_str)
                else {
                    continue;
                };
                if piece.is_empty() {
                    continue;
                }
                let key = (choice_index, tool_index);
                arguments_first
                    .entry(key)
                    .or_insert((chunk_idx, choice_arr_idx, tool_arr_idx));
                arguments.entry(key).or_default().push_str(piece);
            }
        }
    }

    let mut redacted_content = BTreeMap::new();
    for (choice_index, text) in content {
        redacted_content.insert(choice_index, redact(&text)?);
    }
    let mut redacted_arguments = BTreeMap::new();
    for (key, text) in arguments {
        redacted_arguments.insert(key, redact(&text)?);
    }

    apply_coalesced_content(&mut chunks, &content_first, &redacted_content);
    apply_coalesced_arguments(&mut chunks, &arguments_first, &redacted_arguments);
    // Raw token logprobs can reconstruct redacted content; drop them.
    strip_logprobs(&mut chunks);

    let mut out = String::new();
    for chunk in &chunks {
        push_sse_data(&mut out, &chunk.to_string());
    }
    if saw_done {
        push_sse_data(&mut out, "[DONE]");
    }

    Ok(BufferedSseTransform {
        sse: out,
        chunks: chunks.len(),
    })
}

fn strip_logprobs(chunks: &mut [Value]) {
    for chunk in chunks.iter_mut() {
        let Some(choices) = chunk.get_mut("choices").and_then(Value::as_array_mut) else {
            continue;
        };
        for choice in choices.iter_mut() {
            if let Some(logprobs) = choice.get_mut("logprobs") {
                *logprobs = Value::Null;
            }
            if let Some(delta) = choice.get_mut("delta") {
                if let Some(logprobs) = delta.get_mut("logprobs") {
                    *logprobs = Value::Null;
                }
            }
        }
    }
}

fn apply_coalesced_content(
    chunks: &mut [Value],
    first: &BTreeMap<u64, (usize, usize)>,
    redacted: &BTreeMap<u64, String>,
) {
    for (choice_index, text) in redacted {
        let Some(&(first_chunk, first_choice_arr)) = first.get(choice_index) else {
            continue;
        };
        for (chunk_idx, chunk) in chunks.iter_mut().enumerate() {
            let Some(choices) = chunk.get_mut("choices").and_then(Value::as_array_mut) else {
                continue;
            };
            for (choice_arr_idx, choice) in choices.iter_mut().enumerate() {
                let idx = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
                if idx != *choice_index {
                    continue;
                }
                let Some(content) = choice.pointer_mut("/delta/content") else {
                    continue;
                };
                if !content.is_string() {
                    continue;
                }
                if chunk_idx == first_chunk && choice_arr_idx == first_choice_arr {
                    *content = Value::String(text.clone());
                } else if content.as_str().is_some_and(|s| !s.is_empty()) {
                    *content = Value::String(String::new());
                }
            }
        }
    }
}

fn apply_coalesced_arguments(
    chunks: &mut [Value],
    first: &BTreeMap<(u64, u64), (usize, usize, usize)>,
    redacted: &BTreeMap<(u64, u64), String>,
) {
    for (key, text) in redacted {
        let Some(&(first_chunk, first_choice_arr, first_tool_arr)) = first.get(key) else {
            continue;
        };
        let (choice_index, tool_index) = *key;
        for (chunk_idx, chunk) in chunks.iter_mut().enumerate() {
            let Some(choices) = chunk.get_mut("choices").and_then(Value::as_array_mut) else {
                continue;
            };
            for (choice_arr_idx, choice) in choices.iter_mut().enumerate() {
                let idx = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
                if idx != choice_index {
                    continue;
                }
                let Some(tool_calls) = choice
                    .pointer_mut("/delta/tool_calls")
                    .and_then(Value::as_array_mut)
                else {
                    continue;
                };
                for (tool_arr_idx, call) in tool_calls.iter_mut().enumerate() {
                    let tc_index = call.get("index").and_then(Value::as_u64).unwrap_or(0);
                    if tc_index != tool_index {
                        continue;
                    }
                    let Some(arguments) = call.pointer_mut("/function/arguments") else {
                        continue;
                    };
                    if !arguments.is_string() {
                        continue;
                    }
                    if chunk_idx == first_chunk
                        && choice_arr_idx == first_choice_arr
                        && tool_arr_idx == first_tool_arr
                    {
                        *arguments = Value::String(text.clone());
                    } else if arguments.as_str().is_some_and(|s| !s.is_empty()) {
                        *arguments = Value::String(String::new());
                    }
                }
            }
        }
    }
}

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
    body: crate::proxy::ProviderByteStream,
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
    provider_finished: bool,
    completed: bool,
}

impl IncrementalState {
    /// Handle one decoded upstream frame.
    fn absorb(&mut self, payload: &str) {
        if payload == "[DONE]" {
            self.provider_finished = true;
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
        let mut ctx = crate::redact::RedactionContext::for_response(&self.engine, &self.profile);
        match ctx.redact_prefix(&pending, self.holdback.holdback()) {
            Ok((head, tail)) => {
                // A token placeholder split across two releases could never be
                // restored, so an unclosed bracket goes back into the buffer.
                let (head, carried) = split_trailing_open_bracket(&head, self.holdback.holdback());
                self.holdback.set_pending(format!("{carried}{tail}"));
                self.record(ctx.finish());
                self.emit_text(head);
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
        let mut ctx = crate::redact::RedactionContext::for_response(&self.engine, &self.profile);
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

/// Split off a trailing unclosed bracket group so it can be re-buffered.
///
/// Returns the text that is safe to emit and the fragment to carry forward.
/// A fragment longer than `limit` is emitted anyway: a stray `[` in prose must
/// not stall the stream indefinitely.
fn split_trailing_open_bracket(text: &str, limit: usize) -> (&str, &str) {
    let Some(open) = text.rfind('[') else {
        return (text, "");
    };
    if text[open..].contains(']') {
        return (text, "");
    }
    if text.len() - open > limit {
        return (text, "");
    }
    text.split_at(open)
}

/// Redact an upstream byte stream as it arrives.
///
/// Returns a body that emits OpenAI-compatible SSE frames plus a handle to the
/// redaction totals, which are only complete once the stream has finished.
#[allow(clippy::too_many_arguments)]
pub fn incremental_response(
    body: crate::proxy::ProviderByteStream,
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
        body,
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
        provider_finished: false,
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
            if state.provider_finished {
                state.finish();
                continue;
            }

            match state.body.next().await {
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
    fn buffered_transform_redacts_every_choice_and_preserves_fields() {
        let sse = concat!(
            r#"data: {"id":"c","system_fingerprint":"fp","choices":[{"index":0,"delta":{"content":"a@"}},{"index":1,"delta":{"content":"b@"}}]}"#,
            "\n\n",
            r#"data: {"id":"c","choices":[{"index":0,"delta":{"content":"x.com"}},{"index":1,"delta":{"content":"y.com"}}]}"#,
            "\n\n",
            "data: [DONE]\n\n",
        );
        let transformed =
            transform_buffered_sse(sse, |text| Ok::<_, ()>(text.replace('@', "[at]"))).unwrap();
        assert!(transformed.sse.contains("\"system_fingerprint\":\"fp\""));
        assert!(transformed.sse.contains("a[at]x.com"));
        assert!(transformed.sse.contains("b[at]y.com"));
        assert!(!transformed.sse.contains("a@x.com"));
        assert!(transformed.sse.ends_with("data: [DONE]\n\n"));
    }

    #[test]
    fn buffered_transform_coalesces_tool_arguments_onto_first_fragment() {
        let sse = concat!(
            r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"e\":\""}}]}}]}"#,
            "\n\n",
            r#"data: {"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"a@b.com\"}"}}]}}]}"#,
            "\n\n",
            "data: [DONE]\n\n",
        );
        let transformed =
            transform_buffered_sse(sse, |text| Ok::<_, ()>(text.replace("a@b.com", "REDACTED")))
                .unwrap();
        let chunks: Vec<Value> = iter_sse_data_payloads(&transformed.sse)
            .into_iter()
            .filter(|p| p != "[DONE]")
            .map(|p| serde_json::from_str(&p).unwrap())
            .collect();
        assert_eq!(
            chunks[0]
                .pointer("/choices/0/delta/tool_calls/0/function/arguments")
                .and_then(Value::as_str),
            Some(r#"{"e":"REDACTED"}"#)
        );
        assert_eq!(
            chunks[1]
                .pointer("/choices/0/delta/tool_calls/0/function/arguments")
                .and_then(Value::as_str),
            Some("")
        );
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
    fn a_partial_token_is_carried_forward_instead_of_emitted() {
        let (head, carried) = split_trailing_open_bracket("sent to [EMAIL_ADD", 64);
        assert_eq!(head, "sent to ");
        assert_eq!(carried, "[EMAIL_ADD");
    }

    #[test]
    fn a_closed_bracket_is_emitted_whole() {
        let (head, carried) = split_trailing_open_bracket("sent to [EMAIL_ADDRESS_1]", 64);
        assert_eq!(head, "sent to [EMAIL_ADDRESS_1]");
        assert_eq!(carried, "");
    }

    #[test]
    fn a_stray_bracket_does_not_stall_the_stream() {
        let (head, carried) = split_trailing_open_bracket("a [ very long tail", 4);
        assert_eq!(head, "a [ very long tail");
        assert_eq!(carried, "");
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
