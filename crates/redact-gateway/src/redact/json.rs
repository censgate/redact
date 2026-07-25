// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Payload traversal for the OpenAI-compatible surfaces.
//!
//! Redaction operates on `serde_json::Value` rather than a fixed request
//! struct so unknown provider extensions survive the round-trip untouched
//! while every text-bearing field a policy asks for is still scanned. Which
//! locations are visited is decided by [`crate::policy::ScanTargets`].

use std::collections::HashMap;

use serde_json::Value;

use super::token::{restore_text, RestoreOutcome};
use super::{RedactError, RedactionContext};

/// Redact a chat completion request in place.
pub fn redact_chat_request(
    ctx: &mut RedactionContext<'_>,
    body: &mut Value,
) -> Result<(), RedactError> {
    let scan = ctx.profile().scan.clone();

    if scan.request_messages || scan.request_tool_calls {
        if let Some(messages) = body.get_mut("messages").and_then(Value::as_array_mut) {
            for message in messages.iter_mut() {
                if scan.request_messages {
                    redact_content(ctx, message.get_mut("content"))?;
                }
                if scan.request_tool_calls {
                    redact_tool_calls(ctx, message.get_mut("tool_calls"))?;
                }
            }
        }
    }

    if scan.request_tools {
        redact_tools(ctx, body.get_mut("tools"))?;
        // Some providers still accept the pre-tools `functions` array.
        redact_tools(ctx, body.get_mut("functions"))?;
    }

    if scan.request_user {
        redact_string_field(ctx, body.get_mut("user"))?;
    }

    if scan.request_input {
        redact_text_or_list(ctx, body.get_mut("input"))?;
        redact_text_or_list(ctx, body.get_mut("prompt"))?;
        redact_text_or_list(ctx, body.get_mut("suffix"))?;
    }

    for pointer in &scan.request_pointers {
        redact_pointer(ctx, body, pointer)?;
    }

    Ok(())
}

/// Redact a chat completion (or legacy completion) response in place.
pub fn redact_chat_response(
    ctx: &mut RedactionContext<'_>,
    body: &mut Value,
) -> Result<(), RedactError> {
    let scan = ctx.profile().scan.clone();

    if let Some(choices) = body.get_mut("choices").and_then(Value::as_array_mut) {
        for choice in choices.iter_mut() {
            if scan.response_messages {
                if let Some(message) = choice.get_mut("message") {
                    redact_content(ctx, message.get_mut("content"))?;
                    redact_string_field(ctx, message.get_mut("reasoning_content"))?;
                }
                if let Some(delta) = choice.get_mut("delta") {
                    redact_content(ctx, delta.get_mut("content"))?;
                }
                // Legacy completions place the text directly on the choice.
                redact_string_field(ctx, choice.get_mut("text"))?;
            }
            if scan.response_tool_calls {
                if let Some(message) = choice.get_mut("message") {
                    redact_tool_calls(ctx, message.get_mut("tool_calls"))?;
                }
                if let Some(delta) = choice.get_mut("delta") {
                    redact_tool_calls(ctx, delta.get_mut("tool_calls"))?;
                }
            }
        }
    }

    for pointer in &scan.response_pointers {
        redact_pointer(ctx, body, pointer)?;
    }

    Ok(())
}

/// Redact an embeddings request in place.
pub fn redact_embeddings_request(
    ctx: &mut RedactionContext<'_>,
    body: &mut Value,
) -> Result<(), RedactError> {
    if ctx.profile().scan.request_input {
        redact_text_or_list(ctx, body.get_mut("input"))?;
    }
    if ctx.profile().scan.request_user {
        redact_string_field(ctx, body.get_mut("user"))?;
    }
    let pointers = ctx.profile().scan.request_pointers.clone();
    for pointer in &pointers {
        redact_pointer(ctx, body, pointer)?;
    }
    Ok(())
}

/// Redact the string at an RFC 6901 JSON pointer, if present.
pub fn redact_pointer(
    ctx: &mut RedactionContext<'_>,
    body: &mut Value,
    pointer: &str,
) -> Result<(), RedactError> {
    let Some(target) = body.pointer_mut(pointer) else {
        return Ok(());
    };
    redact_any(ctx, target)
}

/// Restore tokens throughout a response payload.
pub fn restore_chat_response(body: &mut Value, lookup: &HashMap<String, String>) -> RestoreOutcome {
    let mut outcome = RestoreOutcome::default();
    if lookup.is_empty() {
        return outcome;
    }
    restore_value(body, lookup, &mut outcome);
    outcome
}

fn restore_value(
    value: &mut Value,
    lookup: &HashMap<String, String>,
    outcome: &mut RestoreOutcome,
) {
    match value {
        Value::String(text) => {
            let (restored, result) = restore_text(text, lookup);
            *text = restored;
            outcome.restored += result.restored;
            outcome.missing += result.missing;
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                restore_value(item, lookup, outcome);
            }
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                restore_value(item, lookup, outcome);
            }
        }
        _ => {}
    }
}

/// `content` is either a string or an array of typed parts.
fn redact_content(
    ctx: &mut RedactionContext<'_>,
    content: Option<&mut Value>,
) -> Result<(), RedactError> {
    let Some(content) = content else {
        return Ok(());
    };
    match content {
        Value::String(_) => redact_string(ctx, content),
        Value::Array(parts) => {
            for part in parts.iter_mut() {
                // Only textual parts are scanned; image and audio payloads are
                // forwarded untouched rather than being corrupted by redaction.
                let is_text = part
                    .get("type")
                    .and_then(Value::as_str)
                    .map(|kind| kind == "text" || kind == "input_text" || kind == "output_text")
                    .unwrap_or(false);
                if is_text {
                    if let Some(text) = part.get_mut("text") {
                        redact_string(ctx, text)?;
                    }
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Tool call arguments are a JSON document encoded as a string.
fn redact_tool_calls(
    ctx: &mut RedactionContext<'_>,
    tool_calls: Option<&mut Value>,
) -> Result<(), RedactError> {
    let Some(Value::Array(calls)) = tool_calls else {
        return Ok(());
    };
    for call in calls.iter_mut() {
        let Some(function) = call.get_mut("function") else {
            continue;
        };
        let Some(arguments) = function.get_mut("arguments") else {
            continue;
        };
        let Some(raw) = arguments.as_str() else {
            // Some providers send arguments as an object rather than a string.
            redact_any(ctx, arguments)?;
            continue;
        };

        match serde_json::from_str::<Value>(raw) {
            Ok(mut parsed) => {
                redact_any(ctx, &mut parsed)?;
                match serde_json::to_string(&parsed) {
                    Ok(encoded) => *arguments = Value::String(encoded),
                    Err(_) => redact_string(ctx, arguments)?,
                }
            }
            // Malformed or partial arguments are treated as opaque text so a
            // provider quirk cannot smuggle unredacted content upstream.
            Err(_) => redact_string(ctx, arguments)?,
        }
    }
    Ok(())
}

/// Tool definitions carry free text in descriptions and schema annotations.
fn redact_tools(
    ctx: &mut RedactionContext<'_>,
    tools: Option<&mut Value>,
) -> Result<(), RedactError> {
    let Some(Value::Array(tools)) = tools else {
        return Ok(());
    };
    for tool in tools.iter_mut() {
        let function = match tool.get_mut("function") {
            Some(function) => function,
            None => tool,
        };
        redact_string_field(ctx, function.get_mut("description"))?;
        if let Some(parameters) = function.get_mut("parameters") {
            redact_schema_descriptions(ctx, parameters)?;
        }
    }
    Ok(())
}

fn redact_schema_descriptions(
    ctx: &mut RedactionContext<'_>,
    schema: &mut Value,
) -> Result<(), RedactError> {
    match schema {
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                match (key.as_str(), &mut *value) {
                    ("description" | "title", Value::String(_)) => redact_string(ctx, value)?,
                    ("enum" | "examples" | "default", _) => redact_any(ctx, value)?,
                    _ => redact_schema_descriptions(ctx, value)?,
                }
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_schema_descriptions(ctx, item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn redact_string_field(
    ctx: &mut RedactionContext<'_>,
    field: Option<&mut Value>,
) -> Result<(), RedactError> {
    match field {
        Some(value) if value.is_string() => redact_string(ctx, value),
        _ => Ok(()),
    }
}

fn redact_text_or_list(
    ctx: &mut RedactionContext<'_>,
    field: Option<&mut Value>,
) -> Result<(), RedactError> {
    match field {
        Some(value @ Value::String(_)) => redact_string(ctx, value),
        Some(Value::Array(items)) => {
            for item in items.iter_mut() {
                if item.is_string() {
                    redact_string(ctx, item)?;
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Redact every string leaf of an arbitrary value.
fn redact_any(ctx: &mut RedactionContext<'_>, value: &mut Value) -> Result<(), RedactError> {
    match value {
        Value::String(_) => redact_string(ctx, value),
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact_any(ctx, item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for (_, item) in map.iter_mut() {
                redact_any(ctx, item)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

fn redact_string(ctx: &mut RedactionContext<'_>, value: &mut Value) -> Result<(), RedactError> {
    let Some(text) = value.as_str() else {
        return Ok(());
    };
    let redacted = ctx.redact(text)?;
    if redacted != text {
        *value = Value::String(redacted);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EntityAction, Profile, ScanTargets};
    use crate::redact::token::{Dek, TokenSession};
    use redact_core::AnalyzerEngine;
    use serde_json::json;
    use std::sync::Arc;

    fn profile() -> Profile {
        Profile {
            default_action: EntityAction::Replace,
            min_confidence: 0.4,
            ..Profile::default()
        }
    }

    #[test]
    fn message_strings_and_parts_are_redacted() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "mail alice@example.com"},
                {"role": "user", "content": [
                    {"type": "text", "text": "or bob@example.com"},
                    {"type": "image_url", "image_url": {"url": "https://img/carol@example.com.png"}}
                ]}
            ]
        });

        redact_chat_request(&mut ctx, &mut body).unwrap();

        assert_eq!(body["messages"][0]["content"], "mail [EMAIL_ADDRESS]");
        assert_eq!(
            body["messages"][1]["content"][0]["text"],
            "or [EMAIL_ADDRESS]"
        );
        assert_eq!(
            body["messages"][1]["content"][1]["image_url"]["url"],
            "https://img/carol@example.com.png",
            "non-text parts are forwarded untouched"
        );
    }

    #[test]
    fn tool_call_arguments_are_redacted_inside_their_json() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "model": "m",
            "messages": [{
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {
                        "name": "send_mail",
                        "arguments": "{\"to\":\"alice@example.com\",\"retries\":2}"
                    }
                }]
            }]
        });

        redact_chat_request(&mut ctx, &mut body).unwrap();

        let arguments = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let parsed: Value = serde_json::from_str(arguments).unwrap();
        assert_eq!(parsed["to"], "[EMAIL_ADDRESS]");
        assert_eq!(parsed["retries"], 2, "non-string values keep their type");
        assert_eq!(body["messages"][0]["tool_calls"][0]["id"], "call_1");
    }

    #[test]
    fn malformed_tool_arguments_are_still_redacted() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "messages": [{
                "role": "assistant",
                "tool_calls": [{
                    "function": {"name": "f", "arguments": "{\"to\": \"alice@example.com\""}
                }]
            }]
        });

        redact_chat_request(&mut ctx, &mut body).unwrap();

        let arguments = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(arguments.contains("[EMAIL_ADDRESS]"));
        assert!(!arguments.contains("alice@example.com"));
    }

    #[test]
    fn tool_definitions_and_schema_descriptions_are_scanned() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "messages": [],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "lookup",
                    "description": "look up alice@example.com",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "who": {"type": "string", "description": "e.g. bob@example.com"}
                        }
                    }
                }
            }]
        });

        redact_chat_request(&mut ctx, &mut body).unwrap();

        assert_eq!(
            body["tools"][0]["function"]["description"],
            "look up [EMAIL_ADDRESS]"
        );
        assert_eq!(
            body["tools"][0]["function"]["parameters"]["properties"]["who"]["description"],
            "e.g. [EMAIL_ADDRESS]"
        );
        assert_eq!(body["tools"][0]["function"]["name"], "lookup");
    }

    #[test]
    fn every_choice_is_redacted_not_just_the_first() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "choices": [
                {"index": 0, "message": {"role": "assistant", "content": "a@example.com"}},
                {"index": 1, "message": {"role": "assistant", "content": "b@example.com"}}
            ]
        });

        redact_chat_response(&mut ctx, &mut body).unwrap();

        assert_eq!(body["choices"][0]["message"]["content"], "[EMAIL_ADDRESS]");
        assert_eq!(body["choices"][1]["message"]["content"], "[EMAIL_ADDRESS]");
    }

    #[test]
    fn embeddings_input_lists_are_redacted() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "model": "text-embedding-3-small",
            "input": ["alice@example.com", "nothing here"]
        });

        redact_embeddings_request(&mut ctx, &mut body).unwrap();

        assert_eq!(body["input"][0], "[EMAIL_ADDRESS]");
        assert_eq!(body["input"][1], "nothing here");
    }

    #[test]
    fn scan_targets_can_disable_locations() {
        let engine = AnalyzerEngine::new();
        let profile = Profile {
            default_action: EntityAction::Replace,
            min_confidence: 0.4,
            scan: ScanTargets {
                request_tool_calls: false,
                ..ScanTargets::default()
            },
            ..Profile::default()
        };
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "messages": [{
                "role": "assistant",
                "content": "alice@example.com",
                "tool_calls": [{"function": {"name": "f", "arguments": "{\"to\":\"bob@example.com\"}"}}]
            }]
        });

        redact_chat_request(&mut ctx, &mut body).unwrap();

        assert_eq!(body["messages"][0]["content"], "[EMAIL_ADDRESS]");
        assert!(
            body["messages"][0]["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .unwrap()
                .contains("bob@example.com")
        );
    }

    #[test]
    fn extra_pointers_are_scanned() {
        let engine = AnalyzerEngine::new();
        let profile = Profile {
            default_action: EntityAction::Replace,
            min_confidence: 0.4,
            scan: ScanTargets {
                request_pointers: vec!["/metadata/note".to_string()],
                ..ScanTargets::default()
            },
            ..Profile::default()
        };
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "messages": [],
            "metadata": {"note": "ping alice@example.com", "id": "keep"}
        });

        redact_chat_request(&mut ctx, &mut body).unwrap();

        assert_eq!(body["metadata"]["note"], "ping [EMAIL_ADDRESS]");
        assert_eq!(body["metadata"]["id"], "keep");
    }

    #[test]
    fn missing_pointers_are_ignored() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({"messages": []});
        redact_pointer(&mut ctx, &mut body, "/nope/missing").unwrap();
        assert_eq!(body, json!({"messages": []}));
    }

    #[test]
    fn tokenized_values_restore_through_the_whole_response() {
        let engine = AnalyzerEngine::new();
        let profile = Profile {
            default_action: EntityAction::Tokenize,
            min_confidence: 0.4,
            ..Profile::default()
        };
        let dek = Arc::new(Dek::generate().unwrap());
        let mut session = TokenSession::new("s", "t", dek.clone());
        let mut request = json!({
            "messages": [{"role": "user", "content": "write to alice@example.com"}]
        });

        {
            let mut ctx = RedactionContext::with_session(&engine, &profile, &mut session);
            redact_chat_request(&mut ctx, &mut request).unwrap();
        }
        assert_eq!(
            request["messages"][0]["content"],
            "write to [EMAIL_ADDRESS_1]"
        );

        let lookup: HashMap<String, String> = session
            .new_mappings()
            .iter()
            .map(|m| (m.token.clone(), dek.open(&m.sealed_value).unwrap()))
            .collect();

        let mut response = json!({
            "choices": [{"message": {"role": "assistant", "content": "sent to [EMAIL_ADDRESS_1]"}}]
        });
        let outcome = restore_chat_response(&mut response, &lookup);

        assert_eq!(
            response["choices"][0]["message"]["content"],
            "sent to alice@example.com"
        );
        assert_eq!(outcome.restored, 1);
    }

    #[test]
    fn unknown_request_fields_survive_the_round_trip() {
        let engine = AnalyzerEngine::new();
        let profile = profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        let mut body = json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0.2,
            "provider_specific": {"beta": true}
        });

        redact_chat_request(&mut ctx, &mut body).unwrap();

        assert_eq!(body["temperature"], 0.2);
        assert_eq!(body["provider_specific"]["beta"], true);
    }
}
