// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::openai::{ChatCompletionRequest, MessageContent};
use anyhow::Result;
use redact_core::{AnalyzerEngine, AnonymizerConfig};
use serde_json::Value;

/// Summary of redaction applied to a request or response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionOutcome {
    pub redactions_applied: usize,
    pub entity_types: Vec<String>,
}

impl RedactionOutcome {
    pub fn merge(&mut self, other: &RedactionOutcome) {
        self.redactions_applied += other.redactions_applied;
        for label in &other.entity_types {
            if !self.entity_types.contains(label) {
                self.entity_types.push(label.clone());
            }
        }
    }
}

/// Anonymize a single text string.
pub fn redact_text(
    engine: &AnalyzerEngine,
    text: &str,
    config: &AnonymizerConfig,
) -> Result<(String, RedactionOutcome)> {
    if text.is_empty() {
        return Ok((text.to_string(), RedactionOutcome::default()));
    }

    let anonymized = engine.anonymize(text, None, config)?;
    let mut outcome = RedactionOutcome {
        redactions_applied: anonymized.entities.len(),
        entity_types: Vec::new(),
    };
    for entity in &anonymized.entities {
        let label = entity.entity_type.as_str().to_string();
        if !outcome.entity_types.contains(&label) {
            outcome.entity_types.push(label);
        }
    }
    Ok((anonymized.text, outcome))
}

/// Anonymize message content and privacy-sensitive top-level request fields.
pub fn redact_chat_request(
    engine: &AnalyzerEngine,
    request: &mut ChatCompletionRequest,
    config: &AnonymizerConfig,
) -> Result<RedactionOutcome> {
    let mut outcome = RedactionOutcome::default();

    for message in &mut request.messages {
        let Some(content) = message.content.as_mut() else {
            continue;
        };
        match content {
            MessageContent::Text(text) => {
                let (redacted, part) = redact_text(engine, text, config)?;
                if part.redactions_applied > 0 {
                    outcome.merge(&part);
                    *text = redacted;
                }
            }
            MessageContent::Parts(parts) => {
                for part in parts {
                    if part.kind == "text" {
                        if let Some(text) = part.text.as_mut() {
                            let (redacted, redaction) = redact_text(engine, text, config)?;
                            if redaction.redactions_applied > 0 {
                                outcome.merge(&redaction);
                                *text = redacted;
                            }
                        }
                    }
                }
            }
        }
    }

    // OpenAI `user` is commonly an email or internal id — redact in place when present.
    if let Some(Value::String(user)) = request.extra.get("user").cloned() {
        let (redacted, part) = redact_text(engine, &user, config)?;
        if part.redactions_applied > 0 {
            outcome.merge(&part);
            request
                .extra
                .insert("user".to_string(), Value::String(redacted));
        }
    }

    Ok(outcome)
}

/// Anonymize assistant `message.content` fields in an OpenAI chat completion JSON body.
pub fn redact_chat_response_json(
    engine: &AnalyzerEngine,
    body: &mut Value,
    config: &AnonymizerConfig,
) -> Result<RedactionOutcome> {
    let mut outcome = RedactionOutcome::default();

    let Some(choices) = body.get_mut("choices").and_then(|c| c.as_array_mut()) else {
        return Ok(outcome);
    };

    for choice in choices {
        if let Some(content_val) = choice.pointer_mut("/message/content") {
            match content_val {
                Value::String(text) => {
                    let (redacted, part) = redact_text(engine, text, config)?;
                    if part.redactions_applied > 0 {
                        outcome.merge(&part);
                        *text = redacted;
                    }
                }
                Value::Array(parts) => {
                    for part in parts {
                        if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                            if let Some(Value::String(text)) = part.get_mut("text") {
                                let (redacted, redaction) = redact_text(engine, text, config)?;
                                if redaction.redactions_applied > 0 {
                                    outcome.merge(&redaction);
                                    *text = redacted;
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::openai::ChatMessage;
    use redact_core::AnonymizationStrategy;
    use serde_json::json;
    use std::collections::HashMap;

    #[test]
    fn skips_messages_without_content() {
        let engine = AnalyzerEngine::new();
        let config = AnonymizerConfig {
            strategy: AnonymizationStrategy::Replace,
            ..Default::default()
        };
        let mut request = ChatCompletionRequest {
            model: "m".into(),
            messages: vec![ChatMessage {
                role: "assistant".into(),
                content: None,
                extra: Default::default(),
            }],
            stream: None,
            extra: Default::default(),
        };
        let outcome = redact_chat_request(&engine, &mut request, &config).unwrap();
        assert_eq!(outcome.redactions_applied, 0);
    }

    #[test]
    fn redacts_top_level_user_field() {
        let engine = AnalyzerEngine::new();
        let config = AnonymizerConfig {
            strategy: AnonymizationStrategy::Replace,
            ..Default::default()
        };
        let mut request = ChatCompletionRequest {
            model: "m".into(),
            messages: vec![ChatMessage::text("user", "hello")],
            stream: None,
            extra: HashMap::from([("user".into(), json!("alice@example.com"))]),
        };
        let outcome = redact_chat_request(&engine, &mut request, &config).unwrap();
        assert!(outcome.redactions_applied >= 1);
        assert_eq!(
            request.extra.get("user").and_then(|v| v.as_str()),
            Some("[EMAIL_ADDRESS]")
        );
    }
}
