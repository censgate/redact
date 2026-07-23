// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::openai::ChatCompletionRequest;
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

/// Anonymize string content in each chat message in place.
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
        let (redacted, part) = redact_text(engine, content, config)?;
        if part.redactions_applied == 0 {
            continue;
        }
        outcome.merge(&part);
        *content = redacted;
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
        if let Some(content) = choice
            .pointer_mut("/message/content")
            .and_then(|v| v.as_str())
            .map(str::to_string)
        {
            let (redacted, part) = redact_text(engine, &content, config)?;
            if part.redactions_applied > 0 {
                outcome.merge(&part);
                if let Some(slot) = choice.pointer_mut("/message/content") {
                    *slot = Value::String(redacted);
                }
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
            }],
            stream: None,
            extra: Default::default(),
        };
        let outcome = redact_chat_request(&engine, &mut request, &config).unwrap();
        assert_eq!(outcome.redactions_applied, 0);
    }
}
