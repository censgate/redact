// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use crate::openai::ChatCompletionRequest;
use anyhow::Result;
use redact_core::{AnalyzerEngine, AnonymizerConfig};

/// Summary of redaction applied to a chat request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RedactionOutcome {
    pub redactions_applied: usize,
    pub entity_types: Vec<String>,
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
        if content.is_empty() {
            continue;
        }

        let anonymized = engine.anonymize(content, None, config)?;
        let applied = anonymized.entities.len();
        if applied == 0 {
            continue;
        }

        for entity in &anonymized.entities {
            let label = entity.entity_type.as_str().to_string();
            if !outcome.entity_types.contains(&label) {
                outcome.entity_types.push(label);
            }
        }
        outcome.redactions_applied += applied;
        *content = anonymized.text;
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
