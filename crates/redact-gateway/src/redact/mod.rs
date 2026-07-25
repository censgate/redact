// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Policy-driven redaction of text and OpenAI payloads.
//!
//! Detection comes from `redact-core`; the action taken for each detection
//! comes from the active [`Profile`]. A single pass over the detected spans
//! applies the per-entity action, so one payload can mask a card number,
//! tokenize a name, and refuse an API key at the same time.

pub mod json;
pub mod token;

use std::collections::BTreeMap;

use redact_core::anonymizers::apply_anonymization;
use redact_core::{AnalyzerEngine, EntityType, RecognizerResult};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::policy::{EntityAction, MaskOptions, Profile};
use token::{TokenError, TokenSession};

/// Redaction failures.
#[derive(Debug, thiserror::Error)]
pub enum RedactError {
    /// Detection failed inside the engine.
    #[error("detection failed: {0}")]
    Detection(String),

    /// A reversible token could not be minted.
    #[error(transparent)]
    Token(#[from] TokenError),

    /// The profile requires tokenization but no token map is configured.
    #[error("policy requires tokenization but no token map backend is available")]
    TokenizationUnavailable,
}

/// What a redaction pass did.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RedactionOutcome {
    /// Number of spans rewritten.
    pub redactions_applied: usize,
    /// Rewrites per entity type.
    pub entity_counts: BTreeMap<String, usize>,
    /// Rewrites per action.
    pub action_counts: BTreeMap<String, usize>,
    /// Entity types that triggered a block.
    pub blocked_entities: Vec<String>,
    /// Reversible tokens minted.
    pub tokens_issued: usize,
    /// Detections left untouched because policy allowed them.
    pub allowed: usize,
}

impl RedactionOutcome {
    /// Whether policy refused the payload.
    pub fn is_blocked(&self) -> bool {
        !self.blocked_entities.is_empty()
    }

    /// Entity types that were rewritten, in stable order.
    pub fn entity_types(&self) -> Vec<String> {
        self.entity_counts.keys().cloned().collect()
    }

    /// Fold another outcome into this one.
    pub fn merge(&mut self, other: &RedactionOutcome) {
        self.redactions_applied += other.redactions_applied;
        self.tokens_issued += other.tokens_issued;
        self.allowed += other.allowed;
        for (key, count) in &other.entity_counts {
            *self.entity_counts.entry(key.clone()).or_insert(0) += count;
        }
        for (key, count) in &other.action_counts {
            *self.action_counts.entry(key.clone()).or_insert(0) += count;
        }
        for entity in &other.blocked_entities {
            if !self.blocked_entities.contains(entity) {
                self.blocked_entities.push(entity.clone());
            }
        }
    }

    fn record(&mut self, entity_type: &EntityType, action: EntityAction) {
        match action {
            EntityAction::Allow => self.allowed += 1,
            EntityAction::Block => {
                let label = entity_type.as_str().to_string();
                if !self.blocked_entities.contains(&label) {
                    self.blocked_entities.push(label);
                }
                *self
                    .action_counts
                    .entry(action.as_str().to_string())
                    .or_insert(0) += 1;
            }
            _ => {
                self.redactions_applied += 1;
                *self
                    .entity_counts
                    .entry(entity_type.as_str().to_string())
                    .or_insert(0) += 1;
                *self
                    .action_counts
                    .entry(action.as_str().to_string())
                    .or_insert(0) += 1;
                if action == EntityAction::Tokenize {
                    self.tokens_issued += 1;
                }
            }
        }
    }
}

/// Everything a redaction pass needs, carried across a whole payload so token
/// numbering and counters stay consistent between fields.
pub struct RedactionContext<'a> {
    engine: &'a AnalyzerEngine,
    profile: &'a Profile,
    session: Option<&'a mut TokenSession>,
    /// Accumulated result across every field touched by this context.
    pub outcome: RedactionOutcome,
}

impl<'a> RedactionContext<'a> {
    /// Create a context without tokenization support.
    pub fn new(engine: &'a AnalyzerEngine, profile: &'a Profile) -> Self {
        Self {
            engine,
            profile,
            session: None,
            outcome: RedactionOutcome::default(),
        }
    }

    /// Create a context that can mint reversible tokens.
    pub fn with_session(
        engine: &'a AnalyzerEngine,
        profile: &'a Profile,
        session: &'a mut TokenSession,
    ) -> Self {
        Self {
            engine,
            profile,
            session: Some(session),
            outcome: RedactionOutcome::default(),
        }
    }

    /// The profile driving this pass.
    pub fn profile(&self) -> &Profile {
        self.profile
    }

    /// Whether tokenization is available in this context.
    pub fn can_tokenize(&self) -> bool {
        self.session.is_some()
    }

    /// Detect and rewrite a single string according to policy.
    pub fn redact(&mut self, text: &str) -> Result<String, RedactError> {
        if text.trim().is_empty() {
            return Ok(text.to_string());
        }

        let analysis = self
            .engine
            .analyze(text, None)
            .map_err(|e| RedactError::Detection(e.to_string()))?;
        if analysis.detected_entities.is_empty() {
            return Ok(text.to_string());
        }

        // Decide every span first: tokenization needs fallible work that
        // `apply_anonymization` cannot perform inside its closure.
        let mut decisions: Vec<(RecognizerResult, EntityAction, Option<String>)> =
            Vec::with_capacity(analysis.detected_entities.len());
        for entity in analysis.detected_entities {
            let action = self.profile.decide(&entity.entity_type, entity.score);
            self.outcome.record(&entity.entity_type, action);

            let replacement = match action {
                EntityAction::Tokenize => {
                    let original = slice(text, &entity);
                    match self.session.as_deref_mut() {
                        Some(session) => Some(session.token_for(&entity.entity_type, original)?),
                        None => return Err(RedactError::TokenizationUnavailable),
                    }
                }
                _ => None,
            };
            decisions.push((entity, action, replacement));
        }

        if self.outcome.is_blocked() {
            // The caller refuses the request, so the rewritten text is never used.
            return Ok(text.to_string());
        }

        let rewrites: Vec<RecognizerResult> = decisions
            .iter()
            .filter(|(_, action, _)| action.rewrites())
            .map(|(entity, _, _)| entity.clone())
            .collect();
        if rewrites.is_empty() {
            return Ok(text.to_string());
        }

        let profile = self.profile;
        let lookup: BTreeMap<(usize, usize), (EntityAction, Option<String>)> = decisions
            .into_iter()
            .map(|(entity, action, replacement)| {
                ((entity.start, entity.end), (action, replacement))
            })
            .collect();

        let redacted = apply_anonymization(text, &rewrites, |entity, original| {
            match lookup.get(&(entity.start, entity.end)) {
                Some((EntityAction::Tokenize, Some(token))) => token.clone(),
                Some((EntityAction::Mask, _)) => mask_value(original, &profile.mask),
                Some((EntityAction::Hash, _)) => hash_value(original, profile.hash.salt.as_deref()),
                Some((EntityAction::Replace, _)) => profile
                    .replacement_for(&entity.entity_type)
                    .map(str::to_string)
                    .unwrap_or_else(|| entity.entity_type.default_replacement()),
                _ => original.to_string(),
            }
        });

        Ok(redacted)
    }

    /// Redact the part of `text` that is safe to emit while a stream is still open.
    ///
    /// Returns the redacted prefix plus the tail that must be retained. The cut
    /// point starts at `text.len() - holdback` and moves back so it never falls
    /// inside a detected entity. Because an entity that is still arriving is by
    /// definition at the end of the buffer, this makes detection reliable for
    /// any entity shorter than `holdback`; longer ones need the buffered mode.
    pub fn redact_prefix(
        &mut self,
        text: &str,
        holdback: usize,
    ) -> Result<(String, String), RedactError> {
        if text.len() <= holdback {
            return Ok((String::new(), text.to_string()));
        }

        let analysis = self
            .engine
            .analyze(text, None)
            .map_err(|e| RedactError::Detection(e.to_string()))?;

        let mut cut = text.len() - holdback;
        // Never split a detected entity: move the cut back to its start.
        loop {
            match analysis
                .detected_entities
                .iter()
                .filter(|entity| entity.start < cut && entity.end > cut)
                .map(|entity| entity.start)
                .min()
            {
                Some(start) if start < cut => cut = start,
                _ => break,
            }
        }
        while cut > 0 && !text.is_char_boundary(cut) {
            cut -= 1;
        }
        if cut == 0 {
            return Ok((String::new(), text.to_string()));
        }

        let head = self.redact(&text[..cut])?;
        Ok((head, text[cut..].to_string()))
    }

    /// Consume the context and return what it did.
    pub fn finish(self) -> RedactionOutcome {
        self.outcome
    }
}

fn slice<'t>(text: &'t str, entity: &RecognizerResult) -> &'t str {
    let end = entity.end.min(text.len());
    if entity.start >= end || !text.is_char_boundary(entity.start) || !text.is_char_boundary(end) {
        return "";
    }
    &text[entity.start..end]
}

/// Mask a value, mirroring the semantics of the core mask anonymizer.
pub fn mask_value(original: &str, options: &MaskOptions) -> String {
    if options.preserve_format {
        return original
            .chars()
            .map(|c| {
                if c.is_alphanumeric() {
                    options.mask_char
                } else {
                    c
                }
            })
            .collect();
    }

    let chars: Vec<char> = original.chars().collect();
    let len = chars.len();
    if options.start_chars + options.end_chars >= len {
        return original.to_string();
    }

    let mut masked = String::with_capacity(len);
    masked.extend(chars.iter().take(options.start_chars));
    masked.extend(std::iter::repeat_n(
        options.mask_char,
        len - options.start_chars - options.end_chars,
    ));
    masked.extend(chars.iter().skip(len - options.end_chars));
    masked
}

/// Hash a value with an optional salt, returning a short stable digest.
pub fn hash_value(original: &str, salt: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    if let Some(salt) = salt {
        hasher.update(salt.as_bytes());
    }
    hasher.update(original.as_bytes());
    let digest = hasher.finalize();
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("[HASH:{hex}]")
}

/// SHA-256 digest of a payload, used for audit correlation without content.
pub fn content_digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{EntityRule, PolicySet};
    use std::sync::Arc;
    use token::Dek;

    fn engine() -> AnalyzerEngine {
        AnalyzerEngine::new()
    }

    fn profile_with(default_action: EntityAction) -> Profile {
        Profile {
            default_action,
            min_confidence: 0.4,
            ..Profile::default()
        }
    }

    #[test]
    fn replace_uses_entity_labels() {
        let engine = engine();
        let profile = profile_with(EntityAction::Replace);
        let mut ctx = RedactionContext::new(&engine, &profile);
        let out = ctx.redact("Reach me at alice@example.com").unwrap();
        assert_eq!(out, "Reach me at [EMAIL_ADDRESS]");
        assert_eq!(ctx.outcome.redactions_applied, 1);
        assert_eq!(ctx.outcome.entity_types(), vec!["EMAIL_ADDRESS"]);
    }

    #[test]
    fn allow_leaves_content_untouched() {
        let engine = engine();
        let profile = profile_with(EntityAction::Allow);
        let mut ctx = RedactionContext::new(&engine, &profile);
        let text = "Reach me at alice@example.com";
        assert_eq!(ctx.redact(text).unwrap(), text);
        assert_eq!(ctx.outcome.redactions_applied, 0);
        assert_eq!(ctx.outcome.allowed, 1);
    }

    #[test]
    fn block_is_reported_without_rewriting() {
        let engine = engine();
        let profile = profile_with(EntityAction::Block);
        let mut ctx = RedactionContext::new(&engine, &profile);
        let text = "Reach me at alice@example.com";
        assert_eq!(ctx.redact(text).unwrap(), text);
        assert!(ctx.outcome.is_blocked());
        assert_eq!(ctx.outcome.blocked_entities, vec!["EMAIL_ADDRESS"]);
    }

    #[test]
    fn mixed_actions_apply_within_one_string() {
        let engine = engine();
        let mut entities = BTreeMap::new();
        entities.insert(
            "EMAIL_ADDRESS".to_string(),
            EntityRule::new(EntityAction::Mask),
        );
        let profile = Profile {
            default_action: EntityAction::Replace,
            min_confidence: 0.4,
            entities,
            mask: MaskOptions {
                mask_char: '*',
                preserve_format: true,
                ..MaskOptions::default()
            },
            ..Profile::default()
        };
        let mut ctx = RedactionContext::new(&engine, &profile);
        let out = ctx
            .redact("mail alice@example.com or call 555-867-5309")
            .unwrap();
        assert!(out.contains("*****@*******.***"), "got {out}");
        assert!(out.contains("[PHONE_NUMBER]"), "got {out}");
    }

    #[test]
    fn hash_action_is_stable_and_salted() {
        let unsalted = hash_value("alice@example.com", None);
        let salted = hash_value("alice@example.com", Some("pepper"));
        assert_eq!(unsalted, hash_value("alice@example.com", None));
        assert_ne!(unsalted, salted);
        assert!(salted.starts_with("[HASH:"));
    }

    #[test]
    fn tokenize_mints_reversible_placeholders() {
        let engine = engine();
        let profile = profile_with(EntityAction::Tokenize);
        let dek = Arc::new(Dek::generate().unwrap());
        let mut session = TokenSession::new("s", "t", dek.clone());
        let mut ctx = RedactionContext::with_session(&engine, &profile, &mut session);
        let out = ctx.redact("Email alice@example.com now").unwrap();
        assert_eq!(out, "Email [EMAIL_ADDRESS_1] now");
        let outcome = ctx.finish();
        assert_eq!(outcome.tokens_issued, 1);

        let mapping = &session.new_mappings()[0];
        assert_eq!(
            dek.open(&mapping.sealed_value).unwrap(),
            "alice@example.com"
        );
    }

    #[test]
    fn tokenize_without_a_session_is_an_error() {
        let engine = engine();
        let profile = profile_with(EntityAction::Tokenize);
        let mut ctx = RedactionContext::new(&engine, &profile);
        let err = ctx.redact("Email alice@example.com").unwrap_err();
        assert!(matches!(err, RedactError::TokenizationUnavailable));
    }

    #[test]
    fn bundled_default_policy_blocks_credentials() {
        let engine = engine();
        let policy = PolicySet::default();
        let profile = policy.default_profile();
        let mut ctx = RedactionContext::new(&engine, &profile);
        ctx.redact("key AKIAIOSFODNN7EXAMPLE here").unwrap();
        assert!(ctx.outcome.is_blocked());
        assert!(ctx
            .outcome
            .blocked_entities
            .contains(&"AWS_ACCESS_KEY".to_string()));
    }

    #[test]
    fn clean_text_is_returned_unchanged() {
        let engine = engine();
        let profile = profile_with(EntityAction::Replace);
        let mut ctx = RedactionContext::new(&engine, &profile);
        assert_eq!(ctx.redact("nothing to see").unwrap(), "nothing to see");
        assert_eq!(ctx.redact("").unwrap(), "");
        assert_eq!(ctx.outcome.redactions_applied, 0);
    }

    #[test]
    fn outcomes_merge_across_fields() {
        let mut first = RedactionOutcome::default();
        first.record(&EntityType::EmailAddress, EntityAction::Replace);
        let mut second = RedactionOutcome::default();
        second.record(&EntityType::EmailAddress, EntityAction::Replace);
        second.record(&EntityType::UsSsn, EntityAction::Mask);
        first.merge(&second);
        assert_eq!(first.redactions_applied, 3);
        assert_eq!(first.entity_counts["EMAIL_ADDRESS"], 2);
        assert_eq!(first.entity_counts["US_SSN"], 1);
    }

    #[test]
    fn mask_options_control_visible_characters() {
        let options = MaskOptions {
            mask_char: '#',
            start_chars: 2,
            end_chars: 2,
            preserve_format: false,
        };
        assert_eq!(mask_value("1234567890", &options), "12######90");
        assert_eq!(mask_value("abc", &options), "abc", "too short to mask");
    }

    #[test]
    fn content_digest_is_stable_and_not_reversible() {
        let digest = content_digest("alice@example.com");
        assert_eq!(digest.len(), 64);
        assert_eq!(digest, content_digest("alice@example.com"));
        assert!(!digest.contains("alice"));
    }
}
