// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Hybrid identity recognizer: identity-context parser plus optional ONNX NER.
//!
//! Explicit relationship / location / pet context wins over NER. NER fills
//! ORGANIZATION and bare proper names the parser will not invent from
//! capitalization. Production gateways set `required=true` so a missing model
//! fails startup instead of silently dropping NER.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use redact_core::{EntityType, Recognizer, RecognizerResult};
use tracing::{info, warn};

use crate::contextual_identity::detect_contextual_identities;
use crate::recognizer::NerRecognizer;

/// How ONNX NER is loaded for [`IdentityRecognizer`].
#[derive(Debug, Clone, Default)]
pub struct IdentityNerOptions {
    /// Path to `model.onnx`. Tokenizer is discovered beside it.
    pub model_path: Option<PathBuf>,
    /// When true, missing or unloadable NER fails construction.
    pub required: bool,
}

/// PERSON / LOCATION / ORGANIZATION recognizer used by redact-gateway.
pub struct IdentityRecognizer {
    ner: Option<NerRecognizer>,
}

impl std::fmt::Debug for IdentityRecognizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityRecognizer")
            .field(
                "ner_available",
                &self.ner.as_ref().is_some_and(|n| n.is_available()),
            )
            .finish()
    }
}

impl IdentityRecognizer {
    /// Contextual parser only. Used by tests and local gateways without a model.
    pub fn contextual_only() -> Self {
        Self { ner: None }
    }

    /// Load NER from options. Contextual detection always runs.
    pub fn from_options(opts: IdentityNerOptions) -> Result<Self> {
        let Some(path) = opts.model_path.filter(|p| !p.as_os_str().is_empty()) else {
            if opts.required {
                bail!("CENSGATE_NER_REQUIRED is set but CENSGATE_NER_MODEL_PATH is empty");
            }
            info!("identity recognizer: contextual only (no NER model path)");
            return Ok(Self::contextual_only());
        };
        if !path.exists() {
            if opts.required {
                bail!(
                    "CENSGATE_NER_REQUIRED is set but NER model is missing: {}",
                    path.display()
                );
            }
            warn!(
                path = %path.display(),
                "NER model path does not exist; identity recognizer is contextual only"
            );
            return Ok(Self::contextual_only());
        }

        let ner = match NerRecognizer::from_file(&path) {
            Ok(ner) => ner,
            Err(err) if !opts.required => {
                warn!(
                    path = %path.display(),
                    error = %err,
                    "ONNX NER failed to load; identity recognizer is contextual only"
                );
                return Ok(Self::contextual_only());
            }
            Err(err) => return Err(err),
        };
        if !ner.is_available() {
            if opts.required {
                bail!(
                    "CENSGATE_NER_REQUIRED is set but ONNX NER did not become available at {}",
                    path.display()
                );
            }
            warn!(
                path = %path.display(),
                "ONNX NER failed to load; identity recognizer is contextual only"
            );
            return Ok(Self::contextual_only());
        }
        info!(path = %path.display(), "identity recognizer: contextual + ONNX NER");
        Ok(Self { ner: Some(ner) })
    }

    /// Optional load from `CENSGATE_NER_MODEL_PATH` (never required).
    pub fn from_env_optional() -> Option<Self> {
        let path = std::env::var("CENSGATE_NER_MODEL_PATH").ok()?;
        if path.trim().is_empty() {
            return None;
        }
        Self::from_options(IdentityNerOptions {
            model_path: Some(PathBuf::from(path)),
            required: false,
        })
        .ok()
    }

    /// True when an ONNX session is ready.
    pub fn ner_available(&self) -> bool {
        self.ner.as_ref().is_some_and(|n| n.is_available())
    }

    /// Convenience wrapper around [`Self::from_options`].
    pub fn from_model_path(path: impl AsRef<Path>, required: bool) -> Result<Self> {
        Self::from_options(IdentityNerOptions {
            model_path: Some(path.as_ref().to_path_buf()),
            required,
        })
    }
}

impl Recognizer for IdentityRecognizer {
    fn name(&self) -> &str {
        "IdentityRecognizer"
    }

    fn supported_entities(&self) -> &[EntityType] {
        &[
            EntityType::Person,
            EntityType::Location,
            EntityType::Organization,
        ]
    }

    fn analyze(&self, text: &str, language: &str) -> Result<Vec<RecognizerResult>> {
        let contextual = {
            let _span = redact_core::operations_enabled()
                .then(|| tracing::info_span!("redact.gateway.detect.contextual").entered());
            detect_contextual_identities(text)
        };
        let ner = match &self.ner {
            Some(ner) if ner.is_available() => ner.analyze(text, language)?,
            _ => Vec::new(),
        };
        Ok(merge_identity(text, contextual, ner))
    }

    fn supports_language(&self, language: &str) -> bool {
        matches!(
            language,
            "en" | "es" | "fr" | "de" | "it" | "pt" | "nl" | "pl" | "ru" | "zh" | "ja" | "ko"
        )
    }
}

/// Context detections win on overlap. NER-only spans (ORG, uncovered names)
/// are kept. DATE_TIME from NER is dropped here — pattern packs own dates.
fn merge_identity(
    text: &str,
    contextual: Vec<RecognizerResult>,
    ner: Vec<RecognizerResult>,
) -> Vec<RecognizerResult> {
    let sealed = crate::contextual_identity::vault_token_spans(text);
    let mut out = contextual;
    for candidate in ner {
        match candidate.entity_type {
            EntityType::Person | EntityType::Location | EntityType::Organization => {}
            _ => continue,
        }
        if out
            .iter()
            .any(|existing| existing.overlaps_with(&candidate))
        {
            continue;
        }
        if sealed
            .iter()
            .any(|(s, e)| candidate.start < *e && candidate.end > *s)
        {
            continue;
        }
        out.push(candidate);
    }
    stabilize_identity_spans(text, out)
}

/// Merge split same-type PERSON spans and drop possessive `'s` from the
/// entity so `Nimbus` / `Nimbus's` share one surface for tokenization.
fn stabilize_identity_spans(text: &str, mut spans: Vec<RecognizerResult>) -> Vec<RecognizerResult> {
    spans.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<RecognizerResult> = Vec::new();
    for span in spans {
        if let Some(prev) = merged.last_mut() {
            if prev.entity_type == span.entity_type
                && same_word_adjacent(text, prev.end, span.start)
            {
                prev.end = prev.end.max(span.end);
                prev.score = prev.score.max(span.score);
                continue;
            }
        }
        merged.push(span);
    }
    for span in &mut merged {
        span.end = span.end.min(text.len());
        span.start = span.start.min(span.end);
        if span.entity_type != EntityType::Person || span.start >= span.end {
            continue;
        }
        if let Some(end) = person_span_end_without_possessive(text, span.start, span.end) {
            span.end = end;
        }
    }
    merged.retain(|span| span.start < span.end && !is_possessive_only(&text[span.start..span.end]));
    merged
}

fn same_word_adjacent(text: &str, prev_end: usize, next_start: usize) -> bool {
    if next_start < prev_end {
        return true;
    }
    if next_start == prev_end {
        return true;
    }
    if next_start > text.len() || prev_end > text.len() {
        return false;
    }
    let gap = &text[prev_end..next_start];
    !gap.is_empty() && gap.chars().all(|c| c == '\'' || c == '’' || c == '-')
}

fn person_span_end_without_possessive(text: &str, start: usize, end: usize) -> Option<usize> {
    let surface = &text[start..end];
    for suffix in ["'s", "’s", "'S", "’S"] {
        if surface.len() > suffix.len() && surface.ends_with(suffix) {
            return Some(end - suffix.len());
        }
    }
    None
}

fn is_possessive_only(surface: &str) -> bool {
    matches!(surface, "'s" | "’s" | "'S" | "’S" | "'" | "’" | "s" | "S")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_without_path_fails() {
        let err = IdentityRecognizer::from_options(IdentityNerOptions {
            model_path: None,
            required: true,
        })
        .unwrap_err();
        assert!(err.to_string().contains("CENSGATE_NER_REQUIRED"));
    }

    #[test]
    fn required_missing_file_fails() {
        let err = IdentityRecognizer::from_model_path("/nonexistent/model.onnx", true).unwrap_err();
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn optional_missing_file_is_contextual() {
        let rec = IdentityRecognizer::from_model_path("/nonexistent/model.onnx", false).unwrap();
        assert!(!rec.ner_available());
        assert_eq!(
            rec.analyze("Hi Ada", "en").unwrap()[0].entity_type,
            EntityType::Person
        );
    }

    #[test]
    fn context_wins_over_conflicting_ner_span() {
        let contextual = vec![RecognizerResult::new(
            EntityType::Location,
            12,
            18,
            0.9,
            "ctx",
        )];
        let ner = vec![RecognizerResult::new(
            EntityType::Person,
            12,
            18,
            0.99,
            "ner",
        )];
        let merged = merge_identity("we live in jordan", contextual, ner);
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].entity_type, EntityType::Location);
        assert_eq!(merged[0].recognizer_name, "ctx");
    }

    const LAB_ROSTER: &str = "The lab mascot is Nimbus. Nimbus's badge is yellow. Desk neighbors are Reed, Sable, and Quill. Sorrel runs the front desk. Reed files the badges.";

    fn person(start: usize, end: usize, source: &str) -> RecognizerResult {
        RecognizerResult::new(EntityType::Person, start, end, 0.9, source)
    }

    fn find_span(text: &str, needle: &str) -> (usize, usize) {
        let start = text.find(needle).expect(needle);
        (start, start + needle.len())
    }

    fn surfaces(text: &str, spans: &[RecognizerResult]) -> Vec<String> {
        spans
            .iter()
            .map(|s| text[s.start..s.end].to_string())
            .collect()
    }

    #[test]
    fn lab_roster_possessive_and_split_stabilize_to_one_token_surface() {
        let (nimbus, nimbus_end) = find_span(LAB_ROSTER, "Nimbus.");
        let nimbus_first = (nimbus, nimbus_end - 1);
        let nimbus_poss = find_span(LAB_ROSTER, "Nimbus's");
        let reed = find_span(LAB_ROSTER, "Reed,");
        let reed = (reed.0, reed.1 - 1);
        let sable = find_span(LAB_ROSTER, "Sable");
        let quill = find_span(LAB_ROSTER, "Quill");
        let sorrel = find_span(LAB_ROSTER, "Sorrel");
        let reed_again = LAB_ROSTER.rfind("Reed").expect("second Reed");
        let reed_again = (reed_again, reed_again + 4);

        let ner = vec![
            person(nimbus_first.0, nimbus_first.1, "ner"),
            person(nimbus_poss.0, nimbus_poss.0 + 6, "ner"),
            person(nimbus_poss.0 + 6, nimbus_poss.1, "ner"),
            person(reed.0, reed.1, "ner"),
            person(sable.0, sable.1, "ner"),
            person(quill.0, quill.1, "ner"),
            person(sorrel.0, sorrel.0 + 3, "ner"),
            person(sorrel.0 + 3, sorrel.1, "ner"),
            person(reed_again.0, reed_again.1, "ner"),
        ];
        let merged = merge_identity(LAB_ROSTER, Vec::new(), ner);
        let got = surfaces(LAB_ROSTER, &merged);
        assert_eq!(
            got,
            vec![
                "Nimbus".to_string(),
                "Nimbus".to_string(),
                "Reed".to_string(),
                "Sable".to_string(),
                "Quill".to_string(),
                "Sorrel".to_string(),
                "Reed".to_string(),
            ]
        );
        assert!(got
            .iter()
            .all(|s| s != "Nimbus's" && s != "'s" && s != "Sor"));
    }

    #[test]
    fn possessive_only_ner_span_is_dropped() {
        let text = "Nimbus's badge";
        let ner = vec![person(0, 6, "ner"), person(6, 8, "ner")];
        let merged = merge_identity(text, Vec::new(), ner);
        assert_eq!(surfaces(text, &merged), vec!["Nimbus".to_string()]);
    }
}
