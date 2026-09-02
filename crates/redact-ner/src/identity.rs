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
        let contextual = detect_contextual_identities(text);
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
    out.sort_by_key(|r| (r.start, r.end));
    out
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
}
