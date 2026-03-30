// Copyright (c) 2026 Censgate LLC.
// Licensed under the Business Source License 1.1 (BUSL-1.1).
// See the LICENSE file in the project root for license details,
// including the Additional Use Grant, Change Date, and Change License.

use anyhow::{anyhow, Result};
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::Value;
use redact_core::{EntityType, Recognizer, RecognizerResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use tracing::{debug, info, warn};

use crate::tokenizer_wrapper::TokenizerWrapper;

/// Configuration for NER recognizer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NerConfig {
    /// Path to ONNX model file
    pub model_path: String,

    /// Path to tokenizer file (optional - will use model_path directory)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokenizer_path: Option<String>,

    /// Minimum confidence threshold
    #[serde(default = "default_confidence")]
    pub min_confidence: f32,

    /// Maximum sequence length
    #[serde(default = "default_max_length")]
    pub max_seq_length: usize,

    /// Entity type mappings from NER labels
    #[serde(default)]
    pub label_mappings: HashMap<String, EntityType>,

    /// Label IDs to label strings mapping
    #[serde(default)]
    pub id2label: HashMap<usize, String>,
}

fn default_confidence() -> f32 {
    0.7
}

fn default_max_length() -> usize {
    512
}

impl Default for NerConfig {
    fn default() -> Self {
        let mut label_mappings = HashMap::new();
        let mut id2label = HashMap::new();

        // Default BIO tagging scheme mappings
        label_mappings.insert("B-PER".to_string(), EntityType::Person);
        label_mappings.insert("I-PER".to_string(), EntityType::Person);
        label_mappings.insert("B-ORG".to_string(), EntityType::Organization);
        label_mappings.insert("I-ORG".to_string(), EntityType::Organization);
        label_mappings.insert("B-LOC".to_string(), EntityType::Location);
        label_mappings.insert("I-LOC".to_string(), EntityType::Location);
        label_mappings.insert("B-DATE".to_string(), EntityType::DateTime);
        label_mappings.insert("I-DATE".to_string(), EntityType::DateTime);
        label_mappings.insert("B-TIME".to_string(), EntityType::DateTime);
        label_mappings.insert("I-TIME".to_string(), EntityType::DateTime);

        // Default id2label for CoNLL-2003 style models
        id2label.insert(0, "O".to_string());
        id2label.insert(1, "B-PER".to_string());
        id2label.insert(2, "I-PER".to_string());
        id2label.insert(3, "B-ORG".to_string());
        id2label.insert(4, "I-ORG".to_string());
        id2label.insert(5, "B-LOC".to_string());
        id2label.insert(6, "I-LOC".to_string());
        id2label.insert(7, "B-MISC".to_string());
        id2label.insert(8, "I-MISC".to_string());

        Self {
            model_path: String::new(),
            tokenizer_path: None,
            min_confidence: default_confidence(),
            max_seq_length: default_max_length(),
            label_mappings,
            id2label,
        }
    }
}

/// NER-based recognizer using ONNX Runtime
///
/// **Status**: ✅ Fully operational with complete ONNX Runtime integration
///
/// This recognizer uses transformer-based Named Entity Recognition models for contextual
/// PII detection. It automatically loads and runs ONNX models with:
/// - Tokenization with HuggingFace tokenizers
/// - ONNX Runtime inference with optimizations
/// - BIO tag parsing for entity span extraction
/// - Thread-safe session management
///
/// **To enable NER**:
/// 1. Export your NER model to ONNX format using `scripts/export_ner_model.py`
/// 2. Set `model_path` to point to your `.onnx` file
/// 3. Optionally provide `tokenizer_path` or place `tokenizer.json` in the same directory
///
/// Without a model, this recognizer gracefully returns empty results and the system
/// falls back to pattern-based detection (36+ entity types).
pub struct NerRecognizer {
    config: NerConfig,
    tokenizer: Option<TokenizerWrapper>,
    session: Option<Mutex<Session>>,
    /// Whether the ONNX model accepts `token_type_ids` as an input.
    /// BERT-family models require it; DistilBERT and others do not.
    /// Determined at model-load time by inspecting `Session::inputs()`.
    needs_token_type_ids: bool,
}

impl std::fmt::Debug for NerRecognizer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NerRecognizer")
            .field("config", &self.config)
            .field("tokenizer", &self.tokenizer)
            .field("session", &self.session.as_ref().map(|_| "Session"))
            .field("needs_token_type_ids", &self.needs_token_type_ids)
            .finish()
    }
}

impl NerRecognizer {
    /// Create a new NER recognizer from a model file.
    ///
    /// Automatically loads `config.json` from the model directory (if present)
    /// to get the correct `id2label` and `label_mappings` for the exported model.
    /// Falls back to default CoNLL-2003 mappings when no config is found.
    pub fn from_file<P: AsRef<Path>>(model_path: P) -> Result<Self> {
        let model_path_ref = model_path.as_ref();
        let model_path_str = model_path_ref.to_string_lossy().to_string();

        // Try loading config.json from model directory (written by export_ner_model.py)
        let config = if let Some(model_dir) = model_path_ref.parent() {
            let config_path = model_dir.join("config.json");
            if config_path.exists() {
                debug!("Loading NER config from: {}", config_path.display());
                match Self::load_config_from_file(&config_path, &model_path_str) {
                    Ok(cfg) => cfg,
                    Err(e) => {
                        warn!("Failed to load NER config.json: {}. Using defaults.", e);
                        NerConfig {
                            model_path: model_path_str,
                            ..Default::default()
                        }
                    }
                }
            } else {
                debug!("No config.json in model directory, using default label mappings");
                NerConfig {
                    model_path: model_path_str,
                    ..Default::default()
                }
            }
        } else {
            NerConfig {
                model_path: model_path_str,
                ..Default::default()
            }
        };

        Self::from_config(config)
    }

    /// Load NER config from a JSON file produced by `export_ner_model.py`.
    ///
    /// Handles format differences between the Python export (string keys, PascalCase
    /// entity names) and Rust types (usize keys, SCREAMING_SNAKE_CASE EntityType).
    fn load_config_from_file(config_path: &Path, model_path: &str) -> Result<NerConfig> {
        let json_str = std::fs::read_to_string(config_path)?;
        let raw: serde_json::Value = serde_json::from_str(&json_str)?;

        let defaults = NerConfig::default();

        // Parse id2label: JSON has string keys like {"0": "O", "1": "B-MISC", ...}
        let id2label = if let Some(obj) = raw.get("id2label").and_then(|v| v.as_object()) {
            let mut map = HashMap::new();
            for (k, v) in obj {
                if let (Ok(id), Some(label)) = (k.parse::<usize>(), v.as_str()) {
                    map.insert(id, label.to_string());
                }
            }
            map
        } else {
            defaults.id2label.clone()
        };

        // Parse label_mappings: JSON has {"B-PER": "Person", ...}
        // EntityType::from() handles case-insensitive conversion
        let label_mappings =
            if let Some(obj) = raw.get("label_mappings").and_then(|v| v.as_object()) {
                let mut map = HashMap::new();
                for (k, v) in obj {
                    if let Some(entity_str) = v.as_str() {
                        map.insert(k.clone(), EntityType::from(entity_str.to_string()));
                    }
                }
                map
            } else {
                // Build label_mappings purely from id2label (no stale defaults).
                let mut map = HashMap::new();
                for label in id2label.values() {
                    if label == "O" {
                        continue;
                    }
                    let entity_type = label.split('-').next_back().unwrap_or(label);
                    match entity_type {
                        "PER" | "PERSON" => {
                            map.insert(label.clone(), EntityType::Person);
                        }
                        "ORG" | "ORGANIZATION" => {
                            map.insert(label.clone(), EntityType::Organization);
                        }
                        "LOC" | "LOCATION" | "GPE" => {
                            map.insert(label.clone(), EntityType::Location);
                        }
                        "DATE" | "TIME" | "DATETIME" => {
                            map.insert(label.clone(), EntityType::DateTime);
                        }
                        _ => {
                            debug!("Unmapped NER label: {} — no EntityType match", label);
                        }
                    }
                }
                map
            };

        let min_confidence = raw
            .get("min_confidence")
            .and_then(|v| v.as_f64())
            .map(|v| v as f32)
            .unwrap_or(defaults.min_confidence);

        let max_seq_length = raw
            .get("max_seq_length")
            .and_then(|v| v.as_u64())
            .map(|v| v as usize)
            .unwrap_or(defaults.max_seq_length);

        // Intentionally ignore tokenizer_path from config.json: the export script
        // writes a build-time path (e.g. /out/models/tokenizer.json) that won't exist
        // at runtime. from_config() auto-discovers tokenizer.json from the model directory.
        let tokenizer_path = None;

        info!(
            "Loaded NER config from {} ({} label mappings, {} id2label entries)",
            config_path.display(),
            label_mappings.len(),
            id2label.len()
        );

        Ok(NerConfig {
            model_path: model_path.to_string(),
            tokenizer_path,
            min_confidence,
            max_seq_length,
            label_mappings,
            id2label,
        })
    }

    /// Create a new NER recognizer from configuration
    pub fn from_config(config: NerConfig) -> Result<Self> {
        // Try to load tokenizer if available
        let tokenizer = if let Some(ref tokenizer_path) = config.tokenizer_path {
            debug!("Loading tokenizer from: {}", tokenizer_path);
            match TokenizerWrapper::from_file(tokenizer_path) {
                Ok(t) => {
                    info!("✓ Tokenizer loaded successfully from: {}", tokenizer_path);
                    Some(t)
                }
                Err(e) => {
                    warn!(
                        "Failed to load tokenizer: {}. NER will not be available.",
                        e
                    );
                    None
                }
            }
        } else if !config.model_path.is_empty() {
            // Try to find tokenizer in same directory as model
            let model_dir = Path::new(&config.model_path).parent();
            if let Some(dir) = model_dir {
                let tokenizer_json = dir.join("tokenizer.json");
                if tokenizer_json.exists() {
                    debug!("Loading tokenizer from: {}", tokenizer_json.display());
                    match TokenizerWrapper::from_file(&tokenizer_json) {
                        Ok(t) => {
                            info!("✓ Tokenizer loaded successfully from model directory");
                            Some(t)
                        }
                        Err(e) => {
                            warn!("Failed to load tokenizer from model directory: {}", e);
                            None
                        }
                    }
                } else {
                    debug!("No tokenizer.json found in model directory");
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        // Try to load ONNX model if path is provided
        let session = if !config.model_path.is_empty() {
            let model_path = Path::new(&config.model_path);
            if model_path.exists() {
                debug!("Loading ONNX model from: {}", config.model_path);
                match Session::builder()?
                    .with_optimization_level(GraphOptimizationLevel::Level3)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .with_intra_threads(4)
                    .map_err(|e| anyhow::anyhow!("{e}"))?
                    .commit_from_file(&config.model_path)
                {
                    Ok(s) => {
                        info!("✓ ONNX model loaded successfully: {}", config.model_path);
                        Some(Mutex::new(s))
                    }
                    Err(e) => {
                        warn!(
                            "Failed to load ONNX model: {}. NER will not be available.",
                            e
                        );
                        None
                    }
                }
            } else {
                debug!(
                    "Model path provided but file does not exist: {}",
                    config.model_path
                );
                None
            }
        } else {
            debug!("No model path provided, NER will not be available");
            None
        };

        // Inspect model inputs at construction time to determine whether the
        // model expects token_type_ids (BERT-family) or not (DistilBERT, etc.).
        let needs_token_type_ids = session.as_ref().is_some_and(|s| {
            let guard = s.lock().expect("session lock poisoned during init");
            let has_it = guard
                .inputs()
                .iter()
                .any(|input| input.name() == "token_type_ids");
            if has_it {
                debug!("Model declares token_type_ids input — will include in inference");
            } else {
                debug!("Model does not declare token_type_ids — omitting from inference");
            }
            has_it
        });

        let is_available = tokenizer.is_some() && session.is_some();
        if is_available {
            info!("✓ NER is fully operational with ONNX Runtime");
        } else {
            info!("⚠ NER not available - using pattern-based detection (36+ entity types)");
            if tokenizer.is_none() {
                debug!("  Missing: tokenizer");
            }
            if session.is_none() {
                debug!("  Missing: ONNX model");
            }
        }

        Ok(Self {
            config,
            tokenizer,
            session,
            needs_token_type_ids,
        })
    }

    /// Get the configuration
    pub fn config(&self) -> &NerConfig {
        &self.config
    }

    /// Check if NER is available (model and tokenizer loaded)
    pub fn is_available(&self) -> bool {
        self.tokenizer.is_some() && self.session.is_some()
    }

    /// Map NER label to entity type
    fn map_label_to_entity(&self, label: &str) -> Option<EntityType> {
        self.config.label_mappings.get(label).cloned()
    }

    /// Run inference on tokenized input
    fn infer(&self, input_ids: &[u32], attention_mask: &[u32]) -> Result<Vec<Vec<f32>>> {
        let session_mutex = self
            .session
            .as_ref()
            .ok_or_else(|| anyhow!("ONNX session not loaded"))?;

        let mut session = session_mutex
            .lock()
            .map_err(|e| anyhow!("Failed to lock session: {}", e))?;

        // Create 2D arrays with shape [1, seq_len]
        let seq_len = input_ids.len();
        let input_ids_i64: Vec<i64> = input_ids.iter().map(|&x| x as i64).collect();
        let attention_mask_i64: Vec<i64> = attention_mask.iter().map(|&x| x as i64).collect();

        let input_ids_value = Value::from_array(([1, seq_len], input_ids_i64))?;
        let attention_mask_value = Value::from_array(([1, seq_len], attention_mask_i64))?;

        // Build inputs list — only include token_type_ids when the model expects it
        // (BERT-family needs it; DistilBERT and others do not).
        let mut inputs: Vec<(std::borrow::Cow<'_, str>, Value)> = vec![
            ("input_ids".into(), input_ids_value.into()),
            ("attention_mask".into(), attention_mask_value.into()),
        ];

        if self.needs_token_type_ids {
            let token_type_ids_i64: Vec<i64> = vec![0i64; seq_len];
            let token_type_ids_value = Value::from_array(([1, seq_len], token_type_ids_i64))?;
            inputs.push(("token_type_ids".into(), token_type_ids_value.into()));
        }

        let outputs = session.run(inputs)?;

        // Extract logits - shape should be [1, seq_len, num_labels]
        let (shape, logits_data) = outputs["logits"].try_extract_tensor::<f32>()?;
        let shape_dims: &[i64] = shape.as_ref();

        if shape_dims.len() != 3 || shape_dims[0] != 1 {
            return Err(anyhow!("Unexpected logits shape: {:?}", shape_dims));
        }

        let seq_len_out = shape_dims[1] as usize;
        let num_labels = shape_dims[2] as usize;

        // Convert to Vec<Vec<f32>> where outer vec is tokens, inner vec is label scores
        let mut result = Vec::new();
        for i in 0..seq_len_out {
            let mut token_logits = Vec::new();
            for j in 0..num_labels {
                let idx = i * num_labels + j;
                token_logits.push(logits_data[idx]);
            }
            result.push(token_logits);
        }

        Ok(result)
    }

    /// Apply softmax to convert logits to probabilities
    fn softmax(logits: &[f32]) -> Vec<f32> {
        let max_logit = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
        let exp_sum: f32 = logits.iter().map(|&x| (x - max_logit).exp()).sum();
        logits
            .iter()
            .map(|&x| (x - max_logit).exp() / exp_sum)
            .collect()
    }

    /// Parse BIO tags and extract entity spans
    fn parse_bio_tags(
        &self,
        _text: &str,
        predictions: &[usize],
        probabilities: &[f32],
        offsets: &[(usize, usize)],
    ) -> Vec<RecognizerResult> {
        let mut results = Vec::new();
        let mut current_entity: Option<(EntityType, usize, usize, Vec<f32>)> = None;

        for (idx, (&pred_id, &prob)) in predictions.iter().zip(probabilities.iter()).enumerate() {
            // Skip padding tokens (offset (0,0))
            if offsets[idx] == (0, 0) {
                continue;
            }

            let label = self
                .config
                .id2label
                .get(&pred_id)
                .map(|s| s.as_str())
                .unwrap_or("O");

            if label.starts_with("B-") {
                // Begin new entity - save previous if exists
                if let Some((entity_type, start, end, probs)) = current_entity.take() {
                    let avg_confidence = probs.iter().sum::<f32>() / probs.len() as f32;
                    if avg_confidence >= self.config.min_confidence {
                        results.push(RecognizerResult::new(
                            entity_type,
                            start,
                            end,
                            avg_confidence,
                            self.name(),
                        ));
                    }
                }

                // Start new entity
                if let Some(entity_type) = self.map_label_to_entity(label) {
                    let start = offsets[idx].0;
                    let end = offsets[idx].1;
                    current_entity = Some((entity_type, start, end, vec![prob]));
                }
            } else if label.starts_with("I-") {
                // Continue current entity
                if let Some((ref entity_type, start, ref mut end, ref mut probs)) = current_entity {
                    // Check if label matches current entity type
                    if let Some(label_entity) = self.map_label_to_entity(label) {
                        if label_entity == *entity_type {
                            *end = offsets[idx].1;
                            probs.push(prob);
                        } else {
                            // Different entity type - save current and start new
                            let avg_confidence = probs.iter().sum::<f32>() / probs.len() as f32;
                            if avg_confidence >= self.config.min_confidence {
                                results.push(RecognizerResult::new(
                                    entity_type.clone(),
                                    start,
                                    *end,
                                    avg_confidence,
                                    self.name(),
                                ));
                            }
                            current_entity = None;
                        }
                    }
                }
            } else {
                // "O" tag or unknown - end current entity
                if let Some((entity_type, start, end, probs)) = current_entity.take() {
                    let avg_confidence = probs.iter().sum::<f32>() / probs.len() as f32;
                    if avg_confidence >= self.config.min_confidence {
                        results.push(RecognizerResult::new(
                            entity_type,
                            start,
                            end,
                            avg_confidence,
                            self.name(),
                        ));
                    }
                }
            }
        }

        // Don't forget the last entity
        if let Some((entity_type, start, end, probs)) = current_entity {
            let avg_confidence = probs.iter().sum::<f32>() / probs.len() as f32;
            if avg_confidence >= self.config.min_confidence {
                results.push(RecognizerResult::new(
                    entity_type,
                    start,
                    end,
                    avg_confidence,
                    self.name(),
                ));
            }
        }

        results
    }
}

impl Recognizer for NerRecognizer {
    fn name(&self) -> &str {
        "NerRecognizer"
    }

    fn supported_entities(&self) -> &[EntityType] {
        &[
            EntityType::Person,
            EntityType::Organization,
            EntityType::Location,
            EntityType::DateTime,
        ]
    }

    fn analyze(&self, text: &str, _language: &str) -> Result<Vec<RecognizerResult>> {
        // Check if NER is available
        if !self.is_available() {
            return Ok(vec![]);
        }

        let tokenizer = self.tokenizer.as_ref().unwrap();

        // Tokenize input
        let mut encoding = tokenizer.encode(text, true)?;

        // Get padding token ID
        let pad_id = tokenizer.get_padding_id().unwrap_or(0);

        // Pad/truncate to max sequence length
        encoding.pad_to_length(self.config.max_seq_length, pad_id);

        // Run inference
        let logits = self.infer(&encoding.ids, &encoding.attention_mask)?;

        // Convert logits to predictions
        let mut predictions = Vec::new();
        let mut probabilities = Vec::new();

        for token_logits in &logits {
            let probs = Self::softmax(token_logits);
            let (pred_id, &max_prob) = probs
                .iter()
                .enumerate()
                .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap())
                .unwrap();
            predictions.push(pred_id);
            probabilities.push(max_prob);
        }

        // Parse BIO tags to extract entities
        let results = self.parse_bio_tags(text, &predictions, &probabilities, &encoding.offsets);

        Ok(results)
    }

    fn supports_language(&self, language: &str) -> bool {
        // Most multilingual NER models support these languages
        matches!(
            language,
            "en" | "es" | "fr" | "de" | "it" | "pt" | "nl" | "pl" | "ru" | "zh" | "ja" | "ko"
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_default_config() {
        let config = NerConfig::default();
        assert_eq!(config.min_confidence, 0.7);
        assert_eq!(config.max_seq_length, 512);
        assert!(!config.label_mappings.is_empty());
    }

    #[test]
    fn test_label_mapping() {
        let config = NerConfig::default();
        let recognizer = NerRecognizer::from_config(config).unwrap();

        assert_eq!(
            recognizer.map_label_to_entity("B-PER"),
            Some(EntityType::Person)
        );
        assert_eq!(
            recognizer.map_label_to_entity("B-ORG"),
            Some(EntityType::Organization)
        );
        assert_eq!(recognizer.map_label_to_entity("O"), None);
    }

    #[test]
    fn test_recognizer_without_model() {
        let config = NerConfig::default();
        let recognizer = NerRecognizer::from_config(config).unwrap();

        // Should not be available without model
        assert!(!recognizer.is_available());

        // Should return empty results
        let results = recognizer.analyze("John Doe", "en").unwrap();
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn test_recognizer_without_model_has_no_token_type_ids() {
        let config = NerConfig::default();
        let recognizer = NerRecognizer::from_config(config).unwrap();

        // No session loaded → flag defaults to false
        assert!(!recognizer.needs_token_type_ids);
    }

    // ---- load_config_from_file tests ----

    /// Helper: write `contents` to a temp file and return its path.
    fn write_temp_config(contents: &str) -> tempfile::NamedTempFile {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(contents.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn test_load_config_valid_with_both_id2label_and_label_mappings() {
        let json = r#"{
            "id2label": {
                "0": "O",
                "1": "B-MISC",
                "2": "I-MISC",
                "3": "B-PER",
                "4": "I-PER",
                "5": "B-ORG",
                "6": "I-ORG",
                "7": "B-LOC",
                "8": "I-LOC"
            },
            "label_mappings": {
                "B-PER": "Person",
                "I-PER": "Person",
                "B-ORG": "Organization",
                "I-ORG": "Organization",
                "B-LOC": "Location",
                "I-LOC": "Location"
            },
            "min_confidence": 0.8,
            "max_seq_length": 256,
            "tokenizer_path": "/build/time/tokenizer.json"
        }"#;

        let f = write_temp_config(json);
        let cfg = NerRecognizer::load_config_from_file(f.path(), "/runtime/model.onnx").unwrap();

        // id2label parsed correctly
        assert_eq!(cfg.id2label.len(), 9);
        assert_eq!(cfg.id2label[&3], "B-PER");
        assert_eq!(cfg.id2label[&5], "B-ORG");

        // label_mappings parsed correctly (PascalCase → EntityType)
        assert_eq!(cfg.label_mappings.len(), 6);
        assert_eq!(cfg.label_mappings["B-PER"], EntityType::Person);
        assert_eq!(cfg.label_mappings["B-ORG"], EntityType::Organization);
        assert_eq!(cfg.label_mappings["B-LOC"], EntityType::Location);

        // Scalars honoured
        assert_eq!(cfg.min_confidence, 0.8);
        assert_eq!(cfg.max_seq_length, 256);

        // model_path overridden to runtime value
        assert_eq!(cfg.model_path, "/runtime/model.onnx");

        // tokenizer_path always suppressed regardless of config.json content
        assert!(cfg.tokenizer_path.is_none());
    }

    #[test]
    fn test_load_config_fallback_derives_label_mappings_from_id2label() {
        // config.json has id2label but no label_mappings → derived path
        let json = r#"{
            "id2label": {
                "0": "O",
                "1": "B-MISC",
                "2": "I-MISC",
                "3": "B-PER",
                "4": "I-PER",
                "5": "B-ORG",
                "6": "I-ORG",
                "7": "B-LOC",
                "8": "I-LOC"
            }
        }"#;

        let f = write_temp_config(json);
        let cfg = NerRecognizer::load_config_from_file(f.path(), "/m.onnx").unwrap();

        // Derived mappings should include PER, ORG, LOC but NOT MISC or stale defaults
        assert_eq!(cfg.label_mappings.get("B-PER"), Some(&EntityType::Person));
        assert_eq!(cfg.label_mappings.get("I-PER"), Some(&EntityType::Person));
        assert_eq!(
            cfg.label_mappings.get("B-ORG"),
            Some(&EntityType::Organization)
        );
        assert_eq!(cfg.label_mappings.get("B-LOC"), Some(&EntityType::Location));

        // MISC labels should NOT appear (no EntityType mapping exists)
        assert!(cfg.label_mappings.get("B-MISC").is_none());
        assert!(cfg.label_mappings.get("I-MISC").is_none());

        // No stale defaults: B-DATE / I-DATE should NOT leak in because
        // they are not present in the provided id2label
        assert!(cfg.label_mappings.get("B-DATE").is_none());
        assert!(cfg.label_mappings.get("I-DATE").is_none());
    }

    #[test]
    fn test_load_config_tokenizer_path_always_none() {
        // Even when config.json explicitly sets tokenizer_path, the loader
        // must suppress it (build-time path is stale at runtime).
        let json = r#"{
            "tokenizer_path": "/out/models/tokenizer.json",
            "id2label": { "0": "O", "1": "B-PER" }
        }"#;

        let f = write_temp_config(json);
        let cfg = NerRecognizer::load_config_from_file(f.path(), "/m.onnx").unwrap();
        assert!(cfg.tokenizer_path.is_none());
    }

    #[test]
    fn test_load_config_malformed_json_returns_err() {
        let f = write_temp_config("{ this is not valid json }}}");
        let result = NerRecognizer::load_config_from_file(f.path(), "/m.onnx");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_empty_json_uses_defaults() {
        // An empty JSON object should fall back to defaults for every field
        let f = write_temp_config("{}");
        let cfg = NerRecognizer::load_config_from_file(f.path(), "/m.onnx").unwrap();

        let defaults = NerConfig::default();
        assert_eq!(cfg.min_confidence, defaults.min_confidence);
        assert_eq!(cfg.max_seq_length, defaults.max_seq_length);
        // id2label falls back to defaults (no "id2label" key in JSON)
        assert_eq!(cfg.id2label.len(), defaults.id2label.len());
    }
}
