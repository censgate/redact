// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! NER-based PII Recognition using ONNX Runtime
//!
//! This crate provides Named Entity Recognition (NER) capabilities for PII detection
//! using quantized ONNX models for efficient inference.
//!
//! # Features
//!
//! - ONNX Runtime integration for model inference
//! - Support for quantized int8 models
//! - Token-based NER with entity span detection
//! - Compatible with various NER model architectures (BERT, RoBERTa, etc.)
//!
//! # Example
//!
//! ```no_run
//! use redact_ner::NerRecognizer;
//! use redact_core::recognizers::Recognizer;
//!
//! // Load model
//! let recognizer = NerRecognizer::from_file("model.onnx").unwrap();
//!
//! // Analyze text
//! let text = "John Doe works at Acme Corp in New York";
//! let results = recognizer.analyze(text, "en").unwrap();
//!
//! for result in results {
//!     println!("{:?}: {}", result.entity_type, result.text.unwrap());
//! }
//! ```

mod recognizer;
mod tokenizer_wrapper;

pub use recognizer::{NerConfig, NerRecognizer};

#[cfg(test)]
mod tests {
    // All tests are in the submodules (recognizer and tokenizer_wrapper)
}
