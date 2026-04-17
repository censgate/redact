// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Redact Core - PII Detection and Anonymization Engine
//!
//! A high-performance, Rust-based PII detection and anonymization library
//! designed as a replacement for Microsoft Presidio.
//!
//! # Features
//!
//! - **Pattern-based Detection**: Regex-based PII recognizers for structured data
//! - **NER Support**: Named Entity Recognition using ONNX Runtime (via redact-ner)
//! - **Multiple Anonymization Strategies**: Replace, mask, hash, encrypt
//! - **Policy-Aware**: Configurable rules and thresholds
//! - **Multi-platform**: Server, WASM, mobile support
//! - **High Performance**: Zero-copy where possible, efficient overlap resolution
//!
//! # Example
//!
//! ```no_run
//! use redact_core::{AnalyzerEngine, AnonymizerConfig, AnonymizationStrategy};
//!
//! let mut analyzer = AnalyzerEngine::new();
//!
//! let text = "Contact John Doe at john@example.com or 555-1234";
//! let result = analyzer.analyze(text, None).unwrap();
//!
//! println!("Detected {} entities", result.detected_entities.len());
//!
//! // Anonymize with replacement strategy
//! let config = AnonymizerConfig {
//!     strategy: AnonymizationStrategy::Replace,
//!     ..Default::default()
//! };
//! let anonymized = analyzer.anonymize(text, None, &config).unwrap();
//! println!("Anonymized: {}", anonymized.text);
//! ```

pub mod anonymizers;
pub mod engine;
pub mod policy;
pub mod recognizers;
pub mod types;

// Re-export commonly used types
pub use anonymizers::{AnonymizationStrategy, AnonymizerConfig, AnonymizerRegistry};
pub use engine::AnalyzerEngine;
pub use recognizers::{Recognizer, RecognizerRegistry};
pub use types::{
    AnalysisMetadata, AnalysisResult, AnonymizedResult, EntityType, RecognizerResult, Token,
};

/// Version of the redact-core library
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }
}
