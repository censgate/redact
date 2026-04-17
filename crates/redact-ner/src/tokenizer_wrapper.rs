// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

/// Tokenizer wrapper for NER models
///
/// Wraps the HuggingFace tokenizers crate and provides helpers for
/// converting between token offsets and character offsets
use anyhow::{anyhow, Result};
use std::path::Path;
use tokenizers::Tokenizer;

#[derive(Debug)]
pub struct TokenizerWrapper {
    tokenizer: Tokenizer,
}

impl TokenizerWrapper {
    /// Load tokenizer from a JSON file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let tokenizer =
            Tokenizer::from_file(path).map_err(|e| anyhow!("Failed to load tokenizer: {}", e))?;

        Ok(Self { tokenizer })
    }

    /// Encode text into tokens with character offsets
    pub fn encode(&self, text: &str, add_special_tokens: bool) -> Result<Encoding> {
        let encoding = self
            .tokenizer
            .encode(text, add_special_tokens)
            .map_err(|e| anyhow!("Tokenization failed: {}", e))?;

        let ids = encoding.get_ids().to_vec();
        let tokens = encoding.get_tokens().to_vec();
        let offsets = encoding.get_offsets().to_vec();
        let attention_mask = encoding.get_attention_mask().to_vec();

        Ok(Encoding {
            ids,
            tokens,
            offsets,
            attention_mask,
        })
    }

    /// Get the padding token ID
    pub fn get_padding_id(&self) -> Option<u32> {
        self.tokenizer.get_padding().map(|p| p.pad_id)
    }

    /// Get the vocabulary size
    #[allow(dead_code)]
    pub fn vocab_size(&self) -> usize {
        self.tokenizer.get_vocab_size(true)
    }
}

#[derive(Debug, Clone)]
pub struct Encoding {
    /// Token IDs
    pub ids: Vec<u32>,
    /// Token strings
    pub tokens: Vec<String>,
    /// Character offsets for each token (start, end)
    pub offsets: Vec<(usize, usize)>,
    /// Attention mask (1 for real tokens, 0 for padding)
    pub attention_mask: Vec<u32>,
}

impl Encoding {
    /// Pad or truncate to a specific length
    pub fn pad_to_length(&mut self, max_length: usize, pad_id: u32) {
        if self.ids.len() > max_length {
            // Truncate
            self.ids.truncate(max_length);
            self.tokens.truncate(max_length);
            self.offsets.truncate(max_length);
            self.attention_mask.truncate(max_length);
        } else if self.ids.len() < max_length {
            // Pad
            let padding_needed = max_length - self.ids.len();
            self.ids.extend(std::iter::repeat_n(pad_id, padding_needed));
            self.tokens
                .extend(std::iter::repeat_n("[PAD]".to_string(), padding_needed));
            self.offsets
                .extend(std::iter::repeat_n((0, 0), padding_needed));
            self.attention_mask
                .extend(std::iter::repeat_n(0, padding_needed));
        }
    }

    /// Get the number of real (non-padding) tokens
    #[allow(dead_code)]
    pub fn real_length(&self) -> usize {
        self.attention_mask.iter().filter(|&&m| m == 1).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encoding_pad_truncate() {
        let mut encoding = Encoding {
            ids: vec![1, 2, 3],
            tokens: vec!["a".to_string(), "b".to_string(), "c".to_string()],
            offsets: vec![(0, 1), (1, 2), (2, 3)],
            attention_mask: vec![1, 1, 1],
        };

        // Test padding
        encoding.pad_to_length(5, 0);
        assert_eq!(encoding.ids.len(), 5);
        assert_eq!(encoding.ids[3], 0);
        assert_eq!(encoding.ids[4], 0);
        assert_eq!(encoding.attention_mask[3], 0);
        assert_eq!(encoding.real_length(), 3);

        // Test truncation
        encoding.pad_to_length(2, 0);
        assert_eq!(encoding.ids.len(), 2);
        assert_eq!(encoding.real_length(), 2);
    }
}
