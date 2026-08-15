// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Charset-aware Shannon entropy scoring for generic secrets.
//!
//! This module is WASM-safe: no filesystem, clock, network, or extra crates.

use std::collections::BTreeMap;

/// Minimum candidate length (inclusive) for generic secrets.
pub const MIN_LEN: usize = 20;
/// Maximum candidate length (inclusive) for generic secrets.
pub const MAX_LEN: usize = 128;
/// Margin below the expected uniform-string entropy.
pub const ENTROPY_MARGIN: f64 = 0.30;
/// Absolute information-content floor in bits.
pub const MIN_BITS: f64 = 80.0;
/// Confidence at the entropy floor.
pub const CONFIDENCE_FLOOR: f32 = 0.60;
/// Confidence near the charset maximum. Never ≥ 0.90 (prefixed types).
pub const CONFIDENCE_CEILING: f32 = 0.85;

/// Character-set class used to pick a threshold.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CharsetClass {
    Hex,
    Base64,
    Alphanumeric,
}

impl CharsetClass {
    /// Alphabet size used for the uniform-entropy expectation.
    pub fn alphabet_size(self) -> usize {
        match self {
            CharsetClass::Hex => 16,
            CharsetClass::Base64 => 64,
            CharsetClass::Alphanumeric => 62,
        }
    }
}

/// Shannon entropy in bits per character, computed over Unicode scalar values.
pub fn shannon_entropy(value: &str) -> f64 {
    let n = value.chars().count();
    if n == 0 {
        return 0.0;
    }
    let mut counts: BTreeMap<char, usize> = BTreeMap::new();
    for c in value.chars() {
        *counts.entry(c).or_insert(0) += 1;
    }
    let n_f = n as f64;
    // BTreeMap so the fold order is stable (HashMap iteration is not).
    counts.values().fold(0.0, |acc, &count| {
        let p = count as f64 / n_f;
        acc - p * p.log2()
    })
}

/// Expected Shannon entropy of a uniformly random string of length `n` over `k` symbols.
///
/// Miller–Madow: \(E[\hat H] \approx \log_2 K - (K-1)/(2 N \ln 2)\).
pub fn expected_uniform_entropy(k: usize, n: usize) -> f64 {
    if n == 0 || k == 0 {
        return 0.0;
    }
    let k_f = k as f64;
    let n_f = n as f64;
    k_f.log2() - (k_f - 1.0) / (2.0 * n_f * std::f64::consts::LN_2)
}

/// Classify a candidate. Markerless `[A-Za-z0-9]+` is alphanumeric, never base64.
pub fn classify_charset(value: &str) -> Option<CharsetClass> {
    if value.is_empty() {
        return None;
    }
    if is_screaming_snake(value) || is_path_shaped(value) {
        return None;
    }

    let all_hex = value.chars().all(|c| c.is_ascii_hexdigit());
    let has_hex_letter = value.chars().any(|c| matches!(c, 'a'..='f' | 'A'..='F'));
    if all_hex && has_hex_letter {
        return Some(CharsetClass::Hex);
    }

    let has_plus_slash_eq = value.chars().any(|c| matches!(c, '+' | '/' | '='));
    let has_minus = value.contains('-');
    let has_underscore = value.contains('_');
    let base64_alphabet = value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '-' | '_'));
    if base64_alphabet && (has_plus_slash_eq || (has_minus && has_underscore)) {
        return Some(CharsetClass::Base64);
    }

    if value.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Some(CharsetClass::Alphanumeric);
    }
    None
}

fn is_screaming_snake(value: &str) -> bool {
    value.contains('_')
        && value
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && value.chars().any(|c| c.is_ascii_uppercase())
}

fn is_path_shaped(value: &str) -> bool {
    value.contains('/') && value.contains('.')
        || value.starts_with('/')
        || value.contains("/build/")
        || value.contains("/time/")
}

/// Score a candidate against the length-aware floor. `None` means reject.
pub fn score_entropy(value: &str) -> Option<f32> {
    let n = value.chars().count();
    if !(MIN_LEN..=MAX_LEN).contains(&n) {
        return None;
    }
    let class = classify_charset(value)?;
    if class != CharsetClass::Hex {
        let has_digit = value.chars().any(|c| c.is_ascii_digit());
        let has_letter = value.chars().any(|c| c.is_ascii_alphabetic());
        if !has_digit || !has_letter {
            return None;
        }
    }
    let h = shannon_entropy(value);
    let k = class.alphabet_size();
    let floor = expected_uniform_entropy(k, n) - ENTROPY_MARGIN;
    if h < floor {
        return None;
    }
    if (n as f64) * h < MIN_BITS {
        return None;
    }
    let max = (k as f64).log2();
    let span = (max - floor).max(1e-6);
    let t = ((h - floor) / span).clamp(0.0, 1.0);
    let confidence = CONFIDENCE_FLOOR as f64 + t * (CONFIDENCE_CEILING - CONFIDENCE_FLOOR) as f64;
    Some(confidence as f32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markerless_alnum_is_not_base64() {
        let value = "AbCdEfGhIjKlMnOpQrStUvWx0123";
        assert_eq!(classify_charset(value), Some(CharsetClass::Alphanumeric));
    }

    #[test]
    fn hex_requires_a_to_f() {
        assert_eq!(
            classify_charset("abcdef0123456789abcdef0123456789"),
            Some(CharsetClass::Hex)
        );
        assert_eq!(
            classify_charset("01234567890123456789012345678901"),
            Some(CharsetClass::Alphanumeric)
        );
    }

    #[test]
    fn base64_needs_structural_evidence() {
        assert_eq!(
            classify_charset("dXNlcm5hbWU6cGFzc3dvcmQ="),
            Some(CharsetClass::Base64)
        );
        assert_eq!(
            classify_charset("abc-def_ghi-jkl_mnopqrstuvwx"),
            Some(CharsetClass::Base64)
        );
    }

    #[test]
    fn screaming_snake_is_not_base64() {
        assert_eq!(classify_charset("ANTHROPIC_API_KEY_PLACEHOLDER_XX"), None);
        assert_eq!(classify_charset("A1B2C3D4E5F6G7H8I9A_"), None);
        assert!(score_entropy("A1B2C3D4E5F6G7H8I9A_").is_none());
    }

    #[test]
    fn empty_entropy_is_zero() {
        assert_eq!(shannon_entropy(""), 0.0);
    }

    #[test]
    fn uniform_hex_passes_length_aware_floor() {
        // 32 hex chars drawn from a wide alphabet.
        let value = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        assert!(score_entropy(value).is_some());
    }

    #[test]
    fn short_values_are_rejected() {
        assert!(score_entropy("abcdef0123456789").is_none());
    }

    #[test]
    fn confidence_stays_in_band() {
        let value = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let score = score_entropy(value).unwrap();
        assert!((CONFIDENCE_FLOOR..=CONFIDENCE_CEILING).contains(&score));
    }
}
