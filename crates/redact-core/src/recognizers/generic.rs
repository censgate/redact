// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Context-gated generic secret detection (`GENERIC_SECRET`).
//!
//! Assignment-like positions only. Value-only spans. Shared with pack loaders
//! via [`evaluate_generic_candidate`].

use lazy_static::lazy_static;
use regex::Regex;

use super::entropy::score_entropy;
use super::Recognizer;
use crate::types::{EntityType, RecognizerResult};
use anyhow::Result;

const MIN_SCORE: f32 = 0.5;
const UUID_STRONG_CONFIDENCE: f32 = 0.70;

const ALLOW_TOKENS: &[&str] = &[
    "secret",
    "token",
    "password",
    "passwd",
    "pwd",
    "apikey",
    "credential",
    "auth",
    "bearer",
];

const ALLOW_PAIRS: &[(&str, &str)] = &[
    ("api", "key"),
    ("access", "key"),
    ("access", "token"),
    ("private", "key"),
    ("client", "secret"),
    ("x", "api"),
];

const DENY_TOKENS: &[&str] = &[
    "checksum",
    "integrity",
    "digest",
    "sha",
    "sha1",
    "sha256",
    "md5",
    "etag",
    "revision",
    "rev",
    "commit",
    "fingerprint",
    "thumbprint",
    "tokenizer",
];

const DENY_PAIRS: &[(&str, &str)] = &[
    ("key", "id"),
    ("public", "key"),
    ("secret", "name"),
    ("token", "type"),
];

const STRONG_KEYWORDS: &[&str] = &["api_key", "client_secret", "access_token", "secret"];

const STOPWORDS: &[&str] = &[
    "password",
    "changeme",
    "secret",
    "xxx",
    "xxxx",
    "xxxxx",
    "test",
    "example",
    "todo",
    "placeholder",
    "your_api_key_here",
    "your-key-here",
    "your_key_here",
];

lazy_static! {
    static ref ASSIGNMENT: Regex = Regex::new(
        r#"(?x)(?i)
        (?:^|[\s;{,])
        (?:export\s+|-\s*e\s+)?
        ["']?
        (?P<key>[A-Za-z_][A-Za-z0-9_.-]*)
        ["']?
        \s*[=:]\s*
        ["']?
        (?P<value>[^\s"'<>,;]+)
        "#
    )
    .expect("assignment regex");
    static ref BEARER: Regex =
        Regex::new(r#"(?i)(?:^|[\s;])Authorization\s*:\s*Bearer\s+(?P<value>[^\s"'<>,;]+)"#)
            .expect("bearer regex");
    static ref UUID_RE: Regex =
        Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
            .expect("uuid regex");
    static ref HEX_COLOR: Regex =
        Regex::new(r"(?i)^#?(?:[0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$").expect("hex color regex");
}

/// How the left-hand side of an assignment should be treated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LhsClass {
    Secret,
    Digest,
    Other,
}

/// Split a key on `_` / `-` / `.` and camelCase boundaries.
pub fn segment_key(key: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = key.chars().collect();
    for (i, &c) in chars.iter().enumerate() {
        if c == '_' || c == '-' || c == '.' {
            if !current.is_empty() {
                segments.push(std::mem::take(&mut current));
            }
            continue;
        }
        if c.is_ascii_uppercase()
            && i > 0
            && (chars[i - 1].is_ascii_lowercase() || chars[i - 1].is_ascii_digit())
            && !current.is_empty()
        {
            segments.push(std::mem::take(&mut current));
        }
        current.push(c.to_ascii_lowercase());
    }
    if !current.is_empty() {
        segments.push(current);
    }
    segments
}

fn has_pair(segments: &[String], left: &str, right: &str) -> bool {
    segments.windows(2).any(|w| w[0] == left && w[1] == right)
}

fn has_token(segments: &[String], token: &str) -> bool {
    if token.contains('_') || token.contains('-') {
        let parts: Vec<&str> = token.split(['_', '-']).collect();
        if parts.len() == 2 {
            return has_pair(segments, parts[0], parts[1]);
        }
    }
    segments.iter().any(|s| s == token)
}

fn env_suffix_is_secret(segments: &[String]) -> bool {
    let n = segments.len();
    if n == 0 {
        return false;
    }
    matches!(
        segments[n - 1].as_str(),
        "secret" | "token" | "password" | "passwd"
    ) || (n >= 2
        && segments[n - 1] == "key"
        && (segments[n - 2] == "api" || segments[n - 2] == "access"))
}

/// Classify an assignment key using the closed allow/deny lists.
pub fn classify_lhs(key: &str) -> LhsClass {
    let segments = segment_key(key);
    let allow = ALLOW_TOKENS.iter().any(|t| has_token(&segments, t))
        || ALLOW_PAIRS.iter().any(|(a, b)| has_pair(&segments, a, b))
        || env_suffix_is_secret(&segments);
    if allow {
        return LhsClass::Secret;
    }
    let deny = DENY_TOKENS.iter().any(|t| has_token(&segments, t))
        || DENY_PAIRS.iter().any(|(a, b)| has_pair(&segments, a, b))
        || has_token(&segments, "hash");
    if deny {
        return LhsClass::Digest;
    }
    LhsClass::Other
}

fn is_strong_keyword(key: &str) -> bool {
    let segments = segment_key(key);
    STRONG_KEYWORDS.iter().any(|kw| has_token(&segments, kw))
}

fn is_stopword(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    STOPWORDS.contains(&lower.as_str())
        || lower.starts_with("your_")
        || lower.starts_with("your-")
        || lower.ends_with("_here")
        || lower.ends_with("-here")
}

fn is_identifier_only(value: &str) -> bool {
    !value.chars().any(|c| c.is_ascii_digit())
        && value
            .chars()
            .all(|c| c.is_ascii_alphabetic() || matches!(c, '_' | '-' | '.'))
}

fn is_hash_shaped_hex(value: &str) -> bool {
    let n = value.chars().count();
    matches!(n, 32 | 40 | 64 | 128) && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_jwt(value: &str) -> bool {
    value.starts_with("eyJ") && value.matches('.').count() >= 2
}

fn looks_like_pem(value: &str) -> bool {
    value.contains("BEGIN") && value.contains("PRIVATE KEY")
}

fn surrounding_is_data_uri(surrounding: &str) -> bool {
    let lower = surrounding.to_ascii_lowercase();
    lower.contains("data:image") || lower.contains("data:application") || lower.contains("data:")
}

/// Shared generic-candidate validator used by core and pack loaders.
///
/// Packs must pass the same LHS and surrounding context; they cannot score a
/// bare value and skip the gate.
pub fn evaluate_generic_candidate(value: &str, lhs: &str, surrounding: &str) -> Option<f32> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if is_stopword(value) {
        return None;
    }
    if is_identifier_only(value) {
        return None;
    }
    if HEX_COLOR.is_match(value) {
        return None;
    }
    if looks_like_jwt(value) || looks_like_pem(value) {
        return None;
    }
    if surrounding_is_data_uri(surrounding) {
        return None;
    }

    match classify_lhs(lhs) {
        LhsClass::Other => None,
        LhsClass::Digest => None,
        LhsClass::Secret => {
            if UUID_RE.is_match(value) {
                return if is_strong_keyword(lhs) {
                    Some(UUID_STRONG_CONFIDENCE)
                } else {
                    None
                };
            }
            if is_hash_shaped_hex(value) && classify_lhs(lhs) == LhsClass::Digest {
                return None;
            }
            score_entropy(value)
        }
    }
}

fn floor_char_boundary(s: &str, mut i: usize) -> usize {
    while i > 0 && !s.is_char_boundary(i) {
        i -= 1;
    }
    i
}

fn ceil_char_boundary(s: &str, mut i: usize) -> usize {
    while i < s.len() && !s.is_char_boundary(i) {
        i += 1;
    }
    i
}

/// Context-gated generic secret recognizer.
#[derive(Debug)]
pub struct GenericSecretRecognizer {
    name: String,
}

impl GenericSecretRecognizer {
    pub fn new() -> Self {
        Self {
            name: "GenericSecretRecognizer".to_string(),
        }
    }
}

impl Default for GenericSecretRecognizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Recognizer for GenericSecretRecognizer {
    fn name(&self) -> &str {
        &self.name
    }

    fn supported_entities(&self) -> &[EntityType] {
        &[EntityType::GenericSecret]
    }

    fn min_score(&self) -> f32 {
        MIN_SCORE
    }

    fn analyze(&self, text: &str, _language: &str) -> Result<Vec<RecognizerResult>> {
        let mut results = Vec::new();
        for caps in ASSIGNMENT.captures_iter(text) {
            let Some(key) = caps.name("key") else {
                continue;
            };
            let Some(value) = caps.name("value") else {
                continue;
            };
            if key.as_str().eq_ignore_ascii_case("authorization")
                && value.as_str().eq_ignore_ascii_case("basic")
            {
                continue;
            }
            let window_start = floor_char_boundary(text, key.start().saturating_sub(24));
            let window_end = ceil_char_boundary(text, (value.end() + 24).min(text.len()));
            let surrounding = &text[window_start..window_end];
            if let Some(score) =
                evaluate_generic_candidate(value.as_str(), key.as_str(), surrounding)
            {
                if score >= MIN_SCORE {
                    results.push(
                        RecognizerResult::new(
                            EntityType::GenericSecret,
                            value.start(),
                            value.end(),
                            score,
                            self.name.clone(),
                        )
                        .with_text(text),
                    );
                }
            }
        }
        for caps in BEARER.captures_iter(text) {
            let Some(value) = caps.name("value") else {
                continue;
            };
            let window_start = floor_char_boundary(text, value.start().saturating_sub(32));
            let window_end = ceil_char_boundary(text, (value.end() + 8).min(text.len()));
            let surrounding = &text[window_start..window_end];
            if let Some(score) =
                evaluate_generic_candidate(value.as_str(), "authorization_bearer", surrounding)
            {
                if score >= MIN_SCORE {
                    results.push(
                        RecognizerResult::new(
                            EntityType::GenericSecret,
                            value.start(),
                            value.end(),
                            score,
                            self.name.clone(),
                        )
                        .with_text(text),
                    );
                }
            }
        }
        Ok(results)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_secret_is_secret_lhs() {
        assert_eq!(classify_lhs("SHARED_SECRET"), LhsClass::Secret);
        assert_eq!(classify_lhs("shared_secret"), LhsClass::Secret);
    }

    #[test]
    fn checksum_is_digest() {
        assert_eq!(classify_lhs("checksum"), LhsClass::Digest);
        assert_eq!(classify_lhs("content_sha256"), LhsClass::Digest);
    }

    #[test]
    fn password_hash_is_secret() {
        assert_eq!(classify_lhs("password_hash"), LhsClass::Secret);
    }

    #[test]
    fn camel_case_public_key_is_digest() {
        assert_eq!(classify_lhs("public_key"), LhsClass::Digest);
        assert_eq!(classify_lhs("publicKey"), LhsClass::Digest);
        // `token` is an allow token, so it wins over the public_key pair.
        assert_eq!(classify_lhs("publicKeyToken"), LhsClass::Secret);
    }

    #[test]
    fn stopword_rejected() {
        assert!(evaluate_generic_candidate("password", "api_key", "").is_none());
        assert!(evaluate_generic_candidate("your-key-here", "api_key", "").is_none());
    }

    #[test]
    fn identifier_only_rejected() {
        assert!(evaluate_generic_candidate("SessionInterface", "token", "").is_none());
    }

    #[test]
    fn uuid_under_strong_keyword() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert!(evaluate_generic_candidate(uuid, "api_key", "").is_some());
        assert!(evaluate_generic_candidate(uuid, "revision", "").is_none());
        assert!(evaluate_generic_candidate(uuid, "name", "").is_none());
    }

    #[test]
    fn value_only_span() {
        let rec = GenericSecretRecognizer::new();
        let secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let text = format!("api_key={secret}");
        let hits = rec.analyze(&text, "en").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].start, "api_key=".len());
        assert_eq!(hits[0].end, text.len());
        assert_eq!(hits[0].text.as_deref(), Some(secret));
    }

    #[test]
    fn digest_assignment_emits_nothing() {
        let rec = GenericSecretRecognizer::new();
        let text = format!("integrity={}", "a".repeat(64));
        let hits = rec.analyze(&text, "en").unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn json_quoted_key_is_a_closed_form() {
        let rec = GenericSecretRecognizer::new();
        let secret = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
        let text = format!(r#"{{"client_secret": "{secret}"}}"#);
        let hits = rec.analyze(&text, "en").unwrap();
        assert_eq!(hits.len(), 1);
        assert_eq!(&text[hits[0].start..hits[0].end], secret);
    }
}
