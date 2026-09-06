// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Reversible tokens and the sealed mappings that back them.
//!
//! Tokenization replaces a detected value with a stable placeholder such as
//! `[EMAIL_ADDRESS_1]`. The original value is sealed with AES-256-GCM before it
//! leaves this module, so a token map backend only ever stores ciphertext.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand::Rng as _;
use redact_core::anonymizers::encrypt::EncryptAnonymizer;
use redact_core::EntityType;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Tokenization failures.
#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    /// The configured data encryption key could not be used.
    #[error("invalid data encryption key: {0}")]
    InvalidKey(String),

    /// Sealing a value failed.
    #[error("could not seal token mapping: {0}")]
    Seal(String),

    /// Opening a sealed value failed.
    #[error("could not open token mapping: {0}")]
    Open(String),
}

/// A 32-byte data encryption key used to seal token mappings.
///
/// The key never leaves the process. Sealed values are portable across
/// gateway instances that share the same key, which is what allows a
/// horizontally scaled deployment to restore tokens minted by a peer.
#[derive(Clone)]
pub struct Dek {
    key: [u8; 32],
}

impl std::fmt::Debug for Dek {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Dek").finish_non_exhaustive()
    }
}

impl Dek {
    /// Build a key from raw bytes.
    pub fn from_bytes(key: [u8; 32]) -> Self {
        Self { key }
    }

    /// Decode a base64 encoded 32-byte key.
    pub fn from_base64(encoded: &str) -> Result<Self, TokenError> {
        let raw = BASE64
            .decode(encoded.trim())
            .map_err(|e| TokenError::InvalidKey(e.to_string()))?;
        let key: [u8; 32] = raw.try_into().map_err(|raw: Vec<u8>| {
            TokenError::InvalidKey(format!("expected 32 bytes, got {}", raw.len()))
        })?;
        Ok(Self { key })
    }

    /// Generate a random key.
    ///
    /// A generated key exists only for the lifetime of the process, so tokens
    /// minted with it cannot be restored after a restart or by another replica.
    pub fn generate() -> Result<Self, TokenError> {
        let mut key = [0u8; 32];
        rand::rng().fill_bytes(&mut key);
        Ok(Self { key })
    }

    /// Encode this key as base64 so it can be persisted by an operator.
    pub fn to_base64(&self) -> String {
        BASE64.encode(self.key)
    }

    /// Seal a plaintext value.
    pub fn seal(&self, plaintext: &str) -> Result<String, TokenError> {
        EncryptAnonymizer::with_dek(self.key)
            .seal_with_dek(plaintext)
            .map_err(|e| TokenError::Seal(e.to_string()))
    }

    /// Open a sealed value.
    pub fn open(&self, sealed: &str) -> Result<String, TokenError> {
        EncryptAnonymizer::decrypt_with_dek(&self.key, sealed)
            .map_err(|e| TokenError::Open(e.to_string()))
    }
}

/// One reversible token and its sealed original value.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMapping {
    /// Placeholder written into the outbound payload, e.g. `[EMAIL_ADDRESS_1]`.
    pub token: String,
    /// Entity type that produced the token.
    pub entity_type: String,
    /// Base64 AES-256-GCM envelope holding the original value.
    pub sealed_value: String,
    /// When the mapping was created.
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Per-conversation token allocation state.
///
/// A session keeps one token per distinct value so the same person referenced
/// twice in a prompt is tokenized consistently, which materially improves model
/// output quality compared with minting a fresh token per occurrence.
#[derive(Debug)]
pub struct TokenSession {
    id: String,
    tenant: String,
    dek: Arc<Dek>,
    counters: BTreeMap<String, usize>,
    by_value: HashMap<String, String>,
    mappings: Vec<TokenMapping>,
}

impl TokenSession {
    /// Start a session with no previously issued tokens.
    pub fn new(id: impl Into<String>, tenant: impl Into<String>, dek: Arc<Dek>) -> Self {
        Self {
            id: id.into(),
            tenant: tenant.into(),
            dek,
            counters: BTreeMap::new(),
            by_value: HashMap::new(),
            mappings: Vec::new(),
        }
    }

    /// Resume a session from mappings previously loaded from a token map.
    pub fn resume(
        id: impl Into<String>,
        tenant: impl Into<String>,
        dek: Arc<Dek>,
        existing: Vec<TokenMapping>,
    ) -> Self {
        let mut session = Self::new(id, tenant, dek);
        for mapping in existing {
            if let Some(index) = token_index(&mapping.token) {
                let counter = session
                    .counters
                    .entry(mapping.entity_type.clone())
                    .or_insert(0);
                *counter = (*counter).max(index);
            }
            if let Ok(plaintext) = session.dek.open(&mapping.sealed_value) {
                session
                    .by_value
                    .insert(plaintext.clone(), mapping.token.clone());
                if mapping.entity_type == EntityType::Person.as_str() {
                    let key = person_reuse_key(&plaintext);
                    if key != plaintext {
                        session.by_value.insert(key, mapping.token.clone());
                    }
                }
            }
            session.mappings.push(mapping);
        }
        session.mappings.clear();
        session
    }

    /// Session identifier.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Tenant that owns this session.
    pub fn tenant(&self) -> &str {
        &self.tenant
    }

    /// Issue (or reuse) a token for a detected value.
    pub fn token_for(
        &mut self,
        entity_type: &EntityType,
        plaintext: &str,
    ) -> Result<String, TokenError> {
        if let Some(existing) = self.by_value.get(plaintext) {
            return Ok(existing.clone());
        }
        if *entity_type == EntityType::Person {
            let key = person_reuse_key(plaintext);
            if let Some(existing) = self.by_value.get(&key) {
                return Ok(existing.clone());
            }
        }

        let label = entity_type.as_str().to_string();
        let counter = self.counters.entry(label.clone()).or_insert(0);
        *counter += 1;
        let token = format!("[{label}_{counter}]");

        let sealed = self.dek.seal(plaintext)?;
        self.by_value.insert(plaintext.to_string(), token.clone());
        if *entity_type == EntityType::Person {
            let key = person_reuse_key(plaintext);
            if key != plaintext {
                self.by_value.insert(key, token.clone());
            }
        }
        self.mappings.push(TokenMapping {
            token: token.clone(),
            entity_type: label,
            sealed_value: sealed,
            created_at: chrono::Utc::now(),
        });
        Ok(token)
    }

    /// Mappings minted during this request.
    pub fn new_mappings(&self) -> &[TokenMapping] {
        &self.mappings
    }

    /// Take the mappings minted during this request.
    pub fn take_new_mappings(&mut self) -> Vec<TokenMapping> {
        std::mem::take(&mut self.mappings)
    }

    /// Whether any token was issued.
    pub fn is_empty(&self) -> bool {
        self.mappings.is_empty()
    }
}

/// PERSON vault keys: trim, drop a trailing `'s`, ASCII-fold. `Nimbus` and
/// `Nimbus's` therefore share one token without a platform-side cache.
fn person_reuse_key(plaintext: &str) -> String {
    let trimmed = plaintext.trim();
    let bare = ["'s", "’s", "'S", "’S"]
        .iter()
        .find(|suffix| trimmed.len() > suffix.len() && trimmed.ends_with(*suffix))
        .map(|suffix| &trimmed[..trimmed.len() - suffix.len()])
        .unwrap_or(trimmed);
    bare.to_ascii_lowercase()
}

fn token_index(token: &str) -> Option<usize> {
    token
        .trim_end_matches(']')
        .rsplit('_')
        .next()
        .and_then(|tail| tail.parse::<usize>().ok())
}

/// Result of restoring tokens in a payload.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Tokens replaced with their original values.
    pub restored: usize,
    /// Tokens present in the text with no known mapping.
    pub missing: usize,
}

/// Replace tokens in `text` with their original values.
///
/// Tokens without a mapping are left verbatim and counted, because deleting
/// them would silently corrupt a model answer.
pub fn restore_text(text: &str, lookup: &HashMap<String, String>) -> (String, RestoreOutcome) {
    let mut outcome = RestoreOutcome::default();
    if text.is_empty() {
        return (text.to_string(), outcome);
    }

    let mut result = String::with_capacity(text.len());
    let mut rest = text;

    while let Some(open) = rest.find('[') {
        result.push_str(&rest[..open]);
        let after = &rest[open..];
        match after.find(']') {
            Some(close) => {
                let candidate = &after[..=close];
                if is_token_shaped(candidate) {
                    match lookup.get(candidate) {
                        Some(original) => {
                            result.push_str(original);
                            outcome.restored += 1;
                        }
                        None => {
                            result.push_str(candidate);
                            outcome.missing += 1;
                        }
                    }
                } else {
                    result.push_str(candidate);
                }
                rest = &after[close + 1..];
            }
            None => {
                result.push_str(after);
                rest = "";
                break;
            }
        }
    }
    result.push_str(rest);
    (result, outcome)
}

/// Derive the token-map session key that binds a caller-supplied session id to
/// an authenticated subject.
///
/// Callers continue to address sessions with their own id (header or
/// `/v1/restore` body). Persistence uses
/// `hex(SHA-256(subject || 0x00 || caller_session_id))` so:
/// - one subject cannot read another's mappings even inside a shared tenant;
/// - the raw subject never appears in vault paths (no path-injection risk and
///   no subject leakage into storage keys);
/// - unknown sessions and foreign-subject sessions are indistinguishable
///   (empty mapping list either way — no probing oracle).
pub fn subject_bound_session_key(caller_session_id: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(subject.as_bytes());
    hasher.update([0u8]);
    hasher.update(caller_session_id.as_bytes());
    let digest = hasher.finalize();
    digest
        .iter()
        .fold(String::with_capacity(64), |mut out, byte| {
            use std::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
}

/// Whether a bracketed string looks like a gateway token, e.g. `[US_SSN_2]`.
fn is_token_shaped(candidate: &str) -> bool {
    let inner = candidate
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or("");
    let Some((label, index)) = inner.rsplit_once('_') else {
        return false;
    };
    !label.is_empty()
        && !index.is_empty()
        && index.chars().all(|c| c.is_ascii_digit())
        && label
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session() -> TokenSession {
        TokenSession::new("sess-1", "tenant-1", Arc::new(Dek::generate().unwrap()))
    }

    #[test]
    fn seal_and_open_round_trip() {
        let dek = Dek::generate().unwrap();
        let sealed = dek.seal("alice@example.com").unwrap();
        assert_ne!(sealed, "alice@example.com");
        assert_eq!(dek.open(&sealed).unwrap(), "alice@example.com");
    }

    #[test]
    fn keys_are_portable_via_base64() {
        let dek = Dek::generate().unwrap();
        let encoded = dek.to_base64();
        let restored = Dek::from_base64(&encoded).unwrap();
        let sealed = dek.seal("secret").unwrap();
        assert_eq!(restored.open(&sealed).unwrap(), "secret");
    }

    #[test]
    fn short_keys_are_rejected() {
        assert!(Dek::from_base64("dG9vLXNob3J0").is_err());
        assert!(Dek::from_base64("not base64!!").is_err());
    }

    #[test]
    fn a_foreign_key_cannot_open_a_sealed_value() {
        let sealed = Dek::generate().unwrap().seal("secret").unwrap();
        assert!(Dek::generate().unwrap().open(&sealed).is_err());
    }

    #[test]
    fn tokens_are_numbered_per_entity_type() {
        let mut session = session();
        let first = session
            .token_for(&EntityType::EmailAddress, "a@example.com")
            .unwrap();
        let second = session
            .token_for(&EntityType::EmailAddress, "b@example.com")
            .unwrap();
        let phone = session
            .token_for(&EntityType::PhoneNumber, "555-0100")
            .unwrap();
        assert_eq!(first, "[EMAIL_ADDRESS_1]");
        assert_eq!(second, "[EMAIL_ADDRESS_2]");
        assert_eq!(phone, "[PHONE_NUMBER_1]");
    }

    #[test]
    fn repeated_values_reuse_the_same_token() {
        let mut session = session();
        let first = session
            .token_for(&EntityType::Person, "Alice Smith")
            .unwrap();
        let again = session
            .token_for(&EntityType::Person, "Alice Smith")
            .unwrap();
        assert_eq!(first, again);
        assert_eq!(session.new_mappings().len(), 1);
    }

    #[test]
    fn person_possessive_and_case_reuse_one_token() {
        let mut session = session();
        let first = session.token_for(&EntityType::Person, "Nimbus").unwrap();
        let poss = session.token_for(&EntityType::Person, "Nimbus's").unwrap();
        let folded = session.token_for(&EntityType::Person, "nimbus").unwrap();
        assert_eq!(first, "[PERSON_1]");
        assert_eq!(poss, first);
        assert_eq!(folded, first);
        assert_eq!(session.new_mappings().len(), 1);

        let other = session.token_for(&EntityType::Person, "Sorrel").unwrap();
        assert_eq!(other, "[PERSON_2]");
    }

    #[test]
    fn resume_reuses_normalized_person() {
        let dek = Arc::new(Dek::generate().unwrap());
        let mut original = TokenSession::new("s", "t", dek.clone());
        original.token_for(&EntityType::Person, "Reed").unwrap();
        let existing = original.take_new_mappings();

        let mut resumed = TokenSession::resume("s", "t", dek, existing);
        let reused = resumed.token_for(&EntityType::Person, "Reed's").unwrap();
        assert_eq!(reused, "[PERSON_1]");
        assert!(resumed.is_empty(), "normalized reuse should not mint");
    }

    #[test]
    fn mappings_only_carry_ciphertext() {
        let mut session = session();
        session
            .token_for(&EntityType::EmailAddress, "alice@example.com")
            .unwrap();
        let mapping = &session.new_mappings()[0];
        assert!(!mapping.sealed_value.contains("alice"));
        assert_eq!(mapping.entity_type, "EMAIL_ADDRESS");
    }

    #[test]
    fn resuming_continues_numbering_and_reuses_values() {
        let dek = Arc::new(Dek::generate().unwrap());
        let mut original = TokenSession::new("s", "t", dek.clone());
        original
            .token_for(&EntityType::EmailAddress, "a@example.com")
            .unwrap();
        let existing = original.take_new_mappings();

        let mut resumed = TokenSession::resume("s", "t", dek, existing);
        let reused = resumed
            .token_for(&EntityType::EmailAddress, "a@example.com")
            .unwrap();
        assert_eq!(reused, "[EMAIL_ADDRESS_1]");
        assert!(resumed.is_empty(), "reuse should not mint a new mapping");

        let fresh = resumed
            .token_for(&EntityType::EmailAddress, "b@example.com")
            .unwrap();
        assert_eq!(fresh, "[EMAIL_ADDRESS_2]");
    }

    #[test]
    fn restore_replaces_known_tokens_only() {
        let mut lookup = HashMap::new();
        lookup.insert("[EMAIL_ADDRESS_1]".to_string(), "a@example.com".to_string());
        let (text, outcome) = restore_text(
            "Mail [EMAIL_ADDRESS_1] and [EMAIL_ADDRESS_9] about [urgent] matters",
            &lookup,
        );
        assert_eq!(
            text,
            "Mail a@example.com and [EMAIL_ADDRESS_9] about [urgent] matters"
        );
        assert_eq!(outcome.restored, 1);
        assert_eq!(outcome.missing, 1);
    }

    #[test]
    fn restore_leaves_ordinary_brackets_alone() {
        let lookup = HashMap::new();
        let (text, outcome) = restore_text("array[0] and [see note] and [unclosed", &lookup);
        assert_eq!(text, "array[0] and [see note] and [unclosed");
        assert_eq!(outcome, RestoreOutcome::default());
    }

    #[test]
    fn token_shape_detection_is_conservative() {
        assert!(is_token_shaped("[US_SSN_2]"));
        assert!(is_token_shaped("[PERSON_10]"));
        assert!(!is_token_shaped("[PERSON]"));
        assert!(!is_token_shaped("[person_1]"));
        assert!(!is_token_shaped("[EMAIL_ADDRESS_x]"));
    }

    #[test]
    fn subject_bound_keys_isolate_subjects_and_avoid_raw_subject() {
        let a = subject_bound_session_key("s1", "key:aaaaaaaa");
        let b = subject_bound_session_key("s1", "key:bbbbbbbb");
        let a_again = subject_bound_session_key("s1", "key:aaaaaaaa");
        assert_eq!(a, a_again);
        assert_ne!(a, b);
        assert_eq!(a.len(), 64);
        assert!(!a.contains("key:"));
        assert!(!a.contains("aaaaaaaa"));
        assert!(!a.contains("s1"));
    }
}
