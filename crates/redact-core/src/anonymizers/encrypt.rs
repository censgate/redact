// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use super::{apply_anonymization, Anonymizer, AnonymizerConfig};
use crate::types::{AnonymizedResult, RecognizerResult, Token};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use anyhow::{anyhow, Result};
use pbkdf2::pbkdf2_hmac;
use rand::RngExt;
use sha2::Sha256;
use uuid::Uuid;

/// Version byte for key-once DEK envelopes (`0x01 || nonce(12) || ciphertext+tag`).
const DEK_ENVELOPE_VERSION: u8 = 0x01;

/// Minimum byte length for a DEK envelope after base64 decode (version + nonce).
const DEK_ENVELOPE_MIN_LEN: usize = 1 + 12;

/// Encrypt anonymizer for reversible anonymization
#[derive(Debug, Clone)]
pub struct EncryptAnonymizer {
    key_derivation_iterations: u32,
    dek: Option<[u8; 32]>,
}

impl EncryptAnonymizer {
    pub fn new() -> Self {
        Self {
            key_derivation_iterations: 100_000,
            dek: None,
        }
    }

    /// Create an encrypt anonymizer that seals values with a pre-derived 32-byte DEK.
    ///
    /// Uses AES-256-GCM directly (no PBKDF2, no per-value salt). Each seal generates a
    /// fresh random 12-byte nonce. Output is base64-encoded:
    /// `0x01 || nonce(12) || ciphertext_with_tag`.
    pub fn with_dek(dek: [u8; 32]) -> Self {
        Self {
            key_derivation_iterations: 100_000,
            dek: Some(dek),
        }
    }

    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.key_derivation_iterations = iterations;
        self
    }

    /// Seal a value using the configured DEK (key-once mode).
    pub fn seal_with_dek(&self, value: &str) -> Result<String> {
        let dek = self
            .dek
            .as_ref()
            .ok_or_else(|| anyhow!("DEK not configured; use EncryptAnonymizer::with_dek"))?;
        Self::seal_value_with_dek(dek, value)
    }

    /// Decrypt a key-once envelope produced by [`Self::seal_with_dek`] or [`Self::with_dek`].
    pub fn decrypt_with_dek(dek: &[u8; 32], envelope_b64: &str) -> Result<String> {
        let envelope = base64_decode(envelope_b64)?;
        Self::decrypt_envelope_with_dek(dek, &envelope)
    }

    /// Derive encryption key from password
    fn derive_key(&self, password: &str, salt: &[u8]) -> [u8; 32] {
        let mut key = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            salt,
            self.key_derivation_iterations,
            &mut key,
        );
        key
    }

    /// Encrypt a value
    fn encrypt_value(&self, value: &str, password: &str) -> Result<(String, Vec<u8>)> {
        // Generate cryptographically secure random salt
        let mut rng = rand::rng();
        let salt: [u8; 16] = rng.random();

        // Derive key
        let key_bytes = self.derive_key(password, &salt);
        let cipher = Aes256Gcm::new((&key_bytes).into());

        // Generate cryptographically secure random nonce
        let nonce_bytes: [u8; 12] = rng.random();
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Encrypt
        let ciphertext = cipher
            .encrypt(nonce, value.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        // Combine salt + nonce + ciphertext
        let mut encrypted = Vec::new();
        encrypted.extend_from_slice(&salt);
        encrypted.extend_from_slice(&nonce_bytes);
        encrypted.extend_from_slice(&ciphertext);

        // Encode to base64
        let encoded = base64_encode(&encrypted);

        Ok((encoded, encrypted))
    }

    fn seal_value_with_dek(dek: &[u8; 32], value: &str) -> Result<String> {
        let mut rng = rand::rng();
        let nonce_bytes: [u8; 12] = rng.random();
        let cipher = Aes256Gcm::new(dek.into());
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, value.as_bytes())
            .map_err(|e| anyhow!("Encryption failed: {}", e))?;

        let mut envelope = Vec::with_capacity(DEK_ENVELOPE_MIN_LEN + ciphertext.len());
        envelope.push(DEK_ENVELOPE_VERSION);
        envelope.extend_from_slice(&nonce_bytes);
        envelope.extend_from_slice(&ciphertext);

        Ok(base64_encode(&envelope))
    }

    fn decrypt_envelope_with_dek(dek: &[u8; 32], envelope: &[u8]) -> Result<String> {
        if envelope.len() < DEK_ENVELOPE_MIN_LEN {
            return Err(anyhow!("Invalid encrypted data"));
        }

        if envelope[0] != DEK_ENVELOPE_VERSION {
            return Err(anyhow!(
                "Unsupported envelope version: expected 0x{:02x}, got 0x{:02x}",
                DEK_ENVELOPE_VERSION,
                envelope[0]
            ));
        }

        let nonce_bytes = &envelope[1..13];
        let ciphertext = &envelope[13..];

        let cipher = Aes256Gcm::new(dek.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }

    /// Decrypt a value
    pub fn decrypt_value(&self, encrypted: &[u8], password: &str) -> Result<String> {
        if encrypted.len() < 28 {
            // 16 (salt) + 12 (nonce) minimum
            return Err(anyhow!("Invalid encrypted data"));
        }

        // Extract components
        let salt = &encrypted[0..16];
        let nonce_bytes = &encrypted[16..28];
        let ciphertext = &encrypted[28..];

        // Derive key
        let key_bytes = self.derive_key(password, salt);
        let cipher = Aes256Gcm::new((&key_bytes).into());
        let nonce = Nonce::from_slice(nonce_bytes);

        // Decrypt
        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| anyhow!("Decryption failed: {}", e))?;

        String::from_utf8(plaintext).map_err(|e| anyhow!("Invalid UTF-8: {}", e))
    }
}

impl Default for EncryptAnonymizer {
    fn default() -> Self {
        Self::new()
    }
}

impl Anonymizer for EncryptAnonymizer {
    fn name(&self) -> &str {
        "EncryptAnonymizer"
    }

    fn anonymize(
        &self,
        text: &str,
        entities: Vec<RecognizerResult>,
        config: &AnonymizerConfig,
    ) -> Result<AnonymizedResult> {
        if self.dek.is_none() && config.encryption_key.is_none() {
            return Err(anyhow!("Encryption key not provided"));
        }

        // Pre-encrypt all values and build tokens
        let mut tokens = Vec::new();
        let entity_map: std::collections::HashMap<(usize, usize), String> = entities
            .iter()
            .map(|entity| {
                let token_id = Uuid::new_v4().to_string();
                let original = &text[entity.start..entity.end];

                // Encrypt the original value
                let encrypted = if let Some(dek) = &self.dek {
                    Self::seal_value_with_dek(dek, original)
                        .unwrap_or_else(|_| base64_encode(original.as_bytes()))
                } else {
                    let password = config.encryption_key.as_ref().unwrap();
                    self.encrypt_value(original, password)
                        .map(|(encoded, _)| encoded)
                        .unwrap_or_else(|_| base64_encode(original.as_bytes()))
                };

                // Create token
                tokens.push(Token {
                    token_id: token_id.clone(),
                    original_value: encrypted,
                    entity_type: entity.entity_type.clone(),
                    start: entity.start,
                    end: entity.end,
                    expires_at: None,
                });

                ((entity.start, entity.end), format!("<TOKEN_{}>", token_id))
            })
            .collect();

        let anonymized_text = apply_anonymization(text, &entities, |entity, _original| {
            entity_map
                .get(&(entity.start, entity.end))
                .cloned()
                .unwrap_or_else(|| format!("<TOKEN_{}>", Uuid::new_v4()))
        });

        Ok(AnonymizedResult {
            text: anonymized_text,
            entities,
            tokens: Some(tokens),
        })
    }
}

// Simple base64 encoding
fn base64_encode(bytes: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();

    for chunk in bytes.chunks(3) {
        let mut buf = [0u8; 3];
        buf[..chunk.len()].copy_from_slice(chunk);

        let b1 = (buf[0] >> 2) as usize;
        let b2 = (((buf[0] & 0x03) << 4) | (buf[1] >> 4)) as usize;
        let b3 = (((buf[1] & 0x0F) << 2) | (buf[2] >> 6)) as usize;
        let b4 = (buf[2] & 0x3F) as usize;

        result.push(CHARSET[b1] as char);
        result.push(CHARSET[b2] as char);
        result.push(if chunk.len() > 1 {
            CHARSET[b3] as char
        } else {
            '='
        });
        result.push(if chunk.len() > 2 {
            CHARSET[b4] as char
        } else {
            '='
        });
    }

    result
}

fn base64_decode(input: &str) -> Result<Vec<u8>> {
    const DECODE: [u8; 128] = {
        let mut table = [255u8; 128];
        let chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut i = 0;
        while i < 64 {
            table[chars[i] as usize] = i as u8;
            i += 1;
        }
        table
    };

    let input = input.trim_end_matches('=');
    if input.is_empty() {
        return Ok(Vec::new());
    }

    let mut output = Vec::with_capacity(input.len() * 3 / 4);
    let bytes = input.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let remaining = bytes.len() - i;
        if remaining >= 4 {
            let b1 = DECODE[bytes[i] as usize];
            let b2 = DECODE[bytes[i + 1] as usize];
            let b3 = DECODE[bytes[i + 2] as usize];
            let b4 = DECODE[bytes[i + 3] as usize];
            if b1 == 255 || b2 == 255 || b3 == 255 || b4 == 255 {
                return Err(anyhow!("Invalid base64 input"));
            }
            output.push((b1 << 2) | (b2 >> 4));
            output.push((b2 << 4) | (b3 >> 2));
            output.push((b3 << 6) | b4);
            i += 4;
        } else if remaining == 3 {
            let b1 = DECODE[bytes[i] as usize];
            let b2 = DECODE[bytes[i + 1] as usize];
            let b3 = DECODE[bytes[i + 2] as usize];
            if b1 == 255 || b2 == 255 || b3 == 255 {
                return Err(anyhow!("Invalid base64 input"));
            }
            output.push((b1 << 2) | (b2 >> 4));
            output.push((b2 << 4) | (b3 >> 2));
            break;
        } else if remaining == 2 {
            let b1 = DECODE[bytes[i] as usize];
            let b2 = DECODE[bytes[i + 1] as usize];
            if b1 == 255 || b2 == 255 {
                return Err(anyhow!("Invalid base64 input"));
            }
            output.push((b1 << 2) | (b2 >> 4));
            break;
        } else {
            return Err(anyhow!("Invalid base64 input"));
        }
    }

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityType;

    #[test]
    fn test_encrypt_anonymizer() {
        let anonymizer = EncryptAnonymizer::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig {
            encryption_key: Some("test_password".to_string()),
            ..Default::default()
        };

        let result = anonymizer.anonymize(text, entities, &config).unwrap();

        assert!(result.text.contains("<TOKEN_"));
        assert!(result.tokens.is_some());
        assert_eq!(result.tokens.unwrap().len(), 1);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let anonymizer = EncryptAnonymizer::new();
        let password = "test_password";
        let original = "sensitive_data";

        let (encrypted, encrypted_bytes) = anonymizer.encrypt_value(original, password).unwrap();

        assert!(!encrypted.is_empty());
        assert_ne!(encrypted, original);

        let decrypted = anonymizer
            .decrypt_value(&encrypted_bytes, password)
            .unwrap();
        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_encrypt_without_key() {
        let anonymizer = EncryptAnonymizer::new();
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig::default(); // No encryption key

        let result = anonymizer.anonymize(text, entities, &config);
        assert!(result.is_err());
    }

    #[test]
    fn test_dek_round_trip() {
        let dek = [0x42u8; 32];
        let anonymizer = EncryptAnonymizer::with_dek(dek);
        let original = "sensitive_pii_value";

        let envelope = anonymizer.seal_with_dek(original).unwrap();
        let decrypted = EncryptAnonymizer::decrypt_with_dek(&dek, &envelope).unwrap();

        assert_eq!(decrypted, original);
    }

    #[test]
    fn test_dek_different_nonces_produce_different_ciphertext() {
        let dek = [0x11u8; 32];
        let anonymizer = EncryptAnonymizer::with_dek(dek);
        let plaintext = "same_plaintext";

        let envelope_a = anonymizer.seal_with_dek(plaintext).unwrap();
        let envelope_b = anonymizer.seal_with_dek(plaintext).unwrap();

        assert_ne!(envelope_a, envelope_b);
        assert_eq!(
            EncryptAnonymizer::decrypt_with_dek(&dek, &envelope_a).unwrap(),
            plaintext
        );
        assert_eq!(
            EncryptAnonymizer::decrypt_with_dek(&dek, &envelope_b).unwrap(),
            plaintext
        );
    }

    #[test]
    fn test_dek_wrong_key_fails_to_decrypt() {
        let dek = [0x01u8; 32];
        let wrong_dek = [0x02u8; 32];
        let anonymizer = EncryptAnonymizer::with_dek(dek);

        let envelope = anonymizer.seal_with_dek("secret").unwrap();
        let result = EncryptAnonymizer::decrypt_with_dek(&wrong_dek, &envelope);

        assert!(result.is_err());
    }

    #[test]
    fn test_dek_version_byte_mismatch_errors() {
        let dek = [0x99u8; 32];
        let anonymizer = EncryptAnonymizer::with_dek(dek);
        let envelope = anonymizer.seal_with_dek("secret").unwrap();
        let mut bytes = base64_decode(&envelope).unwrap();
        bytes[0] = 0x02;
        let bad_envelope = base64_encode(&bytes);

        let result = EncryptAnonymizer::decrypt_with_dek(&dek, &bad_envelope);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Unsupported envelope version"));
    }

    #[test]
    fn test_dek_anonymize_without_password() {
        let dek = [0x55u8; 32];
        let anonymizer = EncryptAnonymizer::with_dek(dek);
        let text = "Email: john@example.com";
        let entities = vec![RecognizerResult::new(
            EntityType::EmailAddress,
            7,
            23,
            0.9,
            "test",
        )];
        let config = AnonymizerConfig::default();

        let result = anonymizer.anonymize(text, entities, &config).unwrap();
        let token = result.tokens.as_ref().unwrap().first().unwrap();

        assert!(result.text.contains("<TOKEN_"));
        assert_eq!(
            EncryptAnonymizer::decrypt_with_dek(&dek, &token.original_value).unwrap(),
            "john@example.com"
        );
    }
}
