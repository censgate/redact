// Copyright (c) 2026 Censgate LLC.
// Licensed under the Business Source License 1.1 (BUSL-1.1).
// See the LICENSE file in the project root for license details,
// including the Additional Use Grant, Change Date, and Change License.

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

/// Encrypt anonymizer for reversible anonymization
#[derive(Debug, Clone)]
pub struct EncryptAnonymizer {
    key_derivation_iterations: u32,
}

impl EncryptAnonymizer {
    pub fn new() -> Self {
        Self {
            key_derivation_iterations: 100_000,
        }
    }

    pub fn with_iterations(mut self, iterations: u32) -> Self {
        self.key_derivation_iterations = iterations;
        self
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
        let password = config
            .encryption_key
            .as_ref()
            .ok_or_else(|| anyhow!("Encryption key not provided"))?;

        // Pre-encrypt all values and build tokens
        let mut tokens = Vec::new();
        let entity_map: std::collections::HashMap<(usize, usize), String> = entities
            .iter()
            .map(|entity| {
                let token_id = Uuid::new_v4().to_string();
                let original = &text[entity.start..entity.end];

                // Encrypt the original value
                let encrypted = self
                    .encrypt_value(original, password)
                    .unwrap_or_else(|_| (base64_encode(original.as_bytes()), vec![]));

                // Create token
                tokens.push(Token {
                    token_id: token_id.clone(),
                    original_value: encrypted.0,
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
}
