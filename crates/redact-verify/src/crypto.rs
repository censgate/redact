//! Signature decoding and verification primitives.

use crate::error::{InputError, InputErrorKind};
use crate::keys::{EcCurve, EcPublic, Ed25519Public};
use base64::Engine;
use ring::signature::{self, UnparsedPublicKey};
use sha2::{Digest, Sha256};

/// Decodes a Go-compatible standard-base64 signature field.
pub(crate) fn decode_signature(signature: &str) -> Result<Vec<u8>, InputError> {
    let parts: Vec<&str> = signature.split(':').collect();
    let encoded = if parts.len() >= 3 {
        parts[parts.len() - 1]
    } else {
        signature
    };
    let encoded = encoded.replace(['\r', '\n'], "");
    base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| {
            InputError::new(
                InputErrorKind::InvalidEncoding,
                "invalid_signature_encoding",
                "signature is not standard base64",
            )
        })
}

/// Extracts a positive vault version marker, or returns None for a bare signature.
pub(crate) fn signature_version(signature: &str) -> Option<i64> {
    let parts: Vec<&str> = signature.split(':').collect();
    if parts.len() < 3 || parts[0] != "vault" {
        return None;
    }
    let version = parts[1].strip_prefix('v')?;
    if version.is_empty() || !version.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let parsed = version.parse::<i64>().ok()?;
    (parsed > 0).then_some(parsed)
}

pub(crate) fn verify_ed25519(
    key: &Ed25519Public,
    input: &[u8],
    signature: &str,
) -> Result<(), &'static str> {
    let bytes = decode_signature(signature).map_err(|_| "invalid_signature_encoding")?;
    let signature = ed25519_dalek::Signature::try_from(bytes.as_slice())
        .map_err(|_| "invalid_signature_length")?;
    key.key
        .verify_strict(input, &signature)
        .map_err(|_| "invalid_signature")
}

pub(crate) fn verify_tree_head(
    key: &EcPublic,
    input: &[u8],
    signature: &str,
) -> Result<(), &'static str> {
    let bytes = decode_signature(signature).map_err(|_| "invalid_signature_encoding")?;
    let algorithm = match key.curve {
        EcCurve::P256 => &signature::ECDSA_P256_SHA256_ASN1,
        EcCurve::P384 => &signature::ECDSA_P384_SHA256_ASN1,
    };
    UnparsedPublicKey::new(algorithm, &key.point)
        .verify(input, &bytes)
        .map_err(|_| "invalid_signature")
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
