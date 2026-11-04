//! Independent local key material, SPKI parsing, and signer thumbprints.

use crate::error::{InputError, InputErrorKind};
use crate::wire::{KeySet, PublicKey};
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use spki::der::{asn1::ObjectIdentifier, Decode};
use spki::SubjectPublicKeyInfoOwned;
use std::fmt;

/// Independently supplied keys used to verify a sealed evidence pack.
///
/// Embedded pack keys are only compared with these trusted keys and never
/// establish trust by themselves.
pub struct TrustedKeys {
    pub(crate) chain: Ed25519Public,
    pub(crate) chain_version: i64,
    pub(crate) tree_head: Option<EcPublic>,
    pub(crate) erasure_authority: Option<Ed25519Public>,
}

impl fmt::Debug for TrustedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TrustedKeys")
            .field("chain_version", &self.chain_version)
            .field(
                "tree_head",
                &self
                    .tree_head
                    .as_ref()
                    .map(|k| (k.curve.name(), k.signer_kid.as_str())),
            )
            .field("erasure_authority", &self.erasure_authority.is_some())
            .finish_non_exhaustive()
    }
}

/// Parsed Ed25519 public verification key.
#[derive(Clone)]
pub(crate) struct Ed25519Public {
    pub key: VerifyingKey,
    pub bytes: [u8; 32],
    pub signer_kid: String,
}

/// Supported ECDSA public key and its verified curve/point.
#[derive(Clone)]
pub(crate) struct EcPublic {
    pub curve: EcCurve,
    pub point: Vec<u8>,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
    pub signer_kid: String,
}

/// ECDSA curves supported by the offline tree-head verifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EcCurve {
    P256,
    P384,
}

impl EcCurve {
    pub fn name(self) -> &'static str {
        match self {
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        }
    }
}

impl TrustedKeys {
    /// Parses the documented local JSON key set.
    ///
    /// The JSON object contains chain, optional tree_head, and optional
    /// erasure_authority public-key entries.
    pub fn from_json(raw: &[u8]) -> Result<Self, InputError> {
        let value: Value = serde_json::from_slice(raw).map_err(|_| {
            InputError::new(
                InputErrorKind::InvalidTrust,
                "invalid_keyset_json",
                "local key set is not valid JSON",
            )
        })?;
        let root = value
            .as_object()
            .ok_or_else(|| trust_error("local key set must be an object"))?;
        let keys = root.get("keys").and_then(Value::as_object).unwrap_or(root);
        let chain = parse_key_entry(
            keys.get("chain")
                .ok_or_else(|| trust_error("chain key is required"))?,
        )?;
        let mut trusted = Self {
            chain: parse_ed25519_public(&chain.public_key)?,
            chain_version: chain.version,
            tree_head: keys
                .get("tree_head")
                .filter(|v| !v.is_null())
                .map(parse_key_entry)
                .transpose()?
                .map(|k| parse_ec_public(&k.public_key))
                .transpose()?,
            erasure_authority: None,
        };
        if let Some(value) = root
            .get("erasure_authority")
            .or_else(|| keys.get("erasure_authority"))
        {
            if !value.is_null() {
                let key = parse_key_entry(value)?;
                trusted.erasure_authority = Some(parse_ed25519_public(&key.public_key)?);
            }
        }
        Ok(trusted)
    }

    /// Creates a trust set from an independently supplied Ed25519 key.
    ///
    /// Accepted forms are SPKI PEM, 32-byte hexadecimal, padded standard
    /// base64, and unpadded standard base64.
    pub fn from_ed25519(material: &str) -> Result<Self, InputError> {
        Ok(Self {
            chain: parse_ed25519_public(material)?,
            chain_version: 0,
            tree_head: None,
            erasure_authority: None,
        })
    }

    /// Adds an independently supplied ECDSA P-256 or P-384 tree-head key.
    pub fn with_tree_head(mut self, material: &str) -> Result<Self, InputError> {
        self.tree_head = Some(parse_ec_public(material)?);
        Ok(self)
    }

    /// Adds a separately trusted Ed25519 erasure-authority key.
    pub fn with_erasure_authority(mut self, material: &str) -> Result<Self, InputError> {
        self.erasure_authority = Some(parse_ed25519_public(material)?);
        Ok(self)
    }
}

pub(crate) fn bind_embedded_keys(
    trusted: &TrustedKeys,
    embedded: Option<&KeySet>,
) -> Result<(), &'static str> {
    let Some(keys) = embedded else { return Ok(()) };
    if !keys.chain.public_key.trim().is_empty() {
        let embedded_chain = parse_ed25519_public(&keys.chain.public_key)
            .map_err(|_| "embedded_chain_key_invalid")?;
        if embedded_chain.bytes != trusted.chain.bytes {
            return Err("embedded_chain_key_mismatch");
        }
    }
    if let (Some(trusted_tree), Some(embedded_tree)) = (&trusted.tree_head, &keys.tree_head) {
        if !embedded_tree.public_key.trim().is_empty() {
            let embedded_tree = parse_ec_public(&embedded_tree.public_key).map_err(|error| {
                if error.code == "unsupported_curve" {
                    "unsupported_curve"
                } else {
                    "embedded_tree_head_key_invalid"
                }
            })?;
            if embedded_tree.curve != trusted_tree.curve
                || embedded_tree.x != trusted_tree.x
                || embedded_tree.y != trusted_tree.y
            {
                return Err("embedded_tree_head_key_mismatch");
            }
        }
    }
    Ok(())
}

pub(crate) fn embedded_chain_version(embedded: Option<&KeySet>, trusted_version: i64) -> i64 {
    embedded
        .map(|keys| keys.chain.version)
        .filter(|version| *version != 0)
        .unwrap_or(trusted_version)
}

pub(crate) fn parse_ed25519_public(material: &str) -> Result<Ed25519Public, InputError> {
    let text = material.trim();
    if text.is_empty() {
        return Err(trust_error("Ed25519 public key is empty"));
    }
    let bytes = if text.starts_with("-----BEGIN") {
        let der = decode_pem(text)?;
        let spki = SubjectPublicKeyInfoOwned::from_der(&der)
            .map_err(|_| trust_error("invalid Ed25519 SPKI PEM"))?;
        if spki.algorithm.oid.to_string() != "1.3.101.112" {
            return Err(trust_error("SPKI PEM is not Ed25519"));
        }
        if spki.algorithm.parameters.is_some() {
            return Err(trust_error("Ed25519 SPKI parameters are unsupported"));
        }
        spki.subject_public_key
            .as_bytes()
            .ok_or_else(|| trust_error("invalid Ed25519 public key bit string"))?
            .to_vec()
    } else {
        decode_key_text(text)?
    };
    if bytes.len() != 32 {
        return Err(trust_error("Ed25519 public key must contain 32 bytes"));
    }
    let mut array = [0u8; 32];
    array.copy_from_slice(&bytes);
    let key =
        VerifyingKey::from_bytes(&array).map_err(|_| trust_error("invalid Ed25519 public key"))?;
    let kid = ed25519_thumbprint(&array);
    Ok(Ed25519Public {
        key,
        bytes: array,
        signer_kid: kid,
    })
}

pub(crate) fn parse_ec_public(material: &str) -> Result<EcPublic, InputError> {
    let der = decode_pem(material.trim())?;
    let spki = SubjectPublicKeyInfoOwned::from_der(&der)
        .map_err(|_| trust_error("invalid ECDSA SPKI PEM"))?;
    if spki.algorithm.oid.to_string() != "1.2.840.10045.2.1" {
        return Err(trust_error("SPKI PEM is not ECDSA"));
    }
    let curve_oid = spki
        .algorithm
        .parameters
        .as_ref()
        .and_then(|parameters| parameters.decode_as::<ObjectIdentifier<32>>().ok())
        .map(|oid| oid.to_string())
        .ok_or_else(|| trust_error("ECDSA SPKI curve is missing"))?;
    let curve = match curve_oid.as_str() {
        "1.2.840.10045.3.1.7" => EcCurve::P256,
        "1.3.132.0.34" => EcCurve::P384,
        _ => {
            return Err(InputError::new(
                InputErrorKind::InvalidTrust,
                "unsupported_curve",
                "ECDSA curve is unsupported",
            ))
        }
    };
    let point = spki
        .subject_public_key
        .as_bytes()
        .ok_or_else(|| trust_error("invalid ECDSA public key bit string"))?
        .to_vec();
    let coordinate_len = match curve {
        EcCurve::P256 => 32,
        EcCurve::P384 => 48,
    };
    if point.len() != coordinate_len * 2 + 1 || point.first() != Some(&4) {
        return Err(trust_error("ECDSA public point must be uncompressed"));
    }
    let x = point[1..coordinate_len + 1].to_vec();
    let y = point[coordinate_len + 1..].to_vec();
    // Constructing an UnparsedPublicKey performs curve-point validation at verify time.
    let kid = ec_thumbprint(curve, &x, &y);
    Ok(EcPublic {
        curve,
        point,
        x,
        y,
        signer_kid: kid,
    })
}

fn parse_key_entry(value: &Value) -> Result<PublicKey, InputError> {
    let obj = value
        .as_object()
        .ok_or_else(|| trust_error("public key entry must be an object"))?;
    let get = |name: &str| -> Result<String, InputError> {
        match obj.get(name) {
            None | Some(Value::Null) => Ok(String::new()),
            Some(Value::String(s)) => Ok(s.clone()),
            _ => Err(trust_error("public key metadata field has an invalid type")),
        }
    };
    let version = match obj.get("version") {
        None | Some(Value::Null) => 0,
        Some(Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| trust_error("public key version is invalid"))?,
        _ => return Err(trust_error("public key version has an invalid type")),
    };
    Ok(PublicKey {
        _key_id: get("key_id")?,
        _key_name: get("key_name")?,
        _algorithm: get("algorithm")?,
        version,
        public_key: get("public_key")?,
    })
}

fn decode_pem(text: &str) -> Result<Vec<u8>, InputError> {
    let mut in_body = false;
    let mut contents = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN ") {
            in_body = true;
            continue;
        }
        if line.starts_with("-----END ") {
            break;
        }
        if in_body {
            contents.push_str(line);
        }
    }
    if contents.is_empty() {
        return Err(trust_error("expected SPKI PEM"));
    }
    base64::engine::general_purpose::STANDARD
        .decode(contents.as_bytes())
        .map_err(|_| trust_error("invalid SPKI PEM base64"))
}

fn decode_key_text(text: &str) -> Result<Vec<u8>, InputError> {
    if let Ok(bytes) = hex::decode(text) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(text) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD_NO_PAD.decode(text) {
        if !bytes.is_empty() {
            return Ok(bytes);
        }
    }
    Err(trust_error(
        "public key is not SPKI PEM, hex, or standard base64",
    ))
}

fn ed25519_thumbprint(public: &[u8; 32]) -> String {
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public);
    let json = format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
}

fn ec_thumbprint(curve: EcCurve, x: &[u8], y: &[u8]) -> String {
    let crv = curve.name();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(x);
    let y = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(y);
    let json = format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(json.as_bytes()))
}

fn trust_error(message: &'static str) -> InputError {
    InputError::new(InputErrorKind::InvalidTrust, "invalid_trust", message)
}
