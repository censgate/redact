//! Private wire representations for the current sealed pack.

use crate::error::{InputError, InputErrorKind};
use serde_json::{Map, Value};

/// Zero hash used by the current chain format.
pub(crate) const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Decoded sealed envelope. Raw values remain available for privacy inspection.
#[derive(Debug)]
pub(crate) struct Envelope {
    pub raw: Value,
    pub schema_version: i64,
    pub pack_id: String,
    pub tenant_id: String,
    pub body: Vec<u8>,
    pub body_hash: String,
    pub body_signature: String,
    pub _key_name: String,
    pub _key_version: i64,
}

/// Decoded body and its optional current-format metadata.
#[derive(Debug)]
pub(crate) struct Body {
    pub raw: Value,
    pub schema_version: i64,
    pub pack_id: String,
    pub tenant_id: String,
    pub _region: String,
    pub batches: Vec<Batch>,
    pub r1: Option<R1>,
    pub keys: Option<KeySet>,
    pub scope: Scope,
}

/// One signed event or tombstone replacement.
#[derive(Debug)]
pub(crate) struct Batch {
    pub raw: Value,
    pub event: Option<Value>,
    pub record: Record,
    pub signature: String,
    pub key_version: i64,
    pub tombstone: Option<Value>,
}

/// Legacy wire record fields.
#[derive(Debug, Clone)]
pub(crate) struct Record {
    pub raw: Value,
    pub seq: u64,
    pub prev_hash: String,
    pub hash: String,
    pub event_id: String,
    pub chain_id: String,
    pub canonical: Option<Vec<u8>>,
}

/// Current signed tree-head metadata.
#[derive(Debug, Clone)]
pub(crate) struct R1 {
    pub merkle_root: String,
    pub signature: String,
}

/// Optional embedded public verification keys.
#[derive(Debug, Clone, Default)]
pub(crate) struct KeySet {
    pub chain: PublicKey,
    pub tree_head: Option<PublicKey>,
}

/// Public key metadata embedded in a body or local key file.
#[derive(Debug, Clone, Default)]
pub(crate) struct PublicKey {
    pub _key_id: String,
    pub _key_name: String,
    pub _algorithm: String,
    pub version: i64,
    pub public_key: String,
}

/// Scope identifies a filtered export when any member is nonempty.
#[derive(Debug, Clone, Default)]
pub(crate) struct Scope {
    pub from: String,
    pub to: String,
    pub session_id: String,
    pub subject_ref: String,
    pub run_id: String,
}

impl Scope {
    pub fn filtered(&self) -> bool {
        !self.from.is_empty()
            || !self.to.is_empty()
            || !self.session_id.is_empty()
            || !self.subject_ref.is_empty()
            || !self.run_id.is_empty()
    }
}

pub(crate) fn parse_envelope(raw: &[u8]) -> Result<Envelope, InputError> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| {
        InputError::new(
            InputErrorKind::InvalidFormat,
            "invalid_envelope_json",
            "envelope is not valid JSON",
        )
    })?;
    let obj = as_object(&value, "envelope")?;
    let body_value = obj.get("body").ok_or_else(|| {
        InputError::new(
            InputErrorKind::InvalidFormat,
            "missing_body",
            "envelope body is required",
        )
    })?;
    let body = decode_bytes(body_value, "body")?.ok_or_else(|| {
        InputError::new(
            InputErrorKind::InvalidFormat,
            "missing_body",
            "envelope body is empty",
        )
    })?;
    if body.is_empty() {
        return Err(InputError::new(
            InputErrorKind::InvalidFormat,
            "missing_body",
            "envelope body is empty",
        ));
    }
    Ok(Envelope {
        raw: value.clone(),
        schema_version: integer(obj, "schema_version")?.unwrap_or(0),
        pack_id: string(obj, "pack_id")?,
        tenant_id: string(obj, "tenant_id")?,
        body,
        body_hash: string(obj, "body_hash")?,
        body_signature: string(obj, "body_signature")?,
        _key_name: string(obj, "key_name")?,
        _key_version: integer(obj, "key_version")?.unwrap_or(0),
    })
}

pub(crate) fn parse_body(raw: &[u8]) -> Result<Body, InputError> {
    let value: Value = serde_json::from_slice(raw).map_err(|_| {
        InputError::new(
            InputErrorKind::InvalidFormat,
            "invalid_body_json",
            "decoded body is not valid JSON",
        )
    })?;
    let obj = as_object(&value, "body")?;
    let batches = match obj.get("batches") {
        Some(Value::Array(rows)) => rows.iter().map(parse_batch).collect::<Result<_, _>>()?,
        Some(Value::Null) | None => Vec::new(),
        _ => {
            return Err(InputError::new(
                InputErrorKind::InvalidFormat,
                "invalid_batches",
                "body batches must be an array",
            ))
        }
    };
    let r1 = obj
        .get("r1")
        .filter(|v| !v.is_null())
        .map(parse_r1)
        .transpose()?;
    let keys = obj
        .get("keys")
        .filter(|v| !v.is_null())
        .map(parse_keyset)
        .transpose()?;
    let scope = obj
        .get("scope")
        .filter(|v| !v.is_null())
        .map(parse_scope)
        .transpose()?
        .unwrap_or_default();
    Ok(Body {
        raw: value.clone(),
        schema_version: integer(obj, "schema_version")?.unwrap_or(0),
        pack_id: string(obj, "pack_id")?,
        tenant_id: string(obj, "tenant_id")?,
        _region: string(obj, "region")?,
        batches,
        r1,
        keys,
        scope,
    })
}

fn parse_batch(value: &Value) -> Result<Batch, InputError> {
    let obj = as_object(value, "batch")?;
    let record = obj
        .get("record")
        .ok_or_else(|| invalid_shape("batch record is required"))?;
    let event = match obj.get("event") {
        None | Some(Value::Null) => None,
        Some(Value::Object(_)) => obj.get("event").cloned(),
        _ => return Err(invalid_shape("event must be an object or null")),
    };
    Ok(Batch {
        raw: value.clone(),
        event,
        record: parse_record(record)?,
        signature: string(obj, "signature")?,
        key_version: integer(obj, "key_version")?.unwrap_or(0),
        tombstone: obj.get("tombstone").filter(|v| !v.is_null()).cloned(),
    })
}

fn parse_record(value: &Value) -> Result<Record, InputError> {
    let obj = as_object(value, "record")?;
    let canonical = match obj.get("canonical") {
        None | Some(Value::Null) => None,
        Some(v) => decode_bytes(v, "canonical")?,
    };
    Ok(Record {
        raw: value.clone(),
        seq: uint(obj, "seq")?.unwrap_or(0),
        prev_hash: string(obj, "prev_hash")?,
        hash: string(obj, "hash")?,
        event_id: string(obj, "event_id")?,
        chain_id: string(obj, "chain_id")?,
        canonical: canonical.filter(|v| !v.is_empty()),
    })
}

fn parse_r1(value: &Value) -> Result<R1, InputError> {
    let obj = as_object(value, "r1")?;
    Ok(R1 {
        merkle_root: string(obj, "merkle_root")?,
        signature: string(obj, "signature")?,
    })
}

fn parse_keyset(value: &Value) -> Result<KeySet, InputError> {
    let obj = as_object(value, "keys")?;
    let chain = obj
        .get("chain")
        .map(parse_public_key)
        .transpose()?
        .unwrap_or_default();
    let tree_head = obj
        .get("tree_head")
        .filter(|v| !v.is_null())
        .map(parse_public_key)
        .transpose()?;
    Ok(KeySet { chain, tree_head })
}

fn parse_public_key(value: &Value) -> Result<PublicKey, InputError> {
    let obj = as_object(value, "public key")?;
    Ok(PublicKey {
        _key_id: string(obj, "key_id")?,
        _key_name: string(obj, "key_name")?,
        _algorithm: string(obj, "algorithm")?,
        version: integer(obj, "version")?.unwrap_or(0),
        public_key: string(obj, "public_key")?,
    })
}

fn parse_scope(value: &Value) -> Result<Scope, InputError> {
    let obj = as_object(value, "scope")?;
    Ok(Scope {
        from: string(obj, "from")?,
        to: string(obj, "to")?,
        session_id: string(obj, "session_id")?,
        subject_ref: string(obj, "subject_ref")?,
        run_id: string(obj, "run_id")?,
    })
}

fn as_object<'a>(value: &'a Value, what: &str) -> Result<&'a Map<String, Value>, InputError> {
    value.as_object().ok_or_else(|| {
        InputError::new(
            InputErrorKind::InvalidFormat,
            "invalid_shape",
            format!("{what} must be an object"),
        )
    })
}

fn string(obj: &Map<String, Value>, key: &str) -> Result<String, InputError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(invalid_shape("string field has an invalid type")),
    }
}

fn uint(obj: &Map<String, Value>, key: &str) -> Result<Option<u64>, InputError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .map(Some)
            .ok_or_else(|| invalid_shape("integer field is invalid")),
        _ => Err(invalid_shape("integer field has an invalid type")),
    }
}

fn integer(obj: &Map<String, Value>, key: &str) -> Result<Option<i64>, InputError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_i64()
            .map(Some)
            .ok_or_else(|| invalid_shape("integer field is invalid")),
        _ => Err(invalid_shape("integer field has an invalid type")),
    }
}

pub(crate) fn decode_bytes(value: &Value, field: &str) -> Result<Option<Vec<u8>>, InputError> {
    match value {
        Value::String(s) => {
            if s.is_empty() {
                return Ok(None);
            }
            let stripped = s.replace(['\r', '\n'], "");
            base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                stripped.as_bytes(),
            )
            .map(Some)
            .map_err(|_| {
                InputError::new(
                    InputErrorKind::InvalidEncoding,
                    "invalid_base64",
                    format!("{field} must use standard base64"),
                )
            })
        }
        Value::Array(values) => {
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                let byte = value.as_u64().filter(|n| *n <= 255).ok_or_else(|| {
                    InputError::new(
                        InputErrorKind::InvalidFormat,
                        "invalid_byte_array",
                        format!("{field} byte array contains an invalid value"),
                    )
                })?;
                bytes.push(byte as u8);
            }
            if bytes.is_empty() {
                Ok(None)
            } else {
                Ok(Some(bytes))
            }
        }
        _ => Err(InputError::new(
            InputErrorKind::InvalidFormat,
            "invalid_byte_field",
            format!("{field} must be a base64 string or byte array"),
        )),
    }
}

fn invalid_shape(message: &'static str) -> InputError {
    InputError::new(InputErrorKind::InvalidFormat, "invalid_shape", message)
}
