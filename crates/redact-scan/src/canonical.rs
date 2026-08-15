// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 of canonical JSON with `content_hash` omitted / empty.
pub fn content_hash<T: Serialize>(report: &T) -> Result<String> {
    let mut value = serde_json::to_value(report)?;
    if let Value::Object(map) = &mut value {
        map.remove("content_hash");
    }
    let canonical = canonicalize(&value)?;
    Ok(hex_sha256(canonical.as_bytes()))
}

pub(crate) fn hex_sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn canonicalize(value: &Value) -> Result<String> {
    Ok(canonical_value(value).to_string())
}

fn canonical_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = serde_json::Map::new();
            for k in keys {
                out.insert(k.clone(), canonical_value(&map[k]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonical_value).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hash_is_stable_under_key_order() {
        let a = json!({"b": 1, "a": 2, "content_hash": "x"});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(content_hash(&a).unwrap(), content_hash(&b).unwrap());
    }
}
