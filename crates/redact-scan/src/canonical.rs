// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// SHA-256 hex of RFC 8785-style canonical JSON with `content_hash` omitted.
///
/// Object keys are sorted; insignificant whitespace is omitted.
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
    use serde::Serialize;

    #[derive(Serialize)]
    struct First {
        b: i32,
        a: i32,
        content_hash: String,
    }

    #[derive(Serialize)]
    struct Second {
        a: i32,
        b: i32,
    }

    #[test]
    fn hash_is_stable_under_struct_field_order() {
        let first = First {
            b: 1,
            a: 2,
            content_hash: "ignored".into(),
        };
        let second = Second { a: 2, b: 1 };
        let first_json = serde_json::to_string(&first).unwrap();
        let second_json = serde_json::to_string(&second).unwrap();
        assert_ne!(
            first_json, second_json,
            "fixture must serialize keys in different orders"
        );
        assert_eq!(
            content_hash(&first).unwrap(),
            content_hash(&second).unwrap()
        );
    }
}
