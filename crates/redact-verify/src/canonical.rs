//! Platform-v1 event projection and Go-compatible deterministic JSON bytes.

use crate::error::{InputError, InputErrorKind};
use chrono::{DateTime, Utc};
use serde_json::Value;

/// The normalized event fields used by the current record hash projection.
#[derive(Debug, Clone)]
pub(crate) struct CanonicalEvent {
    pub event_id: String,
    pub event_name: String,
    pub timestamp: String,
    pub tenant_id: String,
    pub region: String,
    pub shard: String,
    pub epoch: String,
    pub gateway_instance: String,
    pub action: String,
    pub outcome: String,
    pub profile: String,
    pub caller: String,
    pub subject_ref: String,
    pub session_id: String,
    pub redactions: i64,
    pub tokens_issued: i64,
    pub entity_types: Option<Vec<String>>,
    pub content_sha256: String,
    pub error_type: String,
    pub trace_id: String,
    pub span_id: String,
    pub boundary: String,
    pub destination_class: String,
    pub destination_vendor: String,
    pub destination_id: String,
}

impl CanonicalEvent {
    /// Reads legacy wire fields and applies Go zero-value semantics.
    pub fn from_value(value: &Value) -> Result<Self, InputError> {
        let obj = value
            .as_object()
            .ok_or_else(|| invalid("event must be an object"))?;
        Ok(Self {
            event_id: string(obj.get("event_id"))?,
            event_name: string(obj.get("event_name"))?,
            timestamp: normalize_timestamp(obj.get("timestamp"))?,
            tenant_id: string(obj.get("tenant_id"))?,
            region: string(obj.get("region"))?,
            shard: string(obj.get("shard"))?,
            epoch: string(obj.get("epoch"))?,
            gateway_instance: string(obj.get("gateway_instance"))?,
            action: string(obj.get("action"))?,
            outcome: string(obj.get("outcome"))?,
            profile: string(obj.get("profile"))?,
            caller: string(obj.get("caller"))?,
            subject_ref: string(obj.get("subject_ref"))?,
            session_id: string(obj.get("session_id"))?,
            redactions: integer(obj.get("redactions"))?,
            tokens_issued: integer(obj.get("tokens_issued"))?,
            entity_types: string_array(obj.get("entity_types"))?,
            content_sha256: string(obj.get("content_sha256"))?,
            error_type: string(obj.get("error_type"))?,
            trace_id: string(obj.get("trace_id"))?,
            span_id: string(obj.get("span_id"))?,
            boundary: string(obj.get("boundary"))?,
            destination_class: string(obj.get("destination_class"))?,
            destination_vendor: string(obj.get("destination_vendor"))?,
            destination_id: string(obj.get("destination_id"))?,
        })
    }

    /// Encodes the exact ordered platform-v1 canonical event JSON.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = String::from("{");
        macro_rules! field {
            ($name:literal, $value:expr) => {{
                if out.len() > 1 {
                    out.push(',');
                }
                push_string(&mut out, $name);
                out.push(':');
                push_string(&mut out, $value);
            }};
        }
        macro_rules! integer_field {
            ($name:literal, $value:expr) => {{
                if out.len() > 1 {
                    out.push(',');
                }
                push_string(&mut out, $name);
                out.push(':');
                out.push_str(&$value.to_string());
            }};
        }
        field!("action", &self.action);
        field!("boundary", &self.boundary);
        field!("caller", &self.caller);
        field!("content_sha256", &self.content_sha256);
        field!("destination_class", &self.destination_class);
        field!("destination_id", &self.destination_id);
        field!("destination_vendor", &self.destination_vendor);
        if out.len() > 1 {
            out.push(',');
        }
        push_string(&mut out, "entity_types");
        out.push(':');
        if let Some(items) = &self.entity_types {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                push_string(&mut out, item);
            }
            out.push(']');
        } else {
            out.push_str("null");
        }
        field!("epoch", &self.epoch);
        field!("error_type", &self.error_type);
        field!("event_id", &self.event_id);
        field!("event_name", &self.event_name);
        field!("gateway_instance", &self.gateway_instance);
        field!("outcome", &self.outcome);
        field!("profile", &self.profile);
        integer_field!("redactions", self.redactions);
        field!("region", &self.region);
        field!("session_id", &self.session_id);
        field!("shard", &self.shard);
        field!("span_id", &self.span_id);
        field!("subject_ref", &self.subject_ref);
        field!("tenant_id", &self.tenant_id);
        field!("timestamp", &self.timestamp);
        integer_field!("tokens_issued", self.tokens_issued);
        field!("trace_id", &self.trace_id);
        out.push('}');
        out.into_bytes()
    }
}

fn string(value: Option<&Value>) -> Result<String, InputError> {
    match value {
        None | Some(Value::Null) => Ok(String::new()),
        Some(Value::String(value)) => Ok(value.clone()),
        _ => Err(invalid("event string field has an invalid type")),
    }
}

fn integer(value: Option<&Value>) -> Result<i64, InputError> {
    match value {
        None | Some(Value::Null) => Ok(0),
        Some(Value::Number(n)) => n
            .as_i64()
            .ok_or_else(|| invalid("event count is not an integer")),
        _ => Err(invalid("event count has an invalid type")),
    }
}

fn string_array(value: Option<&Value>) -> Result<Option<Vec<String>>, InputError> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .ok_or_else(|| invalid("entity_types contains a non-string value"))
            })
            .collect::<Result<Vec<_>, _>>()
            .map(Some),
        _ => Err(invalid("entity_types must be an array or null")),
    }
}

pub(crate) fn normalize_timestamp(value: Option<&Value>) -> Result<String, InputError> {
    let Some(value) = value.filter(|v| !v.is_null()) else {
        return Ok("0001-01-01T00:00:00Z".to_owned());
    };
    let text = value
        .as_str()
        .ok_or_else(|| invalid("event timestamp must be a string"))?;
    if text.is_empty() {
        return Err(invalid("event timestamp is invalid"));
    }
    if text.len() < 19 || text.get(17..19) == Some("60") {
        return Err(invalid("event timestamp is invalid"));
    }
    // Go parses arbitrary fractional precision and truncates below nanoseconds.
    let normalized_input = truncate_fraction(text);
    let parsed = DateTime::parse_from_rfc3339(&normalized_input)
        .map_err(|_| invalid("event timestamp is invalid"))?;
    let utc = parsed.with_timezone(&Utc);
    let mut output = utc.format("%Y-%m-%dT%H:%M:%S").to_string();
    let nanos = utc.timestamp_subsec_nanos();
    if nanos != 0 {
        output.push('.');
        let fraction = format!("{nanos:09}");
        output.push_str(fraction.trim_end_matches('0'));
    }
    output.push('Z');
    Ok(output)
}

fn truncate_fraction(text: &str) -> String {
    let Some(t_pos) = text.find(['T', 't']) else {
        return text.to_owned();
    };
    let suffix_pos = text[t_pos + 1..]
        .find(['+', '-', 'Z', 'z'])
        .map(|p| t_pos + 1 + p)
        .unwrap_or(text.len());
    let Some(dot) = text[t_pos + 1..suffix_pos].find('.') else {
        return text.to_owned();
    };
    let dot = t_pos + 1 + dot;
    let fractional = &text[dot + 1..suffix_pos];
    if fractional.len() <= 9 {
        return text.to_owned();
    }
    if !fractional.as_bytes().iter().all(u8::is_ascii_digit) {
        return text.to_owned();
    }
    format!("{}{}", &text[..dot + 10], &text[suffix_pos..])
}

fn push_string(out: &mut String, value: &str) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    out.push('"');
    for ch in value.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            c if (c as u32) < 0x20 => {
                let n = c as u8;
                out.push_str("\\u00");
                out.push(HEX[(n >> 4) as usize] as char);
                out.push(HEX[(n & 0x0f) as usize] as char);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn invalid(message: &'static str) -> InputError {
    InputError::new(InputErrorKind::InvalidFormat, "invalid_event", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_conversion_truncates_subnanoseconds() {
        let value = serde_json::json!("2024-02-03T04:05:06.123456789987+02:30");
        assert_eq!(
            normalize_timestamp(Some(&value)).unwrap(),
            "2024-02-03T01:35:06.123456789Z"
        );
    }

    #[test]
    fn canonical_default_projection_order_matches_golden() {
        let event = serde_json::json!({
            "event_id": "test-record-1",
            "event_name": "test.event",
            "timestamp": "2025-01-02T03:04:05Z",
            "tenant_id": "test-tenant",
            "region": "test-region",
            "action": "chat",
            "outcome": "allowed",
            "profile": "strict",
            "caller": "test-principal",
            "entity_types": null
        });
        let actual = CanonicalEvent::from_value(&event).unwrap().encode();
        assert_eq!(
            actual,
            br#"{"action":"chat","boundary":"","caller":"test-principal","content_sha256":"","destination_class":"","destination_id":"","destination_vendor":"","entity_types":null,"epoch":"","error_type":"","event_id":"test-record-1","event_name":"test.event","gateway_instance":"","outcome":"allowed","profile":"strict","redactions":0,"region":"test-region","session_id":"","shard":"","span_id":"","subject_ref":"","tenant_id":"test-tenant","timestamp":"2025-01-02T03:04:05Z","tokens_issued":0,"trace_id":""}"#
        );
    }

    #[test]
    fn null_and_empty_entity_lists_remain_distinct() {
        let null = CanonicalEvent::from_value(&serde_json::json!({}))
            .unwrap()
            .encode();
        let empty = CanonicalEvent::from_value(&serde_json::json!({"entity_types": []}))
            .unwrap()
            .encode();
        assert!(String::from_utf8(null)
            .unwrap()
            .contains(r#""entity_types":null"#));
        assert!(String::from_utf8(empty)
            .unwrap()
            .contains(r#""entity_types":[]"#));
    }

    #[test]
    fn go_html_control_and_unicode_escaping_is_preserved() {
        let value = serde_json::json!({
            "event_name": "<&>\u{2028}\u{2029}\n\t\u{0001}",
            "timestamp": null
        });
        let encoded =
            String::from_utf8(CanonicalEvent::from_value(&value).unwrap().encode()).unwrap();
        assert!(encoded.contains(r#""event_name":"\u003c\u0026\u003e\u2028\u2029\n\t\u0001""#));
        assert!(encoded.contains(r#""timestamp":"0001-01-01T00:00:00Z""#));
        assert!(normalize_timestamp(Some(&Value::String(String::new()))).is_err());
        assert!(normalize_timestamp(Some(&Value::String("2025-01-02T03:04:60Z".into()))).is_err());
    }
}
