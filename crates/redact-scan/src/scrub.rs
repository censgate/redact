// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use regex::Regex;
use std::sync::OnceLock;

fn password_query() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(
            r#"(?i)(password|passwd|pwd|secret)(?:=|%3[Dd])(?:'([^']*)'|"([^"]*)"|([^&\s]+))"#,
        )
        .expect("password query regex")
    })
}

/// Percent-decode `%XX` sequences. Invalid sequences are left unchanged.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            if h1.is_ascii_hexdigit() && h2.is_ascii_hexdigit() {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).expect("ascii hex");
                out.push(u8::from_str_radix(hex, 16).expect("ascii hex"));
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn fully_percent_decode(input: &str) -> String {
    let mut current = input.to_string();
    for _ in 0..3 {
        let next = percent_decode(&current);
        if next == current {
            break;
        }
        current = next;
    }
    current
}

fn scrub_decode_rounds(input: &str) -> String {
    let mut current = scrub_patterns(input);
    for _ in 0..3 {
        let next = percent_decode(&current);
        if next == current {
            break;
        }
        current = scrub_patterns(&next);
    }
    current
}

/// Redact `user:password@` using the last `@` in the URL authority.
///
/// That last `@` is the host delimiter (RFC 3986). Encoded `@` / `:` inside
/// the password therefore cannot split the credential.
fn scrub_url_userinfo(input: &str) -> String {
    let lower = input.to_ascii_lowercase();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        let Some(rel) = lower[i..].find("://") else {
            out.push_str(&input[i..]);
            break;
        };
        let scheme_end = i + rel + 3;
        out.push_str(&input[i..scheme_end]);
        let rest = &input[scheme_end..];
        let auth_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let authority = &rest[..auth_end];
        if let Some(at) = authority.rfind('@') {
            let userinfo = &authority[..at];
            let hostport = &authority[at + 1..];
            if let Some(user) = userinfo_user(userinfo) {
                out.push_str(user);
                out.push_str(":***@");
                out.push_str(hostport);
            } else {
                out.push_str(authority);
            }
        } else {
            out.push_str(authority);
        }
        i = scheme_end + auth_end;
    }
    out
}

fn userinfo_user(userinfo: &str) -> Option<&str> {
    if let Some((user, _)) = userinfo.split_once(':') {
        return Some(user);
    }
    let lower = userinfo.to_ascii_lowercase();
    lower.find("%3a").map(|idx| &userinfo[..idx])
}

fn scrub_password_params(input: &str) -> String {
    password_query()
        .replace_all(input, |caps: &regex::Captures| format!("{}=***", &caps[1]))
        .into_owned()
}

fn scrub_patterns(input: &str) -> String {
    scrub_password_params(&scrub_url_userinfo(input))
}

/// Redact credentials from any string that may appear in logs or errors.
///
/// Handles `user:pass@`, `password=`, and percent-encoded variants
/// (`user%3Apass`, `password%3D…`, `%40` / `%26` inside passwords).
/// Patterns run on the raw string first so encoded reserved bytes stay
/// inside the credential; then each percent-decode pass is scrubbed again
/// (nested `%25` encodings included).
pub fn scrub(input: &str) -> String {
    scrub_decode_rounds(input)
}

/// If `secret` is non-empty and appears in `input`, replace every occurrence.
pub fn scrub_secret(input: &str, secret: &str) -> String {
    let mut out = scrub(input);
    if secret.is_empty() {
        return out;
    }
    if out.contains(secret) {
        out = out.replace(secret, "***");
    }
    let decoded_secret = fully_percent_decode(secret);
    if decoded_secret != secret && out.contains(&decoded_secret) {
        out = out.replace(&decoded_secret, "***");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_url_password() {
        let s = scrub("postgres://alice:s3cret-pass@db.example/app");
        assert!(!s.contains("s3cret-pass"));
        assert!(s.contains("alice:***@"));
    }

    #[test]
    fn scrubs_query_password() {
        let s = scrub("error password=hunter2 extra");
        assert!(!s.contains("hunter2"));
        assert!(s.contains("password=***"));
    }

    #[test]
    fn scrubs_quoted_libpq_password() {
        let s = scrub("libpq connect failed: host=db user=app password='pa ss' dbname=prod");
        assert!(!s.contains("pa ss"), "{s}");
        assert!(s.contains("password=***"), "{s}");
        let d = scrub(r#"libpq connect failed password="pa ss" dbname=prod"#);
        assert!(!d.contains("pa ss"), "{d}");
        assert!(d.contains("password=***"), "{d}");
    }

    #[test]
    fn scrubs_percent_encoded_password_in_url() {
        let s = scrub("postgres://alice:p%40ssword@db.example/app");
        assert!(!s.contains("p%40ssword"), "{s}");
        assert!(!s.contains("p@ssword"), "{s}");
        assert!(!s.contains("ssword"), "{s}");
        assert!(s.contains("alice:***@"), "{s}");
    }

    #[test]
    fn scrubs_percent_encoded_userinfo_delimiter() {
        let s = scrub("postgres://alice%3As3cret-pass@db.example/app");
        assert!(!s.contains("s3cret-pass"));
        assert!(s.contains("alice:***@"));
    }

    #[test]
    fn scrubs_combined_encoded_separator_and_at() {
        let s = scrub("postgres://alice%3As3cret%40pass@db.example/app");
        assert!(!s.contains("s3cret"), "{s}");
        assert!(!s.contains("pass@"), "{s}");
        assert!(s.contains("alice:***@"), "{s}");
    }

    #[test]
    fn scrubs_password_with_encoded_reserved_bytes() {
        let s = scrub("postgres://alice:a%26b%2Fc%3Fd@db.example/app");
        assert!(!s.contains("a%26b"), "{s}");
        assert!(!s.contains("a&b"), "{s}");
        assert!(s.contains("alice:***@"), "{s}");
    }

    #[test]
    fn scrubs_encoded_query_password_with_encoded_ampersand() {
        let s = scrub("login failed password%3Dpa%26ss");
        assert!(!s.contains("pa%26ss"), "{s}");
        assert!(!s.contains("pa&ss"), "{s}");
        assert!(s.contains("password=***"), "{s}");
    }

    #[test]
    fn leaves_username_only_url() {
        let s = scrub("postgres://alice@db.example/app");
        assert_eq!(s, "postgres://alice@db.example/app");
    }

    #[test]
    fn scrubs_double_encoded_query_password() {
        let s = scrub("login failed password%253Dpa%2526ss");
        assert!(!s.contains("pa%26ss"), "{s}");
        assert!(!s.contains("pa&ss"), "{s}");
        assert!(s.contains("password=***"), "{s}");
    }

    #[test]
    fn percent_decode_leaves_invalid_and_unicode_sequences() {
        assert_eq!(percent_decode("%€"), "%€");
        assert_eq!(percent_decode("%ZZ"), "%ZZ");
        assert_eq!(percent_decode("ok%20x"), "ok x");
    }
}
