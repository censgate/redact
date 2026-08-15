// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use regex::Regex;
use std::sync::OnceLock;

fn url_userinfo() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)([a-z][a-z0-9+.-]*://)([^:/?#]+):([^@/?#]+)@").expect("url userinfo regex")
    })
}

fn password_query() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(password|passwd|pwd|secret)=([^&\s]+)").expect("password query regex")
    })
}

/// Percent-decode `%XX` sequences. Invalid sequences are left unchanged.
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(v) = u8::from_str_radix(&input[i + 1..i + 3], 16) {
                out.push(v);
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

fn scrub_patterns(input: &str) -> String {
    let out = url_userinfo()
        .replace_all(input, |caps: &regex::Captures| {
            format!("{}{}:***@", &caps[1], &caps[2])
        })
        .into_owned();
    password_query()
        .replace_all(&out, |caps: &regex::Captures| format!("{}=***", &caps[1]))
        .into_owned()
}

/// Redact credentials from any string that may appear in logs or errors.
///
/// Handles `user:pass@`, `password=`, and percent-encoded variants
/// (`user%3Apass`, `password%3D…`, `%40` in passwords) by decoding first.
pub fn scrub(input: &str) -> String {
    let decoded = fully_percent_decode(input);
    scrub_patterns(&decoded)
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
    fn scrubs_percent_encoded_password_in_url() {
        let s = scrub("postgres://alice:p%40ssword@db.example/app");
        assert!(!s.contains("p%40ssword"));
        assert!(!s.contains("p@ssword"));
        assert!(s.contains("alice:***@"));
    }

    #[test]
    fn scrubs_percent_encoded_userinfo_delimiter() {
        let s = scrub("postgres://alice%3As3cret-pass@db.example/app");
        assert!(!s.contains("s3cret-pass"));
        assert!(s.contains("alice:***@"));
    }

    #[test]
    fn scrubs_percent_encoded_password_query() {
        let s = scrub("login failed password%3Dhunter2");
        assert!(!s.contains("hunter2"));
        assert!(s.contains("password=***"));
    }
}
