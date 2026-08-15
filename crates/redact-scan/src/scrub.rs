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

/// Redact credentials from any string that may appear in logs or errors.
pub fn scrub(input: &str) -> String {
    let mut out = url_userinfo()
        .replace_all(input, |caps: &regex::Captures| {
            format!("{}{}:***@", &caps[1], &caps[2])
        })
        .into_owned();
    out = password_query()
        .replace_all(&out, |caps: &regex::Captures| format!("{}=***", &caps[1]))
        .into_owned();
    // Percent-encoded userinfo (`user%3Apass@` is uncommon; cover `pass%40word` leftovers
    // by also stripping raw password tokens when explicitly provided.
    out
}

/// If `secret` is non-empty and appears in `input`, replace every occurrence.
pub fn scrub_secret(input: &str, secret: &str) -> String {
    let mut out = scrub(input);
    if !secret.is_empty() && out.contains(secret) {
        out = out.replace(secret, "***");
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
}
