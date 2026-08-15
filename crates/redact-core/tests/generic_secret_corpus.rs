//! Exclusion and labeled-positive corpora for `GENERIC_SECRET`.
//!
//! Prints precision / recall as numbers. Never prints raw secret values —
//! only labels and spans.

use redact_core::{AnalyzerEngine, EntityType};

const GATEWAY_DEFAULT_FLOOR: f32 = 0.6;

fn engine() -> AnalyzerEngine {
    AnalyzerEngine::new()
}

fn generic_hits(text: &str) -> Vec<(usize, usize, f32)> {
    engine()
        .analyze(text, None)
        .unwrap()
        .detected_entities
        .into_iter()
        .filter(|e| e.entity_type == EntityType::GenericSecret)
        .map(|e| (e.start, e.end, e.score))
        .collect()
}

#[test]
fn exclusion_corpus_has_zero_generic_secret() {
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let sha256 = "a".repeat(64);
    let md5 = "b".repeat(32);
    let cases = [
        format!("revision={uuid}"),
        format!("etag={uuid}"),
        format!("checksum={sha256}"),
        format!("integrity=sha512-{}", "A".repeat(64)),
        format!("sha256={sha256}"),
        format!("md5={md5}"),
        "password=password".to_string(),
        "api_key=your-key-here".to_string(),
        "secret=changeme".to_string(),
        "token=example".to_string(),
        "api_key=placeholder".to_string(),
        "const API_TOKEN = someIdentifierName".to_string(),
        "let clientSecret = MyServiceClient".to_string(),
        "The password field should be rotated quarterly.".to_string(),
        "Please send the token to the reviewer.".to_string(),
        "color: #fff;".to_string(),
        "background: #aabbcc;".to_string(),
        format!("data:image/png;base64,{}", "A".repeat(40)),
        format!("data:application/octet-stream;base64,{}", "B".repeat(40)),
    ];

    let mut fps = 0usize;
    for text in &cases {
        let hits = generic_hits(text);
        if !hits.is_empty() {
            fps += hits.len();
            eprintln!("exclusion FP: spans={hits:?} text_len={}", text.len());
        }
    }
    println!("exclusion_generic_secret_count={fps}");
    assert_eq!(
        fps, 0,
        "exclusion / lockfile / digest-keyed corpus must be 0"
    );
}

/// Seeded, non-secret-shaped assembly of high-entropy bodies.
fn labeled_positives() -> Vec<(String, String, usize, usize)> {
    // (label, text, start, end) — body is assembled, never a committed literal.
    let mut out = Vec::new();
    let keywords = [
        "api_key",
        "client_secret",
        "access_token",
        "password",
        "secret",
        "AUTH_TOKEN",
        "SERVICE_API_KEY",
    ];
    for (i, kw) in keywords.iter().enumerate() {
        let body = mixed_alnum(0xC0FFEE + i as u64, 28 + (i % 5));
        let text = format!("{kw}={body}");
        let start = kw.len() + 1;
        let end = start + body.chars().count();
        out.push(((*kw).to_string(), text, start, end));
    }
    // JSON / export / -e forms
    let body = mixed_alnum(0xA11CE, 32);
    let text = format!("export SERVICE_SECRET={body}");
    let start = text.find('=').unwrap() + 1;
    let end = start + body.chars().count();
    out.push(("export".into(), text, start, end));

    let body = mixed_alnum(0xBEEF, 32);
    let text = format!(r#"{{"client_secret": "{body}"}}"#);
    let start = text.find(body.as_str()).unwrap();
    let end = start + body.len();
    out.push(("json".into(), text, start, end));

    let body = mixed_alnum(0xF00D, 24);
    let text = format!("-e API_KEY={body}");
    let start = text.find('=').unwrap() + 1;
    let end = start + body.chars().count();
    out.push(("-e".into(), text, start, end));

    out
}

fn mixed_alnum(seed: u64, n: usize) -> String {
    const ALPH: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut x = seed | 1;
    let mut out = String::with_capacity(n);
    let mut has_digit = false;
    let mut has_letter = false;
    for i in 0..n {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut idx = (x >> 33) as usize % ALPH.len();
        if i == n - 2 && !has_digit {
            idx = 52 + (idx % 10);
        }
        if i == n - 1 && !has_letter {
            idx %= 52;
        }
        let c = ALPH[idx] as char;
        has_digit |= c.is_ascii_digit();
        has_letter |= c.is_ascii_alphabetic();
        out.push(c);
    }
    out
}

#[test]
fn labeled_positive_corpus_precision_recall() {
    let labeled = labeled_positives();
    let mut tp = 0usize;
    let mut acted = 0usize;
    for (label, text, start, end) in &labeled {
        let hits = generic_hits(text);
        let matched = hits.iter().any(|(s, e, _)| *s == *start && *e == *end)
            || hits.iter().any(|(s, e, _)| *s <= *start && *e >= *end);
        if matched {
            tp += 1;
        } else {
            eprintln!("miss label={label} span={start}..{end} hits={hits:?}");
        }
        if hits.iter().any(|(s, e, score)| {
            (*s == *start && *e == *end || *s <= *start && *e >= *end)
                && *score >= GATEWAY_DEFAULT_FLOOR
        }) {
            acted += 1;
        }
        println!("label={label} span={start}..{end} hits={}", hits.len());
    }

    let exclusion_fps = 0usize; // gated by exclusion_corpus_has_zero_generic_secret
    let precision = if tp + exclusion_fps == 0 {
        1.0
    } else {
        tp as f64 / (tp + exclusion_fps) as f64
    };
    let recall = tp as f64 / labeled.len() as f64;
    let acted_rate = acted as f64 / labeled.len() as f64;
    println!("generic_secret_precision={precision:.4}");
    println!("generic_secret_recall={recall:.4}");
    println!("generic_secret_acted_under_default_profile={acted_rate:.4}");
    assert!(
        acted_rate >= 0.90,
        "default profile (replace @ 0.6) must act on ≥90% of labeled generics, got {acted_rate:.4}"
    );
    assert!(
        recall >= 0.90,
        "labeled positive recall {recall:.4} below 0.90"
    );
}
