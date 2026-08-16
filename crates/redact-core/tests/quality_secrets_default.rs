//! Default-pack secret quality: exact spans for compiled named types and
//! `GENERIC_SECRET`. Tokens are assembled at run time so committed source
//! has no contiguous secret-shaped literal.

mod common;

use common::quality::{expected_span, run_runtime_cases, Baseline, CorpusConfig, RuntimeCase};
use redact_core::AnalyzerEngine;

fn token(prefix: &str, body: &str) -> String {
    format!("{prefix}{body}")
}

fn secrets_config() -> CorpusConfig {
    CorpusConfig {
        language: "en".to_string(),
        min_score: 0.6,
        ner: false,
        entity_types_in_scope: vec![
            "GENERIC_SECRET".into(),
            "HUGGINGFACE_TOKEN".into(),
            "DATABRICKS_TOKEN".into(),
            "DIGITALOCEAN_TOKEN".into(),
            "NOTION_API_KEY".into(),
            "PERPLEXITY_API_KEY".into(),
            "HTTP_BASIC_AUTH".into(),
            "AWS_ACCESS_KEY".into(),
            "GITLAB_TOKEN".into(),
            "GUID".into(),
            "SHA1_HASH".into(),
            "SHA256_HASH".into(),
            "MD5_HASH".into(),
        ],
    }
}

fn baseline() -> Baseline {
    Baseline {
        corpus_sha256: String::new(),
        max_fp_overall: 0,
        max_fp_negative_tier: 0,
        min_precision_ppm: 1_000_000,
        require_contract_exact: true,
    }
}

fn contract(id: &str, input: String, entity_type: &str, raw: &str) -> RuntimeCase {
    let expected = vec![expected_span(&input, entity_type, raw)];
    RuntimeCase {
        id: id.to_string(),
        input,
        expected,
        tier: "contract".into(),
    }
}

fn negative(id: &str, input: String) -> RuntimeCase {
    RuntimeCase {
        id: id.to_string(),
        input,
        expected: Vec::new(),
        tier: "negative".into(),
    }
}

fn mixed_hex(seed: u64, n: usize) -> String {
    const ALPH: &[u8] = b"0123456789abcdef";
    let mut x = seed | 1;
    let mut out = String::with_capacity(n);
    for i in 0..n {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
        let mut idx = (x >> 33) as usize % ALPH.len();
        if i == 0 {
            idx = 10 + (idx % 6);
        }
        if i == 1 {
            idx %= 10;
        }
        out.push(ALPH[idx] as char);
    }
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

fn cases() -> Vec<RuntimeCase> {
    let mut out = Vec::new();

    let hf = token("hf_", &"A".repeat(34));
    out.push(contract(
        "huggingface-token",
        format!("model token {hf}"),
        "HUGGINGFACE_TOKEN",
        &hf,
    ));

    let dapi = token("dapi", &"a".repeat(32));
    out.push(contract(
        "databricks-token",
        format!("workspace {dapi}"),
        "DATABRICKS_TOKEN",
        &dapi,
    ));

    let dop = token("dop_v1_", &"a".repeat(64));
    out.push(contract(
        "digitalocean-token",
        format!("do token {dop}"),
        "DIGITALOCEAN_TOKEN",
        &dop,
    ));

    let ntn = token("ntn_", &format!("{}{}", "1".repeat(11), "A".repeat(35)));
    out.push(contract(
        "notion-api-key",
        format!("notion {ntn}"),
        "NOTION_API_KEY",
        &ntn,
    ));

    let pplx = token("pplx-", &"A".repeat(48));
    out.push(contract(
        "perplexity-api-key",
        format!("pplx {pplx}"),
        "PERPLEXITY_API_KEY",
        &pplx,
    ));

    let basic = format!("{}{}", "dXNlcm5hbWU6", "cGFzc3dvcmQ=");
    out.push(contract(
        "http-basic-canonical",
        format!("Authorization: Basic {basic}"),
        "HTTP_BASIC_AUTH",
        &basic,
    ));
    out.push(contract(
        "http-basic-case-insensitive",
        format!("Authorization: BASIC {basic}"),
        "HTTP_BASIC_AUTH",
        &basic,
    ));

    let akia = token("AKIA", "IOSFODNN7EXAMPLE");
    out.push(contract(
        "aws-akia",
        format!("aws {akia}"),
        "AWS_ACCESS_KEY",
        &akia,
    ));

    let absk = token("ABSK", &format!("{}==", "A".repeat(109)));
    out.push(contract(
        "aws-bedrock-absk-padded",
        format!("bedrock {absk} trailing"),
        "AWS_ACCESS_KEY",
        &absk,
    ));

    let short_lived = token("bedrock-api-key-", "YmVkcm9jay5hbWF6b25hd3MuY29t");
    out.push(contract(
        "aws-bedrock-short-lived",
        format!("key {short_lived}"),
        "AWS_ACCESS_KEY",
        &short_lived,
    ));

    let glpat = token("glpat-", &"A".repeat(20));
    out.push(contract(
        "gitlab-glpat",
        format!("gitlab {glpat}"),
        "GITLAB_TOKEN",
        &glpat,
    ));

    let glagent = token("glagent-", &"A".repeat(50));
    out.push(contract(
        "gitlab-glagent",
        format!("agent {glagent}"),
        "GITLAB_TOKEN",
        &glagent,
    ));

    let generic_body = mixed_alnum(0xC0FFEE, 28);
    let generic_text = format!("api_key={generic_body}");
    out.push(contract(
        "generic-secret-assignment",
        generic_text,
        "GENERIC_SECRET",
        &generic_body,
    ));

    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let strong_uuid = format!("api_key={uuid}");
    out.push(RuntimeCase {
        id: "uuid-strong-keyword-is-generic-secret".into(),
        input: strong_uuid.clone(),
        expected: vec![expected_span(&strong_uuid, "GENERIC_SECRET", uuid)],
        tier: "contract".into(),
    });

    let sha1 = mixed_hex(0x5A11, 40);
    let secret_sha1 = format!("api_key={sha1}");
    out.push(RuntimeCase {
        id: "sha1-under-secret-keyword-is-generic".into(),
        input: secret_sha1.clone(),
        expected: vec![expected_span(&secret_sha1, "GENERIC_SECRET", &sha1)],
        tier: "contract".into(),
    });

    // Exclusion / lockfile / digest-keyed: no GENERIC_SECRET. Weak-keyword
    // UUID must stay GUID (the documented hole is strong-keyword only).
    let weak_uuid = format!("revision={uuid}");
    out.push(RuntimeCase {
        id: "uuid-weak-keyword-is-guid".into(),
        input: weak_uuid.clone(),
        expected: vec![expected_span(&weak_uuid, "GUID", uuid)],
        tier: "contract".into(),
    });

    let etag = format!("etag={uuid}");
    out.push(RuntimeCase {
        id: "etag-uuid-is-guid-not-generic".into(),
        input: etag.clone(),
        expected: vec![expected_span(&etag, "GUID", uuid)],
        tier: "contract".into(),
    });
    let checksum = format!("checksum={}", "a".repeat(64));
    out.push(RuntimeCase {
        id: "checksum-sha256-is-hash-not-generic".into(),
        input: checksum.clone(),
        expected: vec![expected_span(&checksum, "SHA256_HASH", &"a".repeat(64))],
        tier: "contract".into(),
    });
    out.push(negative(
        "exclusion-integrity-lockfile",
        format!("integrity=sha512-{}", "A+/".repeat(24)),
    ));
    out.push(negative(
        "exclusion-password-stopword",
        "password=password".into(),
    ));
    out.push(negative(
        "exclusion-placeholder-key",
        "api_key=your-key-here".into(),
    ));
    out.push(negative(
        "exclusion-prose-token",
        "Please send the token to the reviewer.".into(),
    ));
    out.push(negative("exclusion-hex-color", "color: #aabbcc;".into()));
    out.push(negative(
        "exclusion-data-uri",
        format!("data:image/png;base64,{}", "A+/".repeat(16)),
    ));
    out.push(negative(
        "http-basic-noncanonical-unused-bits",
        format!("Authorization: Basic {}", "dTpwYXN="),
    ));
    out.push(negative(
        "huggingface-truncated",
        format!("token {}", token("hf_", "tooshort")),
    ));
    out.push(negative(
        "optional-shopify-not-default",
        format!("shop {}", token("shpat_", &"a".repeat(32))),
    ));

    out
}

#[test]
fn secrets_default_exact_span_quality() {
    let config = secrets_config();
    run_runtime_cases(
        &AnalyzerEngine::new(),
        "secrets-default",
        &config,
        &cases(),
        &baseline(),
    );
}
