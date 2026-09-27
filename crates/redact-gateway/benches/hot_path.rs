// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! In-process microbenchmark of the gateway redaction hot path.
//!
//! This is the work an agent platform pays on every request before any
//! network hop: policy, pattern detection, and the chat JSON walk. It does
//! not include HTTP, TLS, or the provider. The release-mode tripwire that
//! runs in CI is `tests/hot_path_budget.rs`.
//!
//! ```text
//! cargo bench -p redact-gateway --bench hot_path
//! ```

use std::hint::black_box;
use std::sync::Arc;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use redact_core::AnalyzerEngine;
use redact_gateway::policy::{PolicySet, Profile};
use redact_gateway::redact::json::redact_chat_request;
use redact_gateway::redact::RedactionContext;
use serde_json::{json, Value};

fn profile() -> Arc<Profile> {
    PolicySet::default().default_profile()
}

fn redact_text(engine: &AnalyzerEngine, profile: &Profile, text: &str) -> String {
    let mut ctx = RedactionContext::new(engine, profile);
    ctx.redact(text).expect("redact")
}

fn chat_body(user: &str) -> Value {
    json!({
        "model": "agent",
        "messages": [
            {"role": "system", "content": "You are a deployment assistant. Be brief."},
            {"role": "user", "content": user}
        ]
    })
}

fn bench_text(c: &mut Criterion) {
    let engine = AnalyzerEngine::new();
    let profile = profile();
    let mut group = c.benchmark_group("gateway_redact_text");
    group.sample_size(30);

    let cases = [
        (
            "ascii_clean",
            "List three deployment checks for the staging cluster.",
        ),
        (
            "ascii_email",
            "Email me at alice@example.com about the rollout.",
        ),
        ("multibyte_vi", "Số tài khoản ngân hàng: 841234567890"),
    ];

    for (name, text) in cases {
        group.throughput(Throughput::Bytes(text.len() as u64));
        group.bench_with_input(BenchmarkId::from_parameter(name), &text, |b, text| {
            b.iter(|| black_box(redact_text(&engine, profile.as_ref(), black_box(text))));
        });
    }
    group.finish();
}

fn bench_chat(c: &mut Criterion) {
    let engine = AnalyzerEngine::new();
    let profile = profile();
    let mut group = c.benchmark_group("gateway_chat_request");
    group.sample_size(30);

    let short = chat_body("Email me at alice@example.com about the rollout.");
    let notes = "Review the rollout notes and reply in one paragraph. ".repeat(80);
    let long_user = format!(
        "Check the canary error budget and name the next action. {notes}Email alice@example.com if blocked."
    );
    let long = chat_body(&long_user);

    for (name, body) in [("short_email", short), ("agent_page", long)] {
        let bytes = body.to_string().len() as u64;
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::from_parameter(name), &body, |b, body| {
            b.iter(|| {
                let mut owned = body.clone();
                let mut ctx = RedactionContext::new(&engine, profile.as_ref());
                redact_chat_request(&mut ctx, black_box(&mut owned)).expect("chat redact");
                black_box(owned);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_text, bench_chat);
criterion_main!(benches);
