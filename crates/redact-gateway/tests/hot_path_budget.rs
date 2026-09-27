// Copyright 2026 Censgate LLC. // pragma: allowlist secret
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Release-mode tripwire for the gateway redaction hot path.
//!
//! `cargo test` is a debug build, so its ceiling only catches a hang or a
//! blow-up. The number that matters for agent platforms is release p50.
//! CI runs this file with `--release`.
//!
//! Ceilings are several times a quiet measurement so a shared runner does
//! not flap. They are not a latency SLO. Tighten them when a real speedup
//! should stick. Do not raise them to hide a regression without saying why.
//!
//! Keep the cases aligned with `benches/hot_path.rs`.

use std::hint::black_box;
use std::time::{Duration, Instant};

use redact_core::AnalyzerEngine;
use redact_gateway::policy::{PolicySet, Profile};
use redact_gateway::redact::json::redact_chat_request;
use redact_gateway::redact::RedactionContext;
use serde_json::{json, Value};

/// Release p50 ceilings, in microseconds.
///
/// Measured on 2026-09-27 (release, median of 100 calls): ascii clean 6µs,
/// email 7µs, Vietnamese bank sentence 29µs, short chat 14µs, ~4KB chat
/// 187µs. Each ceiling is about 15× that sample so a busy CI runner can be
/// slower without flapping. A uniform 2× change stays under the ceiling and
/// still prints. The page-to-clean ratio below catches a slowdown that hits
/// only the long agent prompt.
const RELEASE_ASCII_CLEAN_US: u128 = 100;
const RELEASE_ASCII_EMAIL_US: u128 = 120;
const RELEASE_MULTIBYTE_US: u128 = 500;
const RELEASE_CHAT_SHORT_US: u128 = 250;
const RELEASE_CHAT_PAGE_US: u128 = 3_000;

/// `chat_page` p50 divided by `ascii_clean` p50. The 2026-09-27 sample was ~31.
const RELEASE_PAGE_TO_CLEAN: u128 = 80;

/// Debug builds are not the shipping artifact. The cap only rejects a
/// pathological slowdown.
const DEBUG_US: u128 = 100_000;

#[test]
fn gateway_hot_path_stays_inside_its_budget() {
    let engine = AnalyzerEngine::new();
    let profile = PolicySet::default().default_profile();
    let profile = profile.as_ref();
    let page = agent_page();

    let clean = "List three deployment checks for the staging cluster.";
    let email = "Email me at alice@example.com about the rollout.";
    let vi = "Số tài khoản ngân hàng: 841234567890";
    let short_chat = chat(email);
    let page_chat = chat(&page);

    assert_eq!(redact(&engine, profile, clean), clean);
    let email_out = redact(&engine, profile, email);
    assert_eq!(email_out, "Email me at [EMAIL_ADDRESS] about the rollout.");
    let vi_out = redact(&engine, profile, vi);
    assert!(
        !vi_out.contains("841234567890"),
        "vietnamese bank number leaked: {vi_out}"
    );
    let short_out = redact_chat(&engine, profile, &short_chat).to_string();
    assert!(short_out.contains("[EMAIL_ADDRESS]"));
    assert!(!short_out.contains("alice@example.com"));
    let page_out = redact_chat(&engine, profile, &page_chat).to_string();
    assert!(page_out.contains("[EMAIL_ADDRESS]"));
    assert!(!page_out.contains("alice@example.com"));

    let iters = if cfg!(debug_assertions) { 20 } else { 100 };
    let samples = [
        (
            "ascii_clean",
            RELEASE_ASCII_CLEAN_US,
            median_elapsed(10, iters, || {
                black_box(redact(&engine, profile, clean));
            }),
        ),
        (
            "ascii_email",
            RELEASE_ASCII_EMAIL_US,
            median_elapsed(10, iters, || {
                black_box(redact(&engine, profile, email));
            }),
        ),
        (
            "multibyte_vi",
            RELEASE_MULTIBYTE_US,
            median_elapsed(10, iters, || {
                black_box(redact(&engine, profile, vi));
            }),
        ),
        (
            "chat_short",
            RELEASE_CHAT_SHORT_US,
            median_elapsed(10, iters, || {
                black_box(redact_chat(&engine, profile, &short_chat));
            }),
        ),
        (
            "chat_page",
            RELEASE_CHAT_PAGE_US,
            median_elapsed(10, iters, || {
                black_box(redact_chat(&engine, profile, &page_chat));
            }),
        ),
    ];

    let mut failed = Vec::new();
    let mut clean_p50 = None;
    let mut page_p50 = None;
    for (name, release_us, p50) in samples {
        let ceiling_us = if cfg!(debug_assertions) {
            DEBUG_US
        } else {
            release_us
        };
        let p50_us = p50.as_micros();
        eprintln!(
            "gateway hot path {name} p50={p50_us}µs ceiling={ceiling_us}µs ({build})",
            build = if cfg!(debug_assertions) {
                "debug"
            } else {
                "release"
            }
        );
        if name == "ascii_clean" {
            clean_p50 = Some(p50_us);
        }
        if name == "chat_page" {
            page_p50 = Some(p50_us);
        }
        if p50_us > ceiling_us {
            failed.push(format!("{name} p50 {p50_us}µs exceeds {ceiling_us}µs"));
        }
    }
    if !cfg!(debug_assertions) {
        let clean = clean_p50.expect("ascii_clean sample");
        let page = page_p50.expect("chat_page sample");
        let ratio = page / clean.max(1);
        eprintln!("gateway hot path chat_page/ascii_clean={ratio} ceiling={RELEASE_PAGE_TO_CLEAN}");
        if ratio > RELEASE_PAGE_TO_CLEAN {
            failed.push(format!(
                "chat_page/ascii_clean {ratio} exceeds {RELEASE_PAGE_TO_CLEAN}"
            ));
        }
    }
    assert!(failed.is_empty(), "gateway hot path regression: {failed:?}");
}

fn redact(engine: &AnalyzerEngine, profile: &Profile, text: &str) -> String {
    let mut ctx = RedactionContext::new(engine, profile);
    ctx.redact(text).expect("redact")
}

fn redact_chat(engine: &AnalyzerEngine, profile: &Profile, body: &Value) -> Value {
    let mut owned = body.clone();
    let mut ctx = RedactionContext::new(engine, profile);
    redact_chat_request(&mut ctx, &mut owned).expect("chat redact");
    owned
}

fn chat(user: &str) -> Value {
    json!({
        "model": "agent",
        "messages": [
            {"role": "system", "content": "You are a deployment assistant. Be brief."},
            {"role": "user", "content": user}
        ]
    })
}

fn agent_page() -> String {
    let notes = "Review the rollout notes and reply in one paragraph. ".repeat(80);
    format!(
        "Check the canary error budget and name the next action. {notes}Email alice@example.com if blocked."
    )
}

fn median_elapsed(warmup: usize, iters: usize, mut body: impl FnMut()) -> Duration {
    for _ in 0..warmup {
        body();
    }
    let mut samples = Vec::with_capacity(iters);
    for _ in 0..iters {
        let start = Instant::now();
        body();
        samples.push(start.elapsed());
    }
    samples.sort_unstable();
    samples[samples.len() / 2]
}
