// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! JavaScript-runtime smoke tests for the WASM bindings.
//!
//! Run with: `wasm-pack test --node crates/redact-wasm`
//!
//! These execute under `wasm32-unknown-unknown` via the wasm-bindgen Node
//! runner, covering the Timer path that must not call `Instant::now()`.

#[cfg(target_arch = "wasm32")]
mod wasm32 {
    use redact_wasm::RedactEngine;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn constructor_and_analyze_run_without_instant_panic() {
        let engine = RedactEngine::new();
        let json = engine.analyze("Contact john@example.com");
        assert!(
            json.contains("EMAIL_ADDRESS"),
            "analyze must detect email under wasm32: {json}"
        );
        assert!(
            json.contains("processing_time_ms"),
            "Timer path must populate metadata (0 ms on wasm32): {json}"
        );
        // On wasm32, Timer skips Instant::now(); elapsed is always 0.
        assert!(
            json.contains("\"processing_time_ms\":0"),
            "wasm Timer must record 0 ms (proves Instant::now was not called): {json}"
        );
    }

    #[wasm_bindgen_test]
    fn anonymize_replace_and_mask() {
        let engine = RedactEngine::new();
        let replaced = engine.anonymize("Email: john@example.com", "replace");
        assert!(replaced.contains("[EMAIL_ADDRESS]"), "{replaced}");
        let masked = engine.anonymize("Email: john@example.com", "mask");
        assert!(masked.contains("anonymized"), "{masked}");
        assert!(!masked.contains("\"error\""), "{masked}");
    }

    #[wasm_bindgen_test]
    fn anonymize_hash_requires_salt_contract() {
        let engine = RedactEngine::new();
        let rejected = engine.anonymize("Email: john@example.com", "hash");
        assert!(rejected.contains("\"error\""), "{rejected}");
        assert!(rejected.contains("anonymize_with_hash"), "{rejected}");

        let empty = engine.anonymize_with_hash("Email: john@example.com", "");
        assert!(empty.contains("\"error\""), "{empty}");
        assert!(empty.to_ascii_lowercase().contains("salt"), "{empty}");

        let hashed = engine.anonymize_with_hash("Email: john@example.com", "runtime-salt");
        assert!(!hashed.contains("\"error\""), "{hashed}");
        assert!(hashed.contains("EMAIL_ADDRESS_"), "{hashed}");
    }

    #[wasm_bindgen_test]
    fn supported_entities_lists_pattern_types() {
        let engine = RedactEngine::new();
        let json = engine.supported_entities();
        assert!(json.contains("EMAIL_ADDRESS"), "{json}");
        assert!(json.contains("US_SSN"), "{json}");
        assert!(!json.contains("PERSON"), "{json}");
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[test]
fn wasm_runtime_suite_is_exercised_by_wasm_pack() {
    // Native `cargo test` does not execute the wasm32 module above.
    // CI runs: `wasm-pack test --node crates/redact-wasm`
}
