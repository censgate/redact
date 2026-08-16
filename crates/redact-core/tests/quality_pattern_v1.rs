//! Pattern-v1 PII precision harness.
//!
//! Scores `testdata/quality/pattern-v1.json` with exact UTF-8 spans.
//! Precision 1.0 here is a hermetic-set result, not a general claim.

mod common;

use common::quality::{load_baseline, load_json_corpus, run_corpus, sha256_hex};
use redact_core::AnalyzerEngine;

#[test]
fn pattern_v1_precision_gates() {
    let (corpus, bytes) = load_json_corpus("pattern-v1.json");
    let baseline = load_baseline("pattern-v1-baseline.json");
    assert_eq!(
        sha256_hex(&bytes),
        baseline.corpus_sha256,
        "pattern-v1.json hash mismatch; update testdata/quality/pattern-v1-baseline.json when changing the corpus"
    );
    run_corpus(&AnalyzerEngine::new(), &corpus, &baseline);
}
