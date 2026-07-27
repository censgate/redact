//! Pattern-v1 quality corpus: exact-span scoring + baseline ratchet.
//!
//! Config: AnalyzerEngine defaults, language `en`, min score 0.5, no NER.

use redact_core::AnalyzerEngine;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Corpus {
    version: String,
    config: CorpusConfig,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct CorpusConfig {
    language: String,
    entity_types_in_scope: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    input: String,
    expected: Vec<ExpectedSpan>,
    tier: String,
}

#[derive(Debug, Deserialize, Clone)]
struct ExpectedSpan {
    entity_type: String,
    start: usize,
    end: usize,
    raw: String,
}

#[derive(Debug, Deserialize)]
struct Baseline {
    corpus_sha256: String,
    max_fp_overall: u32,
    max_fp_negative_tier: u32,
    min_precision_ppm: u32,
    require_contract_exact: bool,
}

#[derive(Debug, Default)]
struct Counts {
    tp: u32,
    fp: u32,
    fn_: u32,
}

fn quality_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/quality")
}

fn load_corpus() -> (Corpus, Vec<u8>) {
    let path = quality_dir().join("pattern-v1.json");
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let corpus: Corpus =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    assert_eq!(corpus.version, "pattern-v1");
    (corpus, bytes)
}

fn load_baseline() -> Baseline {
    let path = quality_dir().join("pattern-v1-baseline.json");
    let bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn score_case(
    engine: &AnalyzerEngine,
    case: &Case,
    in_scope: &HashSet<String>,
    language: &str,
) -> Counts {
    for exp in &case.expected {
        let slice = case
            .input
            .get(exp.start..exp.end)
            .unwrap_or_else(|| panic!("{}: span {}..{} out of range", case.id, exp.start, exp.end));
        assert_eq!(
            slice, exp.raw,
            "{}: raw mismatch for {}..{}",
            case.id, exp.start, exp.end
        );
    }

    let analysis = engine
        .analyze(&case.input, Some(language))
        .unwrap_or_else(|e| panic!("{}: analyze failed: {e}", case.id));

    let mut preds: Vec<(String, usize, usize)> = analysis
        .detected_entities
        .iter()
        .map(|e| (e.entity_type.as_str().to_string(), e.start, e.end))
        .filter(|(t, _, _)| in_scope.contains(t))
        .collect();
    preds.sort();

    let mut expected: Vec<(String, usize, usize)> = case
        .expected
        .iter()
        .map(|e| (e.entity_type.clone(), e.start, e.end))
        .collect();
    expected.sort();

    let mut counts = Counts::default();
    let mut used_pred = vec![false; preds.len()];

    for exp in &expected {
        if let Some((idx, _)) = preds
            .iter()
            .enumerate()
            .find(|(i, p)| !used_pred[*i] && *p == exp)
        {
            used_pred[idx] = true;
            counts.tp += 1;
        } else {
            counts.fn_ += 1;
        }
    }
    for (i, _) in preds.iter().enumerate() {
        if !used_pred[i] {
            counts.fp += 1;
        }
    }
    counts
}

#[test]
fn pattern_v1_quality_baseline() {
    let (corpus, corpus_bytes) = load_corpus();
    let baseline = load_baseline();

    let digest = sha256_hex(&corpus_bytes);
    assert_eq!(
        digest, baseline.corpus_sha256,
        "pattern-v1.json hash mismatch; update baseline corpus_sha256 when changing the corpus"
    );

    assert_eq!(corpus.config.language, "en");
    let in_scope: HashSet<String> = corpus.config.entity_types_in_scope.into_iter().collect();

    let engine = AnalyzerEngine::new();
    let mut overall = Counts::default();
    let mut negative_fp = 0u32;
    let mut per_case: HashMap<String, Counts> = HashMap::new();

    for case in &corpus.cases {
        let c = score_case(&engine, case, &in_scope, &corpus.config.language);
        if case.tier == "negative" {
            negative_fp += c.fp;
        }
        if baseline.require_contract_exact && case.tier == "contract" {
            assert_eq!(c.fn_, 0, "contract case {} has FN={}", case.id, c.fn_);
            assert_eq!(
                c.fp, 0,
                "contract case {} has FP={} (preds may include in-scope extras)",
                case.id, c.fp
            );
        }
        overall.tp += c.tp;
        overall.fp += c.fp;
        overall.fn_ += c.fn_;
        per_case.insert(case.id.clone(), c);
    }

    let denom = overall.tp + overall.fp;
    let precision_ppm = if denom == 0 {
        1_000_000
    } else {
        (u64::from(overall.tp) * 1_000_000 / u64::from(denom)) as u32
    };

    eprintln!(
        "pattern-v1 overall tp={} fp={} fn={} precision_ppm={} negative_fp={}",
        overall.tp, overall.fp, overall.fn_, precision_ppm, negative_fp
    );
    for (id, c) in &per_case {
        if c.fp > 0 || c.fn_ > 0 {
            eprintln!("  {id}: tp={} fp={} fn={}", c.tp, c.fp, c.fn_);
        }
    }

    assert!(
        overall.fp <= baseline.max_fp_overall,
        "overall FP {} exceeds max_fp_overall {}",
        overall.fp,
        baseline.max_fp_overall
    );
    assert!(
        negative_fp <= baseline.max_fp_negative_tier,
        "negative-tier FP {} exceeds max_fp_negative_tier {}",
        negative_fp,
        baseline.max_fp_negative_tier
    );
    assert!(
        precision_ppm >= baseline.min_precision_ppm,
        "precision_ppm {} below min_precision_ppm {}",
        precision_ppm,
        baseline.min_precision_ppm
    );
}
