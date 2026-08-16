//! Shared exact-span scorer for hermetic pattern-quality corpora.

use std::collections::HashSet;
use std::path::PathBuf;

use redact_core::AnalyzerEngine;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Deserialize)]
pub struct Corpus {
    pub version: String,
    pub config: CorpusConfig,
    pub cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
pub struct CorpusConfig {
    pub language: String,
    pub min_score: f32,
    pub ner: bool,
    pub entity_types_in_scope: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct Case {
    pub id: String,
    pub input: String,
    pub expected: Vec<ExpectedSpan>,
    pub tier: String,
}

#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
pub struct ExpectedSpan {
    pub entity_type: String,
    pub start: usize,
    pub end: usize,
    pub raw: String,
}

#[derive(Debug, Deserialize)]
pub struct Baseline {
    pub corpus_sha256: String,
    pub max_fp_overall: u32,
    pub max_fp_negative_tier: u32,
    pub min_precision_ppm: u32,
    pub require_contract_exact: bool,
}

#[derive(Debug, Default)]
pub struct Counts {
    pub tp: u32,
    pub fp: u32,
    pub fn_: u32,
}

pub fn quality_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/quality")
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub fn load_json_corpus(name: &str) -> (Corpus, Vec<u8>) {
    let path = quality_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let corpus: Corpus =
        serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()));
    (corpus, bytes)
}

pub fn load_baseline(name: &str) -> Baseline {
    let path = quality_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

pub fn enforce_corpus_config(corpus: &Corpus, expected_version: &str) {
    assert_eq!(corpus.version, expected_version);
    assert!(
        !corpus.config.ner,
        "NER quality is out of scope for {expected_version}; set config.ner=false"
    );
    assert!(
        corpus.config.min_score > 0.0,
        "{expected_version}: config.min_score must be enforced and > 0"
    );
    assert!(
        !corpus.config.entity_types_in_scope.is_empty(),
        "{expected_version}: entity_types_in_scope must not be empty"
    );

    let mut seen = HashSet::new();
    for case in &corpus.cases {
        assert!(
            seen.insert(case.id.as_str()),
            "duplicate case id: {}",
            case.id
        );
        for exp in &case.expected {
            let slice = case.input.get(exp.start..exp.end).unwrap_or_else(|| {
                panic!(
                    "{}: span {}..{} out of range (len={})",
                    case.id,
                    exp.start,
                    exp.end,
                    case.input.len()
                )
            });
            assert_eq!(
                slice, exp.raw,
                "{}: raw mismatch for {}..{}",
                case.id, exp.start, exp.end
            );
            assert!(
                corpus
                    .config
                    .entity_types_in_scope
                    .iter()
                    .any(|t| t == &exp.entity_type),
                "{}: expected type {} is outside entity_types_in_scope",
                case.id,
                exp.entity_type
            );
        }
    }
}

pub type Pred = (String, usize, usize);

pub fn predictions_for_case(
    engine: &AnalyzerEngine,
    case: &Case,
    config: &CorpusConfig,
) -> Vec<Pred> {
    let result = engine
        .analyze(&case.input, Some(&config.language))
        .unwrap_or_else(|e| panic!("{}: analyze failed: {e}", case.id));

    let in_scope: HashSet<&str> = config
        .entity_types_in_scope
        .iter()
        .map(String::as_str)
        .collect();

    let mut preds = Vec::new();
    for entity in result.detected_entities {
        let ty = entity.entity_type.as_str().to_string();
        if entity.score < config.min_score {
            panic!(
                "{}: engine emitted {} @ {} below config.min_score {}",
                case.id, ty, entity.score, config.min_score
            );
        }
        if !in_scope.contains(ty.as_str()) {
            panic!(
                "{}: prediction {} {}..{} is outside entity_types_in_scope",
                case.id, ty, entity.start, entity.end
            );
        }
        preds.push((ty, entity.start, entity.end));
    }
    preds
}

pub fn score_case(preds: &[Pred], expected: &[ExpectedSpan]) -> Counts {
    let mut counts = Counts::default();
    let mut used = vec![false; preds.len()];
    let expected: Vec<Pred> = expected
        .iter()
        .map(|e| (e.entity_type.clone(), e.start, e.end))
        .collect();

    for exp in &expected {
        if let Some((idx, _)) = preds
            .iter()
            .enumerate()
            .find(|(i, p)| !used[*i] && *p == exp)
        {
            used[idx] = true;
            counts.tp += 1;
        } else {
            counts.fn_ += 1;
        }
    }
    for (i, pred) in preds.iter().enumerate() {
        if !used[i] {
            counts.fp += 1;
            let _ = pred;
        }
    }
    counts
}

pub fn run_corpus(engine: &AnalyzerEngine, corpus: &Corpus, baseline: &Baseline) {
    enforce_corpus_config(corpus, &corpus.version);

    let mut overall = Counts::default();
    let mut negative_fp = 0u32;
    let mut failures = Vec::new();

    for case in &corpus.cases {
        let preds = predictions_for_case(engine, case, &corpus.config);
        let counts = score_case(&preds, &case.expected);
        if case.tier == "negative" {
            negative_fp += counts.fp;
        }
        if baseline.require_contract_exact
            && case.tier == "contract"
            && (counts.fp > 0 || counts.fn_ > 0)
        {
            failures.push(format!(
                "{}: contract not exact tp={} fp={} fn={} preds={preds:?}",
                case.id, counts.tp, counts.fp, counts.fn_
            ));
        }
        if case.tier == "negative" && counts.fp > 0 {
            failures.push(format!("{}: negative-tier FP preds={preds:?}", case.id));
        }
        overall.tp += counts.tp;
        overall.fp += counts.fp;
        overall.fn_ += counts.fn_;
    }

    let denom = overall.tp + overall.fp;
    let precision_ppm = if denom == 0 {
        1_000_000
    } else {
        (u64::from(overall.tp) * 1_000_000 / u64::from(denom)) as u32
    };

    println!(
        "quality_{} tp={} fp={} fn={} precision_ppm={} negative_fp={}",
        corpus.version, overall.tp, overall.fp, overall.fn_, precision_ppm, negative_fp
    );

    if !failures.is_empty() {
        panic!("quality failures:\n{}", failures.join("\n"));
    }
    assert!(
        overall.fp <= baseline.max_fp_overall,
        "fp {} exceeds max_fp_overall {}",
        overall.fp,
        baseline.max_fp_overall
    );
    assert!(
        negative_fp <= baseline.max_fp_negative_tier,
        "negative fp {} exceeds max_fp_negative_tier {}",
        negative_fp,
        baseline.max_fp_negative_tier
    );
    assert!(
        precision_ppm >= baseline.min_precision_ppm,
        "precision_ppm {precision_ppm} below {}",
        baseline.min_precision_ppm
    );
}

/// Programmatic case used by runtime-assembled secret corpora.
pub struct RuntimeCase {
    pub id: String,
    pub input: String,
    pub expected: Vec<ExpectedSpan>,
    pub tier: String,
}

pub fn run_runtime_cases(
    engine: &AnalyzerEngine,
    version: &str,
    config: &CorpusConfig,
    cases: &[RuntimeCase],
    baseline: &Baseline,
) {
    let corpus = Corpus {
        version: version.to_string(),
        config: CorpusConfig {
            language: config.language.clone(),
            min_score: config.min_score,
            ner: config.ner,
            entity_types_in_scope: config.entity_types_in_scope.clone(),
        },
        cases: cases
            .iter()
            .map(|c| Case {
                id: c.id.clone(),
                input: c.input.clone(),
                expected: c.expected.clone(),
                tier: c.tier.clone(),
            })
            .collect(),
    };
    run_corpus(engine, &corpus, baseline);
}

pub fn expected_span(input: &str, entity_type: &str, raw: &str) -> ExpectedSpan {
    let start = input
        .find(raw)
        .unwrap_or_else(|| panic!("raw {raw:?} not in {input:?}"));
    ExpectedSpan {
        entity_type: entity_type.to_string(),
        start,
        end: start + raw.len(),
        raw: raw.to_string(),
    }
}
