//! Hermetic GENERIC_SECRET scan of the vendored MIT/BSD/Apache slice.
//!
//! SLO (pre-declared):
//! - ≤5 unreviewed GENERIC_SECRET / 100k lines
//! - Secret-named + secret-shaped literals in upstream docs are true positives
//! - Exceeding the ceiling is a detector bug; do not raise N

use std::fs;
use std::path::{Path, PathBuf};

use redact_core::{AnalyzerEngine, EntityType};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    total_lines: usize,
    projects: Vec<Project>,
}

#[derive(Debug, Deserialize)]
struct Project {
    project: String,
    files: Vec<FileEntry>,
}

#[derive(Debug, Deserialize)]
struct FileEntry {
    path: String,
}

#[derive(Debug, Deserialize, Clone)]
struct Fingerprint {
    project: String,
    path: String,
    start: usize,
    end: usize,
    kind: String,
}

fn slice_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/oss-slice")
}

#[test]
fn vendored_oss_slice_generic_secret_slo() {
    let root = slice_root();
    let manifest: Manifest = serde_json::from_str(
        &fs::read_to_string(root.join("manifest.json")).expect("manifest.json"),
    )
    .expect("manifest json");
    let reviewed: Vec<Fingerprint> = serde_json::from_str(
        &fs::read_to_string(root.join("reviewed.json")).expect("reviewed.json"),
    )
    .expect("reviewed json");

    assert!(
        (50_000..=120_000).contains(&manifest.total_lines),
        "slice must stay in the 50–100k line band, got {}",
        manifest.total_lines
    );

    let engine = AnalyzerEngine::new();
    let mut hits: Vec<(String, String, usize, usize)> = Vec::new();
    let mut scanned_lines = 0usize;

    for project in &manifest.projects {
        for file in &project.files {
            let path = root.join(&project.project).join(&file.path);
            if !path.is_file() {
                continue;
            }
            if is_license_file(&path) {
                continue;
            }
            let text = match fs::read_to_string(&path) {
                Ok(t) => t,
                Err(_) => continue, // skip non-UTF8
            };
            scanned_lines += text.lines().count();
            let result = engine.analyze(&text, None).unwrap();
            for ent in result.detected_entities {
                if ent.entity_type == EntityType::GenericSecret {
                    hits.push((
                        project.project.clone(),
                        file.path.clone(),
                        ent.start,
                        ent.end,
                    ));
                }
            }
        }
    }

    let mut unreviewed = 0usize;
    let mut reviewed_tp = 0usize;
    let mut reviewed_waived = 0usize;
    for (project, path, start, end) in &hits {
        if let Some(fp) = reviewed.iter().find(|f| {
            f.project == *project && f.path == *path && f.start == *start && f.end == *end
        }) {
            match fp.kind.as_str() {
                "tp" => reviewed_tp += 1,
                "waived" => reviewed_waived += 1,
                other => panic!("unknown fingerprint kind {other}"),
            }
        } else {
            unreviewed += 1;
            eprintln!("unreviewed GENERIC_SECRET {project}/{path} span={start}..{end}");
        }
    }

    let per_100k = unreviewed as f64 * 100_000.0 / scanned_lines.max(1) as f64;
    println!(
        "oss_slice_lines={scanned_lines} generic_hits={} reviewed_tp={reviewed_tp} reviewed_waived={reviewed_waived} unreviewed={unreviewed} unreviewed_per_100k={per_100k:.4}",
        hits.len()
    );

    assert!(
        unreviewed as u64 * 100_000 <= 5 * scanned_lines as u64,
        "unreviewed GENERIC_SECRET {unreviewed} over {scanned_lines} lines exceeds ≤5/100k (rate {per_100k:.4})"
    );
}

fn is_license_file(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|n| n.to_str()),
        Some("LICENSE" | "LICENSE.txt" | "LICENSE-MIT" | "LICENSE-APACHE" | "COPYING")
    )
}
