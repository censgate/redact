// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Human-readable table output. Never prints sample values.

use crate::report::ScanReport;

/// Render a tab-separated table of findings.
pub fn render_table(report: &ScanReport) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "scan {}  {}  fingerprint={}  pack={}\n",
        report.scan_id, report.scanned_at, report.target.fingerprint, report.scanner.pattern_pack
    ));
    if report.findings.is_empty() {
        out.push_str("No findings.\n");
        return out;
    }
    out.push_str("table\tcolumn\tpath\tentity\tlayer\tmatches\tsampled\tconfidence\tevidence\n");
    for f in &report.findings {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{:.2}\t{:?}\n",
            f.table,
            f.column,
            f.json_path.as_deref().unwrap_or("-"),
            f.entity_type.as_str(),
            f.layer,
            f.match_count,
            f.sampled_rows,
            f.confidence,
            f.evidence_class
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layers::ScanLayer;
    use crate::report::{Sampling, Scanner, Target};
    use chrono::{TimeZone, Utc};
    use uuid::Uuid;

    #[test]
    fn empty_report_mentions_rule_of_three() {
        let report = ScanReport {
            scan_id: Uuid::nil(),
            scanned_at: Utc.with_ymd_and_hms(2026, 8, 15, 0, 0, 0).unwrap(),
            target: Target {
                fingerprint: "abc".into(),
                engine: "postgres".into(),
                version: "16".into(),
            },
            scanner: Scanner {
                version: "0.9.1".into(),
                pattern_pack: "builtin@1".into(),
            },
            sampling: Sampling {
                layers: vec![ScanLayer::Sample],
                rows_per_column: 1000,
                method: "TABLESAMPLE SYSTEM".into(),
            },
            findings: vec![],
            content_hash: String::new(),
        };
        let s = render_table(&report);
        assert!(s.contains("No findings."));
        assert!(!s.contains("0.3%"));
        assert!(!s.contains("user@"));
    }
}
