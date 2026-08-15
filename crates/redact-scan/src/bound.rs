// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Rule of three for negative sampling results.

/// If 0 matches in `n` samples, the 95% CI upper bound is `3/n`.
pub fn prevalence_upper_95(sampled_rows: u64, match_count: u64) -> Option<f64> {
    if match_count != 0 || sampled_rows == 0 {
        return None;
    }
    Some(3.0 / sampled_rows as f64)
}

/// Human-readable rule-of-three note for table output.
pub fn rule_of_three_message(sampled_rows: u64) -> String {
    let bound = prevalence_upper_95(sampled_rows, 0).unwrap_or(0.0);
    format!(
        "0 matches in {sampled_rows} sampled rows; prevalence above {:.1}% is unlikely at 95% confidence.",
        bound * 100.0
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thousand_rows_is_point_three_percent() {
        let p = prevalence_upper_95(1000, 0).unwrap();
        assert!((p - 0.003).abs() < 1e-12);
        let msg = rule_of_three_message(1000);
        assert!(msg.contains("0.3%"));
    }
}
