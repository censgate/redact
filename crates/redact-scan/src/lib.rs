// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Read-only Postgres PII discovery scanner.
//!
//! Prefer a replica or staging database. Reports list locations and counts
//! only — never sample values.

/// Rule-of-three helper for negative samples.
pub mod bound;
/// Canonical JSON hashing for [`ScanReport::content_hash`].
pub mod canonical;
/// Layer 0 catalog metadata.
pub mod catalog;
/// Command-line argument types.
pub mod cli;
/// Pattern-engine wrapper that drops matched text.
pub mod detect;
/// Scrubbed scanner errors.
pub mod error;
/// Human-readable table output.
pub mod format;
/// Identifier quoting.
pub mod ident;
/// Layer 2 JSON path sampling.
pub mod json_scan;
/// Discovery layer identifiers (`0`, `0.5`, `1`, `2`).
pub mod layers;
/// Value-free report types.
pub mod report;
/// Read-only session and privilege checks.
pub mod safety;
/// Layer 1 table sampling.
pub mod sample;
/// Scan orchestration.
pub mod scan;
/// Name and type heuristics.
pub mod score;
/// Credential redaction for logs and errors.
pub mod scrub;
/// Layer 0.5 planner statistics.
pub mod stats;
/// Optional HTTP POST of the report JSON.
pub mod upload;

pub use error::ScanError;
pub use report::{Finding, ScanReport};
pub use scan::run_scan;

/// Process exit code when the scan completed with no fail-on match.
pub const EXIT_CLEAN: i32 = 0;
/// Process exit code when `--fail-on` matched at least one finding.
pub const EXIT_FINDINGS: i32 = 1;
/// Process exit code for usage errors, safety refusals, and I/O failures.
pub const EXIT_ERROR: i32 = 2;
