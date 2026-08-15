// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Read-only Postgres PII discovery scanner.
//!
//! Prefer a replica or staging database. Reports list locations and counts
//! only — never sample values.

/// Canonical JSON hashing for [`ScanReport::content_hash`].
pub mod canonical;
/// Command-line argument types.
pub mod cli;
/// Scrubbed scanner errors.
pub mod error;
/// Discovery layer identifiers (`0`, `0.5`, `1`, `2`).
pub mod layers;
/// Value-free report types.
pub mod report;
/// Credential redaction for logs and errors.
pub mod scrub;

pub use error::ScanError;
pub use report::{Finding, ScanReport};

/// Process exit code when the scan completed with no fail-on match.
pub const EXIT_CLEAN: i32 = 0;
/// Process exit code when `--fail-on` matched at least one finding.
pub const EXIT_FINDINGS: i32 = 1;
/// Process exit code for usage errors, safety refusals, and I/O failures.
pub const EXIT_ERROR: i32 = 2;
