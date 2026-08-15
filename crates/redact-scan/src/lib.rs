// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

//! Read-only Postgres PII discovery scanner.
//!
//! Prefer a replica or staging database. Reports list locations and counts
//! only — never sample values.

pub mod canonical;
pub mod cli;
pub mod error;
pub mod layers;
pub mod report;
pub mod scrub;

pub use error::ScanError;
pub use report::{Finding, ScanReport};

pub const EXIT_CLEAN: i32 = 0;
pub const EXIT_FINDINGS: i32 = 1;
pub const EXIT_ERROR: i32 = 2;
