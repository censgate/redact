// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use std::path::PathBuf;
use std::time::Duration;

use crate::layers::{default_layers, parse_layers, ScanLayer};

#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum OutputFormat {
    Json,
    Table,
}

#[derive(Debug, Parser)]
#[command(
    name = "redact-scan",
    about = "Read-only Postgres PII discovery scanner",
    version
)]
pub struct Cli {
    /// Postgres connection URL (also reads DATABASE_URL)
    #[arg(long, env = "DATABASE_URL")]
    pub url: Option<String>,

    /// Schema to scan
    #[arg(long, default_value = "public")]
    pub schema: String,

    /// Comma-separated layers: 0,0.5,1,2
    #[arg(long, default_value = "0,0.5,1,2")]
    pub layers: String,

    /// Maximum rows to sample per candidate column
    #[arg(long, default_value_t = 1000)]
    pub sample_rows: u32,

    /// Statement timeout (e.g. 30s)
    #[arg(long, default_value = "30s")]
    pub statement_timeout: String,

    /// Output format
    #[arg(long, value_enum, default_value_t = OutputFormat::Json)]
    pub format: OutputFormat,

    /// Write the report to this path
    #[arg(long)]
    pub out: Option<PathBuf>,

    /// Optional HTTP endpoint that receives the report JSON
    #[arg(long)]
    pub report_url: Option<String>,

    /// Bearer token for --report-url (also reads REDACT_SCAN_API_KEY)
    #[arg(long, env = "REDACT_SCAN_API_KEY")]
    pub api_key: Option<String>,

    /// Extra header for --report-url, repeatable (`Name: value`)
    #[arg(long = "report-header")]
    pub report_headers: Vec<String>,

    /// Exit 1 when findings match this entity type, or `any`
    #[arg(long)]
    pub fail_on: Option<String>,

    /// Write local debug samples (incompatible with --report-url)
    #[arg(long)]
    pub include_samples: bool,

    /// Path for local debug samples (required with --include-samples and --format json)
    #[arg(long)]
    pub samples_out: Option<PathBuf>,
}

impl Cli {
    pub fn parsed_layers(&self) -> Result<Vec<ScanLayer>> {
        if self.layers.trim().is_empty() {
            return Ok(default_layers());
        }
        parse_layers(&self.layers)
    }

    pub fn statement_timeout(&self) -> Result<Duration> {
        parse_duration(&self.statement_timeout)
    }

    /// Reject unsafe flag combinations before any network I/O.
    pub fn validate_preflight(&self) -> Result<()> {
        if self.include_samples && self.report_url.is_some() {
            return Err(anyhow!(
                "--include-samples cannot be used with --report-url"
            ));
        }
        if self.include_samples && self.format == OutputFormat::Json && self.samples_out.is_none() {
            return Err(anyhow!(
                "--include-samples with --format json requires --samples-out"
            ));
        }
        if self.url.is_none() && self.report_url.is_none() {
            // Allow --include-samples + --report-url error path without --url.
            // A real scan still needs --url; checked in run().
        }
        Ok(())
    }
}

pub fn parse_duration(s: &str) -> Result<Duration> {
    let s = s.trim();
    if let Some(ms) = s.strip_suffix("ms") {
        let n: u64 = ms.parse()?;
        return Ok(Duration::from_millis(n));
    }
    if let Some(sec) = s.strip_suffix('s') {
        let n: u64 = sec.parse()?;
        return Ok(Duration::from_secs(n));
    }
    if let Some(min) = s.strip_suffix('m') {
        let n: u64 = min.parse()?;
        return Ok(Duration::from_secs(n * 60));
    }
    let n: u64 = s.parse()?;
    Ok(Duration::from_secs(n))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_samples_with_report_url_is_rejected() {
        let cli = Cli::parse_from([
            "redact-scan",
            "--include-samples",
            "--report-url",
            "http://127.0.0.1:9/hook",
            "--samples-out",
            "/tmp/s.json",
        ]);
        let err = cli.validate_preflight().unwrap_err().to_string();
        assert!(err.contains("--include-samples"));
        assert!(err.contains("--report-url"));
    }

    #[test]
    fn duration_parse() {
        assert_eq!(parse_duration("30s").unwrap(), Duration::from_secs(30));
        assert_eq!(parse_duration("500ms").unwrap(), Duration::from_millis(500));
    }
}
