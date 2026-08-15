// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use clap::Parser;
use redact_scan::cli::{Cli, OutputFormat};
use redact_scan::detect::fail_on_matches;
use redact_scan::error::ScanError;
use redact_scan::report::DebugSamples;
use redact_scan::scrub::scrub;
use redact_scan::upload::post_report;
use redact_scan::{run_scan, EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS};
use std::process::ExitCode;

fn main() -> ExitCode {
    install_panic_hook();
    match run() {
        Ok(code) => ExitCode::from(code as u8),
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::from(EXIT_ERROR as u8)
        }
    }
}

fn run() -> Result<i32, ScanError> {
    let cli = Cli::parse();
    cli.validate_preflight().map_err(ScanError::new)?;
    if cli.url.is_none() {
        return Err(ScanError::new("--url is required"));
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("redact_scan=info")),
        )
        .init();

    let rt = tokio::runtime::Runtime::new().map_err(ScanError::new)?;
    if cli.include_samples {
        redact_scan::report::enable_sample_sink();
    }
    let report = rt.block_on(run_scan(&cli))?;
    let json = serde_json::to_string_pretty(&report).map_err(ScanError::new)?;
    let rendered = match cli.format {
        OutputFormat::Json => json.clone(),
        OutputFormat::Table => redact_scan::format::render_table(&report),
    };

    if let Some(path) = &cli.out {
        std::fs::write(path, &json).map_err(ScanError::new)?;
    } else {
        println!("{rendered}");
    }

    if cli.include_samples {
        let samples = DebugSamples {
            scan_id: report.scan_id,
            notes: "local debug only; ScanReport contains no values".into(),
            samples: redact_scan::report::take_samples(),
        };
        if let Some(path) = &cli.samples_out {
            std::fs::write(
                path,
                serde_json::to_vec_pretty(&samples).map_err(ScanError::new)?,
            )
            .map_err(ScanError::new)?;
        }
    }

    if let Some(url) = &cli.report_url {
        rt.block_on(post_report(
            url,
            cli.api_key.as_deref(),
            &cli.report_headers,
            &report,
        ))?;
    }

    if let Some(spec) = &cli.fail_on {
        if fail_on_matches(spec, &report.findings)? {
            return Ok(EXIT_FINDINGS);
        }
    }
    Ok(EXIT_CLEAN)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("panic: {}", scrub(&info.to_string()));
    }));
}
