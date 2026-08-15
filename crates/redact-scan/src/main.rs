// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use clap::Parser;
use redact_scan::cli::Cli;
use redact_scan::error::ScanError;
use redact_scan::scrub::scrub;
use redact_scan::{run_scan, EXIT_CLEAN, EXIT_ERROR};
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
    let report = rt.block_on(run_scan(&cli))?;
    let json = serde_json::to_string_pretty(&report).map_err(ScanError::new)?;
    if let Some(path) = &cli.out {
        std::fs::write(path, &json).map_err(ScanError::new)?;
    } else {
        println!("{json}");
    }
    Ok(EXIT_CLEAN)
}

fn install_panic_hook() {
    std::panic::set_hook(Box::new(move |info| {
        eprintln!("panic: {}", scrub(&info.to_string()));
    }));
}
