// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0. See the LICENSE file
// in the project root for license information.

use clap::Parser;
use redact_scan::cli::Cli;
use redact_scan::error::ScanError;
use redact_scan::scrub::scrub;
use redact_scan::EXIT_ERROR;
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
    Err(ScanError::new(
        "scan execution is not implemented in this revision",
    ))
}

fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = scrub(&info.to_string());
        eprintln!("panic: {msg}");
        default(info);
    }));
}
