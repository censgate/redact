use clap::{ArgGroup, Parser, ValueEnum};
use redact_verify::{verify_file, InputError, TrustedKeys, VerificationReport, VerificationResult};
use serde::Serialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Clone, Copy, ValueEnum)]
enum OutputFormat {
    Text,
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "redact-verify",
    about = "Offline verifier for sealed ledger evidence packs",
    group(ArgGroup::new("trust").required(true).args(["keys", "pubkey"]))
)]
struct Args {
    /// Local sealed pack envelope JSON file.
    #[arg(long)]
    pack: PathBuf,
    /// Local JSON key set containing chain, optional tree_head, and optional erasure_authority keys.
    #[arg(long, conflicts_with = "pubkey")]
    keys: Option<PathBuf>,
    /// Local Ed25519 public key file (hex, base64, or SPKI PEM).
    #[arg(long, conflicts_with = "keys")]
    pubkey: Option<PathBuf>,
    /// Optional local ECDSA tree-head SPKI PEM file; requires --pubkey.
    #[arg(long, requires = "pubkey")]
    tree_head_pubkey: Option<PathBuf>,
    /// Reserved compatibility flag. Verification remains offline.
    #[arg(long)]
    online: bool,
    /// Report format.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Serialize)]
struct InputFailure<'a> {
    result: VerificationResult,
    code: &'a str,
    reason: &'a str,
}

fn main() -> ExitCode {
    let args = Args::parse();
    if args.online {
        eprintln!(
            "--online is reserved; verification remains offline and no network calls are made."
        );
    }
    match run(&args) {
        Ok(report) => {
            render_report(&report, args.format);
            ExitCode::from(report.result.exit_code())
        }
        Err(error) => {
            render_error(&error, args.format);
            ExitCode::from(2)
        }
    }
}

fn run(args: &Args) -> Result<VerificationReport, InputError> {
    let trusted = if let Some(path) = &args.keys {
        let raw = fs::read(path).map_err(|_| {
            InputError::new(
                redact_verify::InputErrorKind::Io,
                "keys_read_failed",
                "could not read local key set",
            )
        })?;
        TrustedKeys::from_json(&raw)?
    } else {
        let path = args
            .pubkey
            .as_ref()
            .expect("clap requires one trust source");
        let material = fs::read_to_string(path).map_err(|_| {
            InputError::new(
                redact_verify::InputErrorKind::Io,
                "pubkey_read_failed",
                "could not read local public key",
            )
        })?;
        let mut trusted = TrustedKeys::from_ed25519(&material)?;
        if let Some(path) = &args.tree_head_pubkey {
            let material = fs::read_to_string(path).map_err(|_| {
                InputError::new(
                    redact_verify::InputErrorKind::Io,
                    "tree_head_key_read_failed",
                    "could not read local tree-head key",
                )
            })?;
            trusted = trusted.with_tree_head(&material)?;
        }
        trusted
    };
    verify_file(&args.pack, &trusted)
}

fn render_report(report: &VerificationReport, format: OutputFormat) {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(report).expect("report serializes")
        ),
        OutputFormat::Text => {
            println!(
                "result={}",
                format!("{:?}", report.result).to_ascii_lowercase()
            );
            println!("checked={}", report.checked);
            println!("erased={}", report.erased);
            println!(
                "body_hash={}",
                format!("{:?}", report.body_hash.status).to_ascii_lowercase()
            );
            println!(
                "body_signature={}",
                format!("{:?}", report.body_signature.status).to_ascii_lowercase()
            );
            println!(
                "key_binding={}",
                format!("{:?}", report.key_binding.status).to_ascii_lowercase()
            );
            println!(
                "anchoring_status={}",
                format!("{:?}", report.anchoring_status).to_ascii_lowercase()
            );
            println!(
                "merkle_inclusion={}",
                format!("{:?}", report.merkle_inclusion.status).to_ascii_lowercase()
            );
            for issue in &report.issues {
                println!(
                    "issue={} required={} {}",
                    issue.code, issue.required, issue.message
                );
            }
        }
    }
}

fn render_error(error: &InputError, format: OutputFormat) {
    match format {
        OutputFormat::Json => println!(
            "{}",
            serde_json::to_string_pretty(&InputFailure {
                result: VerificationResult::Unproven,
                code: error.code,
                reason: &error.message,
            })
            .expect("input error serializes")
        ),
        OutputFormat::Text => println!("result=unproven reason={} {}", error.code, error.message),
    }
}
