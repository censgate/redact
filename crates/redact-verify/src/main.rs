mod evaluate;
mod leaves;
mod merkle;
mod pack;
mod trust;

use anyhow::{bail, Context, Result};
use base64::Engine;
use clap::Parser;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use evaluate::{evaluate_r1, evaluate_r2, recompute_body_hash, Report};
use leaves::pack_sign_preimage;
use pack::{chain_consistent, completeness, Body, Envelope};
use std::convert::TryFrom;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "redact-verify",
    about = "Independent ledger evidence-pack verifier"
)]
struct Args {
    /// Path to a pack envelope JSON
    #[arg(long)]
    pack: PathBuf,
    /// Ed25519 public key (hex or PEM) for body_signature
    #[arg(long)]
    pubkey: PathBuf,
    /// Optionally re-query Rekor (never required; default is offline)
    #[arg(long, default_value_t = false)]
    online: bool,
    #[arg(long, default_value = "text")]
    format: String,
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("malformed: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<ExitCode> {
    let args = Args::parse();
    if args.online {
        eprintln!("--online is optional and is not used for the offline verdict");
    }
    let raw = fs::read(&args.pack).with_context(|| format!("read {}", args.pack.display()))?;
    let env: Envelope = serde_json::from_slice(&raw).context("envelope json")?;
    if env.pack_id.is_empty() || env.body.is_empty() {
        bail!("missing pack_id or body");
    }
    let body_octets = base64::engine::general_purpose::STANDARD
        .decode(env.body.trim())
        .or_else(|_| {
            // Some emitters store raw bytes as a JSON string that is already the blob.
            Ok::<Vec<u8>, base64::DecodeError>(env.body.as_bytes().to_vec())
        })
        .context("body base64")?;
    let recomputed = recompute_body_hash(&body_octets);
    let body: Body = serde_json::from_slice(&body_octets).context("inner body json")?;

    let mut chain_status = "pass";
    if let Err(e) = chain_consistent(&body) {
        eprintln!("chain: {e}");
        chain_status = "fail";
    }
    let tip_sigs = if body.batches.iter().all(|b| !b.signature.is_empty()) {
        "pass"
    } else {
        "fail"
    };
    let body_hash_status = if recomputed.eq_ignore_ascii_case(&env.body_hash) {
        "pass"
    } else {
        "fail"
    };

    let pubkey_raw = fs::read_to_string(&args.pubkey).context("pubkey")?;
    let builder_ok = verify_body_sig(&env, &pubkey_raw, &recomputed);
    let body_sig_status = if builder_ok { "pass" } else { "fail" };

    let tip = body.tip.as_ref();
    let events = evaluate_r1(
        tip.map(|t| t.chain_id()).unwrap_or(""),
        tip.map(|t| t.seq()).unwrap_or(0),
        tip.map(|t| t.hash()).unwrap_or(""),
        body.r1.as_ref(),
    );
    let pack = evaluate_r2(&recomputed, &env);
    let (within, covers) = completeness(&body);

    let report = Report {
        chain_consistent: chain_status.into(),
        tip_signatures: tip_sigs.into(),
        body_hash: body_hash_status.into(),
        body_signature: body_sig_status.into(),
        events_anchored: events.clone(),
        pack_anchored: pack.clone(),
        pack_anchored_reason: pack.reason.clone(),
        complete_within_range: within,
        range_covers_tip: covers,
        builder_signed: builder_ok,
    };

    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("chain_consistent={}", report.chain_consistent);
        println!("tip_signatures={}", report.tip_signatures);
        println!("body_hash={}", report.body_hash);
        println!(
            "body_signature={} (builder_signed only)",
            report.body_signature
        );
        println!(
            "events_anchored={} reason={}",
            report.events_anchored.status, report.events_anchored.reason
        );
        println!(
            "pack_anchored={} reason={}",
            report.pack_anchored.status, report.pack_anchored_reason
        );
        println!("complete_within_range={}", report.complete_within_range);
        println!("range_covers_tip={}", report.range_covers_tip);
    }

    let all_pass = report.chain_consistent == "pass"
        && report.tip_signatures == "pass"
        && report.body_hash == "pass"
        && report.body_signature == "pass"
        && report.events_anchored.status == "pass"
        && report.pack_anchored.status == "pass";
    if all_pass {
        Ok(ExitCode::from(0))
    } else {
        Ok(ExitCode::from(1))
    }
}

fn verify_body_sig(env: &Envelope, pubkey: &str, body_hash: &str) -> bool {
    let pre = pack_sign_preimage(&env.pack_id, &env.tenant_id, body_hash);
    let pk = match parse_ed25519_pub(pubkey) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig_bytes = parse_vault_sig(&env.body_signature);
    let Ok(sig) = Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    pk.verify(&pre, &sig).is_ok()
}

fn parse_ed25519_pub(s: &str) -> Result<VerifyingKey, anyhow::Error> {
    let t = s.trim();
    if t.contains("BEGIN") {
        bail!("PEM ed25519 not parsed; use 32-byte hex");
    }
    let raw = hex::decode(t.trim())?;
    if raw.len() != 32 {
        bail!("ed25519 pubkey must be 32 bytes");
    }
    let mut a = [0u8; 32];
    a.copy_from_slice(&raw);
    Ok(VerifyingKey::from_bytes(&a)?)
}

fn parse_vault_sig(sig: &str) -> Vec<u8> {
    let part = sig.rsplit(':').next().unwrap_or(sig);
    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(part) {
        return b;
    }
    hex::decode(part).unwrap_or_default()
}
