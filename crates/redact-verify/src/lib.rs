//! Offline verification for sealed ledger evidence packs.
//!
//! This crate verifies exact decoded body bytes, the platform-v1 record
//! projection, Ed25519 record and pack signatures, optional independently
//! trusted ECDSA tree-head signatures, and explicitly specified signed
//! tombstone replacements. It performs no network access and has no dependency
//! on redact-core.
//!
//! Public normalized metadata is aligned with the AAT draft (draft-09).
//! Current platform canonicalisation is platform-v1 deterministic JSON and
//! differs from native JCS/AAT chaining.
//!
//! ```no_run
//! use redact_verify::{verify_pack, TrustedKeys};
//!
//! // This is a public test key from a fixed documentation example.
//! let key = "-----BEGIN PUBLIC KEY-----\n\
//! MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=\n\
//! -----END PUBLIC KEY-----";
//! let trusted = TrustedKeys::from_ed25519(key).expect("valid local public key");
//! let result = verify_pack(br#"{}"#, &trusted);
//! assert!(result.is_err()); // Replace with the bytes of a local sealed pack.
//! ```

mod canonical;
mod chain;
mod crypto;
mod error;
mod keys;
pub mod leaves;
pub mod merkle;
mod model;
mod privacy;
mod tombstone;
mod verify;
mod wire;

pub use crate::error::{InputError, InputErrorKind};
pub use crate::keys::TrustedKeys;
pub use crate::model::{
    AatRecord, AnchoringStatus, Canonicalisation, CheckResult, CheckStatus, CoverageReport,
    Principal, RecordPhase, RecordReport, VerificationIssue, VerificationReport,
    VerificationResult,
};
pub use crate::verify::verify_pack;

/// Reads and verifies a pack from a local filesystem path.
pub fn verify_file(
    path: impl AsRef<std::path::Path>,
    trusted: &TrustedKeys,
) -> Result<VerificationReport, InputError> {
    let raw = std::fs::read(path).map_err(|_| {
        InputError::new(
            InputErrorKind::Io,
            "pack_read_failed",
            "could not read local pack file",
        )
    })?;
    verify_pack(&raw, trusted)
}
