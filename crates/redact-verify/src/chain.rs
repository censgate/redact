//! Current record hash, signature input, and sequence-continuity formulas.

use crate::crypto::sha256_hex;
use crate::wire::{Batch, GENESIS};

/// Hashes a platform-v1 canonical event without separators between fields.
pub(crate) fn record_hash(
    previous: &str,
    canonical: &[u8],
    event_id: &str,
    timestamp: &str,
) -> String {
    let effective_previous = if previous.is_empty() {
        GENESIS
    } else {
        previous
    };
    let mut input = Vec::with_capacity(
        effective_previous.len() + canonical.len() + event_id.len() + timestamp.len(),
    );
    input.extend_from_slice(effective_previous.as_bytes());
    input.extend_from_slice(canonical);
    input.extend_from_slice(event_id.as_bytes());
    input.extend_from_slice(timestamp.as_bytes());
    sha256_hex(&input)
}

/// Builds the direct Ed25519 record signature input bytes.
pub(crate) fn record_signature_input(chain_id: &str, sequence: u64, hash: &str) -> Vec<u8> {
    format!("{chain_id}|{sequence}|{hash}").into_bytes()
}

/// Sequence and previous-hash continuity findings for sequence-sorted rows.
#[derive(Debug, Default)]
pub(crate) struct Continuity {
    pub gaps: Vec<(u64, u64)>,
    pub issues: Vec<&'static str>,
}

/// Checks sequence prefixes, adjacency, gaps, genesis, and checked increments.
pub(crate) fn check_continuity(rows: &[&Batch], filtered: bool) -> Continuity {
    let mut result = Continuity::default();
    for (index, batch) in rows.iter().enumerate() {
        let record = &batch.record;
        if record.seq == 0 {
            result.issues.push("zero_sequence");
        }
        if index == 0 {
            if !filtered && record.seq != 1 {
                result.issues.push("sequence_prefix_gap");
            }
            if record.seq == 1 && !record.prev_hash.is_empty() && record.prev_hash != GENESIS {
                result.issues.push("genesis_prev_hash_mismatch");
            }
            continue;
        }
        let previous = rows[index - 1];
        if record.seq == previous.record.seq {
            // Duplicate detection is reported by the orchestrator; do not emit
            // a nonsensical missing range for two rows at the same sequence.
            continue;
        }
        match previous.record.seq.checked_add(1) {
            Some(next) if record.seq == next => {
                if record.prev_hash != previous.record.hash {
                    result.issues.push("chain_link_mismatch");
                }
            }
            Some(next) => {
                result.gaps.push((next, record.seq.saturating_sub(1)));
                if !filtered {
                    result.issues.push("sequence_gap");
                }
            }
            None => result.issues.push("sequence_overflow"),
        }
        if record.seq == 1 && !record.prev_hash.is_empty() && record.prev_hash != GENESIS {
            result.issues.push("genesis_prev_hash_mismatch");
        }
    }
    result
}
