use sha2::{Digest, Sha256};

use crate::leaves::{pack_leaf_data, root_digest, tip_leaf_data};
use crate::merkle::{decode_path, verify_inclusion};
use crate::pack::{Attestation, Envelope, R1Proof};
use crate::trust::{eutl_qualifies, known_anchor_key};

#[derive(Debug, Clone, serde::Serialize)]
pub struct Claim {
    pub status: String,
    pub reason: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Report {
    pub chain_consistent: String,
    pub tip_signatures: String,
    pub body_hash: String,
    pub body_signature: String,
    pub events_anchored: Claim,
    pub pack_anchored: Claim,
    pub pack_anchored_reason: String,
    pub complete_within_range: bool,
    pub range_covers_tip: bool,
    pub builder_signed: bool,
}

pub fn recompute_body_hash(body: &[u8]) -> String {
    hex::encode(Sha256::digest(body))
}

pub fn evaluate_r2(recomputed_hash: &str, env: &Envelope) -> Claim {
    let att = match &env.attestation {
        Some(a) => a,
        None => {
            return Claim {
                status: "unproven".into(),
                reason: "r2_stripped".into(),
            }
        }
    };
    evaluate_r2_att(recomputed_hash, att, &env.pack_id)
}

pub fn evaluate_r2_att(recomputed_hash: &str, att: &Attestation, pack_id: &str) -> Claim {
    let stripped = att.status.is_empty()
        && att.rekor.is_none()
        && att.merkle_proof.is_empty()
        && att.round.is_empty()
        && att.root.is_empty();
    if stripped {
        return Claim {
            status: "unproven".into(),
            reason: "r2_stripped".into(),
        };
    }
    if att.status == "pending"
        || att.status == "failed"
        || att.rekor.is_none()
        || att.root.is_empty()
    {
        return Claim {
            status: "unproven".into(),
            reason: "r2_pending".into(),
        };
    }
    if recomputed_hash.is_empty() || !recomputed_hash.eq_ignore_ascii_case(&att.body_hash) {
        return Claim {
            status: "fail".into(),
            reason: "body_hash_mismatch".into(),
        };
    }
    let data = match pack_leaf_data(pack_id, recomputed_hash) {
        Ok(d) => d,
        Err(_) => {
            return Claim {
                status: "fail".into(),
                reason: "leaf_not_in_root".into(),
            }
        }
    };
    match verify_r2_inclusion(&data, att) {
        Ok(()) => verify_root_binding(
            &att.root,
            att.rekor.as_ref(),
            &att.tsa,
            &att.key_name,
            &att.residency,
        ),
        Err(reason) => Claim {
            status: "fail".into(),
            reason,
        },
    }
}

fn verify_r2_inclusion(data: &[u8], att: &Attestation) -> Result<(), String> {
    let path = decode_path(&att.merkle_proof)?;
    let root_b = hex::decode(&att.root).map_err(|_| "merkle_root_mismatch".to_string())?;
    if root_b.len() != 32 {
        return Err("merkle_root_mismatch".into());
    }
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_b);
    verify_inclusion(data, att.leaf_index, att.tree_size, &path, &root)
        .map_err(|_| "leaf_not_in_root".to_string())
}

pub fn evaluate_r1(chain_id: &str, seq: u64, tip_hash: &str, r1: Option<&R1Proof>) -> Claim {
    let Some(r1) = r1 else {
        return Claim {
            status: "unproven".into(),
            reason: "r2_pending".into(),
        };
    };
    if r1.merkle_root.is_empty() || r1.rekor.is_none() {
        return Claim {
            status: "unproven".into(),
            reason: "r2_pending".into(),
        };
    }
    let data = match tip_leaf_data(chain_id, seq, tip_hash) {
        Ok(d) => d,
        Err(_) => {
            return Claim {
                status: "fail".into(),
                reason: "leaf_not_in_root".into(),
            }
        }
    };
    let path = match decode_path(&r1.path) {
        Ok(p) => p,
        Err(_) => {
            return Claim {
                status: "fail".into(),
                reason: "leaf_not_in_root".into(),
            }
        }
    };
    let root_b = match hex::decode(&r1.merkle_root) {
        Ok(b) if b.len() == 32 => b,
        _ => {
            return Claim {
                status: "fail".into(),
                reason: "merkle_root_mismatch".into(),
            }
        }
    };
    let mut root = [0u8; 32];
    root.copy_from_slice(&root_b);
    if verify_inclusion(&data, r1.leaf_index, r1.tree_size, &path, &root).is_err() {
        return Claim {
            status: "fail".into(),
            reason: "leaf_not_in_root".into(),
        };
    }
    verify_root_binding(
        &r1.merkle_root,
        r1.rekor.as_ref(),
        &r1.tsa,
        &r1.key_name,
        &r1.residency,
    )
}

fn verify_root_binding(
    root_hex: &str,
    rekor: Option<&crate::pack::RekorReceipt>,
    tsa: &[crate::pack::TsaReceipt],
    key_name: &str,
    residency: &str,
) -> Claim {
    let Some(rec) = rekor else {
        return Claim {
            status: "fail".into(),
            reason: "rekor_unverified".into(),
        };
    };
    let digest = root_digest(root_hex);
    let want = hex::encode(digest);
    if !rec.data_hash.eq_ignore_ascii_case(&want) {
        return Claim {
            status: "fail".into(),
            reason: "rekor_unverified".into(),
        };
    }
    let kid = if key_name.is_empty() {
        crate::trust::ANCHOR_KEY_ID
    } else {
        key_name
    };
    if !known_anchor_key(kid) {
        return Claim {
            status: "fail".into(),
            reason: "unknown_key_id".into(),
        };
    }
    if rec.set.is_empty() && rec.checkpoint.is_empty() {
        return Claim {
            status: "fail".into(),
            reason: "rekor_unverified".into(),
        };
    }
    // Fake unit-test receipts never pass production verify.
    if rec.set.starts_with("fake-set:") {
        return Claim {
            status: "fail".into(),
            reason: "rekor_unverified".into(),
        };
    }
    let eu = residency == "eu" || residency.is_empty();
    if !any_tsa_ok(tsa, &digest, eu) {
        return Claim {
            status: "fail".into(),
            reason: if eu {
                if tsa.is_empty() {
                    "qtsa_pending"
                } else {
                    "qtsa_unqualified"
                }
            } else {
                "tsa_unverified"
            }
            .into(),
        };
    }
    Claim {
        status: "pass".into(),
        reason: "ok".into(),
    }
}

fn any_tsa_ok(
    recs: &[crate::pack::TsaReceipt],
    digest: &[u8; 32],
    require_qualified: bool,
) -> bool {
    for r in recs {
        if !r.ok || r.tsr_b64.is_empty() {
            continue;
        }
        let Ok(raw) =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &r.tsr_b64)
        else {
            continue;
        };
        if raw.starts_with(b"FAKE-TSR:") {
            continue;
        }
        if require_qualified && !eutl_qualifies(&raw) {
            continue;
        }
        if let Some(imprint) = extract_imprint(&raw) {
            if imprint == *digest {
                return true;
            }
        }
    }
    false
}

fn extract_imprint(tsr: &[u8]) -> Option<[u8; 32]> {
    // SHA-256 OID 2.16.840.1.101.3.4.2.1
    let oid = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    let pos = tsr.windows(oid.len()).position(|w| w == oid)?;
    let rest = &tsr[pos + oid.len()..];
    for i in 0..rest.len().saturating_sub(34) {
        if rest[i] == 0x04 && rest[i + 1] == 0x20 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&rest[i + 2..i + 34]);
            return Some(out);
        }
    }
    None
}
