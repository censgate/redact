use sha2::{Digest, Sha256};

pub fn tip_leaf_data(chain_id: &str, seq: u64, tip_hash_hex: &str) -> Result<Vec<u8>, String> {
    validate_tip_chain_id(chain_id)?;
    if tip_hash_hex.is_empty() {
        return Err("empty tip hash".into());
    }
    let pre = format!("{chain_id}|{seq}|{tip_hash_hex}");
    Ok(Sha256::digest(pre.as_bytes()).to_vec())
}

pub fn pack_leaf_data(pack_id: &str, body_hash_hex: &str) -> Result<Vec<u8>, String> {
    if pack_id.is_empty() || pack_id.contains('|') {
        return Err("invalid pack_id".into());
    }
    if body_hash_hex.is_empty() {
        return Err("empty body_hash".into());
    }
    let pre = format!("pack|{pack_id}|{body_hash_hex}");
    Ok(Sha256::digest(pre.as_bytes()).to_vec())
}

pub fn validate_tip_chain_id(chain_id: &str) -> Result<(), String> {
    if chain_id.is_empty() || chain_id.contains('|') {
        return Err("invalid chain_id".into());
    }
    if chain_id == "pack" || chain_id.starts_with("pack|") || chain_id.starts_with("pack/") {
        return Err("chain_id reserved pack prefix".into());
    }
    Ok(())
}

pub fn root_preimage(merkle_root_hex: &str) -> Vec<u8> {
    format!("anchor-root|v1|{merkle_root_hex}").into_bytes()
}

pub fn root_digest(merkle_root_hex: &str) -> [u8; 32] {
    Sha256::digest(root_preimage(merkle_root_hex)).into()
}

pub fn pack_sign_preimage(pack_id: &str, tenant_id: &str, body_hash: &str) -> Vec<u8> {
    format!("anchor-pack|v1|{pack_id}|{tenant_id}|{body_hash}").into_bytes()
}
