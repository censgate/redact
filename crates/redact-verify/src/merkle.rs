use sha2::{Digest, Sha256};

/// RFC 6962: leaf = SHA256(0x00 || data), node = SHA256(0x01 || left || right).
/// No padding. Empty path only when tree_size==1 and leaf==root.

pub fn leaf_hash(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    h.finalize().into()
}

pub fn node_hash(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn largest_power_of_two_less_than(n: usize) -> usize {
    let mut p = 1;
    while p * 2 < n {
        p *= 2;
    }
    p
}

pub fn root(datas: &[Vec<u8>]) -> Result<[u8; 32], String> {
    if datas.is_empty() {
        return Err("empty tree".into());
    }
    Ok(mth(datas))
}

fn mth(datas: &[Vec<u8>]) -> [u8; 32] {
    if datas.len() == 1 {
        return leaf_hash(&datas[0]);
    }
    let k = largest_power_of_two_less_than(datas.len());
    node_hash(&mth(&datas[..k]), &mth(&datas[k..]))
}

pub fn prove(datas: &[Vec<u8>], index: usize) -> Result<Vec<[u8; 32]>, String> {
    if index >= datas.len() {
        return Err("leaf index out of range".into());
    }
    Ok(prove_rec(datas, index))
}

fn prove_rec(datas: &[Vec<u8>], index: usize) -> Vec<[u8; 32]> {
    if datas.len() == 1 {
        return Vec::new();
    }
    let k = largest_power_of_two_less_than(datas.len());
    if index < k {
        let mut p = prove_rec(&datas[..k], index);
        p.push(mth(&datas[k..]));
        p
    } else {
        let mut p = prove_rec(&datas[k..], index - k);
        p.push(mth(&datas[..k]));
        p
    }
}

pub fn verify_inclusion(
    data: &[u8],
    index: usize,
    tree_size: usize,
    path: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), String> {
    if tree_size < 1 || index >= tree_size {
        return Err("invalid index".into());
    }
    let h = leaf_hash(data);
    if tree_size == 1 {
        if !path.is_empty() {
            return Err("empty path required when tree_size==1".into());
        }
        if &h != expected_root {
            return Err("leaf_not_in_root".into());
        }
        return Ok(());
    }
    let got = reconstruct(&h, index, tree_size, path)?;
    if &got != expected_root {
        return Err("leaf_not_in_root".into());
    }
    Ok(())
}

fn reconstruct(
    hash: &[u8; 32],
    index: usize,
    tree_size: usize,
    path: &[[u8; 32]],
) -> Result<[u8; 32], String> {
    if tree_size == 1 {
        if !path.is_empty() {
            return Err("empty path required when tree_size==1".into());
        }
        return Ok(*hash);
    }
    if path.is_empty() {
        return Err("short inclusion path".into());
    }
    let k = largest_power_of_two_less_than(tree_size);
    let sib = path[path.len() - 1];
    let rest = &path[..path.len() - 1];
    if index < k {
        let left = reconstruct(hash, index, k, rest)?;
        Ok(node_hash(&left, &sib))
    } else {
        let right = reconstruct(hash, index - k, tree_size - k, rest)?;
        Ok(node_hash(&sib, &right))
    }
}

pub fn decode_path(hexes: &[String]) -> Result<Vec<[u8; 32]>, String> {
    let mut out = Vec::new();
    for h in hexes {
        let b = hex::decode(h).map_err(|e| e.to_string())?;
        if b.len() != 32 {
            return Err("sibling must be 32 bytes".into());
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&b);
        out.push(a);
    }
    Ok(out)
}
