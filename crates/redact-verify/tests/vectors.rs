//! RFC 6962 compatibility vectors, separate from current pack verification.

use redact_verify::{leaves, merkle};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vectors {
    leaves: Vec<VecLeaf>,
    root_hex: String,
    root_digest_hex: String,
    proofs: Vec<VecProof>,
}

#[derive(Deserialize)]
struct VecLeaf {
    kind: String,
    chain_id: Option<String>,
    seq: Option<u64>,
    tip_hash: Option<String>,
    pack_id: Option<String>,
    body_hash: Option<String>,
    data_hex: String,
}

#[derive(Deserialize)]
struct VecProof {
    index: usize,
    tree_size: usize,
    path: Vec<String>,
}

#[test]
fn legacy_three_leaf_vectors() {
    let vectors: Vectors = serde_json::from_str(include_str!("../testdata/vectors.json")).unwrap();
    let mut data = Vec::new();
    for leaf in &vectors.leaves {
        let actual = if leaf.kind == "tip" {
            leaves::tip_leaf_data(
                leaf.chain_id.as_deref().unwrap(),
                leaf.seq.unwrap(),
                leaf.tip_hash.as_deref().unwrap(),
            )
            .unwrap()
        } else {
            leaves::pack_leaf_data(
                leaf.pack_id.as_deref().unwrap(),
                leaf.body_hash.as_deref().unwrap(),
            )
            .unwrap()
        };
        assert_eq!(hex::encode(&actual), leaf.data_hex);
        data.push(actual);
    }
    let root = merkle::root(&data).unwrap();
    assert_eq!(hex::encode(root), vectors.root_hex);
    assert_eq!(
        hex::encode(leaves::root_digest(&vectors.root_hex)),
        vectors.root_digest_hex
    );
    for proof in vectors.proofs {
        let path = merkle::decode_path(&proof.path).unwrap();
        merkle::verify_inclusion(
            &data[proof.index],
            proof.index,
            proof.tree_size,
            &path,
            &root,
        )
        .unwrap();
    }
}

#[test]
fn singleton_and_path_validation() {
    let data = vec![b"single".to_vec()];
    let root = merkle::root(&data).unwrap();
    let proof = merkle::prove(&data, 0).unwrap();
    assert!(proof.is_empty());
    merkle::verify_inclusion(&data[0], 0, 1, &proof, &root).unwrap();
    assert!(merkle::verify_inclusion(&data[0], 0, 1, &[[0; 32]], &root).is_err());
    assert!(merkle::verify_inclusion(&data[0], 1, 1, &[], &root).is_err());
}

#[test]
fn crate_has_no_redact_core_dependency() {
    let manifest = include_str!("../Cargo.toml");
    assert!(!manifest.contains("redact-core ="));
}
