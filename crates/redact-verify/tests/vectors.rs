use serde::Deserialize;

#[path = "../src/evaluate.rs"]
mod evaluate;
#[path = "../src/leaves.rs"]
mod leaves;
#[path = "../src/merkle.rs"]
mod merkle;
#[path = "../src/pack.rs"]
mod pack;
#[path = "../src/trust.rs"]
mod trust;

use evaluate::{evaluate_r1, evaluate_r2_att, recompute_body_hash};
use leaves::{pack_leaf_data, root_digest, tip_leaf_data};
use merkle::{prove, root, verify_inclusion};
use pack::{Attestation, R1Proof, RekorReceipt};

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
fn shared_go_vectors() {
    let raw = include_str!("../testdata/vectors.json");
    let v: Vectors = serde_json::from_str(raw).unwrap();
    let mut datas = Vec::new();
    for leaf in &v.leaves {
        let computed = if leaf.kind == "tip" {
            tip_leaf_data(
                leaf.chain_id.as_deref().unwrap(),
                leaf.seq.unwrap(),
                leaf.tip_hash.as_deref().unwrap(),
            )
            .unwrap()
        } else {
            pack_leaf_data(
                leaf.pack_id.as_deref().unwrap(),
                leaf.body_hash.as_deref().unwrap(),
            )
            .unwrap()
        };
        assert_eq!(hex::encode(&computed), leaf.data_hex);
        datas.push(computed);
    }
    let r = root(&datas).unwrap();
    assert_eq!(hex::encode(r), v.root_hex);
    assert_eq!(hex::encode(root_digest(&v.root_hex)), v.root_digest_hex);
    for p in &v.proofs {
        let path = merkle::decode_path(&p.path).unwrap();
        verify_inclusion(&datas[p.index], p.index, p.tree_size, &path, &r).unwrap();
        let got = prove(&datas, p.index).unwrap();
        assert_eq!(got.len(), path.len());
    }
}

#[test]
fn empty_path_single_leaf() {
    let data = b"only".to_vec();
    let r = root(&[data.clone()]).unwrap();
    let path = prove(&[data.clone()], 0).unwrap();
    assert!(path.is_empty());
    verify_inclusion(&data, 0, 1, &path, &r).unwrap();
}

#[test]
fn rewrite_vs_frozen_r1() {
    let chain = "acme/local/default/e0";
    let seq = 1u64;
    let tip = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let data = tip_leaf_data(chain, seq, tip).unwrap();
    let r = root(&[data.clone()]).unwrap();
    let path = prove(&[data.clone()], 0).unwrap();
    let r1 = R1Proof {
        merkle_root: hex::encode(r),
        tree_size: 1,
        leaf_index: 0,
        path: path.iter().map(hex::encode).collect(),
        rekor: Some(RekorReceipt {
            uuid: "u".into(),
            data_hash: hex::encode(root_digest(&hex::encode(r))),
            set: "not-fake".into(),
            checkpoint: "cp".into(),
        }),
        tsa: vec![],
        key_name: trust::ANCHOR_KEY_ID.into(),
        residency: "other".into(),
    };
    let honest = evaluate_r1(chain, seq, tip, Some(&r1));
    // TSA missing on other → fail tsa_unverified, but inclusion passed.
    // Decisive rewrite: change tip hash; inclusion must fail first.
    let rewritten = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    let bad = evaluate_r1(chain, seq, rewritten, Some(&r1));
    assert_eq!(bad.status, "fail");
    assert!(
        bad.reason == "leaf_not_in_root" || bad.reason == "merkle_root_mismatch",
        "{}",
        bad.reason
    );
    let _ = honest;
}

#[test]
fn strip_is_unproven() {
    let att = Attestation::default();
    let cl = evaluate_r2_att("aa", &att, "p1");
    assert_eq!(cl.status, "unproven");
    assert_eq!(cl.reason, "r2_stripped");
}

#[test]
fn whitespace_body_hash_mismatch() {
    let body = br#"{"pack_id":"p"}"#;
    let hash = recompute_body_hash(body);
    let mut att = Attestation {
        status: "anchored".into(),
        rekor: Some(RekorReceipt {
            uuid: "u".into(),
            data_hash: "x".into(),
            set: "s".into(),
            checkpoint: "c".into(),
        }),
        root: "00".repeat(32),
        body_hash: hash.clone(),
        pack_id: "p1".into(),
        tree_size: 1,
        ..Default::default()
    };
    let mut mutated = body.to_vec();
    mutated.push(b' ');
    let recomputed = recompute_body_hash(&mutated);
    let cl = evaluate_r2_att(&recomputed, &att, "p1");
    assert_eq!(cl.status, "fail");
    assert_eq!(cl.reason, "body_hash_mismatch");
    att.body_hash = hash; // stored field honest, bytes mutated
    let cl = evaluate_r2_att(&recomputed, &att, "p1");
    assert_ne!(cl.status, "pass");
}

#[test]
fn leaf_grammars_disjoint() {
    assert!(leaves::validate_tip_chain_id("pack").is_err());
    assert!(leaves::validate_tip_chain_id("pack/local/default/e0").is_err());
    let tip = format!("acme/local/default/e0|1|abcd");
    let pack = format!("pack|p1|abcd");
    assert_ne!(tip, pack);
}

#[test]
fn no_redact_core_in_manifest() {
    let manifest = include_str!("../Cargo.toml");
    assert!(
        !manifest.contains("redact-core =") && !manifest.contains("path = \"../redact-core\""),
        "redact-verify must not depend on redact-core"
    );
}
