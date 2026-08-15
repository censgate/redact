use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub schema_version: u32,
    pub pack_id: String,
    pub tenant_id: String,
    #[serde(default)]
    pub body: String,
    #[serde(default)]
    pub body_hash: String,
    #[serde(default)]
    pub body_signature: String,
    #[serde(default)]
    pub key_name: String,
    #[serde(default)]
    pub attestation: Option<Attestation>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct Attestation {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub round: String,
    #[serde(default)]
    pub merkle_proof: Vec<String>,
    #[serde(default)]
    pub leaf_index: usize,
    #[serde(default)]
    pub tree_size: usize,
    #[serde(default)]
    pub root: String,
    pub rekor: Option<RekorReceipt>,
    #[serde(default)]
    pub tsa: Vec<TsaReceipt>,
    #[serde(default)]
    pub residency: String,
    #[serde(default)]
    pub key_name: String,
    #[serde(default)]
    pub body_hash: String,
    #[serde(default)]
    pub pack_id: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RekorReceipt {
    #[serde(default)]
    pub uuid: String,
    #[serde(default)]
    pub data_hash: String,
    #[serde(default)]
    pub set: String,
    #[serde(default)]
    pub checkpoint: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TsaReceipt {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub tsr_b64: String,
    #[serde(default)]
    pub ok: bool,
}

#[derive(Debug, Deserialize)]
pub struct Body {
    #[serde(default)]
    pub pack_id: String,
    #[serde(default)]
    pub tenant_id: String,
    pub seq_range: Option<SeqRange>,
    pub tip: Option<Tip>,
    #[serde(default)]
    pub batches: Vec<Batch>,
    pub r1: Option<R1Proof>,
    #[serde(default)]
    pub controls: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct SeqRange {
    pub from: u64,
    pub to: u64,
}

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
#[allow(non_snake_case)]
pub struct Tip {
    #[serde(default)]
    pub ChainID: String,
    #[serde(default)]
    pub chain_id: String,
    #[serde(default)]
    pub Seq: u64,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub Hash: String,
    #[serde(default)]
    pub hash: String,
}

impl Tip {
    pub fn chain_id(&self) -> &str {
        if !self.chain_id.is_empty() {
            &self.chain_id
        } else {
            &self.ChainID
        }
    }
    pub fn seq(&self) -> u64 {
        if self.seq != 0 {
            self.seq
        } else {
            self.Seq
        }
    }
    pub fn hash(&self) -> &str {
        if !self.hash.is_empty() {
            &self.hash
        } else {
            &self.Hash
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Batch {
    pub event: Option<serde_json::Value>,
    pub record: Record,
    #[serde(default)]
    pub signature: String,
}

#[derive(Debug, Deserialize)]
pub struct Record {
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub prev_hash: String,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub event_id: String,
    #[serde(default)]
    pub chain_id: String,
}

#[derive(Debug, Deserialize)]
pub struct R1Proof {
    #[serde(default)]
    pub merkle_root: String,
    #[serde(default)]
    pub tree_size: usize,
    #[serde(default)]
    pub leaf_index: usize,
    #[serde(default)]
    pub path: Vec<String>,
    pub rekor: Option<RekorReceipt>,
    #[serde(default)]
    pub tsa: Vec<TsaReceipt>,
    #[serde(default)]
    pub key_name: String,
    #[serde(default)]
    pub residency: String,
}

pub fn completeness(body: &Body) -> (bool, bool) {
    let Some(range) = &body.seq_range else {
        return (
            body.batches.is_empty(),
            body.tip.as_ref().map(|t| t.seq()) == Some(0),
        );
    };
    let tip_seq = body.tip.as_ref().map(|t| t.seq()).unwrap_or(0);
    if body.batches.is_empty() {
        return (range.from == 0 && range.to == 0, tip_seq == 0);
    }
    let mut seen = std::collections::HashSet::new();
    for b in &body.batches {
        seen.insert(b.record.seq);
    }
    let mut within = true;
    let mut s = range.from;
    while s <= range.to {
        if !seen.contains(&s) {
            within = false;
            break;
        }
        s += 1;
    }
    (within, range.to == tip_seq)
}

pub fn chain_consistent(body: &Body) -> Result<(), String> {
    let mut prev = String::from("0000000000000000000000000000000000000000000000000000000000000000");
    for (i, b) in body.batches.iter().enumerate() {
        if b.record.event_id.is_empty() || b.record.hash.is_empty() {
            return Err(format!("incomplete record at {}", i));
        }
        if i > 0 && b.record.prev_hash != prev {
            return Err(format!("prev_hash mismatch event {}", b.record.event_id));
        }
        if b.signature.is_empty() {
            return Err(format!("missing signature event {}", b.record.event_id));
        }
        prev = b.record.hash.clone();
    }
    Ok(())
}
