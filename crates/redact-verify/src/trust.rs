//! Compiled-in trust anchors. Pack-supplied keys cannot pass the offline test.
//! EUTL snapshot date: 2026-08-15 (`trust/eutl-2026-08-15/`).

pub const ANCHOR_KEY_ID: &str = "censgate-anchor-ecdsa-p256-v1";
pub const EUTL_SNAPSHOT: &str = "2026-08-15";

/// Known global anchor key ids. Values are PEM placeholders until production
/// pubkeys are pinned; unknown ids fail closed (`unknown_key_id`).
pub fn known_anchor_key(id: &str) -> bool {
    id == ANCHOR_KEY_ID
}

/// A token is qualified only if it chains to the pinned EUTL QTST snapshot
/// and carries a QCStatement at genTime. An empty snapshot cannot pass.
pub fn eutl_qualifies(_tsr: &[u8]) -> bool {
    false
}
