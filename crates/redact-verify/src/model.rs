//! Draft-09 aligned normalized metadata and verification report types.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Verification result. Exit codes are stable for automation:
/// 0 = pass, 1 = fail, 2 = unproven (also unreadable input and CLI usage
/// errors), 3 = erased (verified, but at least one record was replaced by a
/// signed tombstone).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    /// All required checks for the current format succeeded.
    Pass,
    /// A signed tombstone replacement was verified.
    Erased,
    /// Required evidence failed integrity, privacy, or consistency checks.
    Fail,
    /// Required independent evidence is missing or the format is unsupported.
    Unproven,
}

impl VerificationResult {
    /// Returns the process exit code associated with this result.
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Fail => 1,
            Self::Unproven => 2,
            Self::Erased => 3,
        }
    }
}

/// Status for an individual verification check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check succeeded.
    Pass,
    /// The check found a contradiction or invalid evidence.
    Fail,
    /// The evidence needed to complete the check is unavailable.
    Unproven,
    /// The evidence is intentionally absent or not applicable.
    NotAnchored,
    /// Original event evidence is absent under a verified tombstone.
    Erased,
}

/// A check result with explicit effect on the overall verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    /// Result for this check.
    pub status: CheckStatus,
    /// Whether failure or an unproven result controls the overall verdict.
    pub required: bool,
    /// Stable machine-readable reason code.
    pub reason: String,
}

/// A normalized principal identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Principal {
    /// Principal identifier supplied by the native field or legacy caller alias.
    pub id: String,
    /// Optional principal type supplied by native evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,
    /// Optional role supplied by native evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    /// Optional authority supplied by native evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority: Option<String>,
    /// Original structured principal object when supplied in native evidence.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub native_fields: Option<Value>,
}

/// Lifecycle phase for an AAT record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordPhase {
    /// Record emitted before an action.
    Pre,
    /// Record emitted after an action.
    Post,
    /// Record emitted concurrently with an action.
    Concurrent,
}

/// Canonicalisation profile used for retained canonical evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Canonicalisation {
    /// Current platform-v1 deterministic JSON projection.
    PlatformV1,
}

/// A draft-09 aligned, normalized ledger record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AatRecord {
    /// Stable record identifier.
    pub record_id: String,
    /// One-based ledger sequence number.
    pub sequence_number: u64,
    /// Record chain identifier.
    pub chain_id: String,
    /// Tenant identifier for the event.
    pub tenant_id: String,
    /// Stored hash of the record projection.
    pub record_hash: String,
    /// Previous record hash, with genesis represented as None.
    pub prev_hash: Option<String>,
    /// Event timestamp normalized to UTC RFC3339Nano form.
    pub timestamp: String,
    /// Legacy or native action type, preserved verbatim.
    pub action_type: String,
    /// Outcome value.
    pub outcome: String,
    /// Subject reference when supplied by the event.
    pub subject_ref: String,
    /// Session identifier.
    pub session_id: String,
    /// Normalized principal where available.
    pub principal: Option<Principal>,
    /// Native trust level where supplied.
    pub trust_level: Option<String>,
    /// Native record phase where supplied.
    pub record_phase: Option<RecordPhase>,
    /// Native agent identifier where supplied.
    pub agent_id: Option<String>,
    /// Native agent version where supplied.
    pub agent_version: Option<String>,
    /// Parent record identifier where supplied.
    pub parent_record_id: Option<String>,
    /// Run identifier where supplied.
    pub run_id: Option<String>,
    /// Native action detail and namespaced legacy operational metadata.
    pub action_detail: Value,
    /// Signer key thumbprint where supplied and validated.
    pub signer_kid: Option<String>,
    /// Stored canonical event JSON, when present and valid UTF-8 JSON.
    pub canonical_json: Option<Value>,
    /// Canonicalisation profile for retained canonical JSON.
    pub canonicalisation: Option<Canonicalisation>,
}

/// Whether a tree-head signature is absent, valid, invalid, or unproven.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchoringStatus {
    /// No signed root was included.
    NotAnchored,
    /// The root signature is valid under the independent tree-head key.
    Pass,
    /// The root signature or trusted key binding is invalid.
    Fail,
    /// A signed root exists but no independent tree-head key was supplied.
    Unproven,
}

/// A stable verification issue that does not include offending values.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationIssue {
    /// Stable issue code.
    pub code: String,
    /// Safe diagnostic that omits evidence values.
    pub message: String,
    /// Whether the issue affects the overall result.
    pub required: bool,
}

/// Observed coverage facts and limitations of the current pack format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageReport {
    /// Whether the pack has a nonempty export scope filter.
    pub filtered: bool,
    /// First sequence present, if any.
    pub first_sequence: Option<u64>,
    /// Last sequence present, if any.
    pub last_sequence: Option<u64>,
    /// Missing sequence ranges observed between exported rows.
    pub gaps: Vec<(u64, u64)>,
    /// Whether rows link across all adjacent exported sequence numbers.
    pub continuity: CheckResult,
    /// Completeness of the tail cannot be authenticated in the current format.
    pub tail_completeness: CheckResult,
    /// Completeness of the full chain cannot be authenticated in the current format.
    pub global_completeness: CheckResult,
}

/// Verification result for one normalized record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordReport {
    /// Normalized record metadata.
    pub record: AatRecord,
    /// Record hash computation result.
    pub hash: CheckResult,
    /// Record signature result.
    pub signature: CheckResult,
    /// Stored canonical comparison result.
    pub canonical: CheckResult,
    /// Original record status for signed tombstones.
    pub original_record: CheckResult,
}

/// Complete offline verification report.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Aggregated result.
    pub result: VerificationResult,
    /// Number of ledger rows checked.
    pub checked: usize,
    /// Number of verified signed tombstone rows.
    pub erased: usize,
    /// Normalized record identifiers in sequence order.
    pub record_ids: Vec<String>,
    /// Per-record results.
    pub records: Vec<RecordReport>,
    /// Exact decoded body hash result.
    pub body_hash: CheckResult,
    /// Pack signature result over the declared body hash text.
    pub body_signature: CheckResult,
    /// Binding between embedded and independently trusted keys.
    pub key_binding: CheckResult,
    /// Tree-head signature status.
    pub tree_head_signature: CheckResult,
    /// Summary anchoring status.
    pub anchoring_status: AnchoringStatus,
    /// Merkle inclusion result; current packs carry no inclusion proof.
    pub merkle_inclusion: CheckResult,
    /// Optional EUTL-qualified timestamp / Rekor transparency-log anchoring.
    /// Informational: reported `unproven` when absent, and also when present,
    /// because no pinned EUTL or Rekor trust material exists yet. Never affects
    /// the overall result.
    pub external_anchoring: CheckResult,
    /// Opaque raw commitment status; no opening is performed offline.
    pub raw_commitment: CheckResult,
    /// Observed coverage and authenticated-coverage limitations.
    pub coverage: CoverageReport,
    /// Stable issues without evidence values.
    pub issues: Vec<VerificationIssue>,
}
