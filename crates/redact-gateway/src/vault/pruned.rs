// Copyright 2026 Censgate LLC.
// Licensed under the Apache License, Version 2.0.

//! Values-free evidence and identity checks for pruned legacy KV v2 history.

use std::{collections::HashMap, path::Path};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::TokenMapError;

const EVIDENCE_SCHEMA: &str = "redact-legacy-pruned-evidence-v1";
const MAX_EVIDENCE_ENTRIES: usize = 100_000;

/// The documented `identity_epoch` for the aks-censgate beta store: the first
/// write on the migrated OpenBao data (2026-09-26T18:14:16Z). Between 2026-09-10
/// and that instant the previous gateway wrote to a separate Raft store
/// (`tokens/`, max_versions=1) that was never carried over, so a context whose
/// key was created earlier may be missing labels. This is documentation and
/// test data; the enforced epoch always comes from the reviewed evidence file.
pub const BETA_MIGRATION_IDENTITY_EPOCH: &str = "2026-09-26T18:14:16Z";

/// Admission policy for history whose retained versions start after version 1.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PrunedHistoryPolicy {
    /// Missing history is an integrity failure (the default).
    #[default]
    Reject,
    /// Require scoped operator evidence and the live identity proof.
    Proven(PrunedProof),
}

/// Operator evidence required in addition to the live metadata/TTL proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrunedProof {
    /// Reviewed writer-history and rollback attestation, bound to exact metadata.
    pub evidence: PrunedEvidence,
}

/// Scoped, expiring operator attestation. Contains no source mappings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrunedEvidence {
    /// Operator's review record identifier; never logged by the gateway.
    pub evidence_id: String,
    /// When the inventory/attestation was generated.
    pub generated_at: DateTime<Utc>,
    /// Hard deadline for admitting a new pruned import.
    pub not_after: DateTime<Utc>,
    /// Start of the attested cumulative-writer, lifetime-TTL, no-rollback period.
    pub identity_epoch: DateTime<Utc>,
    /// Exact source metadata, keyed by [`pruned_evidence_digest`].
    pub entries: HashMap<String, PathFingerprint>,
}

/// Exact KV v2 key metadata at inventory time. Timestamp strings are not normalized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathFingerprint {
    /// Lifetime KV v2 version counter.
    pub current_version: u64,
    /// Oldest version as reported by the server (including its zero sentinel).
    pub oldest_version: u64,
    /// Key generation creation time, exactly as reported by KV v2.
    pub key_created_time: String,
    /// Key update time, exactly as reported by KV v2.
    pub updated_time: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvidenceDocument {
    schema: String,
    evidence_id: String,
    generated_at: DateTime<Utc>,
    not_after: DateTime<Utc>,
    identity_epoch: DateTime<Utc>,
    entries: HashMap<String, PathFingerprint>,
}

impl PrunedEvidence {
    /// Load an evidence JSON file, verifying its pinned SHA-256 and validity.
    /// Errors deliberately omit file names, identifiers and document contents.
    pub fn load(
        path: impl AsRef<Path>,
        expected_sha256_hex: &str,
        now: DateTime<Utc>,
    ) -> Result<Self, TokenMapError> {
        let invalid = || TokenMapError::Unavailable("invalid pruned history evidence".into());
        let bytes = std::fs::read(path).map_err(|_| invalid())?;
        if !is_sha256_hex(expected_sha256_hex)
            || !hex_digest(&Sha256::digest(&bytes)).eq_ignore_ascii_case(expected_sha256_hex)
        {
            return Err(invalid());
        }
        let document: EvidenceDocument = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
        if document.schema != EVIDENCE_SCHEMA
            || document.not_after <= now
            || document.generated_at > now + chrono::Duration::minutes(5)
            || document.identity_epoch > document.generated_at
            || document.identity_epoch > now
            || document.entries.len() > MAX_EVIDENCE_ENTRIES
            || document.entries.keys().any(|key| !is_sha256_hex(key))
        {
            return Err(invalid());
        }
        Ok(Self {
            evidence_id: document.evidence_id,
            generated_at: document.generated_at,
            not_after: document.not_after,
            identity_epoch: document.identity_epoch,
            entries: document.entries,
        })
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

/// Hash a KV path into the domain-separated, lowercase evidence entry key.
pub fn pruned_evidence_digest(path: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(b"redact-legacy-pruned-v1\0");
    digest.update(path.as_bytes());
    hex_digest(&digest.finalize())
}

/// Plain, values-free inputs from a retained version's metadata and payload TTL.
#[derive(Debug, Clone)]
pub struct PrunedVersion {
    /// Version creation time, exactly as returned by KV v2 metadata.
    pub created_time: String,
    /// Expiry from that version's StoredSession payload.
    pub expires_at: DateTime<Utc>,
}

/// Bounded rejection categories for pruned import telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrunedRejection {
    /// Retained history failed the structural checks.
    InvalidHistory,
    /// The evidence admission deadline has passed.
    EvidenceExpired,
    /// This path was not inventoried.
    NoEntry,
    /// Source metadata changed since the inventory.
    FingerprintMismatch,
    /// Key generation predates the operator's attested period.
    BeforeEpoch,
    /// A complete-history context predates the configured identity epoch.
    PreEpochContext,
    /// A creation timestamp is not RFC3339.
    BadTimestamp,
    /// A retained TTL cannot cover the key's exposure window.
    TtlBelowExposure,
    /// Creation times move backwards (including before key creation).
    NonMonotonicVersions,
    /// A retained write gap permits expiry of the earlier version.
    RetainedGapExceedsTtl,
}

impl PrunedRejection {
    /// Stable, bounded telemetry attribute; carries no source identifiers.
    pub fn code(self) -> &'static str {
        match self {
            Self::InvalidHistory => "invalid_history",
            Self::EvidenceExpired => "evidence_expired",
            Self::NoEntry => "no_entry",
            Self::FingerprintMismatch => "fingerprint_mismatch",
            Self::BeforeEpoch => "before_epoch",
            Self::PreEpochContext => "pre_epoch_context",
            Self::BadTimestamp => "bad_timestamp",
            Self::TtlBelowExposure => "ttl_below_exposure",
            Self::NonMonotonicVersions => "non_monotonic_versions",
            Self::RetainedGapExceedsTtl => "retained_gap_exceeds_ttl",
        }
    }
}

impl PrunedHistoryPolicy {
    /// The attested identity epoch, present only when evidence is configured.
    pub fn identity_epoch(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Reject => None,
            Self::Proven(proof) => Some(proof.evidence.identity_epoch),
        }
    }
}

/// Fail closed on a context whose key generation predates the identity epoch,
/// whether or not its retained history is complete. The epoch only exists when
/// evidence is configured, so deployments without it are unaffected.
pub fn check_context_epoch(
    identity_epoch: DateTime<Utc>,
    key_created_time: &str,
) -> Result<(), PrunedRejection> {
    let created = DateTime::parse_from_rfc3339(key_created_time)
        .map_err(|_| PrunedRejection::BadTimestamp)?
        .with_timezone(&Utc);
    if created < identity_epoch {
        return Err(PrunedRejection::PreEpochContext);
    }
    Ok(())
}

/// Prove a pruned key's identity under the scoped operator attestation.
/// `versions` must be in version order and include the latest version. Structural
/// validation (contiguity, live payloads, cumulative identities) is the caller's job.
pub fn prove_pruned_identity(
    evidence: &PrunedEvidence,
    entry_digest: &str,
    live: &PathFingerprint,
    versions: &[PrunedVersion],
    now: DateTime<Utc>,
) -> Result<(), PrunedRejection> {
    if evidence.not_after <= now {
        return Err(PrunedRejection::EvidenceExpired);
    }
    let pinned = evidence
        .entries
        .get(entry_digest)
        .ok_or(PrunedRejection::NoEntry)?;
    if pinned != live {
        return Err(PrunedRejection::FingerprintMismatch);
    }
    let parse = |time: &str| {
        DateTime::parse_from_rfc3339(time)
            .map(|time| time.with_timezone(&Utc))
            .map_err(|_| PrunedRejection::BadTimestamp)
    };
    let key_created = parse(&live.key_created_time)?;
    if key_created < evidence.identity_epoch {
        return Err(PrunedRejection::BeforeEpoch);
    }
    let times: Vec<_> = versions
        .iter()
        .map(|v| parse(&v.created_time))
        .collect::<Result<_, _>>()?;
    let latest = times.last().ok_or(PrunedRejection::InvalidHistory)?;
    if times[0] < key_created || times.windows(2).any(|pair| pair[1] < pair[0]) {
        return Err(PrunedRejection::NonMonotonicVersions);
    }
    let exposure = *latest - key_created;
    let ttls: Vec<_> = versions
        .iter()
        .zip(&times)
        .map(|(v, time)| v.expires_at - *time)
        .collect();
    if ttls.iter().any(|ttl| *ttl < exposure) {
        return Err(PrunedRejection::TtlBelowExposure);
    }
    if times
        .windows(2)
        .zip(&ttls)
        .any(|(pair, ttl)| pair[1] - pair[0] >= *ttl)
    {
        return Err(PrunedRejection::RetainedGapExceedsTtl);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use serde_json::{json, Value};

    struct Fixture {
        now: DateTime<Utc>,
        digest: String,
        live: PathFingerprint,
        evidence: PrunedEvidence,
        versions: Vec<PrunedVersion>,
    }

    impl Fixture {
        fn new() -> Self {
            let now = DateTime::parse_from_rfc3339("2026-11-09T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc);
            let key_created = now - Duration::minutes(10);
            let digest = pruned_evidence_digest("synthetic/path");
            let live = PathFingerprint {
                current_version: 8,
                oldest_version: 6,
                key_created_time: key_created.to_rfc3339(),
                updated_time: (now - Duration::minutes(1)).to_rfc3339(),
            };
            let evidence = PrunedEvidence {
                evidence_id: "synthetic-review".into(),
                generated_at: now,
                not_after: now + Duration::hours(1),
                identity_epoch: now - Duration::days(1),
                entries: HashMap::from([(digest.clone(), live.clone())]),
            };
            let versions = [8, 4, 1]
                .into_iter()
                .map(|minutes_ago| {
                    let created = now - Duration::minutes(minutes_ago);
                    PrunedVersion {
                        created_time: created.to_rfc3339(),
                        expires_at: created + Duration::hours(1),
                    }
                })
                .collect();
            Self {
                now,
                digest,
                live,
                evidence,
                versions,
            }
        }

        fn prove(&self) -> Result<(), PrunedRejection> {
            prove_pruned_identity(
                &self.evidence,
                &self.digest,
                &self.live,
                &self.versions,
                self.now,
            )
        }

        fn pin_live(&mut self) {
            self.evidence
                .entries
                .insert(self.digest.clone(), self.live.clone());
        }

        fn document(&self) -> Value {
            let mut value = serde_json::to_value(&self.evidence).unwrap();
            value["schema"] = json!(EVIDENCE_SCHEMA);
            value
        }
    }

    #[test]
    fn pruned_identity_accepts_matching_attestation_and_sufficient_lifetime_ttls() {
        let mut fixture = Fixture::new();
        assert_eq!(fixture.prove(), Ok(()));
        // TTL == exposure is allowed; expiry at a consecutive gap is not.
        let exposure = Duration::minutes(9);
        for version in &mut fixture.versions {
            let created = DateTime::parse_from_rfc3339(&version.created_time)
                .unwrap()
                .with_timezone(&Utc);
            version.expires_at = created + exposure;
        }
        assert_eq!(fixture.prove(), Ok(()));
        // Equal creation times are non-decreasing and allowed with positive TTL.
        fixture.versions[1] = fixture.versions[0].clone();
        assert_eq!(fixture.prove(), Ok(()));
    }

    #[test]
    fn pruned_identity_rejects_expired_evidence_and_unlisted_paths() {
        let mut fixture = Fixture::new();
        fixture.evidence.not_after = fixture.now;
        assert_eq!(fixture.prove(), Err(PrunedRejection::EvidenceExpired));
        assert_eq!(PrunedRejection::EvidenceExpired.code(), "evidence_expired");
        fixture.evidence.not_after += Duration::seconds(1);
        fixture.evidence.entries.clear();
        assert_eq!(fixture.prove(), Err(PrunedRejection::NoEntry));
        assert_eq!(PrunedRejection::NoEntry.code(), "no_entry");
    }

    #[test]
    fn pruned_identity_requires_every_fingerprint_field_to_match_exactly() {
        for field in ["current", "oldest", "created", "updated"] {
            let mut fixture = Fixture::new();
            match field {
                "current" => fixture.live.current_version += 1,
                "oldest" => fixture.live.oldest_version += 1,
                // Same instant, different string must still reject.
                "created" => {
                    fixture.live.key_created_time =
                        fixture.live.key_created_time.replace("+00:00", "Z")
                }
                _ => fixture.live.updated_time.push(' '),
            }
            assert_eq!(
                fixture.prove(),
                Err(PrunedRejection::FingerprintMismatch),
                "{field}"
            );
        }
        assert_eq!(
            PrunedRejection::FingerprintMismatch.code(),
            "fingerprint_mismatch"
        );
    }

    #[test]
    fn context_epoch_check_is_exact_and_fails_closed() {
        let epoch = DateTime::parse_from_rfc3339(BETA_MIGRATION_IDENTITY_EPOCH)
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(epoch.to_rfc3339(), "2026-09-26T18:14:16+00:00");
        let at = |time: &str| check_context_epoch(epoch, time);
        assert_eq!(at("2026-09-26T18:14:16Z"), Ok(()));
        assert_eq!(at("2026-09-26T18:14:16.000000001Z"), Ok(()));
        assert_eq!(
            at("2026-09-26T18:14:15.999999999Z"),
            Err(PrunedRejection::PreEpochContext)
        );
        assert_eq!(
            at("2026-09-03T04:07:46Z"),
            Err(PrunedRejection::PreEpochContext)
        );
        assert_eq!(at("not-a-time"), Err(PrunedRejection::BadTimestamp));
        assert_eq!(PrunedRejection::PreEpochContext.code(), "pre_epoch_context");
        assert_eq!(PrunedHistoryPolicy::Reject.identity_epoch(), None);
        let fixture = Fixture::new();
        let policy = PrunedHistoryPolicy::Proven(PrunedProof {
            evidence: fixture.evidence.clone(),
        });
        assert_eq!(
            policy.identity_epoch(),
            Some(fixture.evidence.identity_epoch)
        );
    }

    #[test]
    fn pruned_identity_rejects_pre_epoch_keys_and_bad_creation_timestamps() {
        let mut fixture = Fixture::new();
        fixture.evidence.identity_epoch = fixture.now;
        assert_eq!(fixture.prove(), Err(PrunedRejection::BeforeEpoch));
        assert_eq!(PrunedRejection::BeforeEpoch.code(), "before_epoch");
        for index in 0..=fixture.versions.len() {
            let mut fixture = Fixture::new();
            if index == fixture.versions.len() {
                fixture.live.key_created_time = "bad-time-canary".into();
                fixture.pin_live();
            } else {
                fixture.versions[index].created_time = "bad-time-canary".into();
            }
            assert_eq!(fixture.prove(), Err(PrunedRejection::BadTimestamp));
        }
        assert_eq!(PrunedRejection::BadTimestamp.code(), "bad_timestamp");
    }

    #[test]
    fn pruned_identity_rejects_each_ttl_below_exposure_including_the_latest() {
        for index in 0..3 {
            let mut fixture = Fixture::new();
            let created = DateTime::parse_from_rfc3339(&fixture.versions[index].created_time)
                .unwrap()
                .with_timezone(&Utc);
            fixture.versions[index].expires_at = created + Duration::minutes(8);
            assert_eq!(fixture.prove(), Err(PrunedRejection::TtlBelowExposure));
        }
        // The production expiry reset counterexample, with only v2 retained.
        let mut fixture = Fixture::new();
        fixture.versions = vec![PrunedVersion {
            created_time: fixture.live.updated_time.clone(),
            expires_at: fixture.now,
        }];
        assert_eq!(fixture.prove(), Err(PrunedRejection::TtlBelowExposure));
        assert_eq!(
            PrunedRejection::TtlBelowExposure.code(),
            "ttl_below_exposure"
        );
    }

    #[test]
    fn pruned_identity_rejects_non_monotonic_times_and_gaps_at_expiry() {
        let mut fixture = Fixture::new();
        fixture.versions.swap(0, 1);
        assert_eq!(fixture.prove(), Err(PrunedRejection::NonMonotonicVersions));
        fixture.versions[0].created_time = (fixture.now - Duration::days(1)).to_rfc3339();
        assert_eq!(fixture.prove(), Err(PrunedRejection::NonMonotonicVersions));
        assert_eq!(
            PrunedRejection::NonMonotonicVersions.code(),
            "non_monotonic_versions"
        );
        let mut fixture = Fixture::new();
        // A gap equal to W and the earlier TTL passes the exposure check but
        // must fail the independent strict-gap check.
        fixture.versions = vec![
            PrunedVersion {
                created_time: fixture.live.key_created_time.clone(),
                expires_at: fixture.now,
            },
            PrunedVersion {
                created_time: fixture.now.to_rfc3339(),
                expires_at: fixture.now + Duration::hours(1),
            },
        ];
        assert_eq!(fixture.prove(), Err(PrunedRejection::RetainedGapExceedsTtl));
        assert_eq!(
            PrunedRejection::RetainedGapExceedsTtl.code(),
            "retained_gap_exceeds_ttl"
        );
        fixture.versions.clear();
        assert_eq!(fixture.prove(), Err(PrunedRejection::InvalidHistory));
        assert_eq!(PrunedRejection::InvalidHistory.code(), "invalid_history");
    }

    fn load_document(
        value: Value,
        now: DateTime<Utc>,
        pinned: Option<&str>,
    ) -> Result<PrunedEvidence, TokenMapError> {
        let file = tempfile::NamedTempFile::new().unwrap();
        let bytes = serde_json::to_vec(&value).unwrap();
        std::fs::write(file.path(), &bytes).unwrap();
        let digest = hex_digest(&Sha256::digest(&bytes));
        PrunedEvidence::load(file.path(), pinned.unwrap_or(&digest), now)
    }

    #[test]
    fn evidence_load_accepts_valid_pinned_document_and_clock_skew() {
        let fixture = Fixture::new();
        assert_eq!(
            load_document(fixture.document(), fixture.now, None).unwrap(),
            fixture.evidence
        );
        let mut document = fixture.document();
        document["generated_at"] = json!(fixture.now + Duration::minutes(5));
        assert!(load_document(document, fixture.now, None).is_ok());
    }

    #[test]
    fn evidence_load_rejects_digest_mismatch_and_invalid_pins() {
        let fixture = Fixture::new();
        for pin in ["0".repeat(64), "z".repeat(64), "0".repeat(63)] {
            assert!(load_document(fixture.document(), fixture.now, Some(&pin)).is_err());
        }
        assert!(
            PrunedEvidence::load("/nonexistent/evidence", &"0".repeat(64), fixture.now).is_err()
        );
    }

    #[test]
    fn evidence_load_rejects_expiry_schema_and_future_epoch_without_identifiers() {
        let fixture = Fixture::new();
        for (field, value) in [
            ("not_after", json!(fixture.now)),
            ("schema", json!("bad-schema-canary")),
            (
                "generated_at",
                json!(fixture.now + Duration::minutes(5) + Duration::seconds(1)),
            ),
            ("identity_epoch", json!(fixture.now + Duration::seconds(1))),
            ("identity_epoch", json!("bad-time-canary")),
            ("extra-canary", json!(true)),
        ] {
            let mut document = fixture.document();
            document[field] = value;
            let err = load_document(document, fixture.now, None).unwrap_err();
            assert!(!err.to_string().contains("canary"));
            assert!(!err.to_string().contains("synthetic"));
        }
        // Epoch after generation is invalid even if both are in the past.
        let mut document = fixture.document();
        document["generated_at"] = json!(fixture.now - Duration::hours(2));
        document["identity_epoch"] = json!(fixture.now - Duration::hours(1));
        assert!(load_document(document, fixture.now, None).is_err());
        // Future epoch is invalid even within the generation clock-skew allowance.
        let mut document = fixture.document();
        document["generated_at"] = json!(fixture.now + Duration::minutes(4));
        document["identity_epoch"] = json!(fixture.now + Duration::minutes(1));
        assert!(load_document(document, fixture.now, None).is_err());
    }

    #[test]
    fn evidence_load_rejects_unknown_fingerprint_fields_and_invalid_entry_keys() {
        let fixture = Fixture::new();
        let mut document = fixture.document();
        document["entries"][&fixture.digest]["extra-canary"] = json!(true);
        assert!(load_document(document, fixture.now, None).is_err());
        for key in ["x".repeat(64), "0".repeat(63), "0".repeat(65)] {
            let mut document = fixture.document();
            document["entries"] = json!({key: fixture.live});
            assert!(load_document(document, fixture.now, None).is_err());
        }
    }

    #[test]
    fn evidence_load_rejects_oversize_entry_inventory() {
        let fixture = Fixture::new();
        let mut document = fixture.document();
        let entries: serde_json::Map<_, _> = (0..=MAX_EVIDENCE_ENTRIES)
            .map(|i| {
                (
                    format!("{i:064x}"),
                    serde_json::to_value(&fixture.live).unwrap(),
                )
            })
            .collect();
        document["entries"] = Value::Object(entries);
        assert!(load_document(document, fixture.now, None).is_err());
    }

    #[test]
    fn evidence_digest_is_domain_separated_and_lowercase() {
        let digest = pruned_evidence_digest("synthetic/path");
        assert_eq!(
            digest,
            hex_digest(&Sha256::digest(b"redact-legacy-pruned-v1\0synthetic/path"))
        );
        assert!(is_sha256_hex(&digest));
        assert_eq!(digest, digest.to_ascii_lowercase());
        assert_ne!(digest, hex_digest(&Sha256::digest(b"synthetic/path")));
    }
}
