# redact-verify

redact-verify is an offline library and CLI for checking sealed Censgate
evidence packs. It has no redact-core dependency, does not fetch keys, and
does not make network calls. Public normalized records are aligned with the
AAT draft (draft-09). The current platform-v1 hash projection differs from
native JCS/AAT chaining.

## Local use

The chain key must come from an independent local source. A key embedded in a
pack is only compared with the independently supplied key.

    redact-verify --pack evidence-pack.json --pubkey chain-public.pem --format json
    redact-verify --pack evidence-pack.json --keys local-keyset.json --format json

The public key file accepts an Ed25519 SPKI PEM, 32-byte hex, padded standard
base64, or unpadded standard base64. The --keys option accepts this structure:

    {
      "chain": {"public_key": "…", "version": 1},
      "tree_head": {"public_key": "SPKI PEM"},
      "erasure_authority": {"public_key": "…"}
    }

tree_head is an independently trusted ECDSA P-256 or P-384 SPKI PEM key.
erasure_authority is a separately trusted Ed25519 key for the proposed
tombstone extension. The compatibility form --pubkey FILE has version zero;
add --tree-head-pubkey FILE to trust a tree-head key. --keys and --pubkey
are mutually exclusive.

--online remains accepted so existing command lines continue to parse. It
prints the reserved notice to stderr and changes nothing:

    --online is reserved; verification remains offline and no network calls are made.

## Current sealed-pack format

An evidence pack is one JSON envelope. Its body is the standard-base64
encoding of the exact body JSON bytes; byte-valued arrays are also accepted for
Go compatibility. Empty bodies, raw JSON strings, and body objects are
rejected. record.canonical uses the same bytes representation; absent, null,
or empty canonical evidence omits the optional comparison.

The envelope carries schema_version, pack_id, tenant_id, body, body_hash,
body_signature, and optional key_name and key_version. The decoded body carries
schema_version, pack_id, tenant_id, region, batches, and optional r1, keys, and
scope. Omitted or zero schema versions and version 1 are accepted. Unsupported
versions and explicitly unsupported canonicalisation profiles are unproven.

Each ordinary batch has an event object, a chain record, a base64 signature,
and optional key_version. The verifier sorts rows by record.seq, checks their
platform-v1 projection and direct Ed25519 signatures, hashes the exact decoded
body bytes, and verifies the pack signature. Embedded chain and tree-head
public keys are comparison material, never trust sources.

The event projection fields are action, boundary, caller, content_sha256,
destination_class, destination_id, destination_vendor, entity_types, epoch,
error_type, event_id, event_name, gateway_instance, outcome, profile,
redactions, region, session_id, shard, span_id, subject_ref, tenant_id,
timestamp, tokens_issued, and trace_id. A current r1 object contains
merkle_root and optional signature. Scope uses from, to, session_id,
subject_ref, and run_id.

### Hashes and signatures

The chain genesis value is 64 zero hexadecimal characters. For each event,
platform-v1 creates compact UTF-8 JSON containing all 25 known event keys in
lexicographic order. Missing or null strings become empty strings, counts
become zero, and a missing or null entity_types becomes JSON null (an empty
array remains an empty array). Event strings retain their Unicode spelling.
JSON escaping follows Go encoding/json, including HTML and U+2028/U+2029
escapes. Timestamps become UTC RFC3339Nano text, with up to nine fractional
digits and trailing zeroes removed.

    effective_prev = record.prev_hash, or the zero genesis value when empty
    record_hash = lowercase_hex(SHA256(
        UTF8(effective_prev) || canonical_event_json ||
        UTF8(event.event_id) || UTF8(normalized_timestamp)
    ))
    record_signature_input =
        UTF8(record.chain_id + "|" + decimal(record.seq) + "|" + record.hash)

    body_hash = lowercase_hex(SHA256(exact_decoded_body_bytes))
    pack_signature_input =
        UTF8("anchor-pack|v1|" + envelope.pack_id + "|" +
             effective_tenant + "|" + envelope.body_hash)
    tree_head_signature_input =
        UTF8("anchor-root|v1|" + body.r1.merkle_root)

Record hashes compare case-sensitively. The body hash compares
case-insensitively, while pack and tree-head signature inputs preserve the
declared hash or root text exactly. Record and pack signatures use Ed25519.
Tree-head signatures use ECDSA ASN.1 DER over SHA-256 of the tree-head input.

### Input names and normalized output

| Current pack input | Normalized public name |
|---|---|
| event.event_id, record.event_id | record_id (both must agree) |
| record.seq | sequence_number |
| record.hash | record_hash |
| record.prev_hash | prev_hash; genesis is null in output |
| event.action | action_type, preserved verbatim |
| event.caller | principal.id; no role or person type is inferred |
| record.canonical | parsed canonical_json, with canonicalisation=platform_v1 |
| event.event_name | action_detail.censgate_event_name |
| event.profile | action_detail.censgate_profile |
| event.content_sha256 | action_detail.censgate_redacted_content_sha256 |
| Other legacy operational metadata | namespaced action_detail.censgate_* fields |

Native principal, trust_level, record_phase, agent_id, agent_version,
parent_record_id, run_id, action_detail, and signer_kid fields are retained
when present. A supplied signer_kid must match the RFC 7638 thumbprint of the
independently trusted chain key. Legacy key_name and key_id are platform key
references, not signer thumbprints. New native metadata remains covered by
the exact body signature, but current platform-v1 record hashing excludes
additions to the legacy projection; the report marks those additions as
pack-signed only.

## Results and coverage

| Result | Exit | Meaning |
|---|---:|---|
| pass | 0 | Required current-format checks succeeded |
| erased | 0 | Required checks succeeded and a signed tombstone was verified |
| fail | 1 | Required evidence is contradictory, invalid, or privacy-forbidden |
| unproven | 2 | Required independent evidence is missing or the format is unsupported |

| Report check | Required behavior |
|---|---|
| body_hash and body_signature | Required for every supported pack |
| Record hash, canonical comparison, and signature | Required when applicable; stored canonical comparison is omitted when absent |
| Key binding and continuity | Required |
| tree_head_signature | Optional when no signed R1 is present; otherwise independently verified |
| merkle_inclusion and tail/global completeness | Informational unproven limitations of this format |
| raw_commitment | Informational unproven when an opaque commitment is present |

Malformed JSON/base64, unreadable local files, and CLI usage errors also exit 2
with an unproven reason. Missing parsed signatures and empty batch lists fail.
An absent R1 is not_anchored and does not affect pass. A signed R1 without an
independent tree-head key is required unproven.

Unfiltered exports must begin at sequence 1 and cannot contain gaps. A scope is
filtered when any of from, to, session_id, subject_ref, or run_id is nonempty.
Filtered exports may begin later and have gaps; rows that are adjacent in
sequence must still link. The report lists observed first/last sequences,
gaps, and continuity.

The current pack has no authenticated coverage boundary, close/heartbeat
contract, tree size, or inclusion path. Tail and global completeness are
therefore unproven. Merkle inclusion is always reported as unproven with reason
current_format_has_no_inclusion_proof; these limitations do not change the
local cryptographic verdict. The retained RFC 6962 utilities and their vectors
are compatibility helpers only, not a construction defined by the current
pack format.

## Privacy and raw commitments

Verification scans the envelope, decoded body, and stored canonical JSON.
It rejects a payload key, ledger_ingest_token, authorization, private_key,
content_fingerprint, raw_input_hash, raw_input_sha256, raw_content_sha256,
raw_payload_hash, raw_payload_sha256, raw_sha256, and hash descriptors that
explicitly identify a raw or pre-redaction origin. It allows
content_sha256, input_hash, output_hash, parameters_hash, or response_hash by
name; supported meanings refer to redacted material. Schema checks cannot
identify every PII value or establish what an arbitrary digest originally
covered.

action_detail.censgate_raw_commitment is accepted as opaque signed metadata.
The report says raw_commitment=unproven with reason
opaque_keyed_commitment_not_checked_offline. Its intended construction is a
per-tenant keyed commitment such as
HMAC-SHA-256(Ktenant, salt || JCS(raw)). The verifier never requests raw
input, salt, HMAC keys, or an online opening service. An explicitly unkeyed
raw commitment is rejected.

## Signed tombstone extension

The redact-tombstone-v1 replacement contract below is a proposed local
extension, separate from the current platform reference format. A
replacement has event=null and retains the chain sequence, previous hash,
record hash, and identity. It omits original canonical bytes and batch
signature, and adds an exact-field tombstone signed by a separately trusted
erasure authority. Its fields are schema_version, record_id, sequence_number,
chain_id, record_hash, prev_hash, tenant_id, erased_at, reason_code, signer_kid,
sig_alg, and signature. Its signature input is
UTF8("redact-tombstone|v1|") || JCS(fields excluding signature).
erased_at is normalized to UTC RFC3339Nano, and empty previous hash is signed
as genesis.

A valid declaration reports the original hash check as erased with reason
signed_tombstone_original_canonical_absent. It authenticates the erasure
declaration, not physical deletion, and it does not recreate the absent
original event signature. Unknown tombstone versions are unproven; an
unsigned, mismatched, or invalid replacement fails. Chain and erasure keys
have separate roles.

## Library

    use redact_verify::{verify_file, TrustedKeys};

    let key = std::fs::read_to_string("chain-public.pem")?;
    let trusted = TrustedKeys::from_ed25519(&key)?;
    let report = verify_file("evidence-pack.json", &trusted)?;
    println!("{:?}", report.result);

The library reads only the byte slice or local path supplied by its caller. It
does not print, exit, fetch keys, or use network services.

## Compatibility and future formats

This pre-1.0 crate no longer verifies the former proof-only R1/R2 receipt
format. That path depended on placeholder trust anchors and did not establish
the claimed signature trust; those inputs return
unproven: unsupported_legacy_anchor_format.

BagIt layouts, JSONL export, signed coverage boundaries, and independent Redact
attestation wire formats are future contracts absent from the current
reference. The current canonicalisation is platform-v1 deterministic JSON,
not native JCS/AAT chaining. Supported ECDSA tree-head curves are P-256 and
P-384; other curves return unproven: unsupported_curve.
