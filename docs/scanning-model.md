# Scanning model

`redact-scan` is a **read-only** Postgres PII discovery scanner. Prefer a
replica or staging database. The report lists locations and counts — never
sample values.

## Safety

Before any catalog work the scanner:

1. Opens a pool with `max_connections = 1`
2. Sets `default_transaction_read_only = on`, `statement_timeout`, and
   `lock_timeout = 5s`
3. Refuses superuser roles
4. Refuses `INSERT` / `UPDATE` / `DELETE` / `TRUNCATE` (table and column)
5. Quotes enumerated identifiers only — never `SELECT *`
6. Scrubs connection passwords from errors, logs, and the panic hook

`--include-samples` cannot be combined with `--report-url`. Samples are a
local sidecar file and are never merged into `ScanReport`.

## Layers

Select layers independently with `--layers`. Default: `0,0.5,1,2`.

| Layer | Source | User-table reads |
| --- | --- | --- |
| `0` | `pg_catalog` / `information_schema` names, types, comments, unique indexes, FK topology | No |
| `0.5` | `pg_stats` `most_common_vals` and `histogram_bounds` | No |
| `1` | `TABLESAMPLE SYSTEM` + `LIMIT` on ordinary tables (`relkind = r`) | Yes, bounded |
| `2` | JSON/JSONB documents, path-level detections | Yes, bounded |

Layer 0 emits findings for name tokens (`email`, `ssn`, `iban`, …) and for
`inet` / `cidr` types. `json` / unconstrained `text` without a name match
are **candidates only**.

Layer 0.5 runs the built-in pattern pack on planner statistics and drops
the matched text immediately. If `pg_stats` is unreadable the layer is
skipped and other selected layers continue.

Layer 1 samples candidate columns. Percent is
`clamp(1, 100, 200 * sample_rows / n_live_tup)`. When the table is no
larger than `--sample-rows`, `LIMIT` without a full-table random scan is
used. Views are not sampled.

Layer 2 walks sampled JSON documents and reports paths such as
`$.customer.email`. Values are discarded.

Value-based layers use a precision entity set (email, phone, SSN, payment
cards, IBAN, IP, passport, MRN, secrets, …) and exclude high-false-positive
types such as `DATE_TIME`, `GUID`, and hashes unless layer 0 already
nominated that type from the column name.

## Report

`ScanReport` includes `scan_id`, `scanned_at`, a hashed target fingerprint
(`sha256(host|database|schema)`), scanner version, selected layers, and
findings. `content_hash` is SHA-256 of canonical JSON with that field
omitted.

`--out` always writes `ScanReport` JSON. `--format table` is for terminals
and includes a rule-of-three note when a sample found nothing:
“0 matches in 1,000 rows; prevalence above 0.3% is unlikely.”

`--report-url` optionally POSTs the same JSON to a caller-supplied
endpoint (`Authorization: Bearer` when `--api-key` is set;
`--report-header` may be repeated). There is no default host.

Exit codes: `0` clean, `1` when `--fail-on` matches, `2` on error.
