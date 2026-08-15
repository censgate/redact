# redact-scan

Read-only Postgres PII discovery scanner. Prefer a replica or staging database.

```bash
cargo install --path crates/redact-scan
redact-scan --url postgres://reader@localhost/app --schema public --out report.json
```

The report lists table/column locations and entity types. It never includes sample values.

See [docs/scanning-model.md](../../docs/scanning-model.md) for the four discovery layers and safety rails.

## Sample report

```json
{
  "scan_id": "00000000-0000-0000-0000-000000000001",
  "scanned_at": "2026-08-15T00:00:00Z",
  "target": {
    "fingerprint": "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
    "engine": "postgres",
    "version": "16.4"
  },
  "scanner": {
    "version": "0.9.1",
    "pattern_pack": "builtin@54"
  },
  "sampling": {
    "layers": [0.0, 0.5, 1.0, 2.0],
    "rows_per_column": 1000,
    "method": "TABLESAMPLE SYSTEM"
  },
  "findings": [
    {
      "table": "public.customers",
      "column": "email",
      "entity_type": "EMAIL_ADDRESS",
      "layer": 0.0,
      "match_count": 0,
      "sampled_rows": 0,
      "confidence": 0.85,
      "evidence_class": "name_heuristic"
    }
  ],
  "content_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
}
```
