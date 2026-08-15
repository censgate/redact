# redact-scan

Read-only Postgres PII discovery scanner. Prefer a replica or staging database.

```bash
cargo install --path crates/redact-scan
redact-scan --url postgres://reader@localhost/app --schema public --out report.json
```

The report lists table/column locations and entity types. It never includes sample values.
