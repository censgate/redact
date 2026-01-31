# Security Policy

## Reporting Security Vulnerabilities

We take security seriously. If you discover a security vulnerability, please report it responsibly:

1. **Email:** security@censgate.com
2. **Do not** open a public GitHub issue for security vulnerabilities
3. Include steps to reproduce, impact assessment, and any suggested fixes

We aim to respond within 48 hours and will work with you to understand and resolve the issue.

## Supported Versions

| Version | Supported | Notes |
|---------|-----------|-------|
| 0.5.x   | ✅ Yes | Current release (Rust rewrite) |
| 0.1.x - 0.4.x | ❌ No | Legacy Go implementation (deprecated) |

As new versions are released, this table will be updated. We generally support the current minor version and one prior.

## Security Measures

### Code Security
- **Memory safety:** Written in Rust, eliminating buffer overflows, use-after-free, and data races
- **Dependency auditing:** Automated via `cargo audit` in CI pipeline
- **Static analysis:** CodeQL scanning on all PRs and commits

### Data Handling
- **No persistent storage:** PII is processed in-memory only
- **No telemetry:** No data is sent to external services
- **Minimal dependencies:** Reduced attack surface

### Container Security
- **Distroless base image:** Minimal attack surface (no shell, no package manager)
- **Non-root execution:** Containers run as unprivileged user
- **Multi-arch support:** Native ARM64/AMD64 builds (no emulation)

### CI/CD Security
- **Required status checks:** All PRs must pass security audit
- **Signed commits:** Recommended for contributors
- **Dependency updates:** Dependabot enabled for automated security patches

## Security-Related Configuration

When deploying Censgate Redact:

```yaml
# Recommended: Run as non-root
docker run --user nonroot ghcr.io/censgate/redact:latest

# Recommended: Read-only filesystem
docker run --read-only ghcr.io/censgate/redact:latest

# Recommended: Drop all capabilities
docker run --cap-drop=ALL ghcr.io/censgate/redact:latest
```

## Known Limitations

- **NER models:** Third-party ONNX models should be verified before use
- **Pattern matching:** Regex patterns may have edge cases; validate against your data
- **Encryption keys:** When using the `encrypt` anonymizer, secure key management is your responsibility
