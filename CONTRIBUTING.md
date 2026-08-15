# Contributing to Redact

Thank you for your interest in contributing to Redact! This document provides guidelines and information for contributors.

Before you invest time, read [docs/PROJECT_SCOPE.md](docs/PROJECT_SCOPE.md). Pull requests that implement out-of-scope work will not be merged.

Contributors are expected to be respectful in issues, discussions, and pull requests. A formal Code of Conduct file is not published in this repository.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected behavior** vs. **actual behavior**
- **Environment details** (OS, Rust version, etc.)
- **Code samples** or test cases if applicable

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use cases** and **examples**
- **Why this enhancement would be useful** to most users
- **Possible implementation approach** (optional)

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Make your changes**, following the code style guidelines
3. **Add tests** for new functionality
4. **Run the test suite** to ensure all tests pass
5. **Update documentation** as needed
6. **Sign off every commit** with `git commit -s` (Developer Certificate of Origin)
7. **Create a pull request** with a clear title and description
8. **Sign the CLA** when the bot comments (see [License and contributor agreements](#license-and-contributor-agreements))

## Development Setup

### Prerequisites

- Rust 1.88 or higher
- Python 3.8+ (for NER model export scripts)
- Git

### Getting Started

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/redact.git
cd redact

# Add upstream remote
git remote add upstream https://github.com/censgate/redact.git

# Create a feature branch
git checkout -b feature/my-new-feature

# Install development dependencies
cargo build --workspace

# Run tests
cargo test --workspace
```

### Running Tests

```bash
# Run all tests
cargo test --workspace

# Run tests with output
cargo test --workspace -- --nocapture

# Run specific package tests
cargo test --package redact-core

# Run specific test suite
cargo test --package redact-core --test pattern_coverage
cargo test --package redact-core --test integration_policy
cargo test --package redact-core --test error_scenarios
cargo test --package redact-core --test concurrent_operations

# Run benchmarks
cargo bench --package redact-core

# Run NER E2E tests (requires ONNX model)
cargo test --package redact-ner --test ner_e2e -- --ignored
```

### Code Quality

```bash
# Format code
cargo fmt --all

# Run clippy
cargo clippy --all-targets --all-features -- -D warnings

# Check for security vulnerabilities
cargo audit

# Build documentation
cargo doc --no-deps --open
```

## Code Style Guidelines

### Rust Code

- Follow the official [Rust Style Guide](https://doc.rust-lang.org/1.0.0/style/)
- Use `cargo fmt` to format code
- Use `cargo clippy` to catch common mistakes
- Write idiomatic Rust code
- Add doc comments (`///`) for public APIs
- Keep functions focused and small

### Naming Conventions

- **Types**: `PascalCase` (e.g., `AnalyzerEngine`, `EntityType`)
- **Functions/Methods**: `snake_case` (e.g., `analyze_text`, `get_entities`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `MAX_SEQUENCE_LENGTH`)
- **Modules**: `snake_case` (e.g., `anonymizers`, `recognizers`)

### Documentation

- Add doc comments for all public APIs
- Include examples in doc comments where helpful
- Update README.md for user-facing changes
- Update CHANGELOG.md (see below)

### Testing

- Write unit tests for new functions
- Write integration tests for new features
- Aim for high test coverage (target: >75%)
- Test edge cases and error conditions
- Use descriptive test names

```rust
#[test]
fn test_email_detection_with_special_characters() {
    // Test implementation
}
```

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Use `git commit -s` so Git adds a `Signed-off-by: Name <email>` trailer (Developer Certificate of Origin). That is project policy; the CLA bot does not check for it.

### Types

- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks
- `perf`: Performance improvements

### Examples

```
feat(ner): add support for multilingual NER models

Implement label mapping configuration for custom NER models
with multilingual support. Add tests for Spanish and French.

Closes #123
Signed-off-by: Your Name <you@example.com>
```

```
fix(anonymizer): correct hash anonymization for empty strings

The hash anonymizer was panicking on empty input strings.
Add null check and return empty string for empty input.

Signed-off-by: Your Name <you@example.com>
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes
- **MINOR** version for new functionality (backward-compatible)
- **PATCH** version for bug fixes (backward-compatible)

## Release Process

Preferred path (GitHub Actions):

1. Update `CHANGELOG.md` release notes on a `release/vX.Y.Z` branch (or merge notes to `main` first)
2. Bump versions via **Prepare Release** (preferred) or `./scripts/update-version.sh X.Y.Z`.
   Both update workspace/`Cargo.toml` pins **and** documentation version pins
   (`README.md` library examples, `docs/benchmarks/README.md` current-release link,
   CHANGELOG unsupported-version upgrade hint), plus `redact-gateway` crate deps.
3. Open a PR from `release/vX.Y.Z` → `main` and wait for **CI** to pass
4. Merge the PR — **Create Release Tag** creates `vX.Y.Z` and dispatches **Release**
5. The **Release** workflow will:
   - Build binaries for all platforms (`redact` and `redact-gateway`)
   - Publish crates to crates.io (`redact-core`, `redact-ner`, `redact-api`, `redact-cli`, `redact-gateway`)
   - Create a GitHub release
   - Build and push Docker images:
     - default (`Dockerfile`) as `:latest`, `:X.Y.Z`, etc.
     - full image (`Dockerfile.ner`, pattern + ONNX NER) as `:full`, `:X.Y.Z-full`, etc.
     - gateway (`Dockerfile.gateway`) as `ghcr.io/<org>/redact-gateway:latest`, `:X.Y.Z`, etc.

The NER base layer (`ghcr.io/<org>/redact-ner-base`) is built separately via the **NER Base Image** workflow and is not republished on every release.

Manual fallback: `./scripts/update-version.sh X.Y.Z`, review the diff (Cargo + docs), then `git tag -a vX.Y.Z -m "Release vX.Y.Z"` and `git push origin vX.Y.Z`.

## Project Structure

```
redact/
├── crates/
│   ├── redact-core/         # Core detection & anonymization
│   ├── redact-ner/          # NER with ONNX Runtime
│   ├── redact-api/          # REST API server
│   ├── redact-cli/          # CLI tool
│   ├── redact-wasm/         # WASM bindings
│   └── redact-gateway/      # OpenAI-compatible privacy gateway
├── deploy/                  # Gateway Collector config and Kubernetes manifests
├── scripts/                 # Utility scripts
├── examples/                # Usage examples
├── docs/
│   ├── PROJECT_SCOPE.md     # What this repository accepts
│   ├── gateway/             # Gateway operator documentation
│   └── benchmarks/          # Benchmark methodology and results
└── .github/workflows/       # CI/CD pipelines
```

## Areas for Contribution

Confirm the idea is in [project scope](docs/PROJECT_SCOPE.md) before starting.

### High Priority

- [ ] Additional entity type patterns
- [ ] Performance optimizations
- [ ] Documentation improvements
- [ ] Example applications
- [ ] Test coverage improvements

### Medium Priority

- [ ] WASM + inline NER (deferred; see README hybrid architecture)
- [ ] Mobile FFI bindings
- [ ] Additional anonymization strategies
- [ ] Multi-language pattern support
- [ ] Streaming API for large texts

### Low Priority

- [ ] GPU acceleration for NER
- [ ] Custom recognizer plugin system
- [ ] Advanced analytics and reporting
- [ ] Integration with other tools

## Getting Help

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and general discussion
- **Email**: support@censgate.com for private inquiries

## Recognition

Contributors will be recognized in:
- `CONTRIBUTORS.md` file
- GitHub contributors page
- Release notes for significant contributions

## License and contributor agreements

The outbound license for this repository remains the [Apache License 2.0](LICENSE).

### Contributor License Agreement (required)

Every human contributor must sign the [Contributor License Agreement](CLA.md)
before a pull request can be merged.

- **Independent contributors:** when the CLA bot comments on your first pull
  request, post exactly:

  ```
  I have read the CLA Document and I hereby sign the CLA
  ```

- **Employer-owned work:** do not rely on an Individual CLA alone. An
  authorised corporate signer must email a completed Corporate CLA to
  support@censgate.com. A Corporate CLA does **not** replace each
  developer's Individual CLA. Maintainers then add designated GitHub
  usernames to the `allowlist` in `.github/workflows/cla.yml` or to
  `signatures/version1/cla.json` on the `cla-signatures` branch so the
  check can pass.

Individual signatures are GitHub usernames stored on this repository's
`cla-signatures` branch (already public on the pull request). Signed
Corporate CLA documents are kept off this repository.

The CLA is a license grant, not an assignment. It does not change the
Apache-2.0 outbound license.

### Developer Certificate of Origin (required by policy)

Every commit must include a DCO sign-off:

```bash
git commit -s -m "feat: your change"
```

That adds `Signed-off-by: Your Name <you@example.com>`. DCO is per-commit
provenance; the CLA covers rights. DCO is **not** enforced by the CLA bot.
Use the pull-request template checkbox and `git commit -s`.

---

Thank you for contributing to Redact!
