# Contributing to Censgate Redact

Thank you for your interest in contributing to Censgate Redact! This document provides guidelines for contributing to our open-source redaction library and CLI tool.

## Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/censgate/redact.git
   cd redact
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Run tests**
   ```bash
   go test ./...
   ```

4. **Run linter**
   ```bash
   golangci-lint run
   ```

5. **Build the CLI tool**
   ```bash
   go build -o redactctl ./cmd/redactctl
   ```

## CLI Tool Overview

The `redactctl` CLI tool provides comprehensive PII/PHI detection and redaction capabilities:

### Available Commands

- **`redactctl redact`** - Redact PII/PHI from text input (files, stdin, or command line)
- **`redactctl interactive`** - Start an interactive redaction session for testing
- **`redactctl restore`** - Restore original text from redaction tokens
- **`redactctl engine`** - Manage and inspect the redaction engine
  - `engine stats` - View engine statistics
  - `engine patterns` - List active patterns
  - `engine cleanup` - Clean up expired tokens
  - `engine rotate` - Rotate encryption keys
  - `engine test` - Test custom patterns
- **`redactctl version`** - Print version information

### Testing CLI Features

```bash
# Test basic redaction
./redactctl redact "Contact John Doe at john@example.com or 555-123-4567"

# Test interactive mode
./redactctl interactive

# Test file processing
echo "SSN: 123-45-6789" | ./redactctl redact --format json

# Test restoration
./redactctl restore <token>
```

## Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Make your changes** following the code style guidelines
3. **Add tests** for new functionality
4. **Update documentation** if needed
5. **Ensure all tests pass** and linting passes
6. **Submit a pull request** with a clear description

## Code Style

- **Follow Go conventions** and idiomatic Go patterns
- **Use meaningful variable names** that clearly express intent
- **Add comments for public APIs** and complex logic
- **Keep functions small and focused** (single responsibility)
- **Use conventional commits** for commit messages (see below)
- **Follow the project's architecture patterns** for redaction providers and engines

## Testing Guidelines

- **Write unit tests** for all new functionality
- **Test CLI commands** with various input scenarios
- **Test error conditions** and edge cases
- **Ensure backward compatibility** when modifying APIs
- **Test with different output formats** (text, JSON, YAML)

## Version Management

The project uses automated version management:

- **Version updates** are handled by `scripts/update-version.sh`
- **Semantic versioning** is enforced (MAJOR.MINOR.PATCH)
- **Release process** includes automated version updates across the codebase
- **Changelog entries** are automatically generated

### Manual Version Updates

```bash
# Update to a new version
./scripts/update-version.sh v0.4.0

# Dry run to see what would change
./scripts/update-version.sh v0.4.0 --dry-run
```

## Commit Message Format

Follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification:

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat(cli): add interactive mode for testing redaction
fix(engine): resolve memory leak in token cleanup
docs: update CONTRIBUTING.md with CLI information
```

## Architecture Guidelines

- **Use Cobra** for all CLI commands
- **Use Viper** for configuration management following 12-factor principles
- **Follow the redaction provider pattern** for extensibility
- **Implement proper error handling** with detailed error messages
- **Use context.Context** for cancellation and timeouts
- **Ensure thread safety** for concurrent operations

## Reporting Issues

Please use GitHub Issues to report bugs or request features. Include:

- **Clear description** of the issue or feature request
- **Steps to reproduce** (for bugs)
- **Expected vs actual behavior**
- **Environment details** (OS, Go version, etc.)
- **CLI command examples** if applicable

## Documentation

- **API documentation** should be added for public interfaces
- **CLI help text** should be comprehensive and include examples
- **README updates** may be needed for new features
- **Architecture diagrams** should use Mermaid format in `docs/` directory

## Security Considerations

- **Never commit sensitive data** or API keys
- **Use secure defaults** for encryption and tokenization
- **Follow security best practices** for cryptographic operations
- **Test security features** thoroughly
- **Report security vulnerabilities** privately via security@censgate.com

## Getting Help

- **GitHub Discussions** for questions and community support
- **GitHub Issues** for bug reports and feature requests
- **Documentation** in the `docs/` directory
- **CLI help** via `redactctl --help` or `redactctl <command> --help`
