# Changelog

All notable changes to this project will be documented in this file.

## [v0.4.0] - 2025-09-20

### Added
- Version bump to v0.4.0 for upcoming features

### Changed
- Updated version references across codebase
- Updated documentation for v0.4.0

## [v0.3.1] - 2025-09-20

### Security
- **Dependency Security Updates**: Updated multiple dependencies to address security vulnerabilities
  - Updated `gopkg.in/yaml.v3` from v3.0.1 to v3.0.4
  - Updated `gopkg.in/check.v1` from v1.0.0-20190902080502 to v1.0.0-20201130134442
  - Updated `cobra` from v1.9.1 to v1.10.1
  - Updated `viper` from v1.20.1 to v1.21.0
  - Updated multiple indirect dependencies to latest secure versions
  - Addresses 2 moderate vulnerabilities detected by GitHub security scanning

### Fixed
- **CI Workflow Security**: Added proper permissions to GitHub Actions workflow to address security scanning alert
  - Added `contents: read` permission to CI workflow
  - Resolves GitHub Advanced Security code scanning alert

## [v0.3.0] - 2025-09-20

### Added
- Interactive CLI mode with `redactctl interactive` command
- Comprehensive help text for all CLI commands
- Automated version management system

### Fixed
- Fixed stdin input handling for piped commands
- Fixed configuration duration parsing (30d -> 720h)
- Updated license references from MIT to Apache 2.0

### Changed
- Improved CLI command structure and help documentation
- Enhanced error handling and user feedback

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-09

### Added

#### Core Architecture
- **Extensible Redaction Provider Interfaces**: Comprehensive interface hierarchy for pluggable redaction strategies
  - `RedactionProvider`: Base interface for all redaction implementations
  - `PolicyAwareRedactionProvider`: Extended interface with policy integration capabilities
  - `LLMRedactionProvider`: Interface ready for future AI-powered redaction

#### Redaction Engines
- **RedactionEngine**: Enhanced base engine with improved configuration options
- **PolicyAwareRedactionEngine**: Policy-driven redaction with comprehensive rule validation
- **RedactionProviderFactory**: Factory pattern for easy provider instantiation and configuration

#### Redaction Modes
- **Comprehensive Mode Support**: Multiple redaction strategies for different use cases
  - `replace`: Replace with placeholder tokens
  - `mask`: Replace with mask characters (e.g., ****)
  - `remove`: Remove sensitive content entirely
  - `tokenize`: Reversible tokenization for data recovery
  - `hash`: One-way hashing for irreversible redaction
  - `encrypt`: Reversible encryption for secure data handling
  - `llm`: Context-aware AI redaction (interface ready)

#### Policy Integration
- **Rule Validation**: Comprehensive validation of policy rules and patterns
- **Conditional Redaction**: Context-based rule application with flexible conditions
- **Priority-based Processing**: Ordered rule evaluation for consistent results
- **Pattern Matching**: Advanced regex-based content detection

#### Multi-tenancy
- **Policy Management**: Redaction configurations with inheritance
- **PolicyStore Interface**: Pluggable persistence layer for redaction policies
- **InMemoryPolicyStore**: Development and testing implementation
- **Policy Caching**: Performance optimization with intelligent caching strategies

#### Configuration & Extensibility
- **Provider Configuration**: Flexible configuration system for all provider types
- **Custom Patterns**: Support for user-defined redaction patterns
- **TTL Management**: Configurable token expiration and cleanup
- **Statistics & Monitoring**: Comprehensive metrics and performance tracking

### Enhanced
- **Backward Compatibility**: Existing RedactionEngine API remains unchanged
- **Performance Optimizations**: Efficient processing with caching and optimized algorithms
- **Error Handling**: Robust error handling with detailed error messages and codes
- **Logging**: Comprehensive logging with structured output for debugging and monitoring

### Technical Improvements
- **Thread Safety**: All implementations are concurrent-safe with proper synchronization
- **Resource Management**: Proper cleanup and resource management patterns
- **Interface Design**: Clean separation of concerns with well-defined interfaces
- **Type Safety**: Strong typing throughout the codebase with comprehensive validation

### Developer Experience
- **Factory Pattern**: Easy provider creation and configuration
- **Configuration-driven**: Runtime provider selection and configuration
- **Comprehensive Documentation**: Detailed documentation and examples
- **Testing Support**: Comprehensive test coverage and testing utilities

### Future-ready Features
- **LLM Integration**: Interface and architecture ready for AI-powered redaction
- **Database Persistence**: Interface ready for production database backends
- **Advanced Compliance**: Framework ready for regulatory compliance features
- **Streaming Support**: Architecture ready for large content streaming

## [Unreleased]

### Planned
- LLM-based redaction providers (OpenAI, Anthropic, Ollama)
- Database-backed policy storage (PostgreSQL, MongoDB)
- Advanced compliance framework templates
- Performance optimizations for large content processing
- Streaming redaction capabilities
- Enhanced audit and reporting features

---

## Migration Guide

### From Previous Versions

This is the first major release with the new architecture. For users of the basic RedactionEngine:

#### No Breaking Changes
```go
// Existing code continues to work unchanged
engine := redaction.NewRedactionEngine()
result := engine.RedactText("sensitive text")
```

#### New Capabilities
```go
// Use the factory for enhanced features
factory := redaction.NewRedactionProviderFactory()

// Create policy-aware provider
provider, err := factory.CreatePolicyAwareProvider(&redaction.ProviderConfig{
    Type: redaction.ProviderTypePolicyAware,
    MaxTextLength: 1024 * 1024,
    DefaultTTL: 24 * time.Hour,
})

// Create policy-aware provider
policyProvider, err := factory.CreatePolicyAwareProvider(&redaction.ProviderConfig{
    Type: redaction.ProviderTypePolicyAware,
})
```

## Support

- **Documentation**: See README.md for comprehensive usage examples
- **Issues**: Report bugs and feature requests on GitHub
- **Discussions**: Join community discussions for questions and feedback
