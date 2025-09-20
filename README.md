# CensGate Redact

[![Go Reference](https://pkg.go.dev/badge/github.com/censgate/redact.svg)](https://pkg.go.dev/github.com/censgate/redact)
[![Go Report Card](https://goreportcard.com/badge/github.com/censgate/redact)](https://goreportcard.com/report/github.com/censgate/redact)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A powerful, extensible redaction library for Go that provides comprehensive PII/PHI detection and redaction capabilities with policy-aware support.

## Features

### 🔧 Extensible Architecture
- **Pluggable Providers**: Support for different redaction strategies
- **Factory Pattern**: Easy provider instantiation and configuration
- **Interface-driven**: Clean separation of concerns with well-defined interfaces

### 🛡️ Comprehensive Redaction
- **Multiple Modes**: Replace, mask, remove, tokenize, hash, encrypt, and LLM-ready
- **Pattern Detection**: Advanced regex-based detection for various PII/PHI types
- **Custom Patterns**: Support for user-defined redaction patterns
- **Reversible Redaction**: Token-based restoration for authorized access

### 📋 Policy Integration
- **Rule Validation**: Comprehensive validation of policy rules and patterns
- **Conditional Redaction**: Context-based rule application
- **Priority Processing**: Ordered rule evaluation for consistent results


### 🚀 Performance & Reliability
- **Thread-safe**: Concurrent-safe implementations
- **Caching**: Intelligent caching for performance optimization
- **Resource Management**: Proper cleanup and resource handling
- **Overlap Resolution**: Advanced conflict resolution for overlapping redactions
- **Comprehensive Testing**: Extensive test coverage for edge cases and complex scenarios

## Quick Start

### Installation

```bash
go get github.com/censgate/redact@v0.1.0
```

### Basic Usage

```go
package main

import (
    "fmt"
    "log"
    
    "github.com/censgate/redact/pkg/redaction"
)

func main() {
    // Create a basic redaction engine
    engine := redaction.NewRedactionEngine()
    
    // Redact text
    text := "My email is john.doe@example.com and my SSN is 123-45-6789"
    result := engine.RedactText(text)
    
    fmt.Printf("Original: %s\n", result.OriginalText)
    fmt.Printf("Redacted: %s\n", result.RedactedText)
    fmt.Printf("Redactions: %d\n", len(result.Redactions))
    
    // Restore original text (if token-based redaction was used)
    if result.Token != "" {
        original, err := engine.RestoreText(result.Token)
        if err == nil {
            fmt.Printf("Restored: %s\n", original)
        }
    }
}
```

### Using the Factory Pattern

```go
package main

import (
    "context"
    "fmt"
    "time"
    
    "github.com/censgate/redact/pkg/redaction"
)

func main() {
    // Create factory
    factory := redaction.NewRedactionProviderFactory()
    
    // Create policy-aware provider
    provider, err := factory.CreatePolicyAwareProvider(&redaction.ProviderConfig{
        Type:          redaction.ProviderTypePolicyAware,
        MaxTextLength: 1024 * 1024, // 1MB
        DefaultTTL:    24 * time.Hour,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Create redaction request
    request := &redaction.RedactionRequest{
        Text:       "Contact us at support@company.com",
        Mode:       redaction.ModeReplace,
        Reversible: true,
    }
    
    // Perform redaction
    result, err := provider.RedactText(context.Background(), request)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Redacted: %s\n", result.RedactedText)
}
```

### Policy-aware Usage

```go
package main

import (
    "context"
    "log"
    
    "github.com/censgate/redact/pkg/redaction"
)

func main() {
    // Create policy-aware provider
    factory := redaction.NewProviderFactory()
    provider, err := factory.CreatePolicyAwareProvider(&redaction.ProviderConfig{
        Type:        redaction.ProviderTypePolicyAware,
    })
    if err != nil {
        log.Fatal(err)
    }
    
    // Create a basic redaction request
    request := &redaction.Request{
        DefaultMode: redaction.ModeHash,
        Rules: []redaction.PolicyRule{
            {
                Name:     "PHI_EMAIL",
                Patterns: []string{`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`},
                Fields:   []string{"content"},
                Mode:     redaction.ModeEncrypt,
                Enabled:  true,
            },
        },
        Text: "Patient email: patient@hospital.com",
        Mode: redaction.ModeReplace,
    }
    
    // Perform policy-aware redaction
    result, err := provider.RedactText(context.Background(), request)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Policy-redacted: %s\n", result.RedactedText)
}
```

## Supported Redaction Types

### Global Patterns
- **Email addresses**: `john@example.com`
- **Phone numbers**: `(555) 123-4567`, `555-123-4567`
- **Social Security Numbers**: `123-45-6789`
- **Credit card numbers**: `4111-1111-1111-1111`
- **IP addresses**: `192.168.1.1`
- **URLs**: `https://example.com`
- **Dates**: `12/25/2023`, `2023-12-25`
- **MAC addresses**: `00:1B:44:11:3A:B7`
- **Bitcoin addresses**: `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- **Hash values**: MD5, SHA1, SHA256
- **GUIDs/UUIDs**: `550e8400-e29b-41d4-a716-446655440000`
- **Custom patterns**: User-defined regex patterns

### UK-Specific Patterns
- **National Insurance Numbers**: `AB123456C`
- **NHS Numbers**: `123 456 7890`, `NHS: 1234567890`
- **UK Postcodes**: `SW1A 1AA`, `M1 1AA`
- **UK Phone Numbers**: `+44 20 1234 5678`
- **UK Mobile Numbers**: `07123456789`
- **UK Sort Codes**: `12-34-56`
- **UK IBAN**: `GB82 WEST 1234 5698 7654 32`
- **UK Company Numbers**: `12345678`
- **UK Driving License**: `MORGA657054SM9IJ`
- **UK Passport Numbers**: `123456789`

## Redaction Modes

| Mode | Description | Reversible | Example |
|------|-------------|------------|---------|
| `replace` | Replace with placeholder | No | `[EMAIL_REDACTED]` |
| `mask` | Replace with mask characters | No | `****@******.***` |
| `remove` | Remove entirely | No | `` |
| `tokenize` | Replace with reversible token | Yes | `[TOKEN_ABC123]` |
| `hash` | Replace with hash | No | `[HASH_SHA256]` |
| `encrypt` | Replace with encrypted value | Yes | `[ENCRYPTED_DATA]` |
| `llm` | AI-powered context-aware | Configurable | `[AI_REDACTED]` |

## Provider Types

### Basic Provider
- Standard pattern-based redaction
- No policy support
- Single instance

### Policy-Aware Provider
- Policy-driven redaction rules
- Rule validation and conditional logic
- Priority-based processing

- Policy inheritance

### LLM Provider (Coming Soon)
- AI-powered redaction
- Context-aware processing
- Configurable AI models

## Configuration

### Provider Configuration

```go
config := &redaction.ProviderConfig{
    Type:          redaction.ProviderTypeBasic,
    MaxTextLength: 2048 * 1024, // 2MB
    DefaultTTL:    48 * time.Hour,
    LLMConfig: &redaction.LLMConfig{
        Provider:    "openai",
        Model:       "gpt-4",
        Temperature: 0.1,
        MaxTokens:   1000,
    },
}
```

### Policy Rules

```go
rule := redaction.PolicyRule{
    Name:     "SENSITIVE_DATA",
    Patterns: []string{
        `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`, // Email
        `\b\d{3}-\d{2}-\d{4}\b`,                                 // SSN
    },
    Fields:   []string{"content", "description"},
    Mode:     redaction.ModeEncrypt,
    Priority: 100,
    Enabled:  true,
    Conditions: []redaction.PolicyCondition{
        {
            Field:    "user_role",
            Operator: "ne",
            Value:    "admin",
        },
    },
}
```

## Advanced Features

### Custom Policy Store

```go
type CustomPolicyStore struct {
    db *sql.DB
}

// Custom policy store implementation methods would go here
// for storing and retrieving redaction policies
```

### Statistics and Monitoring

```go
stats := provider.GetStats()
fmt.Printf("Total redactions: %v\n", stats["total_redactions"])
fmt.Printf("Active patterns: %v\n", stats["active_patterns"])

capabilities := provider.GetCapabilities()
fmt.Printf("Provider: %s v%s\n", capabilities.Name, capabilities.Version)
fmt.Printf("Supports policies: %v\n", capabilities.SupportsPolicies)
```

## CLI Tool

The package includes a CLI tool for interactive redaction:

```bash
# Install CLI
go install github.com/censgate/redact/cmd/redactctl@latest

# Basic usage
redactctl redact "My email is john@example.com"

# With custom patterns
redactctl redact --pattern "ID-\d{6}" --mode mask "User ID-123456"

# Interactive mode
redactctl interactive
```

## Recent Improvements

### Bug Fixes & Enhancements

#### ✅ **Overlapping Redactions Resolution (v0.1.1)**
Fixed a critical bug in the `resolveOverlappingRedactions` function that could leave unresolved overlaps when a redaction conflicted with multiple existing redactions.

**What was fixed:**
- Removed premature `break` statement that prevented checking all overlaps
- Implemented comprehensive multi-overlap evaluation logic
- Added proper conflict resolution based on length and type priority
- Enhanced test coverage with complex overlapping scenarios

**Impact:**
- Ensures accurate text replacement in all scenarios
- Prevents data leakage from unresolved overlapping patterns
- Improves reliability for complex documents with multiple PII types

**Example of improved behavior:**
```go
// Before: Could miss overlaps, leading to incorrect redaction
text := "Contact: john@company.com, Phone: +44 20 1234 5678, ID: AB123456C"

// After: All overlaps properly resolved with correct priority
// UK-specific patterns take precedence over generic ones
// Longer matches win over shorter ones
result := engine.RedactText(context.Background(), &redaction.Request{Text: text})
// Result: "Contact: [EMAIL_REDACTED], Phone: [UK_PHONE_NUMBER_REDACTED], ID: [UK_NATIONAL_INSURANCE_REDACTED]"
```

#### 🔧 **Enhanced UK Pattern Support**
- Added comprehensive UK-specific redaction patterns
- Improved pattern priority system for regional compliance
- Enhanced test coverage for UK GDPR compliance scenarios

#### 📊 **Improved Testing Framework**
- Added comprehensive test cases for overlapping redaction scenarios
- Enhanced edge case coverage for complex pattern conflicts
- Improved validation for multi-pattern documents

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/censgate/redact.git
cd redact

# Install dependencies
go mod download

# Run tests
go test ./...

# Build CLI
go build -o redactctl ./cmd/redactctl
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security

For security concerns, please see [SECURITY.md](SECURITY.md).

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a detailed history of changes.

## Support

- **Documentation**: [pkg.go.dev](https://pkg.go.dev/github.com/censgate/redact)
- **Issues**: [GitHub Issues](https://github.com/censgate/redact/issues)
- **Discussions**: [GitHub Discussions](https://github.com/censgate/redact/discussions)