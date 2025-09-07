package redaction

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"regexp"
	"sync"
	"time"
)

// RedactionType represents the type of sensitive data
type RedactionType string

const (
	TypeEmail      RedactionType = "email"
	TypePhone      RedactionType = "phone"
	TypeCreditCard RedactionType = "credit_card"
	TypeSSN        RedactionType = "ssn"
	TypeAddress    RedactionType = "address"
	TypeName       RedactionType = "name"
	TypeIPAddress  RedactionType = "ip_address"
	TypeDate       RedactionType = "date"
	TypeTime       RedactionType = "time"
	TypeLink       RedactionType = "link"
	TypeZipCode    RedactionType = "zip_code"
	TypePoBox      RedactionType = "po_box"
	TypeBTCAddress RedactionType = "btc_address"
	TypeMD5Hex     RedactionType = "md5_hex"
	TypeSHA1Hex    RedactionType = "sha1_hex"
	TypeSHA256Hex  RedactionType = "sha256_hex"
	TypeGUID       RedactionType = "guid"
	TypeISBN       RedactionType = "isbn"
	TypeMACAddress RedactionType = "mac_address"
	TypeIBAN       RedactionType = "iban"
	TypeGitRepo    RedactionType = "git_repo"
	TypeCustom     RedactionType = "custom"
)

// RedactionResult represents the result of a redaction operation
type RedactionResult struct {
	OriginalText string      `json:"original_text"`
	RedactedText string      `json:"redacted_text"`
	Redactions   []Redaction `json:"redactions"`
	Token        string      `json:"token,omitempty"`
	Timestamp    time.Time   `json:"timestamp"`
}

// Redaction represents a single redaction operation
type Redaction struct {
	Type        RedactionType `json:"type"`
	Start       int           `json:"start"`
	End         int           `json:"end"`
	Original    string        `json:"original"`
	Replacement string        `json:"replacement"`
	Confidence  float64       `json:"confidence"`
	Context     string        `json:"context,omitempty"`
}

// RedactionEngine handles PII/PHI detection and redaction
// Implements RedactionProvider interface
type RedactionEngine struct {
	patterns map[RedactionType]*regexp.Regexp
	tokens   map[string]TokenInfo
	mutex    sync.RWMutex

	// Configuration
	maxTextLength int
	defaultTTL    time.Duration
}

// TokenInfo stores information about a redaction token
type TokenInfo struct {
	OriginalText  string        `json:"original_text"`
	RedactionType RedactionType `json:"redaction_type"`
	Created       time.Time     `json:"created"`
	Expires       time.Time     `json:"expires"`
}

// NewRedactionEngine creates a new redaction engine
func NewRedactionEngine() *RedactionEngine {
	engine := &RedactionEngine{
		patterns:      make(map[RedactionType]*regexp.Regexp),
		tokens:        make(map[string]TokenInfo),
		maxTextLength: 1024 * 1024, // 1MB default
		defaultTTL:    24 * time.Hour,
	}

	// Initialize default patterns
	engine.initDefaultPatterns()

	return engine
}

// NewRedactionEngineWithConfig creates a new redaction engine with custom configuration
func NewRedactionEngineWithConfig(maxTextLength int, defaultTTL time.Duration) *RedactionEngine {
	engine := &RedactionEngine{
		patterns:      make(map[RedactionType]*regexp.Regexp),
		tokens:        make(map[string]TokenInfo),
		maxTextLength: maxTextLength,
		defaultTTL:    defaultTTL,
	}

	// Initialize default patterns
	engine.initDefaultPatterns()

	return engine
}

// initDefaultPatterns initializes the default detection patterns
func (re *RedactionEngine) initDefaultPatterns() {
	// Email patterns
	re.patterns[TypeEmail] = regexp.MustCompile(`(?i)\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`)

	// Phone number patterns (US format) - with word boundaries to avoid GUID conflicts
	re.patterns[TypePhone] = regexp.MustCompile(`\b(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})\b`)

	// Credit card patterns - simplified pattern for testing
	re.patterns[TypeCreditCard] = regexp.MustCompile(`\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b`)

	// SSN patterns (US format) - more specific to avoid ZIP+4 conflicts
	re.patterns[TypeSSN] = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)

	// IP address patterns (IPv4)
	re.patterns[TypeIPAddress] = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

	// Date patterns (various formats)
	re.patterns[TypeDate] = regexp.MustCompile(`\b(?:0?[1-9]|1[012])[-/](?:0?[1-9]|[12][0-9]|3[01])[-/](?:19|20)\d{2}\b`)

	// Time patterns (24-hour format)
	re.patterns[TypeTime] = regexp.MustCompile(`\b(?:[01]?[0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9])?\s*(?:AM|PM|am|pm)?\b`)

	// Link patterns (URLs)
	re.patterns[TypeLink] = regexp.MustCompile(`\b(?:https?://|www\.)[^\s<>"{}|\\^` + "`" + `\[\]]+`)

	// ZIP code patterns (US format) - more specific to avoid SSN conflicts
	re.patterns[TypeZipCode] = regexp.MustCompile(`\b\d{5}-\d{4}\b`)

	// PO Box patterns
	re.patterns[TypePoBox] = regexp.MustCompile(`\b(?:P\.?O\.?\s*Box|Post\s*Office\s*Box|PO\s*Box)\s+\d+\b`)

	// Bitcoin address patterns
	re.patterns[TypeBTCAddress] = regexp.MustCompile(`\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`)

	// MD5 hash patterns
	re.patterns[TypeMD5Hex] = regexp.MustCompile(`\b[a-fA-F0-9]{32}\b`)

	// SHA1 hash patterns
	re.patterns[TypeSHA1Hex] = regexp.MustCompile(`\b[a-fA-F0-9]{40}\b`)

	// SHA256 hash patterns
	re.patterns[TypeSHA256Hex] = regexp.MustCompile(`\b[a-fA-F0-9]{64}\b`)

	// GUID/UUID patterns
	re.patterns[TypeGUID] = regexp.MustCompile(`\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b`)

	// ISBN patterns (10 or 13 digits)
	re.patterns[TypeISBN] = regexp.MustCompile(`\b(?:ISBN(?:-1[03])?\s*:?\s*)?[0-9X]{10}(?:[-\s][0-9X]{3}){3}\b`)

	// MAC address patterns
	re.patterns[TypeMACAddress] = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b`)

	// IBAN patterns (basic format)
	re.patterns[TypeIBAN] = regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b`)

	// Git repository patterns
	re.patterns[TypeGitRepo] = regexp.MustCompile(`\b(?:git@|https?://)(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[a-zA-Z0-9_.-]+)*\.git\b`)
}

// AddCustomPattern adds a custom detection pattern
func (re *RedactionEngine) AddCustomPattern(name string, pattern string) error {
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}

	re.patterns[RedactionType(name)] = compiled
	return nil
}

// restoreTextInternal restores redacted text using a token (internal method)
func (re *RedactionEngine) restoreTextInternal(token string) (string, error) {
	re.mutex.RLock()
	tokenInfo, exists := re.tokens[token]
	re.mutex.RUnlock()

	if !exists {
		return "", fmt.Errorf("invalid or expired token")
	}

	return tokenInfo.OriginalText, nil
}

// generateReplacement generates a replacement string for redacted content
func (re *RedactionEngine) generateReplacement(redactionType RedactionType, original string) string {
	switch redactionType {
	case TypeEmail:
		return "[EMAIL_REDACTED]"
	case TypePhone:
		return "[PHONE_REDACTED]"
	case TypeCreditCard:
		return "[CREDIT_CARD_REDACTED]"
	case TypeSSN:
		return "[SSN_REDACTED]"
	case TypeAddress:
		return "[ADDRESS_REDACTED]"
	case TypeName:
		return "[NAME_REDACTED]"
	case TypeIPAddress:
		return "[IP_ADDRESS_REDACTED]"
	case TypeDate:
		return "[DATE_REDACTED]"
	case TypeTime:
		return "[TIME_REDACTED]"
	case TypeLink:
		return "[LINK_REDACTED]"
	case TypeZipCode:
		return "[ZIP_CODE_REDACTED]"
	case TypePoBox:
		return "[PO_BOX_REDACTED]"
	case TypeBTCAddress:
		return "[BTC_ADDRESS_REDACTED]"
	case TypeMD5Hex:
		return "[MD5_HASH_REDACTED]"
	case TypeSHA1Hex:
		return "[SHA1_HASH_REDACTED]"
	case TypeSHA256Hex:
		return "[SHA256_HASH_REDACTED]"
	case TypeGUID:
		return "[GUID_REDACTED]"
	case TypeISBN:
		return "[ISBN_REDACTED]"
	case TypeMACAddress:
		return "[MAC_ADDRESS_REDACTED]"
	case TypeIBAN:
		return "[IBAN_REDACTED]"
	case TypeGitRepo:
		return "[GIT_REPO_REDACTED]"
	default:
		return "[REDACTED]"
	}
}

// extractContext extracts context around the redacted content
func (re *RedactionEngine) extractContext(text string, start, end int) string {
	contextStart := max(0, start-20)
	contextEnd := min(len(text), end+20)
	return text[contextStart:contextEnd]
}

// generateToken generates a unique token for reversible redaction
func (re *RedactionEngine) generateToken(result *RedactionResult) string {
	// Generate random token
	bytes := make([]byte, 16)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)

	// Store token information
	tokenInfo := TokenInfo{
		OriginalText:  result.OriginalText,
		RedactionType: result.Redactions[0].Type, // Store first redaction type
		Created:       time.Now(),
		Expires:       time.Now().Add(24 * time.Hour), // Token expires in 24 hours
	}

	re.mutex.Lock()
	re.tokens[token] = tokenInfo
	re.mutex.Unlock()

	return token
}

// GetRedactionStats returns statistics about redaction operations
func (re *RedactionEngine) GetRedactionStats() map[string]interface{} {
	re.mutex.RLock()
	defer re.mutex.RUnlock()

	stats := make(map[string]interface{})
	stats["total_tokens"] = len(re.tokens)
	stats["active_patterns"] = len(re.patterns)

	// Count tokens by type
	typeCounts := make(map[RedactionType]int)
	for _, tokenInfo := range re.tokens {
		typeCounts[tokenInfo.RedactionType]++
	}
	stats["tokens_by_type"] = typeCounts

	return stats
}

// CleanupExpiredTokens removes expired tokens
func (re *RedactionEngine) CleanupExpiredTokens() int {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	now := time.Now()
	removed := 0

	for token, tokenInfo := range re.tokens {
		if now.After(tokenInfo.Expires) {
			delete(re.tokens, token)
			removed++
		}
	}

	return removed
}

// RotateKeys rotates the encryption keys (placeholder implementation)
func (re *RedactionEngine) RotateKeys() error {
	re.mutex.Lock()
	defer re.mutex.Unlock()

	// In a real implementation, this would:
	// 1. Generate new encryption keys
	// 2. Re-encrypt existing tokens with new keys
	// 3. Update key version
	// For now, this is a placeholder that simulates key rotation

	return nil
}

// Helper functions
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Interface implementation methods

// RedactText implements RedactionProvider interface
func (re *RedactionEngine) RedactText(ctx context.Context, request *RedactionRequest) (*RedactionResult, error) {
	if request == nil {
		return nil, fmt.Errorf("redaction request cannot be nil")
	}

	// Validate text length
	if len(request.Text) > re.maxTextLength {
		return nil, fmt.Errorf("text length exceeds maximum allowed size: %d", re.maxTextLength)
	}

	// Use existing redaction logic but with enhanced request handling
	result := re.redactTextInternal(request.Text)

	// Apply custom patterns if provided
	if len(request.CustomPatterns) > 0 {
		result = re.applyCustomPatterns(result, request.CustomPatterns)
	}

	// Handle TTL for tokens
	if request.Reversible && len(result.Redactions) > 0 {
		ttl := request.TTL
		if ttl == 0 {
			ttl = re.defaultTTL
		}
		result.Token = re.generateTokenWithTTL(result, ttl)
	}

	return result, nil
}

// RestoreText implements RedactionProvider interface
func (re *RedactionEngine) RestoreText(ctx context.Context, token string) (*RestoreResult, error) {
	originalText, err := re.restoreTextInternal(token)
	if err != nil {
		return nil, err
	}

	return &RestoreResult{
		OriginalText: originalText,
		Token:        token,
		RestoredAt:   time.Now(),
		Metadata:     map[string]interface{}{"provider": "RedactionEngine"},
	}, nil
}

// GetCapabilities implements RedactionProvider interface
func (re *RedactionEngine) GetCapabilities() *ProviderCapabilities {
	supportedTypes := make([]RedactionType, 0, len(re.patterns))
	for redactionType := range re.patterns {
		supportedTypes = append(supportedTypes, redactionType)
	}

	return &ProviderCapabilities{
		Name:                "RedactionEngine",
		Version:             "1.0.0",
		SupportedTypes:      supportedTypes,
		SupportedModes:      []RedactionMode{ModeReplace, ModeMask, ModeRemove, ModeTokenize},
		SupportsReversible:  true,
		SupportsCustom:      true,
		SupportsLLM:         false,
		SupportsPolicies:    false,
		SupportsMultiTenant: false,
		MaxTextLength:       re.maxTextLength,
		Features: map[string]bool{
			"pattern_matching":   true,
			"token_restoration":  true,
			"custom_patterns":    true,
			"context_extraction": true,
		},
	}
}

// GetStats implements RedactionProvider interface
func (re *RedactionEngine) GetStats() map[string]interface{} {
	return re.GetRedactionStats()
}

// Cleanup implements RedactionProvider interface
func (re *RedactionEngine) Cleanup() error {
	removed := re.CleanupExpiredTokens()
	if removed > 0 {
		// Log cleanup if needed
	}
	return nil
}

// Helper methods for interface implementation

// redactTextInternal performs the core redaction logic (renamed from RedactText)
func (re *RedactionEngine) redactTextInternal(text string) *RedactionResult {
	result := &RedactionResult{
		OriginalText: text,
		RedactedText: text,
		Redactions:   []Redaction{},
		Timestamp:    time.Now(),
	}

	// Process each redaction type
	for redactionType, pattern := range re.patterns {
		matches := pattern.FindAllStringIndex(text, -1)

		for _, match := range matches {
			start, end := match[0], match[1]
			original := text[start:end]

			// Create redaction
			redaction := Redaction{
				Type:        redactionType,
				Start:       start,
				End:         end,
				Original:    original,
				Replacement: re.generateReplacement(redactionType, original),
				Confidence:  0.95, // High confidence for regex matches
				Context:     re.extractContext(text, start, end),
			}

			result.Redactions = append(result.Redactions, redaction)
		}
	}

	// Apply redactions in reverse order to maintain indices
	offset := 0
	for i := len(result.Redactions) - 1; i >= 0; i-- {
		redaction := result.Redactions[i]
		adjustedStart := redaction.Start + offset
		adjustedEnd := redaction.End + offset

		if adjustedStart >= 0 && adjustedEnd <= len(result.RedactedText) {
			result.RedactedText = result.RedactedText[:adjustedStart] +
				redaction.Replacement +
				result.RedactedText[adjustedEnd:]

			// Update offset for next redaction
			offset += len(redaction.Replacement) - (redaction.End - redaction.Start)
		}
	}

	return result
}

// applyCustomPatterns applies custom patterns to the redaction result
func (re *RedactionEngine) applyCustomPatterns(result *RedactionResult, patterns []CustomPattern) *RedactionResult {
	for _, pattern := range patterns {
		compiled, err := regexp.Compile(pattern.Pattern)
		if err != nil {
			continue // Skip invalid patterns
		}

		matches := compiled.FindAllStringIndex(result.RedactedText, -1)
		for _, match := range matches {
			start, end := match[0], match[1]
			original := result.RedactedText[start:end]

			replacement := pattern.Replacement
			if replacement == "" {
				replacement = "[CUSTOM_REDACTED]"
			}

			redaction := Redaction{
				Type:        TypeCustom,
				Start:       start,
				End:         end,
				Original:    original,
				Replacement: replacement,
				Confidence:  pattern.Confidence,
				Context:     re.extractContext(result.RedactedText, start, end),
			}

			result.Redactions = append(result.Redactions, redaction)
		}
	}

	return result
}

// generateTokenWithTTL generates a token with custom TTL
func (re *RedactionEngine) generateTokenWithTTL(result *RedactionResult, ttl time.Duration) string {
	// Generate random token
	bytes := make([]byte, 16)
	rand.Read(bytes)
	token := hex.EncodeToString(bytes)

	// Store token information with custom TTL
	tokenInfo := TokenInfo{
		OriginalText:  result.OriginalText,
		RedactionType: result.Redactions[0].Type, // Store first redaction type
		Created:       time.Now(),
		Expires:       time.Now().Add(ttl),
	}

	re.mutex.Lock()
	re.tokens[token] = tokenInfo
	re.mutex.Unlock()

	return token
}
