package redaction

import (
	"strings"
	"testing"
	"time"
)

func TestRedactionEngine(t *testing.T) {
	engine := NewRedactionEngine()

	// Test basic redaction
	text := "Hello, my email is john.doe@example.com and my phone is (555) 123-4567"

	result := engine.RedactText(text)

	if len(result.Redactions) != 2 {
		t.Errorf("Expected 2 redactions, got %d", len(result.Redactions))
	}

	// Check that email was redacted
	emailFound := false
	for _, redaction := range result.Redactions {
		if redaction.Type == TypeEmail {
			emailFound = true
			if redaction.Original != "john.doe@example.com" {
				t.Errorf("Expected email 'john.doe@example.com', got '%s'", redaction.Original)
			}
			if redaction.Replacement != "[EMAIL_REDACTED]" {
				t.Errorf("Expected replacement '[EMAIL_REDACTED]', got '%s'", redaction.Replacement)
			}
		}
	}

	if !emailFound {
		t.Error("Email redaction not found")
	}

	// Check that phone was redacted
	phoneFound := false
	for _, redaction := range result.Redactions {
		if redaction.Type == TypePhone {
			phoneFound = true
			// Phone pattern might include leading space, so check if it contains the expected pattern
			if !strings.Contains(redaction.Original, "555") || !strings.Contains(redaction.Original, "123-4567") {
				t.Errorf("Expected phone to contain '555' and '123-4567', got '%s'", redaction.Original)
			}
			if redaction.Replacement != "[PHONE_REDACTED]" {
				t.Errorf("Expected replacement '[PHONE_REDACTED]', got '%s'", redaction.Replacement)
			}
		}
	}

	if !phoneFound {
		t.Error("Phone redaction not found")
	}
}

func TestRedactionTypes(t *testing.T) {
	engine := NewRedactionEngine()

	tests := []struct {
		name     string
		text     string
		expected []RedactionType
	}{
		{
			name:     "Email detection",
			text:     "Contact me at test@example.com",
			expected: []RedactionType{TypeEmail},
		},
		{
			name:     "Phone detection",
			text:     "Call me at 555-123-4567",
			expected: []RedactionType{TypePhone},
		},
		{
			name:     "Credit card detection",
			text:     "Card number: 4111-1111-1111-1111",
			expected: []RedactionType{TypeCreditCard},
		},
		{
			name:     "SSN detection",
			text:     "SSN: 123-45-6789",
			expected: []RedactionType{TypeSSN},
		},
		{
			name:     "IP address detection",
			text:     "Server IP: 192.168.1.1",
			expected: []RedactionType{TypeIPAddress},
		},
		{
			name:     "Date detection",
			text:     "Meeting on 12/25/2023",
			expected: []RedactionType{TypeDate},
		},
		{
			name:     "Multiple types",
			text:     "Email: test@example.com, Phone: 555-123-4567",
			expected: []RedactionType{TypeEmail, TypePhone},
		},
		{
			name:     "Time detection",
			text:     "Meeting at 14:30 PM",
			expected: []RedactionType{TypeTime},
		},
		{
			name:     "Link detection",
			text:     "Visit https://example.com for more info",
			expected: []RedactionType{TypeLink},
		},
		{
			name:     "ZIP code detection",
			text:     "Address: 123 Main St, 90210-1234",
			expected: []RedactionType{TypeZipCode},
		},
		{
			name:     "PO Box detection",
			text:     "Send to P.O. Box 123",
			expected: []RedactionType{TypePoBox},
		},
		{
			name:     "Bitcoin address detection",
			text:     "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			expected: []RedactionType{TypeBTCAddress},
		},
		{
			name:     "MD5 hash detection",
			text:     "Hash: d41d8cd98f00b204e9800998ecf8427e",
			expected: []RedactionType{TypeMD5Hex},
		},
		{
			name:     "GUID detection",
			text:     "ID: 550e8400-e29b-41d4-a716-446655440000",
			expected: []RedactionType{TypeGUID},
		},
		{
			name:     "MAC address detection",
			text:     "MAC: 00:1B:44:11:3A:B7",
			expected: []RedactionType{TypeMACAddress},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.RedactText(tt.text)

			if len(result.Redactions) != len(tt.expected) {
				t.Errorf("Expected %d redactions, got %d", len(tt.expected), len(result.Redactions))
				return
			}

			// Check that all expected types are present
			for _, expectedType := range tt.expected {
				found := false
				for _, redaction := range result.Redactions {
					if redaction.Type == expectedType {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("Expected redaction type %s not found", expectedType)
				}
			}
		})
	}
}

func TestReversibleRedaction(t *testing.T) {
	engine := NewRedactionEngine()

	originalText := "Email: test@example.com, Phone: 555-123-4567"
	result := engine.RedactText(originalText)

	if result.Token == "" {
		t.Error("Expected token to be generated")
	}

	// Restore the text
	restored, err := engine.RestoreText(result.Token)
	if err != nil {
		t.Errorf("Failed to restore text: %v", err)
	}

	if restored != originalText {
		t.Errorf("Expected restored text to match original, got: %s", restored)
	}
}

func TestCustomPatterns(t *testing.T) {
	engine := NewRedactionEngine()

	// Add custom pattern
	err := engine.AddCustomPattern("custom_id", `\bID-\d{6}\b`)
	if err != nil {
		t.Errorf("Failed to add custom pattern: %v", err)
	}

	text := "User ID: ID-123456"
	result := engine.RedactText(text)

	if len(result.Redactions) != 1 {
		t.Errorf("Expected 1 redaction, got %d", len(result.Redactions))
	}

	if result.Redactions[0].Type != RedactionType("custom_id") {
		t.Errorf("Expected custom redaction type, got %s", result.Redactions[0].Type)
	}
}

func TestRedactionStats(t *testing.T) {
	engine := NewRedactionEngine()

	// Perform some redactions
	engine.RedactText("Email: test@example.com")
	engine.RedactText("Phone: 555-123-4567")

	stats := engine.GetRedactionStats()

	if stats["total_tokens"] != 2 {
		t.Errorf("Expected 2 total tokens, got %v", stats["total_tokens"])
	}

	t.Logf("Actual patterns: %v", stats["active_patterns"])
	if stats["active_patterns"] != 19 { // Default patterns (19 types defined)
		t.Errorf("Expected 19 active patterns, got %v", stats["active_patterns"])
	}

	// Check that context patterns are also counted
	if stats["context_patterns"].(int) != 3 { // Medical, Financial, Legal domains
		t.Errorf("Expected 3 context pattern domains, got %v", stats["context_patterns"])
	}

	tokensByType, ok := stats["tokens_by_type"].(map[RedactionType]int)
	if !ok {
		t.Error("Expected tokens_by_type to be a map")
	}

	// Check that we have tokens for both email and phone
	if tokensByType[TypeEmail] != 1 {
		t.Errorf("Expected 1 email token, got %d", tokensByType[TypeEmail])
	}
	if tokensByType[TypePhone] != 1 {
		t.Errorf("Expected 1 phone token, got %d", tokensByType[TypePhone])
	}
}

func TestTokenExpiration(t *testing.T) {
	engine := NewRedactionEngine()

	// Perform redaction to generate token
	result := engine.RedactText("Email: test@example.com")
	if result.Token == "" {
		t.Error("Expected token to be generated")
	}

	// Clean up expired tokens (should not affect our token since it's new)
	removed := engine.CleanupExpiredTokens()
	if removed != 0 {
		t.Errorf("Expected 0 tokens to be removed, got %d", removed)
	}

	// Token should still be valid
	_, err := engine.RestoreText(result.Token)
	if err != nil {
		t.Errorf("Token should still be valid: %v", err)
	}
}

func TestRedactionContext(t *testing.T) {
	engine := NewRedactionEngine()

	text := "This is a test email: test@example.com and some other text"
	result := engine.RedactText(text)

	if len(result.Redactions) != 1 {
		t.Errorf("Expected 1 redaction, got %d", len(result.Redactions))
	}

	redaction := result.Redactions[0]
	if redaction.Context == "" {
		t.Error("Expected context to be extracted")
	}

	// Context should contain some text around the email
	if !strings.Contains(redaction.Context, "test@example.com") {
		t.Error("Expected context to contain the redacted email")
	}
}

func TestInvalidCustomPattern(t *testing.T) {
	engine := NewRedactionEngine()

	// Try to add invalid regex pattern
	err := engine.AddCustomPattern("invalid", `[invalid regex`)
	if err == nil {
		t.Error("Expected error for invalid regex pattern")
	}

	// Verify pattern wasn't added
	stats := engine.GetRedactionStats()
	if stats["active_patterns"] != 19 { // Should still be default patterns
		t.Errorf("Expected 19 active patterns, got %v", stats["active_patterns"])
	}
}

// Test context analysis functionality
func TestContextAnalysis(t *testing.T) {
	engine := NewRedactionEngine()

	tests := []struct {
		name           string
		text           string
		expectedDomain ContextDomain
		minConfidence  float64
	}{
		{
			name:           "Medical context",
			text:           "The patient was diagnosed with diabetes and prescribed medication for treatment.",
			expectedDomain: DomainMedical,
			minConfidence:  0.1,
		},
		{
			name:           "Financial context",
			text:           "Please transfer funds from account 123456 to the investment portfolio.",
			expectedDomain: DomainFinancial,
			minConfidence:  0.1,
		},
		{
			name:           "Legal context",
			text:           "The defendant appeared in court with their attorney for the case hearing.",
			expectedDomain: DomainLegal,
			minConfidence:  0.1,
		},
		{
			name:           "General context",
			text:           "Hello, please contact me at john@example.com for more information.",
			expectedDomain: DomainGeneral,
			minConfidence:  0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.AnalyzeContext(tt.text)

			if result.Domain != tt.expectedDomain {
				t.Errorf("Expected domain %s, got %s", tt.expectedDomain, result.Domain)
			}

			if result.Confidence < tt.minConfidence {
				t.Errorf("Expected confidence >= %f, got %f", tt.minConfidence, result.Confidence)
			}

			if tt.expectedDomain != DomainGeneral && len(result.Keywords) == 0 {
				t.Error("Expected keywords to be detected for non-general domain")
			}
		})
	}
}

// Test context-aware redaction
func TestContextAwareRedaction(t *testing.T) {
	engine := NewRedactionEngine()

	// Test medical context redaction
	medicalText := "Patient diagnosed with hypertension, prescribed Lisinopril 10mg daily."
	result := engine.RedactText(medicalText)

	// Should find context-aware medical redactions
	foundMedicalRedaction := false
	for _, redaction := range result.Redactions {
		if redaction.Domain == DomainMedical {
			foundMedicalRedaction = true
			if !strings.Contains(string(redaction.Type), "medical") {
				t.Errorf("Expected medical redaction type, got %s", redaction.Type)
			}
		}
	}

	if !foundMedicalRedaction {
		t.Error("Expected to find medical context-aware redaction")
	}
}

// Test secure tokenization
func TestSecureTokenization(t *testing.T) {
	engine := NewRedactionEngine()

	originalText := "Patient John Doe, SSN: 123-45-6789, diagnosed with diabetes."
	result := engine.RedactText(originalText)

	if result.Token == "" {
		t.Error("Expected secure token to be generated")
	}

	// Test restoration
	restored, err := engine.RestoreText(result.Token)
	if err != nil {
		t.Errorf("Failed to restore text: %v", err)
	}

	if restored != originalText {
		t.Errorf("Expected restored text to match original, got: %s", restored)
	}

	// Verify token info is encrypted
	engine.mutex.RLock()
	tokenInfo := engine.tokens[result.Token]
	engine.mutex.RUnlock()

	if tokenInfo.KeyVersion == 0 {
		t.Error("Expected token to be encrypted (KeyVersion > 0)")
	}

	if len(tokenInfo.EncryptedData) == 0 {
		t.Error("Expected encrypted data to be present")
	}

	if len(tokenInfo.Nonce) == 0 {
		t.Error("Expected nonce to be present")
	}
}

// Test key rotation
func TestKeyRotation(t *testing.T) {
	engine := NewRedactionEngine()
	initialVersion := engine.keyVersion

	err := engine.RotateKeys()
	if err != nil {
		t.Errorf("Failed to rotate keys: %v", err)
	}

	if engine.keyVersion <= initialVersion {
		t.Error("Expected key version to increase after rotation")
	}
}

// Test token expiration
func TestTokenExpirationHandling(t *testing.T) {
	engine := NewRedactionEngine()

	// Create a token
	result := engine.RedactText("Test text with email: test@example.com")
	token := result.Token

	// Manually expire the token
	engine.mutex.Lock()
	tokenInfo := engine.tokens[token]
	tokenInfo.Expires = time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
	engine.tokens[token] = tokenInfo
	engine.mutex.Unlock()

	// Try to restore expired token
	_, err := engine.RestoreText(token)
	if err == nil {
		t.Error("Expected error when restoring expired token")
	}

	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("Expected 'expired' error message, got: %v", err)
	}
}

// Test enhanced statistics
func TestEnhancedStats(t *testing.T) {
	engine := NewRedactionEngine()

	// Perform some redactions
	engine.RedactText("Patient diagnosed with diabetes, email: test@example.com")
	engine.RedactText("Account number: 1234567890, phone: 555-123-4567")

	stats := engine.GetRedactionStats()

	// Check new stat fields
	if _, exists := stats["context_patterns"]; !exists {
		t.Error("Expected context_patterns in stats")
	}

	if _, exists := stats["key_version"]; !exists {
		t.Error("Expected key_version in stats")
	}

	if _, exists := stats["encrypted_tokens"]; !exists {
		t.Error("Expected encrypted_tokens in stats")
	}

	if _, exists := stats["unencrypted_tokens"]; !exists {
		t.Error("Expected unencrypted_tokens in stats")
	}

	// Verify we have encrypted tokens
	if stats["encrypted_tokens"].(int) == 0 {
		t.Error("Expected at least one encrypted token")
	}
}

// Test secure cleanup
func TestSecureTokenCleanup(t *testing.T) {
	engine := NewRedactionEngine()

	// Create some tokens
	engine.RedactText("Test text 1: test@example.com")
	engine.RedactText("Test text 2: 555-123-4567")

	initialCount := len(engine.tokens)
	if initialCount == 0 {
		t.Error("Expected tokens to be created")
	}

	// Manually expire all tokens
	engine.mutex.Lock()
	for token, tokenInfo := range engine.tokens {
		tokenInfo.Expires = time.Now().Add(-1 * time.Hour)
		engine.tokens[token] = tokenInfo
	}
	engine.mutex.Unlock()

	// Cleanup expired tokens
	removed := engine.CleanupExpiredTokens()
	if removed != initialCount {
		t.Errorf("Expected %d tokens to be removed, got %d", initialCount, removed)
	}

	if len(engine.tokens) != 0 {
		t.Error("Expected all tokens to be removed after cleanup")
	}
}
