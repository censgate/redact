package redaction

import (
	"context"
	"strings"
	"testing"
)

func TestRedactionEngine(t *testing.T) {
	engine := NewEngine()

	// Test basic redaction
	text := "Hello, my email is john.doe@example.com and my phone is (555) 123-4567"

	result, err := engine.RedactText(context.Background(), &Request{
		Text: text,
		Mode: ModeReplace,
	})
	if err != nil {
		t.Fatalf("RedactText failed: %v", err)
	}

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

func TestTypes(t *testing.T) {
	engine := NewEngine()

	tests := []struct {
		name     string
		text     string
		expected []Type
	}{
		{
			name:     "Email detection",
			text:     "Contact me at test@example.com",
			expected: []Type{TypeEmail},
		},
		{
			name:     "Phone detection",
			text:     "Call me at 555-123-4567",
			expected: []Type{TypePhone},
		},
		{
			name:     "Credit card detection",
			text:     "Card number: 4111-1111-1111-1111",
			expected: []Type{TypeCreditCard},
		},
		{
			name:     "SSN detection",
			text:     "SSN: 123-45-6789",
			expected: []Type{TypeSSN},
		},
		{
			name:     "IP address detection",
			text:     "Server IP: 192.168.1.1",
			expected: []Type{TypeIPAddress},
		},
		{
			name:     "Date detection",
			text:     "Meeting on 12/25/2023",
			expected: []Type{TypeDate},
		},
		{
			name:     "Multiple types",
			text:     "Email: test@example.com, Phone: 555-123-4567",
			expected: []Type{TypeEmail, TypePhone},
		},
		{
			name:     "Time detection",
			text:     "Meeting at 14:30 PM",
			expected: []Type{TypeTime},
		},
		{
			name:     "Link detection",
			text:     "Visit https://example.com for more info",
			expected: []Type{TypeLink},
		},
		{
			name:     "ZIP code detection",
			text:     "Address: 123 Main St, 12345-6789",
			expected: []Type{TypeZipCode},
		},
		{
			name:     "PO Box detection",
			text:     "Send to P.O. Box 123",
			expected: []Type{TypePoBox},
		},
		{
			name:     "Bitcoin address detection",
			text:     "BTC: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			expected: []Type{TypeBTCAddress},
		},
		{
			name:     "MD5 hash detection",
			text:     "Hash: d41d8cd98f00b204e9800998ecf8427e",
			expected: []Type{TypeMD5Hex},
		},
		{
			name:     "GUID detection",
			text:     "ID: 550e8400-e29b-41d4-a716-446655440000",
			expected: []Type{TypeGUID},
		},
		{
			name:     "MAC address detection",
			text:     "MAC: 00:1B:44:11:3A:B7",
			expected: []Type{TypeMACAddress},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.RedactText(context.Background(), &Request{
				Text: tt.text,
				Mode: ModeReplace,
			})
			if err != nil {
				t.Fatalf("RedactText failed: %v", err)
			}

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
	engine := NewEngine()

	originalText := "Email: test@example.com, Phone: 555-123-4567"
	result, err := engine.RedactText(context.Background(), &Request{
		Text:       originalText,
		Mode:       ModeReplace,
		Reversible: true,
	})
	if err != nil {
		t.Fatalf("RedactText failed: %v", err)
	}

	if result.Token == "" {
		t.Error("Expected token to be generated")
	}

	// Restore the text
	restoreResult, err := engine.RestoreText(context.Background(), result.Token)
	if err != nil {
		t.Errorf("Failed to restore text: %v", err)
	}

	if restoreResult.OriginalText != originalText {
		t.Errorf("Expected restored text to match original, got: %s", restoreResult.OriginalText)
	}
}

func TestCustomPatterns(t *testing.T) {
	engine := NewEngine()

	// Add custom pattern
	err := engine.AddCustomPattern("custom_id", `\bID-\d{6}\b`)
	if err != nil {
		t.Errorf("Failed to add custom pattern: %v", err)
	}

	text := "User ID: ID-123456"
	result, err := engine.RedactText(context.Background(), &Request{
		Text: text,
		Mode: ModeReplace,
		CustomPatterns: []CustomPattern{
			{
				Name:        "custom_id",
				Pattern:     `\bID-\d{6}\b`,
				Replacement: "[CUSTOM_ID_REDACTED]",
			},
		},
	})
	if err != nil {
		t.Fatalf("RedactText failed: %v", err)
	}

	if len(result.Redactions) != 1 {
		t.Errorf("Expected 1 redaction, got %d", len(result.Redactions))
	}

	if result.Redactions[0].Type != Type("custom_id") {
		t.Errorf("Expected custom redaction type, got %s", result.Redactions[0].Type)
	}
}

func TestRedactionStats(t *testing.T) {
	engine := NewEngine()

	// Perform some redactions
	_, _ = engine.RedactText(context.Background(), &Request{
		Text:       "Email: test@example.com",
		Mode:       ModeReplace,
		Reversible: true,
	})
	_, _ = engine.RedactText(context.Background(), &Request{
		Text:       "Phone: 555-123-4567",
		Mode:       ModeReplace,
		Reversible: true,
	})

	stats := engine.GetRedactionStats()

	if stats["total_tokens"] != 2 {
		t.Errorf("Expected 2 total tokens, got %v", stats["total_tokens"])
	}

	t.Logf("Actual patterns: %v", stats["active_patterns"])
	if stats["active_patterns"] != 19 { // Default patterns (19 types initialized)
		t.Errorf("Expected 19 active patterns, got %v", stats["active_patterns"])
	}

	tokensByType, ok := stats["tokens_by_type"].(map[Type]int)
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
	engine := NewEngine()

	// Perform redaction to generate token
	result, err := engine.RedactText(context.Background(), &Request{
		Text:       "Email: test@example.com",
		Mode:       ModeReplace,
		Reversible: true,
	})
	if err != nil {
		t.Fatalf("RedactText failed: %v", err)
	}
	if result.Token == "" {
		t.Error("Expected token to be generated")
	}

	// Clean up expired tokens (should not affect our token since it's new)
	removed := engine.CleanupExpiredTokens()
	if removed != 0 {
		t.Errorf("Expected 0 tokens to be removed, got %d", removed)
	}

	// Token should still be valid
	_, err = engine.RestoreText(context.Background(), result.Token)
	if err != nil {
		t.Errorf("Token should still be valid: %v", err)
	}
}

func TestRedactionContext(t *testing.T) {
	engine := NewEngine()

	text := "This is a test email: test@example.com and some other text"
	result, err := engine.RedactText(context.Background(), &Request{
		Text: text,
		Mode: ModeReplace,
	})
	if err != nil {
		t.Fatalf("RedactText failed: %v", err)
	}

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
	engine := NewEngine()

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
