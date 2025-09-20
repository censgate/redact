package redaction

import (
	"context"
	"testing"
	"time"
)

func TestPolicyAwareProviderCreation(t *testing.T) {
	factory := NewProviderFactory()

	config := &ProviderConfig{
		Type:          ProviderTypePolicyAware,
		MaxTextLength: 1024 * 1024,
		DefaultTTL:    24 * time.Hour,
	}

	// Test that we can create a policy-aware provider
	provider, err := factory.CreatePolicyAwareProvider(config)
	if err != nil {
		t.Fatalf("Failed to create PolicyAwareProvider: %v", err)
	}

	if provider == nil {
		t.Fatal("PolicyAwareProvider should not be nil")
	}

	// Verify it implements the PolicyAwareProvider interface
	_, ok := provider.(PolicyAwareProvider)
	if !ok {
		t.Fatal("Created provider does not implement PolicyAwareProvider interface")
	}

	// Test capabilities
	caps := provider.GetCapabilities()
	if !caps.SupportsPolicies {
		t.Error("PolicyAwareProvider should support policies")
	}

	// Test that it can handle basic redaction
	ctx := context.Background()
	request := &Request{
		Text:       "My email is test@example.com",
		Mode:       ModeReplace,
		Reversible: false,
	}

	result, err := provider.RedactText(ctx, request)
	if err != nil {
		t.Fatalf("Failed to redact text: %v", err)
	}

	if result == nil {
		t.Fatal("Redaction result should not be nil")
	}

	// Test policy rule application
	policyRequest := &PolicyRequest{
		Request: request,
		PolicyRules: []PolicyRule{
			{
				Name:     "TEST_RULE",
				Patterns: []string{`test@example\.com`},
				Fields:   []string{"content"},
				Mode:     ModeReplace,
				Priority: 100,
				Enabled:  true,
			},
		},
		UserID: "test-user",
	}

	policyResult, err := provider.ApplyPolicyRules(ctx, policyRequest)
	if err != nil {
		t.Fatalf("Failed to apply policy rules: %v", err)
	}

	if policyResult == nil {
		t.Fatal("Policy redaction result should not be nil")
	}

	// Test policy validation
	validationErrors := provider.ValidatePolicy(ctx, policyRequest.PolicyRules)
	if len(validationErrors) != 0 {
		t.Errorf("Expected no validation errors, got %d: %v", len(validationErrors), validationErrors)
	}
}

func TestPolicyValidation(t *testing.T) {
	factory := NewProviderFactory()
	config := &ProviderConfig{
		Type:          ProviderTypePolicyAware,
		MaxTextLength: 1024 * 1024,
		DefaultTTL:    24 * time.Hour,
	}

	provider, err := factory.CreatePolicyAwareProvider(config)
	if err != nil {
		t.Fatalf("Failed to create PolicyAwareProvider: %v", err)
	}

	ctx := context.Background()

	// Test validation with invalid rules
	invalidRules := []PolicyRule{
		{
			Name:     "", // Empty name should cause validation error
			Patterns: []string{`test`},
			Mode:     ModeReplace,
			Enabled:  true,
		},
		{
			Name:     "VALID_RULE",
			Patterns: []string{}, // No patterns should cause validation error
			Mode:     ModeReplace,
			Enabled:  true,
		},
		{
			Name:     "NEGATIVE_PRIORITY",
			Patterns: []string{`test`},
			Mode:     ModeReplace,
			Priority: -1, // Negative priority should cause validation error
			Enabled:  true,
		},
		{
			Name:     "INVALID_MODE",
			Patterns: []string{`test`},
			Mode:     Mode("invalid"), // Invalid mode should cause validation error
			Enabled:  true,
		},
	}

	validationErrors := provider.ValidatePolicy(ctx, invalidRules)
	if len(validationErrors) == 0 {
		t.Error("Expected validation errors for invalid rules, but got none")
	}

	expectedErrors := 4 // One for each invalid rule
	if len(validationErrors) != expectedErrors {
		t.Errorf("Expected %d validation errors, got %d: %v", expectedErrors, len(validationErrors), validationErrors)
	}
}

func TestProviderTypeSupport(t *testing.T) {
	factory := NewProviderFactory()
	supportedTypes := factory.GetSupportedProviderTypes()

	// Check that PolicyAware is supported
	policyAwareSupported := false
	for _, providerType := range supportedTypes {
		if providerType == ProviderTypePolicyAware {
			policyAwareSupported = true
			break
		}
	}

	if !policyAwareSupported {
		t.Error("ProviderTypePolicyAware should be in supported provider types")
	}
}
