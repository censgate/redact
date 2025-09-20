package strategies

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// ConsistentHashStrategy replaces sensitive data with consistent hash values
type ConsistentHashStrategy struct {
	name string
	salt string
}

// NewConsistentHashStrategy creates a new consistent hash replacement strategy
func NewConsistentHashStrategy() *ConsistentHashStrategy {
	return &ConsistentHashStrategy{
		name: "consistent_hash",
		salt: "default_salt_change_in_production", // Should be configurable in production
	}
}

// NewConsistentHashStrategyWithSalt creates a new consistent hash strategy with custom salt
func NewConsistentHashStrategyWithSalt(salt string) *ConsistentHashStrategy {
	return &ConsistentHashStrategy{
		name: "consistent_hash",
		salt: salt,
	}
}

// GetName returns the name of the strategy
func (s *ConsistentHashStrategy) GetName() string {
	return s.name
}

// GetDescription returns a description of the strategy
func (s *ConsistentHashStrategy) GetDescription() string {
	return "Replaces sensitive data with consistent hash values for analytical purposes"
}

// Replace performs the replacement using consistent hash strategy
func (s *ConsistentHashStrategy) Replace(ctx context.Context, request *ReplacementRequest) (*ReplacementResult, error) {
	if request == nil {
		return nil, fmt.Errorf("replacement request cannot be nil")
	}

	// Create a consistent hash of the original text
	hash := s.createConsistentHash(request.OriginalText, request.DetectedType)

	// Format the hash based on the detected type and options
	replacedText := s.formatHashForType(hash, request.DetectedType, request.Options)

	return &ReplacementResult{
		ReplacedText: replacedText,
		Strategy:     s.name,
		Confidence:   1.0,   // Hash is always consistent
		Reversible:   false, // Hash is one-way
		Metadata: map[string]interface{}{
			"original_length": len(request.OriginalText),
			"replaced_length": len(replacedText),
			"hash_algorithm":  "sha256",
			"detected_type":   request.DetectedType,
			"consistent":      true,
		},
	}, nil
}

// IsReversible indicates whether this strategy supports reversible operations
func (s *ConsistentHashStrategy) IsReversible() bool {
	return false
}

// GetCapabilities returns the capabilities of this strategy
func (s *ConsistentHashStrategy) GetCapabilities() *StrategyCapabilities {
	return &StrategyCapabilities{
		Name: s.name,
		SupportedTypes: []string{
			"email", "phone", "phone_number", "ssn", "social_security",
			"credit_card", "credit_card_number", "name", "person_name",
			"address", "date", "date_of_birth", "generic", "unknown",
		},
		SupportsReversible: false,
		SupportsFormatting: true,
		RequiresContext:    false,
		PerformanceLevel:   "fast",
		AccuracyLevel:      "high",
	}
}

// createConsistentHash creates a consistent hash of the input text
func (s *ConsistentHashStrategy) createConsistentHash(text, detectedType string) string {
	// Combine text, type, and salt for the hash
	input := fmt.Sprintf("%s:%s:%s", text, detectedType, s.salt)

	// Create SHA-256 hash
	hash := sha256.Sum256([]byte(input))
	return hex.EncodeToString(hash[:])
}

// formatHashForType formats the hash based on the detected type
func (s *ConsistentHashStrategy) formatHashForType(hash, detectedType string, options map[string]interface{}) string {
	// Check if full hash is requested
	if options != nil {
		if fullHash, ok := options["full_hash"]; ok && fullHash.(bool) {
			return hash
		}
	}

	// Format hash based on type for better usability
	switch detectedType {
	case "email":
		return fmt.Sprintf("user_%s@redacted.com", hash[:8])
	case "phone", "phone_number":
		return fmt.Sprintf("555-%s-%s", hash[:3], hash[3:7])
	case "ssn", "social_security":
		return fmt.Sprintf("***-**-%s", hash[:4])
	case "credit_card", "credit_card_number":
		return fmt.Sprintf("****-****-****-%s", hash[:4])
	case "name", "person_name":
		return fmt.Sprintf("Person_%s", hash[:8])
	case "address":
		return fmt.Sprintf("Address_%s", hash[:8])
	case "date", "date_of_birth":
		return fmt.Sprintf("Date_%s", hash[:8])
	default:
		// For unknown types, return a shortened hash with prefix
		return fmt.Sprintf("HASH_%s", hash[:16])
	}
}

// SetSalt allows changing the salt used for hashing
func (s *ConsistentHashStrategy) SetSalt(salt string) {
	s.salt = salt
}

// GetSalt returns the current salt (for testing purposes)
func (s *ConsistentHashStrategy) GetSalt() string {
	return s.salt
}
