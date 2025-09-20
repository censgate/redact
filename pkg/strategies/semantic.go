package strategies

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

// SemanticStrategy replaces sensitive data with semantically similar but fake data
type SemanticStrategy struct {
	name string
}

// NewSemanticStrategy creates a new semantic replacement strategy
func NewSemanticStrategy() *SemanticStrategy {
	return &SemanticStrategy{
		name: "semantic",
	}
}

// GetName returns the name of the strategy
func (s *SemanticStrategy) GetName() string {
	return s.name
}

// GetDescription returns a description of the strategy
func (s *SemanticStrategy) GetDescription() string {
	return "Replaces sensitive data with semantically similar but fake data"
}

// Replace performs the replacement using semantic strategy
func (s *SemanticStrategy) Replace(ctx context.Context, request *ReplacementRequest) (*ReplacementResult, error) {
	if request == nil {
		return nil, fmt.Errorf("replacement request cannot be nil")
	}

	var replacedText string
	var confidence float64 = 0.8

	switch strings.ToLower(request.DetectedType) {
	case "email":
		replacedText = s.generateFakeEmail()
	case "phone", "phone_number":
		replacedText = s.generateFakePhone()
	case "ssn", "social_security":
		replacedText = s.generateFakeSSN()
	case "credit_card", "credit_card_number":
		replacedText = s.generateFakeCreditCard()
	case "name", "person_name":
		replacedText = s.generateFakeName()
	case "address":
		replacedText = s.generateFakeAddress()
	case "date", "date_of_birth":
		replacedText = s.generateFakeDate()
	default:
		// Generic replacement for unknown types
		replacedText = s.generateGenericReplacement(request.OriginalText)
		confidence = 0.6
	}

	return &ReplacementResult{
		ReplacedText: replacedText,
		Strategy:     s.name,
		Confidence:   confidence,
		Reversible:   false, // Semantic strategy is not reversible
		Metadata: map[string]interface{}{
			"original_length": len(request.OriginalText),
			"replaced_length": len(replacedText),
			"detected_type":   request.DetectedType,
		},
	}, nil
}

// IsReversible indicates whether this strategy supports reversible operations
func (s *SemanticStrategy) IsReversible() bool {
	return false
}

// GetCapabilities returns the capabilities of this strategy
func (s *SemanticStrategy) GetCapabilities() *StrategyCapabilities {
	return &StrategyCapabilities{
		Name: s.name,
		SupportedTypes: []string{
			"email", "phone", "phone_number", "ssn", "social_security",
			"credit_card", "credit_card_number", "name", "person_name",
			"address", "date", "date_of_birth",
		},
		SupportsReversible: false,
		SupportsFormatting: true,
		RequiresContext:    false,
		PerformanceLevel:   "fast",
		AccuracyLevel:      "good",
	}
}

// Private helper methods for generating fake data

func (s *SemanticStrategy) generateFakeEmail() string {
	domains := []string{"example.com", "test.org", "sample.net", "demo.co"}
	names := []string{"john.doe", "jane.smith", "alex.johnson", "chris.wilson"}

	rand.Seed(time.Now().UnixNano())
	name := names[rand.Intn(len(names))]
	domain := domains[rand.Intn(len(domains))]

	return fmt.Sprintf("%s@%s", name, domain)
}

func (s *SemanticStrategy) generateFakePhone() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("555-%03d-%04d", rand.Intn(1000), rand.Intn(10000))
}

func (s *SemanticStrategy) generateFakeSSN() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("%03d-%02d-%04d",
		rand.Intn(900)+100, // First 3 digits (100-999)
		rand.Intn(100),     // Middle 2 digits (00-99)
		rand.Intn(10000))   // Last 4 digits (0000-9999)
}

func (s *SemanticStrategy) generateFakeCreditCard() string {
	rand.Seed(time.Now().UnixNano())
	return fmt.Sprintf("4111-1111-1111-%04d", rand.Intn(10000))
}

func (s *SemanticStrategy) generateFakeName() string {
	firstNames := []string{"John", "Jane", "Alex", "Chris", "Taylor", "Jordan"}
	lastNames := []string{"Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia"}

	rand.Seed(time.Now().UnixNano())
	firstName := firstNames[rand.Intn(len(firstNames))]
	lastName := lastNames[rand.Intn(len(lastNames))]

	return fmt.Sprintf("%s %s", firstName, lastName)
}

func (s *SemanticStrategy) generateFakeAddress() string {
	streets := []string{"Main St", "Oak Ave", "Pine Rd", "Elm Dr", "First St"}
	rand.Seed(time.Now().UnixNano())
	number := rand.Intn(9999) + 1
	street := streets[rand.Intn(len(streets))]

	return fmt.Sprintf("%d %s", number, street)
}

func (s *SemanticStrategy) generateFakeDate() string {
	rand.Seed(time.Now().UnixNano())
	year := rand.Intn(50) + 1970 // 1970-2020
	month := rand.Intn(12) + 1   // 1-12
	day := rand.Intn(28) + 1     // 1-28 (safe for all months)

	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

func (s *SemanticStrategy) generateGenericReplacement(original string) string {
	// For unknown types, generate a placeholder of similar length
	length := len(original)
	if length <= 3 {
		return "***"
	} else if length <= 10 {
		return "[REDACTED]"
	} else {
		return "[SENSITIVE_DATA_REDACTED]"
	}
}
