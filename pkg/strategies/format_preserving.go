package strategies

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

// FormatPreservingStrategy replaces sensitive data while preserving the original format
type FormatPreservingStrategy struct {
	name string
}

// NewFormatPreservingStrategy creates a new format-preserving replacement strategy
func NewFormatPreservingStrategy() *FormatPreservingStrategy {
	return &FormatPreservingStrategy{
		name: "format_preserving",
	}
}

// GetName returns the name of the strategy
func (s *FormatPreservingStrategy) GetName() string {
	return s.name
}

// GetDescription returns a description of the strategy
func (s *FormatPreservingStrategy) GetDescription() string {
	return "Replaces sensitive data while preserving the original format and structure"
}

// Replace performs the replacement using format-preserving strategy
func (s *FormatPreservingStrategy) Replace(ctx context.Context, request *ReplacementRequest) (*ReplacementResult, error) {
	if request == nil {
		return nil, fmt.Errorf("replacement request cannot be nil")
	}

	var replacedText string
	var confidence float64 = 0.9

	switch strings.ToLower(request.DetectedType) {
	case "ssn", "social_security":
		replacedText = s.preserveSSNFormat(request.OriginalText)
	case "phone", "phone_number":
		replacedText = s.preservePhoneFormat(request.OriginalText)
	case "credit_card", "credit_card_number":
		replacedText = s.preserveCreditCardFormat(request.OriginalText)
	case "date", "date_of_birth":
		replacedText = s.preserveDateFormat(request.OriginalText)
	case "zip", "postal_code":
		replacedText = s.preserveZipFormat(request.OriginalText)
	case "account_number":
		replacedText = s.preserveAccountNumberFormat(request.OriginalText)
	default:
		// Generic format preservation
		replacedText = s.preserveGenericFormat(request.OriginalText)
		confidence = 0.7
	}

	return &ReplacementResult{
		ReplacedText: replacedText,
		Strategy:     s.name,
		Confidence:   confidence,
		Reversible:   false,
		Metadata: map[string]interface{}{
			"original_length":  len(request.OriginalText),
			"replaced_length":  len(replacedText),
			"format_preserved": true,
			"detected_type":    request.DetectedType,
		},
	}, nil
}

// IsReversible indicates whether this strategy supports reversible operations
func (s *FormatPreservingStrategy) IsReversible() bool {
	return false
}

// GetCapabilities returns the capabilities of this strategy
func (s *FormatPreservingStrategy) GetCapabilities() *StrategyCapabilities {
	return &StrategyCapabilities{
		Name: s.name,
		SupportedTypes: []string{
			"ssn", "social_security", "phone", "phone_number",
			"credit_card", "credit_card_number", "date", "date_of_birth",
			"zip", "postal_code", "account_number",
		},
		SupportsReversible: false,
		SupportsFormatting: true,
		RequiresContext:    false,
		PerformanceLevel:   "fast",
		AccuracyLevel:      "high",
	}
}

// Private helper methods for format preservation

func (s *FormatPreservingStrategy) preserveSSNFormat(original string) string {
	// Match common SSN formats: XXX-XX-XXXX, XXXXXXXXX, XXX XX XXXX

	if strings.Contains(original, "-") {
		return fmt.Sprintf("%03d-%02d-%04d",
			randIntRange(100, 1000),
			randInt(100),
			randInt(10000))
	} else if strings.Contains(original, " ") {
		return fmt.Sprintf("%03d %02d %04d",
			randIntRange(100, 1000),
			randInt(100),
			randInt(10000))
	} else {
		return fmt.Sprintf("%09d", randInt(1000000000))
	}
}

func (s *FormatPreservingStrategy) preservePhoneFormat(original string) string {

	// Analyze the format of the original phone number
	format := s.analyzePhoneFormat(original)

	switch format {
	case "xxx-xxx-xxxx":
		return fmt.Sprintf("555-%03d-%04d", randInt(1000), randInt(10000))
	case "(xxx) xxx-xxxx":
		return fmt.Sprintf("(555) %03d-%04d", randInt(1000), randInt(10000))
	case "xxx.xxx.xxxx":
		return fmt.Sprintf("555.%03d.%04d", randInt(1000), randInt(10000))
	case "xxxxxxxxxx":
		return fmt.Sprintf("555%03d%04d", randInt(1000), randInt(10000))
	default:
		return "555-123-4567" // Default format
	}
}

func (s *FormatPreservingStrategy) preserveCreditCardFormat(original string) string {

	// Preserve spacing and separators
	if strings.Contains(original, "-") {
		return "4111-1111-1111-1111"
	} else if strings.Contains(original, " ") {
		return "4111 1111 1111 1111"
	} else {
		return "4111111111111111"
	}
}

func (s *FormatPreservingStrategy) preserveDateFormat(original string) string {

	// Analyze date format patterns
	if matched, _ := regexp.MatchString(`\d{4}-\d{2}-\d{2}`, original); matched {
		return fmt.Sprintf("%04d-%02d-%02d",
			randIntRange(1970, 2020), randIntRange(1, 13), randIntRange(1, 29))
	} else if matched, _ := regexp.MatchString(`\d{2}/\d{2}/\d{4}`, original); matched {
		return fmt.Sprintf("%02d/%02d/%04d",
			randIntRange(1, 13), randIntRange(1, 29), randIntRange(1970, 2020))
	} else if matched, _ := regexp.MatchString(`\d{2}-\d{2}-\d{4}`, original); matched {
		return fmt.Sprintf("%02d-%02d-%04d",
			randIntRange(1, 13), randIntRange(1, 29), randIntRange(1970, 2020))
	}

	return "01-01-1990" // Default format
}

func (s *FormatPreservingStrategy) preserveZipFormat(original string) string {

	if len(original) == 5 {
		return fmt.Sprintf("%05d", randInt(100000))
	} else if len(original) == 10 && strings.Contains(original, "-") {
		return fmt.Sprintf("%05d-%04d", randInt(100000), randInt(10000))
	}

	return "12345"
}

func (s *FormatPreservingStrategy) preserveAccountNumberFormat(original string) string {

	// Preserve length and any separators
	result := ""
	for _, char := range original {
		if char >= '0' && char <= '9' {
			result += fmt.Sprintf("%d", randInt(10))
		} else {
			result += string(char)
		}
	}

	return result
}

func (s *FormatPreservingStrategy) preserveGenericFormat(original string) string {

	// Replace each character while preserving structure
	result := ""
	for _, char := range original {
		switch {
		case char >= '0' && char <= '9':
			result += fmt.Sprintf("%d", randInt(10))
		case char >= 'A' && char <= 'Z':
			result += string(rune('A' + randInt(26)))
		case char >= 'a' && char <= 'z':
			result += string(rune('a' + randInt(26)))
		default:
			result += string(char) // Preserve special characters
		}
	}

	return result
}

func (s *FormatPreservingStrategy) analyzePhoneFormat(phone string) string {
	// Remove all non-digit characters to count digits
	digitCount := 0
	for _, char := range phone {
		if char >= '0' && char <= '9' {
			digitCount++
		}
	}

	// Analyze format patterns
	if strings.Contains(phone, "(") && strings.Contains(phone, ")") {
		return "(xxx) xxx-xxxx"
	} else if strings.Contains(phone, "-") {
		return "xxx-xxx-xxxx"
	} else if strings.Contains(phone, ".") {
		return "xxx.xxx.xxxx"
	} else if digitCount == 10 {
		return "xxxxxxxxxx"
	}

	return "xxx-xxx-xxxx" // Default format
}
