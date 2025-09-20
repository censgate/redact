package patterns

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// PatternLibrary represents a collection of patterns loaded from YAML
type PatternLibrary struct {
	Version      string                 `yaml:"version"`
	Framework    string                 `yaml:"framework"`
	Jurisdiction string                 `yaml:"jurisdiction"`
	Description  string                 `yaml:"description"`
	LastUpdated  string                 `yaml:"last_updated"`
	Patterns     []Pattern              `yaml:"patterns"`
	Metadata     map[string]interface{} `yaml:"metadata"`
}

// Pattern represents a redaction pattern with metadata
type Pattern struct {
	ID          string                 `yaml:"id"`
	Name        string                 `yaml:"name"`
	Category    string                 `yaml:"category"`
	Regex       string                 `yaml:"regex"`
	Confidence  float64                `yaml:"confidence"`
	Description string                 `yaml:"description"`
	Examples    []string               `yaml:"examples"`
	Replacement string                 `yaml:"replacement"`
	Enabled     bool                   `yaml:"enabled"`
	Metadata    map[string]interface{} `yaml:"metadata,omitempty"`
}

// ValidationResult represents the result of pattern validation
type ValidationResult struct {
	Valid      bool                   `json:"valid"`
	Errors     []ValidationError      `json:"errors,omitempty"`
	Warnings   []ValidationWarning    `json:"warnings,omitempty"`
	Statistics PatternStatistics      `json:"statistics"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// ValidationError represents a validation error
type ValidationError struct {
	PatternID string `json:"pattern_id,omitempty"`
	Field     string `json:"field"`
	Message   string `json:"message"`
	Code      string `json:"code"`
	Severity  string `json:"severity"`
}

// ValidationWarning represents a validation warning
type ValidationWarning struct {
	PatternID string `json:"pattern_id,omitempty"`
	Field     string `json:"field"`
	Message   string `json:"message"`
	Code      string `json:"code"`
}

// PatternStatistics provides statistics about the pattern library
type PatternStatistics struct {
	TotalPatterns    int                    `json:"total_patterns"`
	EnabledPatterns  int                    `json:"enabled_patterns"`
	Categories       map[string]int         `json:"categories"`
	ConfidenceLevels map[string]int         `json:"confidence_levels"`
	ComplianceScore  float64                `json:"compliance_score"`
	Coverage         map[string]interface{} `json:"coverage"`
}

// PatternValidator validates pattern libraries and individual patterns
type PatternValidator struct {
	strictMode bool
}

// NewPatternValidator creates a new pattern validator
func NewPatternValidator(strictMode bool) *PatternValidator {
	return &PatternValidator{
		strictMode: strictMode,
	}
}

// ValidateLibrary validates an entire pattern library
func (v *PatternValidator) ValidateLibrary(library *PatternLibrary) *ValidationResult {
	result := &ValidationResult{
		Valid:      true,
		Errors:     []ValidationError{},
		Warnings:   []ValidationWarning{},
		Statistics: PatternStatistics{},
		Metadata:   make(map[string]interface{}),
	}

	// Validate library metadata
	v.validateLibraryMetadata(library, result)

	// Validate individual patterns
	patternIDs := make(map[string]bool)
	categories := make(map[string]int)
	confidenceLevels := make(map[string]int)
	enabledCount := 0

	for _, pattern := range library.Patterns {
		// Check for duplicate IDs
		if patternIDs[pattern.ID] {
			result.Errors = append(result.Errors, ValidationError{
				PatternID: pattern.ID,
				Field:     "id",
				Message:   "Duplicate pattern ID found",
				Code:      "DUPLICATE_ID",
				Severity:  "error",
			})
			result.Valid = false
		}
		patternIDs[pattern.ID] = true

		// Validate individual pattern
		patternResult := v.ValidatePattern(&pattern)
		result.Errors = append(result.Errors, patternResult.Errors...)
		result.Warnings = append(result.Warnings, patternResult.Warnings...)
		if !patternResult.Valid {
			result.Valid = false
		}

		// Collect statistics
		categories[pattern.Category]++
		if pattern.Enabled {
			enabledCount++
		}

		// Categorize confidence levels
		confidenceLevel := v.categorizeConfidence(pattern.Confidence)
		confidenceLevels[confidenceLevel]++
	}

	// Calculate statistics
	result.Statistics = PatternStatistics{
		TotalPatterns:    len(library.Patterns),
		EnabledPatterns:  enabledCount,
		Categories:       categories,
		ConfidenceLevels: confidenceLevels,
		ComplianceScore:  v.calculateComplianceScore(library, result),
	}

	// Add coverage information
	result.Statistics.Coverage = v.calculateCoverage(library)

	return result
}

// ValidatePattern validates an individual pattern
func (v *PatternValidator) ValidatePattern(pattern *Pattern) *ValidationResult {
	result := &ValidationResult{
		Valid:    true,
		Errors:   []ValidationError{},
		Warnings: []ValidationWarning{},
	}

	// Validate required fields
	if pattern.ID == "" {
		result.Errors = append(result.Errors, ValidationError{
			PatternID: pattern.ID,
			Field:     "id",
			Message:   "Pattern ID is required",
			Code:      "MISSING_ID",
			Severity:  "error",
		})
		result.Valid = false
	}

	if pattern.Name == "" {
		result.Errors = append(result.Errors, ValidationError{
			PatternID: pattern.ID,
			Field:     "name",
			Message:   "Pattern name is required",
			Code:      "MISSING_NAME",
			Severity:  "error",
		})
		result.Valid = false
	}

	if pattern.Category == "" {
		result.Errors = append(result.Errors, ValidationError{
			PatternID: pattern.ID,
			Field:     "category",
			Message:   "Pattern category is required",
			Code:      "MISSING_CATEGORY",
			Severity:  "error",
		})
		result.Valid = false
	}

	if pattern.Regex == "" {
		result.Errors = append(result.Errors, ValidationError{
			PatternID: pattern.ID,
			Field:     "regex",
			Message:   "Pattern regex is required",
			Code:      "MISSING_REGEX",
			Severity:  "error",
		})
		result.Valid = false
	}

	// Validate regex syntax
	if pattern.Regex != "" {
		if _, err := regexp.Compile(pattern.Regex); err != nil {
			result.Errors = append(result.Errors, ValidationError{
				PatternID: pattern.ID,
				Field:     "regex",
				Message:   fmt.Sprintf("Invalid regex syntax: %v", err),
				Code:      "INVALID_REGEX",
				Severity:  "error",
			})
			result.Valid = false
		}
	}

	// Validate confidence range
	if pattern.Confidence < 0.0 || pattern.Confidence > 1.0 {
		result.Errors = append(result.Errors, ValidationError{
			PatternID: pattern.ID,
			Field:     "confidence",
			Message:   "Confidence must be between 0.0 and 1.0",
			Code:      "INVALID_CONFIDENCE",
			Severity:  "error",
		})
		result.Valid = false
	}

	// Validate examples against regex
	if pattern.Regex != "" && len(pattern.Examples) > 0 {
		if regex, err := regexp.Compile(pattern.Regex); err == nil {
			for i, example := range pattern.Examples {
				if !regex.MatchString(example) {
					result.Warnings = append(result.Warnings, ValidationWarning{
						PatternID: pattern.ID,
						Field:     "examples",
						Message:   fmt.Sprintf("Example %d does not match the regex pattern", i+1),
						Code:      "EXAMPLE_MISMATCH",
					})
				}
			}
		}
	}

	// Check for potential performance issues
	v.checkPerformanceIssues(pattern, result)

	// Validate replacement string
	if pattern.Replacement == "" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			PatternID: pattern.ID,
			Field:     "replacement",
			Message:   "No replacement string specified, will use default",
			Code:      "MISSING_REPLACEMENT",
		})
	}

	return result
}

// ValidateYAML validates a YAML pattern library
func (v *PatternValidator) ValidateYAML(yamlData []byte) (*ValidationResult, *PatternLibrary, error) {
	var library PatternLibrary

	if err := yaml.Unmarshal(yamlData, &library); err != nil {
		return &ValidationResult{
			Valid: false,
			Errors: []ValidationError{{
				Field:    "yaml",
				Message:  fmt.Sprintf("YAML parsing error: %v", err),
				Code:     "YAML_PARSE_ERROR",
				Severity: "error",
			}},
		}, nil, err
	}

	result := v.ValidateLibrary(&library)
	return result, &library, nil
}

// validateLibraryMetadata validates library-level metadata
func (v *PatternValidator) validateLibraryMetadata(library *PatternLibrary, result *ValidationResult) {
	if library.Version == "" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "version",
			Message: "Library version not specified",
			Code:    "MISSING_VERSION",
		})
	}

	if library.Framework == "" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "framework",
			Message: "Framework not specified",
			Code:    "MISSING_FRAMEWORK",
		})
	}

	if library.Description == "" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			Field:   "description",
			Message: "Library description not provided",
			Code:    "MISSING_DESCRIPTION",
		})
	}

	if len(library.Patterns) == 0 {
		result.Errors = append(result.Errors, ValidationError{
			Field:    "patterns",
			Message:  "No patterns defined in library",
			Code:     "NO_PATTERNS",
			Severity: "error",
		})
		result.Valid = false
	}
}

// checkPerformanceIssues checks for potential regex performance issues
func (v *PatternValidator) checkPerformanceIssues(pattern *Pattern, result *ValidationResult) {
	regex := pattern.Regex

	// Check for catastrophic backtracking patterns
	if strings.Contains(regex, ".*.*") || strings.Contains(regex, ".+.+") {
		result.Warnings = append(result.Warnings, ValidationWarning{
			PatternID: pattern.ID,
			Field:     "regex",
			Message:   "Potential catastrophic backtracking detected",
			Code:      "PERFORMANCE_RISK",
		})
	}

	// Check for overly broad patterns
	if regex == ".*" || regex == ".+" {
		result.Warnings = append(result.Warnings, ValidationWarning{
			PatternID: pattern.ID,
			Field:     "regex",
			Message:   "Overly broad regex pattern may cause performance issues",
			Code:      "BROAD_PATTERN",
		})
	}

	// Check for complex alternations
	alternationCount := strings.Count(regex, "|")
	if alternationCount > 10 {
		result.Warnings = append(result.Warnings, ValidationWarning{
			PatternID: pattern.ID,
			Field:     "regex",
			Message:   fmt.Sprintf("Complex alternation with %d options may impact performance", alternationCount),
			Code:      "COMPLEX_ALTERNATION",
		})
	}
}

// categorizeConfidence categorizes confidence levels
func (v *PatternValidator) categorizeConfidence(confidence float64) string {
	switch {
	case confidence >= 0.9:
		return "high"
	case confidence >= 0.7:
		return "medium"
	case confidence >= 0.5:
		return "low"
	default:
		return "very_low"
	}
}

// calculateComplianceScore calculates an overall compliance score
func (v *PatternValidator) calculateComplianceScore(library *PatternLibrary, result *ValidationResult) float64 {
	if len(library.Patterns) == 0 {
		return 0.0
	}

	score := 1.0

	// Deduct points for errors
	errorWeight := 0.1
	score -= float64(len(result.Errors)) * errorWeight

	// Deduct smaller points for warnings
	warningWeight := 0.02
	score -= float64(len(result.Warnings)) * warningWeight

	// Bonus for having examples
	patternsWithExamples := 0
	for _, pattern := range library.Patterns {
		if len(pattern.Examples) > 0 {
			patternsWithExamples++
		}
	}
	exampleBonus := float64(patternsWithExamples) / float64(len(library.Patterns)) * 0.1
	score += exampleBonus

	// Ensure score is between 0 and 1
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return score
}

// calculateCoverage calculates coverage metrics
func (v *PatternValidator) calculateCoverage(library *PatternLibrary) map[string]interface{} {
	coverage := make(map[string]interface{})

	// Category coverage
	categories := make(map[string]bool)
	for _, pattern := range library.Patterns {
		categories[pattern.Category] = true
	}
	coverage["categories"] = len(categories)

	// Framework coverage
	if library.Metadata != nil {
		if frameworks, ok := library.Metadata["compliance_frameworks"]; ok {
			coverage["compliance_frameworks"] = frameworks
		}
	}

	return coverage
}
