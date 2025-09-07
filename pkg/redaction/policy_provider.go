package redaction

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// PolicyAwareEngine extends Engine with policy support
// Implements PolicyAwareRedactionProvider interface
type PolicyAwareEngine struct {
	*Engine

	// Policy-specific configuration
	policyCache map[string]*compiledPolicyRules
}

// compiledPolicyRules represents compiled policy rules for efficient execution
type compiledPolicyRules struct {
	// Future: compiled rules will be stored here when policy caching is implemented
}

// NewPolicyAwareEngine creates a new policy-aware redaction engine
func NewPolicyAwareEngine() *PolicyAwareEngine {
	return &PolicyAwareEngine{
		Engine:      NewEngine(),
		policyCache: make(map[string]*compiledPolicyRules),
	}
}

// NewPolicyAwareEngineWithConfig creates a new policy-aware redaction engine with custom configuration
func NewPolicyAwareEngineWithConfig(maxTextLength int, defaultTTL time.Duration) *PolicyAwareEngine {
	return &PolicyAwareEngine{
		Engine:      NewEngineWithConfig(maxTextLength, defaultTTL),
		policyCache: make(map[string]*compiledPolicyRules),
	}
}

// ApplyPolicyRules implements PolicyAwareRedactionProvider interface
func (pare *PolicyAwareEngine) ApplyPolicyRules(ctx context.Context, request *PolicyRequest) (*Result, error) {
	if request == nil || request.Request == nil {
		return nil, fmt.Errorf("policy redaction request cannot be nil")
	}

	// Validate text length
	if len(request.Text) > pare.maxTextLength {
		return nil, fmt.Errorf("text length exceeds maximum allowed size: %d", pare.maxTextLength)
	}

	// Start with base redaction
	result, err := pare.RedactText(ctx, request.Request)
	if err != nil {
		return nil, fmt.Errorf("base redaction failed: %w", err)
	}

	// Apply policy rules
	if len(request.PolicyRules) > 0 {
		policyResult, err := pare.applyPolicyRulesToResult(result, request.PolicyRules, request.Context)
		if err != nil {
			return nil, fmt.Errorf("policy rule application failed: %w", err)
		}
		result = policyResult
	}

	return result, nil
}

// ValidatePolicy implements PolicyAwareRedactionProvider interface
func (pare *PolicyAwareEngine) ValidatePolicy(_ context.Context, rules []PolicyRule) []ValidationError {
	var errors []ValidationError

	for _, rule := range rules {
		// Validate rule name
		if rule.Name == "" {
			errors = append(errors, ValidationError{
				Rule:    rule.Name,
				Message: "rule name cannot be empty",
				Code:    "MISSING_NAME",
			})
			continue
		}

		// Validate patterns
		for i, pattern := range rule.Patterns {
			if pattern == "" {
				errors = append(errors, ValidationError{
					Rule:    rule.Name,
					Field:   fmt.Sprintf("patterns[%d]", i),
					Message: "pattern cannot be empty",
					Code:    "EMPTY_PATTERN",
				})
				continue
			}

			// Try to compile the pattern
			if _, err := regexp.Compile(pattern); err != nil {
				errors = append(errors, ValidationError{
					Rule:    rule.Name,
					Field:   fmt.Sprintf("patterns[%d]", i),
					Message: fmt.Sprintf("invalid regex pattern: %v", err),
					Code:    "INVALID_REGEX",
				})
			}
		}

		// Validate fields
		if len(rule.Fields) == 0 {
			errors = append(errors, ValidationError{
				Rule:    rule.Name,
				Field:   "fields",
				Message: "at least one field must be specified",
				Code:    "MISSING_FIELDS",
			})
		}

		// Validate mode
		if !isValidMode(rule.Mode) {
			errors = append(errors, ValidationError{
				Rule:    rule.Name,
				Field:   "mode",
				Message: fmt.Sprintf("invalid redaction mode: %s", rule.Mode),
				Code:    "INVALID_MODE",
			})
		}

		// Validate conditions
		for i, condition := range rule.Conditions {
			if condition.Field == "" {
				errors = append(errors, ValidationError{
					Rule:    rule.Name,
					Field:   fmt.Sprintf("conditions[%d].field", i),
					Message: "condition field cannot be empty",
					Code:    "MISSING_CONDITION_FIELD",
				})
			}

			if condition.Operator == "" {
				errors = append(errors, ValidationError{
					Rule:    rule.Name,
					Field:   fmt.Sprintf("conditions[%d].operator", i),
					Message: "condition operator cannot be empty",
					Code:    "MISSING_CONDITION_OPERATOR",
				})
			}
		}
	}

	return errors
}

// GetCapabilities overrides the base implementation to indicate policy support
func (pare *PolicyAwareEngine) GetCapabilities() *ProviderCapabilities {
	caps := pare.Engine.GetCapabilities()
	caps.Name = "PolicyAwareEngine"
	caps.SupportsPolicies = true
	caps.Features["policy_rules"] = true
	caps.Features["rule_validation"] = true
	caps.Features["conditional_redaction"] = true
	return caps
}

// Helper methods

// applyPolicyRulesToResult applies policy rules to an existing redaction result
func (pare *PolicyAwareEngine) applyPolicyRulesToResult(
	result *Result, rules []PolicyRule, context *Context) (*Result, error) {
	// Create a copy of the result to modify
	policyResult := &Result{
		OriginalText: result.OriginalText,
		RedactedText: result.RedactedText,
		Redactions:   make([]Redaction, len(result.Redactions)),
		Token:        result.Token,
		Timestamp:    result.Timestamp,
	}
	copy(policyResult.Redactions, result.Redactions)

	// Apply each policy rule
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		// Check if rule conditions are met
		if !pare.evaluateRuleConditions(rule.Conditions, context) {
			continue
		}

		// Apply rule patterns
		for _, pattern := range rule.Patterns {
			compiled, err := regexp.Compile(pattern)
			if err != nil {
				continue // Skip invalid patterns
			}

			// Apply to specified fields
			for _, field := range rule.Fields {
				if pare.shouldApplyToField(field, context) {
					policyResult = pare.applyPatternToResult(policyResult, compiled, rule, pattern)
				}
			}
		}
	}

	return policyResult, nil
}

// evaluateRuleConditions evaluates whether rule conditions are met
func (pare *PolicyAwareEngine) evaluateRuleConditions(conditions []PolicyCondition, context *Context) bool {
	if len(conditions) == 0 {
		return true // No conditions means always apply
	}

	for _, condition := range conditions {
		if !pare.evaluateCondition(condition, context) {
			return false // All conditions must be true (AND logic)
		}
	}

	return true
}

// evaluateCondition evaluates a single policy condition
func (pare *PolicyAwareEngine) evaluateCondition(condition PolicyCondition, context *Context) bool {
	if context == nil {
		return false
	}

	fieldValue := pare.extractFieldValue(condition.Field, context)
	return pare.evaluateOperator(condition.Operator, fieldValue, condition.Value)
}

// extractFieldValue extracts the field value from context based on field name
func (pare *PolicyAwareEngine) extractFieldValue(field string, context *Context) interface{} {
	switch field {
	case "source":
		return context.Source
	case "field":
		return context.Field
	case "content_type":
		return context.ContentType
	case "language":
		return context.Language
	case "user_role":
		return context.UserRole
	case "compliance_reqs":
		return context.ComplianceReqs
	default:
		if context.Metadata != nil {
			return context.Metadata[field]
		}
		return nil
	}
}

// evaluateOperator evaluates the condition operator with field and expected values
func (pare *PolicyAwareEngine) evaluateOperator(operator string, fieldValue, expectedValue interface{}) bool {
	switch operator {
	case "eq":
		return fieldValue == expectedValue
	case "ne":
		return fieldValue != expectedValue
	case "contains":
		return pare.evaluateContainsOperator(fieldValue, expectedValue)
	case "regex":
		return pare.evaluateRegexOperator(fieldValue, expectedValue)
	case "in":
		return pare.evaluateInOperator(fieldValue, expectedValue)
	default:
		return false
	}
}

// evaluateContainsOperator handles the "contains" operator logic
func (pare *PolicyAwareEngine) evaluateContainsOperator(fieldValue, expectedValue interface{}) bool {
	if str, ok := fieldValue.(string); ok {
		if valStr, ok := expectedValue.(string); ok {
			return strings.Contains(str, valStr)
		}
	}
	if slice, ok := fieldValue.([]string); ok {
		if valStr, ok := expectedValue.(string); ok {
			for _, item := range slice {
				if item == valStr {
					return true
				}
			}
		}
	}
	return false
}

// evaluateRegexOperator handles the "regex" operator logic
func (pare *PolicyAwareEngine) evaluateRegexOperator(fieldValue, expectedValue interface{}) bool {
	str, ok := fieldValue.(string)
	if !ok {
		return false
	}
	pattern, ok := expectedValue.(string)
	if !ok {
		return false
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return false
	}
	return compiled.MatchString(str)
}

// evaluateInOperator handles the "in" operator logic
func (pare *PolicyAwareEngine) evaluateInOperator(fieldValue, expectedValue interface{}) bool {
	slice, ok := expectedValue.([]interface{})
	if !ok {
		return false
	}
	for _, item := range slice {
		if fieldValue == item {
			return true
		}
	}
	return false
}

// shouldApplyToField determines if a rule should apply to a specific field
func (pare *PolicyAwareEngine) shouldApplyToField(field string, context *Context) bool {
	if context == nil {
		return true
	}

	// Map policy fields to context fields
	switch field {
	case "messages", "messages.content", "content":
		return context.Field == "messages.content" || context.Field == "content"
	case "metadata":
		return context.Field == "metadata"
	default:
		return context.Field == field
	}
}

// applyPatternToResult applies a compiled pattern to the redaction result
func (pare *PolicyAwareEngine) applyPatternToResult(
	result *Result, pattern *regexp.Regexp, rule PolicyRule, _ string) *Result {
	matches := pattern.FindAllStringIndex(result.RedactedText, -1)

	for _, match := range matches {
		start, end := match[0], match[1]
		original := result.RedactedText[start:end]

		replacement := pare.generatePolicyReplacement(rule.Mode, original, rule.Name)

		redaction := Redaction{
			Type:        TypeCustom,
			Start:       start,
			End:         end,
			Original:    original,
			Replacement: replacement,
			Confidence:  0.90, // High confidence for policy rules
			Context:     pare.extractContext(result.RedactedText, start, end),
		}

		result.Redactions = append(result.Redactions, redaction)

		// Apply the redaction to the text
		result.RedactedText = result.RedactedText[:start] + replacement + result.RedactedText[end:]
	}

	return result
}

// generatePolicyReplacement generates a replacement string based on policy mode
func (pare *PolicyAwareEngine) generatePolicyReplacement(mode Mode, original, ruleName string) string {
	switch mode {
	case ModeReplace:
		return fmt.Sprintf("[POLICY_%s_REDACTED]", strings.ToUpper(ruleName))
	case ModeMask:
		return strings.Repeat("*", len(original))
	case ModeRemove:
		return ""
	case ModeTokenize:
		return fmt.Sprintf("[TOKEN_%s]", strings.ToUpper(ruleName))
	case ModeHash:
		// Simple hash placeholder - in production, use proper hashing
		return fmt.Sprintf("[HASH_%s]", strings.ToUpper(ruleName))
	case ModeEncrypt:
		// Encryption placeholder - in production, use proper encryption
		return fmt.Sprintf("[ENCRYPTED_%s]", strings.ToUpper(ruleName))
	default:
		return fmt.Sprintf("[%s_REDACTED]", strings.ToUpper(ruleName))
	}
}

// isValidMode checks if a redaction mode is valid
func isValidMode(mode Mode) bool {
	validModes := []Mode{
		ModeReplace, ModeMask, ModeRemove, ModeTokenize, ModeHash, ModeEncrypt, ModeLLM,
	}

	for _, validMode := range validModes {
		if mode == validMode {
			return true
		}
	}

	return false
}
