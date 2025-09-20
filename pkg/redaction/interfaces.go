package redaction

import (
	"context"
	"time"
)

// Mode defines how redaction should be performed
type Mode string

// Redaction mode constants for different redaction strategies
const (
	ModeReplace  Mode = "replace"  // Replace with placeholder
	ModeMask     Mode = "mask"     // Replace with mask characters
	ModeRemove   Mode = "remove"   // Remove entirely
	ModeTokenize Mode = "tokenize" // Replace with reversible token
	ModeHash     Mode = "hash"     // Replace with hash
	ModeEncrypt  Mode = "encrypt"  // Replace with encrypted value
	ModeLLM      Mode = "llm"      // Use LLM for context-aware redaction
)

// EngineInterface defines the interface for redaction implementations
// This allows for pluggable redaction strategies including pattern-based and LLM-based redaction
type EngineInterface interface {
	// RedactText performs redaction on the input text according to the strategy
	RedactText(ctx context.Context, request *Request) (*Result, error)

	// RestoreText restores redacted text using a token (if supported)
	RestoreText(ctx context.Context, token string) (*RestoreResult, error)

	// GetCapabilities returns the capabilities of this redaction engine
	GetCapabilities() *EngineCapabilities

	// GetStats returns engine-specific statistics
	GetStats() map[string]interface{}

	// Cleanup performs any necessary cleanup operations
	Cleanup() error
}

// Provider is deprecated, use EngineInterface instead
// Maintained for backward compatibility
type Provider = EngineInterface

// PolicyAwareEngine extends EngineInterface with policy integration
type PolicyAwareEngine interface {
	EngineInterface

	// ApplyPolicyRules applies policy-defined redaction rules
	ApplyPolicyRules(ctx context.Context, request *PolicyRequest) (*Result, error)

	// ValidatePolicy validates that policy rules are compatible with this engine
	ValidatePolicy(ctx context.Context, rules []PolicyRule) []ValidationError
}

// LLMEngine defines interface for LLM-based redaction
type LLMEngine interface {
	PolicyAwareEngine

	// AnalyzeContext performs context analysis for intelligent redaction
	AnalyzeContext(ctx context.Context, request *ContextAnalysisRequest) (*ContextAnalysis, error)
}

// PatternProvider defines interface for pattern-based redaction (database-agnostic)
type PatternProvider interface {
	// GetPatterns returns patterns for a given context
	GetPatterns(ctx context.Context, request *PatternRequest) ([]*Pattern, error)

	// ValidatePattern validates a pattern definition
	ValidatePattern(ctx context.Context, pattern *Pattern) error

	// GetPatternsByCategory returns patterns filtered by category
	GetPatternsByCategory(ctx context.Context, category string) ([]*Pattern, error)
}

// Backward compatibility aliases
type PolicyAwareProvider = PolicyAwareEngine
type LLMProvider = LLMEngine

// Request represents a redaction request
type Request struct {
	Text           string                 `json:"text"`
	Types          []Type                 `json:"redaction_types,omitempty"`
	CustomPatterns []CustomPattern        `json:"custom_patterns,omitempty"`
	Mode           Mode                   `json:"mode"`
	Context        *Context               `json:"context,omitempty"`
	Options        map[string]interface{} `json:"options,omitempty"`
	Reversible     bool                   `json:"reversible"`
	TTL            time.Duration          `json:"ttl,omitempty"`
}

// PolicyRequest represents a policy-driven redaction request
type PolicyRequest struct {
	*Request
	PolicyRules []PolicyRule `json:"policy_rules"`
	UserID      string       `json:"user_id,omitempty"`
}

// LLMRequest represents an LLM-based redaction request
type LLMRequest struct {
	*PolicyRequest
	Model        string                 `json:"model"`
	Temperature  float64                `json:"temperature,omitempty"`
	MaxTokens    int                    `json:"max_tokens,omitempty"`
	SystemPrompt string                 `json:"system_prompt,omitempty"`
	LLMOptions   map[string]interface{} `json:"llm_options,omitempty"`
}

// RestoreResult represents the result of a restoration operation
type RestoreResult struct {
	OriginalText string                 `json:"original_text"`
	Token        string                 `json:"token"`
	RestoredAt   time.Time              `json:"restored_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// Context provides context for redaction operations
type Context struct {
	Source         string                 `json:"source"`       // e.g., "chat", "document", "api"
	Field          string                 `json:"field"`        // e.g., "messages.content"
	ContentType    string                 `json:"content_type"` // e.g., "text/plain", "application/json"
	Language       string                 `json:"language,omitempty"`
	UserRole       string                 `json:"user_role,omitempty"`
	ComplianceReqs []string               `json:"compliance_reqs,omitempty"` // e.g., ["GDPR", "HIPAA"]
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// CustomPattern represents a custom redaction pattern
type CustomPattern struct {
	Name        string  `json:"name"`
	Pattern     string  `json:"pattern"`
	Replacement string  `json:"replacement,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`
	Description string  `json:"description,omitempty"`
}

// PolicyRule represents a policy-defined redaction rule
type PolicyRule struct {
	Name       string                 `json:"name"`
	Patterns   []string               `json:"patterns"`
	Fields     []string               `json:"fields"`
	Mode       Mode                   `json:"mode"`
	Conditions []PolicyCondition      `json:"conditions,omitempty"`
	Priority   int                    `json:"priority"`
	Enabled    bool                   `json:"enabled"`
	Metadata   map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyCondition represents a condition for policy rule application
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, contains, regex, etc.
	Value    interface{} `json:"value"`
}

// Suggestion represents an LLM-generated redaction suggestion
type Suggestion struct {
	Pattern     string   `json:"pattern"`
	Type        Type     `json:"type"`
	Confidence  float64  `json:"confidence"`
	Reasoning   string   `json:"reasoning"`
	Examples    []string `json:"examples,omitempty"`
	Replacement string   `json:"replacement,omitempty"`
}

// EngineCapabilities describes what a redaction engine can do
type EngineCapabilities struct {
	Name               string          `json:"name"`
	Version            string          `json:"version"`
	SupportedTypes     []Type          `json:"supported_types"`
	SupportedModes     []Mode          `json:"supported_modes"`
	SupportsReversible bool            `json:"supports_reversible"`
	SupportsCustom     bool            `json:"supports_custom_patterns"`
	SupportsLLM        bool            `json:"supports_llm"`
	SupportsPolicies   bool            `json:"supports_policies"`
	MaxTextLength      int             `json:"max_text_length,omitempty"`
	Features           map[string]bool `json:"features,omitempty"`
}

// ProviderCapabilities is deprecated, use EngineCapabilities instead
type ProviderCapabilities = EngineCapabilities

// ValidationError represents a policy validation error
type ValidationError struct {
	Rule    string `json:"rule"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// Pattern represents a redaction pattern with metadata
type Pattern struct {
	ID          string                 `json:"id" yaml:"id"`
	Name        string                 `json:"name" yaml:"name"`
	Category    string                 `json:"category" yaml:"category"`
	Regex       string                 `json:"regex" yaml:"regex"`
	Replacement string                 `json:"replacement" yaml:"replacement"`
	Confidence  float64                `json:"confidence" yaml:"confidence"`
	Description string                 `json:"description" yaml:"description"`
	Examples    []string               `json:"examples" yaml:"examples"`
	Metadata    map[string]interface{} `json:"metadata" yaml:"metadata"`
	Enabled     bool                   `json:"enabled" yaml:"enabled"`
}

// PatternRequest represents a request for patterns
type PatternRequest struct {
	Context       *Context `json:"context,omitempty"`
	Categories    []string `json:"categories,omitempty"`
	IncludeGlobal bool     `json:"include_global"`
}

// ContextAnalysisRequest represents a request for context analysis
type ContextAnalysisRequest struct {
	Text     string   `json:"text"`
	Context  *Context `json:"context,omitempty"`
	Language string   `json:"language,omitempty"`
}

// ContextAnalysis represents the result of context analysis
type ContextAnalysis struct {
	DetectedTypes   []Type                 `json:"detected_types"`
	Confidence      float64                `json:"confidence"`
	Suggestions     []Suggestion           `json:"suggestions"`
	RiskAssessment  string                 `json:"risk_assessment"`
	RecommendedMode Mode                   `json:"recommended_mode"`
	Metadata        map[string]interface{} `json:"metadata"`
}
