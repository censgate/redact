package redaction

import (
	"context"
	"time"
)

// RedactionMode defines how redaction should be performed
type RedactionMode string

const (
	ModeReplace   RedactionMode = "replace"   // Replace with placeholder
	ModeMask      RedactionMode = "mask"      // Replace with mask characters
	ModeRemove    RedactionMode = "remove"    // Remove entirely
	ModeTokenize  RedactionMode = "tokenize"  // Replace with reversible token
	ModeHash      RedactionMode = "hash"      // Replace with hash
	ModeEncrypt   RedactionMode = "encrypt"   // Replace with encrypted value
	ModeLLM       RedactionMode = "llm"       // Use LLM for context-aware redaction
)

// RedactionProvider defines the interface for redaction implementations
// This allows for pluggable redaction strategies including LLM-based redaction
type RedactionProvider interface {
	// RedactText performs redaction on the input text according to the strategy
	RedactText(ctx context.Context, request *RedactionRequest) (*RedactionResult, error)
	
	// RestoreText restores redacted text using a token (if supported)
	RestoreText(ctx context.Context, token string) (*RestoreResult, error)
	
	// GetCapabilities returns the capabilities of this redaction provider
	GetCapabilities() *ProviderCapabilities
	
	// GetStats returns provider-specific statistics
	GetStats() map[string]interface{}
	
	// Cleanup performs any necessary cleanup operations
	Cleanup() error
}

// PolicyAwareRedactionProvider extends RedactionProvider with policy integration
type PolicyAwareRedactionProvider interface {
	RedactionProvider
	
	// ApplyPolicyRules applies policy-defined redaction rules
	ApplyPolicyRules(ctx context.Context, request *PolicyRedactionRequest) (*RedactionResult, error)
	
	// ValidatePolicy validates that policy rules are compatible with this provider
	ValidatePolicy(ctx context.Context, rules []PolicyRule) []ValidationError
}

// LLMRedactionProvider defines interface for LLM-based redaction
type LLMRedactionProvider interface {
	PolicyAwareRedactionProvider
	
	// RedactWithLLM uses LLM to perform context-aware redaction
	RedactWithLLM(ctx context.Context, request *LLMRedactionRequest) (*RedactionResult, error)
	
	// GenerateRedactionSuggestions uses LLM to suggest redaction patterns
	GenerateRedactionSuggestions(ctx context.Context, text string, context *RedactionContext) ([]RedactionSuggestion, error)
}

// TenantAwareRedactionProvider defines interface for multi-tenant redaction
type TenantAwareRedactionProvider interface {
	PolicyAwareRedactionProvider
	
	// RedactForTenant performs tenant-specific redaction
	RedactForTenant(ctx context.Context, tenantID string, request *RedactionRequest) (*RedactionResult, error)
	
	// GetTenantPolicy retrieves redaction policy for a specific tenant
	GetTenantPolicy(ctx context.Context, tenantID string) (*TenantPolicy, error)
	
	// SetTenantPolicy sets redaction policy for a specific tenant
	SetTenantPolicy(ctx context.Context, tenantID string, policy *TenantPolicy) error
}

// RedactionRequest represents a redaction request
type RedactionRequest struct {
	Text            string                 `json:"text"`
	RedactionTypes  []RedactionType        `json:"redaction_types,omitempty"`
	CustomPatterns  []CustomPattern        `json:"custom_patterns,omitempty"`
	Mode            RedactionMode          `json:"mode"`
	Context         *RedactionContext      `json:"context,omitempty"`
	Options         map[string]interface{} `json:"options,omitempty"`
	Reversible      bool                   `json:"reversible"`
	TTL             time.Duration          `json:"ttl,omitempty"`
}

// PolicyRedactionRequest represents a policy-driven redaction request
type PolicyRedactionRequest struct {
	*RedactionRequest
	PolicyRules []PolicyRule `json:"policy_rules"`
	TenantID    string       `json:"tenant_id,omitempty"`
	UserID      string       `json:"user_id,omitempty"`
}

// LLMRedactionRequest represents an LLM-based redaction request
type LLMRedactionRequest struct {
	*PolicyRedactionRequest
	Model           string                 `json:"model"`
	Temperature     float64                `json:"temperature,omitempty"`
	MaxTokens       int                    `json:"max_tokens,omitempty"`
	SystemPrompt    string                 `json:"system_prompt,omitempty"`
	LLMOptions      map[string]interface{} `json:"llm_options,omitempty"`
}

// RestoreResult represents the result of a restoration operation
type RestoreResult struct {
	OriginalText string    `json:"original_text"`
	Token        string    `json:"token"`
	RestoredAt   time.Time `json:"restored_at"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// RedactionContext provides context for redaction operations
type RedactionContext struct {
	Source         string                 `json:"source"`          // e.g., "chat", "document", "api"
	Field          string                 `json:"field"`           // e.g., "messages.content"
	ContentType    string                 `json:"content_type"`    // e.g., "text/plain", "application/json"
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
	Name           string                 `json:"name"`
	Patterns       []string               `json:"patterns"`
	Fields         []string               `json:"fields"`
	Mode           RedactionMode          `json:"mode"`
	Conditions     []PolicyCondition      `json:"conditions,omitempty"`
	Priority       int                    `json:"priority"`
	Enabled        bool                   `json:"enabled"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// PolicyCondition represents a condition for policy rule application
type PolicyCondition struct {
	Field    string      `json:"field"`
	Operator string      `json:"operator"` // eq, ne, contains, regex, etc.
	Value    interface{} `json:"value"`
}

// RedactionSuggestion represents an LLM-generated redaction suggestion
type RedactionSuggestion struct {
	Pattern     string          `json:"pattern"`
	Type        RedactionType   `json:"type"`
	Confidence  float64         `json:"confidence"`
	Reasoning   string          `json:"reasoning"`
	Examples    []string        `json:"examples,omitempty"`
	Replacement string          `json:"replacement,omitempty"`
}

// TenantPolicy represents tenant-specific redaction policies
type TenantPolicy struct {
	TenantID        string                 `json:"tenant_id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description,omitempty"`
	Rules           []PolicyRule           `json:"rules"`
	DefaultMode     RedactionMode          `json:"default_mode"`
	ComplianceReqs  []string               `json:"compliance_reqs,omitempty"`
	CustomPatterns  []CustomPattern        `json:"custom_patterns,omitempty"`
	Settings        map[string]interface{} `json:"settings,omitempty"`
	CreatedAt       time.Time              `json:"created_at"`
	UpdatedAt       time.Time              `json:"updated_at"`
	Version         string                 `json:"version"`
}

// ProviderCapabilities describes what a redaction provider can do
type ProviderCapabilities struct {
	Name                string            `json:"name"`
	Version             string            `json:"version"`
	SupportedTypes      []RedactionType   `json:"supported_types"`
	SupportedModes      []RedactionMode   `json:"supported_modes"`
	SupportsReversible  bool              `json:"supports_reversible"`
	SupportsCustom      bool              `json:"supports_custom_patterns"`
	SupportsLLM         bool              `json:"supports_llm"`
	SupportsPolicies    bool              `json:"supports_policies"`
	SupportsMultiTenant bool              `json:"supports_multi_tenant"`
	MaxTextLength       int               `json:"max_text_length,omitempty"`
	Features            map[string]bool   `json:"features,omitempty"`
}

// ValidationError represents a policy validation error
type ValidationError struct {
	Rule    string `json:"rule"`
	Field   string `json:"field,omitempty"`
	Message string `json:"message"`
	Code    string `json:"code"`
}

// RedactionMode defines how redaction should be performed
type RedactionMode string

const (
	ModeReplace   RedactionMode = "replace"   // Replace with placeholder
	ModeMask      RedactionMode = "mask"      // Replace with mask characters
	ModeRemove    RedactionMode = "remove"    // Remove entirely
	ModeTokenize  RedactionMode = "tokenize"  // Replace with reversible token
	ModeHash      RedactionMode = "hash"      // Replace with hash
	ModeEncrypt   RedactionMode = "encrypt"   // Replace with encrypted value
	ModeLLM       RedactionMode = "llm"       // Use LLM for context-aware redaction
)
