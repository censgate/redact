package strategies

import (
	"context"
)

// ReplacementStrategy defines the interface for different replacement strategies
type ReplacementStrategy interface {
	// GetName returns the name of the strategy
	GetName() string

	// GetDescription returns a description of the strategy
	GetDescription() string

	// Replace performs the replacement using this strategy
	Replace(ctx context.Context, request *ReplacementRequest) (*ReplacementResult, error)

	// IsReversible indicates whether this strategy supports reversible operations
	IsReversible() bool

	// GetCapabilities returns the capabilities of this strategy
	GetCapabilities() *StrategyCapabilities
}

// ReplacementRequest represents a request for text replacement
type ReplacementRequest struct {
	OriginalText   string                 `json:"original_text"`
	DetectedType   string                 `json:"detected_type"`
	Context        *ReplacementContext    `json:"context,omitempty"`
	Options        map[string]interface{} `json:"options,omitempty"`
	PreserveFormat bool                   `json:"preserve_format"`
}

// ReplacementResult represents the result of a replacement operation
type ReplacementResult struct {
	ReplacedText string                 `json:"replaced_text"`
	Token        string                 `json:"token,omitempty"`
	Strategy     string                 `json:"strategy"`
	Confidence   float64                `json:"confidence"`
	Reversible   bool                   `json:"reversible"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// ReplacementContext provides context for replacement operations
type ReplacementContext struct {
	OrganizationID string                 `json:"organization_id,omitempty"`
	TenantID       string                 `json:"tenant_id,omitempty"`
	UserID         string                 `json:"user_id,omitempty"`
	Source         string                 `json:"source,omitempty"`
	Field          string                 `json:"field,omitempty"`
	Language       string                 `json:"language,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// StrategyCapabilities describes what a replacement strategy can do
type StrategyCapabilities struct {
	Name               string   `json:"name"`
	SupportedTypes     []string `json:"supported_types"`
	SupportsReversible bool     `json:"supports_reversible"`
	SupportsFormatting bool     `json:"supports_formatting"`
	RequiresContext    bool     `json:"requires_context"`
	PerformanceLevel   string   `json:"performance_level"` // "fast", "medium", "slow"
	AccuracyLevel      string   `json:"accuracy_level"`    // "basic", "good", "high"
}

// StrategyRegistry manages available replacement strategies
type StrategyRegistry interface {
	// Register registers a new strategy
	Register(strategy ReplacementStrategy) error

	// GetStrategy returns a strategy by name
	GetStrategy(name string) (ReplacementStrategy, error)

	// ListStrategies returns all available strategies
	ListStrategies() []ReplacementStrategy

	// GetDefaultStrategy returns the default strategy for a given type
	GetDefaultStrategy(detectedType string) (ReplacementStrategy, error)

	// GetBestStrategy returns the best strategy for a given context
	GetBestStrategy(ctx context.Context, request *StrategySelectionRequest) (ReplacementStrategy, error)
}

// StrategySelectionRequest represents a request to select the best strategy
type StrategySelectionRequest struct {
	DetectedType      string                 `json:"detected_type"`
	Context           *ReplacementContext    `json:"context,omitempty"`
	RequiredFeatures  []string               `json:"required_features,omitempty"`
	PreferredAccuracy string                 `json:"preferred_accuracy,omitempty"`
	PreferredSpeed    string                 `json:"preferred_speed,omitempty"`
	Options           map[string]interface{} `json:"options,omitempty"`
}
