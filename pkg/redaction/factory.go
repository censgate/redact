package redaction

import (
	"fmt"
	"time"
)

// ProviderType represents the type of redaction provider
type ProviderType string

// Provider type constants for different redaction provider implementations
const (
	ProviderTypeBasic       ProviderType = "basic"
	ProviderTypePolicyAware ProviderType = "policy_aware"
	ProviderTypeLLM         ProviderType = "llm"
)

// ProviderConfig holds configuration for creating redaction providers
type ProviderConfig struct {
	Type          ProviderType  `json:"type"`
	MaxTextLength int           `json:"max_text_length,omitempty"`
	DefaultTTL    time.Duration `json:"default_ttl,omitempty"`
	// PolicyStore would be added when policy functionality is implemented
	LLMConfig *LLMConfig `json:"llm_config,omitempty"`
}

// LLMConfig holds configuration for LLM-based redaction providers
type LLMConfig struct {
	Provider    string                 `json:"provider"` // e.g., "openai", "anthropic", "ollama"
	Model       string                 `json:"model"`    // e.g., "gpt-4", "claude-3", "llama2"
	APIKey      string                 `json:"api_key,omitempty"`
	BaseURL     string                 `json:"base_url,omitempty"`
	Temperature float64                `json:"temperature,omitempty"`
	MaxTokens   int                    `json:"max_tokens,omitempty"`
	Options     map[string]interface{} `json:"options,omitempty"`
}

// ProviderFactory creates redaction providers based on configuration
type ProviderFactory struct {
	defaultConfig *ProviderConfig
}

// NewProviderFactory creates a new provider factory
func NewProviderFactory() *ProviderFactory {
	return &ProviderFactory{
		defaultConfig: &ProviderConfig{
			Type:          ProviderTypeBasic,
			MaxTextLength: 1024 * 1024, // 1MB
			DefaultTTL:    24 * time.Hour,
		},
	}
}

// NewProviderFactoryWithDefaults creates a new provider factory with custom defaults
func NewProviderFactoryWithDefaults(config *ProviderConfig) *ProviderFactory {
	if config == nil {
		config = &ProviderConfig{
			Type:          ProviderTypeBasic,
			MaxTextLength: 1024 * 1024,
			DefaultTTL:    24 * time.Hour,
		}
	}

	return &ProviderFactory{
		defaultConfig: config,
	}
}

// CreateProvider creates a redaction provider based on the specified type and configuration
func (factory *ProviderFactory) CreateProvider(providerType ProviderType, config *ProviderConfig) (Provider, error) {
	// Merge with defaults
	finalConfig := factory.mergeConfig(config)

	switch providerType {
	case ProviderTypeBasic:
		return factory.createBasicProvider(finalConfig)
	case ProviderTypePolicyAware:
		return factory.createPolicyAwareProvider(finalConfig)
	case ProviderTypeLLM:
		return factory.createLLMProvider(finalConfig)
	default:
		return nil, fmt.Errorf("unsupported provider type: %s", providerType)
	}
}

// CreateBasicProvider creates a basic redaction provider
func (factory *ProviderFactory) CreateBasicProvider(config *ProviderConfig) (Provider, error) {
	return factory.CreateProvider(ProviderTypeBasic, config)
}

// CreatePolicyAwareProvider creates a policy-aware redaction provider
func (factory *ProviderFactory) CreatePolicyAwareProvider(config *ProviderConfig) (PolicyAwareProvider, error) {
	provider, err := factory.CreateProvider(ProviderTypePolicyAware, config)
	if err != nil {
		return nil, err
	}

	policyProvider, ok := provider.(PolicyAwareProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement PolicyAwareProvider interface")
	}

	return policyProvider, nil
}

// CreateLLMProvider creates an LLM-based redaction provider
func (factory *ProviderFactory) CreateLLMProvider(config *ProviderConfig) (LLMProvider, error) {
	provider, err := factory.CreateProvider(ProviderTypeLLM, config)
	if err != nil {
		return nil, err
	}

	llmProvider, ok := provider.(LLMProvider)
	if !ok {
		return nil, fmt.Errorf("provider does not implement LLMProvider interface")
	}

	return llmProvider, nil
}

// GetSupportedProviderTypes returns a list of supported provider types
func (factory *ProviderFactory) GetSupportedProviderTypes() []ProviderType {
	return []ProviderType{
		ProviderTypeBasic,
		ProviderTypePolicyAware, // Basic implementation - falls back to basic engine
		// ProviderTypeLLM, // Commented out until implemented
	}
}

// ValidateConfig validates a provider configuration
func (factory *ProviderFactory) ValidateConfig(config *ProviderConfig) error {
	if config == nil {
		return fmt.Errorf("config cannot be nil")
	}

	// Validate provider type
	supportedTypes := factory.GetSupportedProviderTypes()
	typeSupported := false
	for _, supportedType := range supportedTypes {
		if config.Type == supportedType {
			typeSupported = true
			break
		}
	}

	if !typeSupported {
		return fmt.Errorf("unsupported provider type: %s", config.Type)
	}

	// Validate configuration values
	if config.MaxTextLength <= 0 {
		return fmt.Errorf("max_text_length must be positive")
	}

	if config.DefaultTTL <= 0 {
		return fmt.Errorf("default_ttl must be positive")
	}

	// Validate LLM config if present
	if config.Type == ProviderTypeLLM && config.LLMConfig != nil {
		if err := factory.validateLLMConfig(config.LLMConfig); err != nil {
			return fmt.Errorf("invalid LLM config: %w", err)
		}
	}

	return nil
}

// Helper methods

// mergeConfig merges the provided config with defaults
func (factory *ProviderFactory) mergeConfig(config *ProviderConfig) *ProviderConfig {
	if config == nil {
		return factory.defaultConfig
	}

	finalConfig := &ProviderConfig{
		Type:          config.Type,
		MaxTextLength: config.MaxTextLength,
		DefaultTTL:    config.DefaultTTL,
		// PolicyStore would be set when policy functionality is implemented
		LLMConfig: config.LLMConfig,
	}

	// Apply defaults for zero values
	if finalConfig.Type == "" {
		finalConfig.Type = factory.defaultConfig.Type
	}

	if finalConfig.MaxTextLength == 0 {
		finalConfig.MaxTextLength = factory.defaultConfig.MaxTextLength
	}

	if finalConfig.DefaultTTL == 0 {
		finalConfig.DefaultTTL = factory.defaultConfig.DefaultTTL
	}

	return finalConfig
}

// createBasicProvider creates a basic redaction engine
func (factory *ProviderFactory) createBasicProvider(config *ProviderConfig) (Provider, error) {
	return NewEngineWithConfig(config.MaxTextLength, config.DefaultTTL), nil
}

// createPolicyAwareProvider creates a policy-aware redaction engine
func (factory *ProviderFactory) createPolicyAwareProvider(config *ProviderConfig) (Provider, error) {
	// Policy aware engine implementation would go here
	return NewEngine(), nil // Fallback to basic engine for now
}

// createLLMProvider creates an LLM-based redaction provider (placeholder)
func (factory *ProviderFactory) createLLMProvider(_ *ProviderConfig) (Provider, error) {
	// TODO: Implement LLM-based redaction provider
	return nil, fmt.Errorf("LLM-based redaction provider not yet implemented")
}

// validateLLMConfig validates LLM configuration
func (factory *ProviderFactory) validateLLMConfig(config *LLMConfig) error {
	if config.Provider == "" {
		return fmt.Errorf("LLM provider cannot be empty")
	}

	if config.Model == "" {
		return fmt.Errorf("LLM model cannot be empty")
	}

	if config.Temperature < 0 || config.Temperature > 2 {
		return fmt.Errorf("temperature must be between 0 and 2")
	}

	if config.MaxTokens < 0 {
		return fmt.Errorf("max_tokens cannot be negative")
	}

	return nil
}

// DefaultFactory provides a default factory instance for convenience.
var DefaultFactory = NewProviderFactory()

// Convenience functions using the default factory

// CreateBasicProvider creates a basic redaction provider using the default factory
func CreateBasicProvider(config *ProviderConfig) (Provider, error) {
	return DefaultFactory.CreateBasicProvider(config)
}

// CreatePolicyAwareProvider creates a policy-aware redaction provider using the default factory
func CreatePolicyAwareProvider(config *ProviderConfig) (PolicyAwareProvider, error) {
	return DefaultFactory.CreatePolicyAwareProvider(config)
}
