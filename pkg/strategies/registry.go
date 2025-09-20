package strategies

import (
	"context"
	"fmt"
	"strings"
	"sync"
)

// DefaultStrategyRegistry implements the StrategyRegistry interface
type DefaultStrategyRegistry struct {
	mu         sync.RWMutex
	strategies map[string]ReplacementStrategy
	defaults   map[string]string // maps detected type to default strategy name
}

// NewDefaultStrategyRegistry creates a new strategy registry with built-in strategies
func NewDefaultStrategyRegistry() *DefaultStrategyRegistry {
	registry := &DefaultStrategyRegistry{
		strategies: make(map[string]ReplacementStrategy),
		defaults:   make(map[string]string),
	}

	// Register built-in strategies
	registry.registerBuiltinStrategies()

	return registry
}

// Register registers a new strategy
func (r *DefaultStrategyRegistry) Register(strategy ReplacementStrategy) error {
	if strategy == nil {
		return fmt.Errorf("strategy cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	name := strategy.GetName()
	if name == "" {
		return fmt.Errorf("strategy name cannot be empty")
	}

	r.strategies[name] = strategy
	return nil
}

// GetStrategy returns a strategy by name
func (r *DefaultStrategyRegistry) GetStrategy(name string) (ReplacementStrategy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	strategy, exists := r.strategies[name]
	if !exists {
		return nil, fmt.Errorf("strategy '%s' not found", name)
	}

	return strategy, nil
}

// ListStrategies returns all available strategies
func (r *DefaultStrategyRegistry) ListStrategies() []ReplacementStrategy {
	r.mu.RLock()
	defer r.mu.RUnlock()

	strategies := make([]ReplacementStrategy, 0, len(r.strategies))
	for _, strategy := range r.strategies {
		strategies = append(strategies, strategy)
	}

	return strategies
}

// GetDefaultStrategy returns the default strategy for a given type
func (r *DefaultStrategyRegistry) GetDefaultStrategy(detectedType string) (ReplacementStrategy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Normalize the detected type
	normalizedType := strings.ToLower(detectedType)

	// Check if we have a specific default for this type
	if defaultName, exists := r.defaults[normalizedType]; exists {
		if strategy, exists := r.strategies[defaultName]; exists {
			return strategy, nil
		}
	}

	// Fall back to semantic strategy as default
	if strategy, exists := r.strategies["semantic"]; exists {
		return strategy, nil
	}

	return nil, fmt.Errorf("no default strategy available for type '%s'", detectedType)
}

// GetBestStrategy returns the best strategy for a given context
func (r *DefaultStrategyRegistry) GetBestStrategy(ctx context.Context, request *StrategySelectionRequest) (ReplacementStrategy, error) {
	if request == nil {
		return nil, fmt.Errorf("strategy selection request cannot be nil")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	// Start with the default strategy for the detected type
	bestStrategy, err := r.GetDefaultStrategy(request.DetectedType)
	if err != nil {
		return nil, err
	}

	// If specific requirements are provided, find a better match
	if len(request.RequiredFeatures) > 0 || request.PreferredAccuracy != "" || request.PreferredSpeed != "" {
		bestStrategy = r.findBestMatch(request, bestStrategy)
	}

	return bestStrategy, nil
}

// registerBuiltinStrategies registers all built-in strategies
func (r *DefaultStrategyRegistry) registerBuiltinStrategies() {
	// Register semantic strategy
	semantic := NewSemanticStrategy()
	r.strategies[semantic.GetName()] = semantic

	// Register format preserving strategy
	formatPreserving := NewFormatPreservingStrategy()
	r.strategies[formatPreserving.GetName()] = formatPreserving

	// Register consistent hash strategy
	consistentHash := NewConsistentHashStrategy()
	r.strategies[consistentHash.GetName()] = consistentHash

	// Register fake data strategy
	fakeData := NewFakeDataStrategy()
	r.strategies[fakeData.GetName()] = fakeData

	// Set up default mappings
	r.setupDefaultMappings()
}

// setupDefaultMappings configures default strategy mappings for different types
func (r *DefaultStrategyRegistry) setupDefaultMappings() {
	// Email types
	r.defaults["email"] = "semantic"
	r.defaults["email_address"] = "semantic"

	// Phone types
	r.defaults["phone"] = "format_preserving"
	r.defaults["phone_number"] = "format_preserving"

	// Financial types
	r.defaults["ssn"] = "format_preserving"
	r.defaults["social_security"] = "format_preserving"
	r.defaults["credit_card"] = "format_preserving"
	r.defaults["credit_card_number"] = "format_preserving"

	// Personal information
	r.defaults["name"] = "fake_data"
	r.defaults["person_name"] = "fake_data"
	r.defaults["address"] = "fake_data"
	r.defaults["date_of_birth"] = "fake_data"

	// Generic types
	r.defaults["generic"] = "consistent_hash"
	r.defaults["unknown"] = "semantic"
}

// findBestMatch finds the best strategy match based on requirements
func (r *DefaultStrategyRegistry) findBestMatch(request *StrategySelectionRequest, defaultStrategy ReplacementStrategy) ReplacementStrategy {
	bestStrategy := defaultStrategy
	bestScore := r.scoreStrategy(defaultStrategy, request)

	// Evaluate all strategies and pick the best one
	for _, strategy := range r.strategies {
		score := r.scoreStrategy(strategy, request)
		if score > bestScore {
			bestScore = score
			bestStrategy = strategy
		}
	}

	return bestStrategy
}

// scoreStrategy scores a strategy based on the selection criteria
func (r *DefaultStrategyRegistry) scoreStrategy(strategy ReplacementStrategy, request *StrategySelectionRequest) float64 {
	capabilities := strategy.GetCapabilities()
	score := 0.0

	// Check if strategy supports the detected type
	typeSupported := false
	for _, supportedType := range capabilities.SupportedTypes {
		if strings.EqualFold(supportedType, request.DetectedType) {
			typeSupported = true
			break
		}
	}
	if !typeSupported {
		return 0.0 // Cannot handle this type
	}

	// Base score for type support
	score += 10.0

	// Check required features
	for _, feature := range request.RequiredFeatures {
		switch feature {
		case "reversible":
			if capabilities.SupportsReversible {
				score += 5.0
			} else {
				return 0.0 // Required feature not supported
			}
		case "format_preserving":
			if capabilities.SupportsFormatting {
				score += 3.0
			}
		}
	}

	// Prefer strategies matching accuracy requirements
	if request.PreferredAccuracy != "" {
		if strings.EqualFold(capabilities.AccuracyLevel, request.PreferredAccuracy) {
			score += 3.0
		}
	}

	// Prefer strategies matching speed requirements
	if request.PreferredSpeed != "" {
		if strings.EqualFold(capabilities.PerformanceLevel, request.PreferredSpeed) {
			score += 2.0
		}
	}

	return score
}

// GetStrategyNames returns the names of all registered strategies
func (r *DefaultStrategyRegistry) GetStrategyNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.strategies))
	for name := range r.strategies {
		names = append(names, name)
	}

	return names
}

// GetStrategyCapabilities returns capabilities for all registered strategies
func (r *DefaultStrategyRegistry) GetStrategyCapabilities() map[string]*StrategyCapabilities {
	r.mu.RLock()
	defer r.mu.RUnlock()

	capabilities := make(map[string]*StrategyCapabilities)
	for name, strategy := range r.strategies {
		capabilities[name] = strategy.GetCapabilities()
	}

	return capabilities
}
