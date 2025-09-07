package redaction

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// TenantAwareEngine extends PolicyAwareEngine with multi-tenant support
// Implements TenantAwareRedactionProvider interface
type TenantAwareEngine struct {
	*PolicyAwareEngine

	// Tenant-specific configuration
	tenantPolicies map[string]*TenantPolicy
	tenantMutex    sync.RWMutex

	// Policy persistence interface (to be implemented)
	policyStore PolicyStore
}

// PolicyStore defines interface for persisting tenant policies
type PolicyStore interface {
	GetTenantPolicy(ctx context.Context, tenantID string) (*TenantPolicy, error)
	SetTenantPolicy(ctx context.Context, tenantID string, policy *TenantPolicy) error
	DeleteTenantPolicy(ctx context.Context, tenantID string) error
	ListTenantPolicies(ctx context.Context) ([]string, error)
}

// InMemoryPolicyStore provides in-memory policy storage for development/testing
type InMemoryPolicyStore struct {
	policies map[string]*TenantPolicy
	mutex    sync.RWMutex
}

// NewInMemoryPolicyStore creates a new in-memory policy store
func NewInMemoryPolicyStore() *InMemoryPolicyStore {
	return &InMemoryPolicyStore{
		policies: make(map[string]*TenantPolicy),
	}
}

// GetTenantPolicy implements PolicyStore interface
func (store *InMemoryPolicyStore) GetTenantPolicy(_ context.Context, tenantID string) (*TenantPolicy, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()

	policy, exists := store.policies[tenantID]
	if !exists {
		return nil, fmt.Errorf("policy not found for tenant: %s", tenantID)
	}

	return policy, nil
}

// SetTenantPolicy implements PolicyStore interface
func (store *InMemoryPolicyStore) SetTenantPolicy(_ context.Context, tenantID string, policy *TenantPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}

	// Update timestamps
	now := time.Now()
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now

	store.mutex.Lock()
	defer store.mutex.Unlock()

	store.policies[tenantID] = policy
	return nil
}

// DeleteTenantPolicy implements PolicyStore interface
func (store *InMemoryPolicyStore) DeleteTenantPolicy(_ context.Context, tenantID string) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	delete(store.policies, tenantID)
	return nil
}

// ListTenantPolicies implements PolicyStore interface
func (store *InMemoryPolicyStore) ListTenantPolicies(_ context.Context) ([]string, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()

	tenants := make([]string, 0, len(store.policies))
	for tenantID := range store.policies {
		tenants = append(tenants, tenantID)
	}

	return tenants, nil
}

// NewTenantAwareEngine creates a new tenant-aware redaction engine
func NewTenantAwareEngine(policyStore PolicyStore) *TenantAwareEngine {
	if policyStore == nil {
		policyStore = NewInMemoryPolicyStore()
	}

	return &TenantAwareEngine{
		PolicyAwareEngine: NewPolicyAwareEngine(),
		tenantPolicies:    make(map[string]*TenantPolicy),
		policyStore:       policyStore,
	}
}

// NewTenantAwareEngineWithConfig creates a new tenant-aware redaction engine with custom configuration
func NewTenantAwareEngineWithConfig(
	maxTextLength int, defaultTTL time.Duration, policyStore PolicyStore) *TenantAwareEngine {
	if policyStore == nil {
		policyStore = NewInMemoryPolicyStore()
	}

	return &TenantAwareEngine{
		PolicyAwareEngine: NewPolicyAwareEngineWithConfig(maxTextLength, defaultTTL),
		tenantPolicies:    make(map[string]*TenantPolicy),
		policyStore:       policyStore,
	}
}

// RedactForTenant implements TenantAwareRedactionProvider interface
func (tare *TenantAwareEngine) RedactForTenant(
	ctx context.Context, tenantID string, request *Request) (*Result, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	// Get tenant policy
	tenantPolicy, err := tare.GetTenantPolicy(ctx, tenantID)
	if err != nil {
		// If no tenant-specific policy, use default redaction
		return tare.RedactText(ctx, request)
	}

	// Create policy redaction request
	policyRequest := &PolicyRequest{
		Request:     request,
		PolicyRules: tenantPolicy.Rules,
		TenantID:    tenantID,
	}

	// Apply tenant-specific custom patterns
	if len(tenantPolicy.CustomPatterns) > 0 {
		if policyRequest.CustomPatterns == nil {
			policyRequest.CustomPatterns = tenantPolicy.CustomPatterns
		} else {
			policyRequest.CustomPatterns = append(policyRequest.CustomPatterns, tenantPolicy.CustomPatterns...)
		}
	}

	// Override mode if not specified
	if policyRequest.Mode == "" {
		policyRequest.Mode = tenantPolicy.DefaultMode
	}

	// Apply tenant context
	if policyRequest.Context == nil {
		policyRequest.Context = &Context{}
	}
	policyRequest.Context.ComplianceReqs = tenantPolicy.ComplianceReqs
	if policyRequest.Context.Metadata == nil {
		policyRequest.Context.Metadata = make(map[string]interface{})
	}
	policyRequest.Context.Metadata["tenant_id"] = tenantID
	policyRequest.Context.Metadata["tenant_policy_version"] = tenantPolicy.Version

	// Apply policy rules
	return tare.ApplyPolicyRules(ctx, policyRequest)
}

// GetTenantPolicy implements TenantAwareRedactionProvider interface
func (tare *TenantAwareEngine) GetTenantPolicy(ctx context.Context, tenantID string) (*TenantPolicy, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenant ID cannot be empty")
	}

	// Check cache first
	tare.tenantMutex.RLock()
	cachedPolicy, exists := tare.tenantPolicies[tenantID]
	tare.tenantMutex.RUnlock()

	if exists {
		return cachedPolicy, nil
	}

	// Load from persistent store
	policy, err := tare.policyStore.GetTenantPolicy(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Cache the policy
	tare.tenantMutex.Lock()
	tare.tenantPolicies[tenantID] = policy
	tare.tenantMutex.Unlock()

	return policy, nil
}

// SetTenantPolicy implements TenantAwareRedactionProvider interface
func (tare *TenantAwareEngine) SetTenantPolicy(ctx context.Context, tenantID string, policy *TenantPolicy) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}

	// Set tenant ID if not already set
	if policy.TenantID == "" {
		policy.TenantID = tenantID
	}

	// Validate tenant ID matches
	if policy.TenantID != tenantID {
		return fmt.Errorf("policy tenant ID (%s) does not match provided tenant ID (%s)", policy.TenantID, tenantID)
	}

	// Validate policy rules
	validationErrors := tare.ValidatePolicy(ctx, policy.Rules)
	if len(validationErrors) > 0 {
		return fmt.Errorf("policy validation failed: %d errors found", len(validationErrors))
	}

	// Store in persistent store
	if err := tare.policyStore.SetTenantPolicy(ctx, tenantID, policy); err != nil {
		return fmt.Errorf("failed to persist tenant policy: %w", err)
	}

	// Update cache
	tare.tenantMutex.Lock()
	tare.tenantPolicies[tenantID] = policy
	tare.tenantMutex.Unlock()

	return nil
}

// DeleteTenantPolicy deletes a tenant policy
func (tare *TenantAwareEngine) DeleteTenantPolicy(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Remove from persistent store
	if err := tare.policyStore.DeleteTenantPolicy(ctx, tenantID); err != nil {
		return fmt.Errorf("failed to delete tenant policy from store: %w", err)
	}

	// Remove from cache
	tare.tenantMutex.Lock()
	delete(tare.tenantPolicies, tenantID)
	tare.tenantMutex.Unlock()

	return nil
}

// ListTenants returns a list of all tenant IDs with policies
func (tare *TenantAwareEngine) ListTenants(ctx context.Context) ([]string, error) {
	return tare.policyStore.ListTenantPolicies(ctx)
}

// GetCapabilities overrides the base implementation to indicate multi-tenant support
func (tare *TenantAwareEngine) GetCapabilities() *ProviderCapabilities {
	caps := tare.PolicyAwareEngine.GetCapabilities()
	caps.Name = "TenantAwareEngine"
	caps.SupportsMultiTenant = true
	caps.Features["multi_tenant"] = true
	caps.Features["tenant_policies"] = true
	caps.Features["policy_caching"] = true
	caps.Features["policy_persistence"] = true
	return caps
}

// RefreshTenantPolicy refreshes a tenant policy from the persistent store
func (tare *TenantAwareEngine) RefreshTenantPolicy(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Load from persistent store
	policy, err := tare.policyStore.GetTenantPolicy(ctx, tenantID)
	if err != nil {
		return fmt.Errorf("failed to refresh tenant policy: %w", err)
	}

	// Update cache
	tare.tenantMutex.Lock()
	tare.tenantPolicies[tenantID] = policy
	tare.tenantMutex.Unlock()

	return nil
}

// ClearPolicyCache clears the tenant policy cache
func (tare *TenantAwareEngine) ClearPolicyCache() {
	tare.tenantMutex.Lock()
	defer tare.tenantMutex.Unlock()

	tare.tenantPolicies = make(map[string]*TenantPolicy)
}

// GetCachedTenantCount returns the number of cached tenant policies
func (tare *TenantAwareEngine) GetCachedTenantCount() int {
	tare.tenantMutex.RLock()
	defer tare.tenantMutex.RUnlock()

	return len(tare.tenantPolicies)
}
