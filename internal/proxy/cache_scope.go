package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/cache/memory"
)

// CacheScope identifies the isolation boundary for cache entries.
// Each unique scope results in a separate cache namespace, preventing
// cross-tenant cache poisoning in multi-tenant deployments.
//
// Security Model:
//   - ListenerName: Isolates caches between different proxy listeners
//   - PolicyHash: Ensures cache invalidation when policies change
//   - TenantID: Isolates caches between different tenants (from JWT claims)
//
// When all fields are empty, the scope is considered "global" and no
// prefix is added to cache keys (for backward compatibility).
type CacheScope struct {
	// ListenerName is the name of the proxy listener (from config).
	ListenerName string
	// PolicyHash is a hash of the policy files used by this listener.
	// This ensures cache invalidation when policies change.
	PolicyHash string
	// TenantID is the tenant identifier from JWT claims.
	// This is typically extracted from the "tenant", "org_id", or "sub" claim.
	TenantID string
}

// IsEmpty returns true if the scope has no isolation boundaries set.
func (s CacheScope) IsEmpty() bool {
	return s.ListenerName == "" && s.PolicyHash == "" && s.TenantID == ""
}

// Prefix returns a cache key prefix for this scope.
// Returns empty string if scope is empty (global cache).
func (s CacheScope) Prefix() string {
	if s.IsEmpty() {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s.ListenerName) + len(s.PolicyHash) + len(s.TenantID) + 3)
	if s.ListenerName != "" {
		b.WriteString(s.ListenerName)
	}
	b.WriteByte('/')
	if s.PolicyHash != "" {
		b.WriteString(s.PolicyHash)
	}
	b.WriteByte('/')
	if s.TenantID != "" {
		b.WriteString(s.TenantID)
	}
	b.WriteByte('/')
	return b.String()
}

// ScopedKey returns a cache key prefixed with the scope.
func (s CacheScope) ScopedKey(key string) string {
	prefix := s.Prefix()
	if prefix == "" {
		return key
	}
	return prefix + key
}

// HashPolicyPaths computes a short hash of policy file paths for cache isolation.
// The hash changes when the set of policy files changes, invalidating cached results.
func HashPolicyPaths(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	h := sha256.New()
	for _, p := range paths {
		h.Write([]byte(p))
		h.Write([]byte{0}) // null separator
	}
	// Use first 8 bytes (16 hex chars) for brevity
	return hex.EncodeToString(h.Sum(nil)[:8])
}

// ScopedOSVCache wraps an OSVCache with scope-based key prefixing.
// This ensures cache entries are isolated per-scope, preventing
// cross-tenant cache poisoning.
type ScopedOSVCache struct {
	scope CacheScope
	inner OSVCache
}

// NewScopedOSVCache creates a scoped OSV cache wrapper.
// If scope is empty, returns the inner cache directly for efficiency.
func NewScopedOSVCache(scope CacheScope, inner OSVCache) OSVCache {
	if scope.IsEmpty() {
		return inner
	}
	return &ScopedOSVCache{scope: scope, inner: inner}
}

// Get retrieves a value from the cache using a scoped key.
func (c *ScopedOSVCache) Get(key string) ([]osv.Vulnerability, bool) {
	return c.inner.Get(c.scope.ScopedKey(key))
}

// Set stores a value in the cache using a scoped key.
func (c *ScopedOSVCache) Set(key string, value []osv.Vulnerability) {
	c.inner.Set(c.scope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *ScopedOSVCache) Stats() memory.Stats {
	return c.inner.Stats()
}

// ScopedLicenseCache wraps a LicenseCache with scope-based key prefixing.
type ScopedLicenseCache struct {
	scope CacheScope
	inner LicenseCache
}

// NewScopedLicenseCache creates a scoped license cache wrapper.
// If scope is empty, returns the inner cache directly for efficiency.
func NewScopedLicenseCache(scope CacheScope, inner LicenseCache) LicenseCache {
	if scope.IsEmpty() {
		return inner
	}
	return &ScopedLicenseCache{scope: scope, inner: inner}
}

// Get retrieves a value from the cache using a scoped key.
func (c *ScopedLicenseCache) Get(key string) ([]string, bool) {
	return c.inner.Get(c.scope.ScopedKey(key))
}

// Set stores a value in the cache using a scoped key.
func (c *ScopedLicenseCache) Set(key string, value []string) {
	c.inner.Set(c.scope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *ScopedLicenseCache) Stats() memory.Stats {
	return c.inner.Stats()
}

// ScopedImageScanCache wraps an ImageScanCache with scope-based key prefixing.
// This is critical for multi-tenant deployments where different tenants
// may have different policies that affect which vulnerabilities are cached.
type ScopedImageScanCache struct {
	scope CacheScope
	inner ImageScanCache
}

// NewScopedImageScanCache creates a scoped image scan cache wrapper.
// If scope is empty, returns the inner cache directly for efficiency.
func NewScopedImageScanCache(scope CacheScope, inner ImageScanCache) ImageScanCache {
	if scope.IsEmpty() {
		return inner
	}
	return &ScopedImageScanCache{scope: scope, inner: inner}
}

// Get retrieves a value from the cache using a scoped key.
func (c *ScopedImageScanCache) Get(key string) (ImageScanResult, bool) {
	return c.inner.Get(c.scope.ScopedKey(key))
}

// Set stores a value in the cache using a scoped key.
func (c *ScopedImageScanCache) Set(key string, value ImageScanResult) {
	c.inner.Set(c.scope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *ScopedImageScanCache) Stats() memory.Stats {
	return c.inner.Stats()
}

// ScopedDigestResolutionCache wraps a DigestResolutionCache with scope-based key prefixing.
type ScopedDigestResolutionCache struct {
	scope CacheScope
	inner DigestResolutionCache
}

// NewScopedDigestResolutionCache creates a scoped digest resolution cache wrapper.
// If scope is empty, returns the inner cache directly for efficiency.
func NewScopedDigestResolutionCache(scope CacheScope, inner DigestResolutionCache) DigestResolutionCache {
	if scope.IsEmpty() {
		return inner
	}
	return &ScopedDigestResolutionCache{scope: scope, inner: inner}
}

// Get retrieves a value from the cache using a scoped key.
func (c *ScopedDigestResolutionCache) Get(key string) (string, bool) {
	return c.inner.Get(c.scope.ScopedKey(key))
}

// Set stores a value in the cache using a scoped key.
func (c *ScopedDigestResolutionCache) Set(key string, value string) {
	c.inner.Set(c.scope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *ScopedDigestResolutionCache) Stats() memory.Stats {
	return c.inner.Stats()
}

// CacheScopeFromContext extracts a CacheScope from the request context.
// It uses JWT claims if available to derive the tenant ID.
//
// Tenant ID is extracted from claims in this order of preference:
//  1. "tenant" claim (common multi-tenant pattern)
//  2. "org_id" claim (organization ID)
//  3. "sub" claim (subject, for single-tenant deployments)
func CacheScopeFromContext(ctx context.Context, listenerName, policyHash string) CacheScope {
	scope := CacheScope{
		ListenerName: listenerName,
		PolicyHash:   policyHash,
	}

	claims := JWTClaimsFromContext(ctx)
	if claims == nil {
		return scope
	}

	// Try common tenant claim names in order of preference
	tenantClaimKeys := []string{"tenant", "org_id", "sub"}
	for _, key := range tenantClaimKeys {
		if val := claims.Get(key); val != nil {
			if s, ok := val.(string); ok && s != "" {
				scope.TenantID = s
				break
			}
		}
	}

	return scope
}

// TenantIDFromContext extracts the tenant ID from the request context.
// Returns empty string if no tenant ID is found.
func TenantIDFromContext(ctx context.Context) string {
	claims := JWTClaimsFromContext(ctx)
	if claims == nil {
		return ""
	}

	// Try common tenant claim names in order of preference
	tenantClaimKeys := []string{"tenant", "org_id", "sub"}
	for _, key := range tenantClaimKeys {
		if val := claims.Get(key); val != nil {
			if s, ok := val.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// WithTenant returns a new CacheScope with the tenant ID set.
// This is useful for adding per-request tenant isolation to a base scope.
func (s CacheScope) WithTenant(tenantID string) CacheScope {
	return CacheScope{
		ListenerName: s.ListenerName,
		PolicyHash:   s.PolicyHash,
		TenantID:     tenantID,
	}
}

// RequestScopedOSVCache wraps an OSVCache with per-request tenant isolation.
// It uses a base scope (listener + policy hash) and adds tenant ID from request context.
//
// RequestScopedOSVCache implements both OSVCache and ContextAwareOSVCache:
//   - Get/Set use base scope only (for backward compatibility)
//   - GetWithContext/SetWithContext add tenant ID from JWT claims
type RequestScopedOSVCache struct {
	baseScope CacheScope
	inner     OSVCache
}

// Compile-time interface assertions
var (
	_ OSVCache             = (*RequestScopedOSVCache)(nil)
	_ ContextAwareOSVCache = (*RequestScopedOSVCache)(nil)
)

// NewRequestScopedOSVCache creates a cache that adds tenant isolation per-request.
// The baseScope should contain ListenerName and PolicyHash; TenantID will be
// extracted from the request context on each operation.
func NewRequestScopedOSVCache(baseScope CacheScope, inner OSVCache) *RequestScopedOSVCache {
	return &RequestScopedOSVCache{baseScope: baseScope, inner: inner}
}

// GetWithContext retrieves a value from the cache using a tenant-scoped key.
func (c *RequestScopedOSVCache) GetWithContext(ctx context.Context, key string) ([]osv.Vulnerability, bool) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	return c.inner.Get(scope.ScopedKey(key))
}

// SetWithContext stores a value in the cache using a tenant-scoped key.
func (c *RequestScopedOSVCache) SetWithContext(ctx context.Context, key string, value []osv.Vulnerability) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	c.inner.Set(scope.ScopedKey(key), value)
}

// Get retrieves a value without context (falls back to base scope only).
// Prefer GetWithContext for tenant isolation.
func (c *RequestScopedOSVCache) Get(key string) ([]osv.Vulnerability, bool) {
	return c.inner.Get(c.baseScope.ScopedKey(key))
}

// Set stores a value without context (falls back to base scope only).
// Prefer SetWithContext for tenant isolation.
func (c *RequestScopedOSVCache) Set(key string, value []osv.Vulnerability) {
	c.inner.Set(c.baseScope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *RequestScopedOSVCache) Stats() memory.Stats {
	return c.inner.Stats()
}

// RequestScopedLicenseCache wraps a LicenseCache with per-request tenant isolation.
//
// RequestScopedLicenseCache implements both LicenseCache and ContextAwareLicenseCache.
type RequestScopedLicenseCache struct {
	baseScope CacheScope
	inner     LicenseCache
}

// Compile-time interface assertions
var (
	_ LicenseCache             = (*RequestScopedLicenseCache)(nil)
	_ ContextAwareLicenseCache = (*RequestScopedLicenseCache)(nil)
)

// NewRequestScopedLicenseCache creates a cache that adds tenant isolation per-request.
func NewRequestScopedLicenseCache(baseScope CacheScope, inner LicenseCache) *RequestScopedLicenseCache {
	return &RequestScopedLicenseCache{baseScope: baseScope, inner: inner}
}

// GetWithContext retrieves a value from the cache using a tenant-scoped key.
func (c *RequestScopedLicenseCache) GetWithContext(ctx context.Context, key string) ([]string, bool) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	return c.inner.Get(scope.ScopedKey(key))
}

// SetWithContext stores a value in the cache using a tenant-scoped key.
func (c *RequestScopedLicenseCache) SetWithContext(ctx context.Context, key string, value []string) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	c.inner.Set(scope.ScopedKey(key), value)
}

// Get retrieves a value without context (falls back to base scope only).
func (c *RequestScopedLicenseCache) Get(key string) ([]string, bool) {
	return c.inner.Get(c.baseScope.ScopedKey(key))
}

// Set stores a value without context (falls back to base scope only).
func (c *RequestScopedLicenseCache) Set(key string, value []string) {
	c.inner.Set(c.baseScope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *RequestScopedLicenseCache) Stats() memory.Stats {
	return c.inner.Stats()
}

// RequestScopedImageScanCache wraps an ImageScanCache with per-request tenant isolation.
//
// RequestScopedImageScanCache implements both ImageScanCache and ContextAwareImageScanCache.
type RequestScopedImageScanCache struct {
	baseScope CacheScope
	inner     ImageScanCache
}

// Compile-time interface assertions
var (
	_ ImageScanCache             = (*RequestScopedImageScanCache)(nil)
	_ ContextAwareImageScanCache = (*RequestScopedImageScanCache)(nil)
)

// NewRequestScopedImageScanCache creates a cache that adds tenant isolation per-request.
func NewRequestScopedImageScanCache(baseScope CacheScope, inner ImageScanCache) *RequestScopedImageScanCache {
	return &RequestScopedImageScanCache{baseScope: baseScope, inner: inner}
}

// GetWithContext retrieves a value from the cache using a tenant-scoped key.
func (c *RequestScopedImageScanCache) GetWithContext(ctx context.Context, key string) (ImageScanResult, bool) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	return c.inner.Get(scope.ScopedKey(key))
}

// SetWithContext stores a value in the cache using a tenant-scoped key.
func (c *RequestScopedImageScanCache) SetWithContext(ctx context.Context, key string, value ImageScanResult) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	c.inner.Set(scope.ScopedKey(key), value)
}

// Get retrieves a value without context (falls back to base scope only).
func (c *RequestScopedImageScanCache) Get(key string) (ImageScanResult, bool) {
	return c.inner.Get(c.baseScope.ScopedKey(key))
}

// Set stores a value without context (falls back to base scope only).
func (c *RequestScopedImageScanCache) Set(key string, value ImageScanResult) {
	c.inner.Set(c.baseScope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *RequestScopedImageScanCache) Stats() memory.Stats {
	return c.inner.Stats()
}

// RequestScopedDigestResolutionCache wraps a DigestResolutionCache with per-request tenant isolation.
//
// RequestScopedDigestResolutionCache implements both DigestResolutionCache and ContextAwareDigestResolutionCache.
type RequestScopedDigestResolutionCache struct {
	baseScope CacheScope
	inner     DigestResolutionCache
}

// Compile-time interface assertions
var (
	_ DigestResolutionCache             = (*RequestScopedDigestResolutionCache)(nil)
	_ ContextAwareDigestResolutionCache = (*RequestScopedDigestResolutionCache)(nil)
)

// NewRequestScopedDigestResolutionCache creates a cache that adds tenant isolation per-request.
func NewRequestScopedDigestResolutionCache(baseScope CacheScope, inner DigestResolutionCache) *RequestScopedDigestResolutionCache {
	return &RequestScopedDigestResolutionCache{baseScope: baseScope, inner: inner}
}

// GetWithContext retrieves a value from the cache using a tenant-scoped key.
func (c *RequestScopedDigestResolutionCache) GetWithContext(ctx context.Context, key string) (string, bool) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	return c.inner.Get(scope.ScopedKey(key))
}

// SetWithContext stores a value in the cache using a tenant-scoped key.
func (c *RequestScopedDigestResolutionCache) SetWithContext(ctx context.Context, key string, value string) {
	scope := c.baseScope.WithTenant(TenantIDFromContext(ctx))
	c.inner.Set(scope.ScopedKey(key), value)
}

// Get retrieves a value without context (falls back to base scope only).
func (c *RequestScopedDigestResolutionCache) Get(key string) (string, bool) {
	return c.inner.Get(c.baseScope.ScopedKey(key))
}

// Set stores a value without context (falls back to base scope only).
func (c *RequestScopedDigestResolutionCache) Set(key string, value string) {
	c.inner.Set(c.baseScope.ScopedKey(key), value)
}

// Stats returns cache statistics from the inner cache.
func (c *RequestScopedDigestResolutionCache) Stats() memory.Stats {
	return c.inner.Stats()
}
