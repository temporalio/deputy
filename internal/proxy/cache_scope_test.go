package proxy

import (
	"context"
	"testing"

	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/auth/jwt"
	"github.com/temporalio/deputy/internal/cache/memory"
)

func TestCacheScopeIsEmpty(t *testing.T) {
	tests := []struct {
		name  string
		scope CacheScope
		want  bool
	}{
		{
			name:  "empty scope",
			scope: CacheScope{},
			want:  true,
		},
		{
			name:  "listener only",
			scope: CacheScope{ListenerName: "go-proxy"},
			want:  false,
		},
		{
			name:  "policy hash only",
			scope: CacheScope{PolicyHash: "abc123"},
			want:  false,
		},
		{
			name:  "tenant only",
			scope: CacheScope{TenantID: "acme-corp"},
			want:  false,
		},
		{
			name: "all fields",
			scope: CacheScope{
				ListenerName: "go-proxy",
				PolicyHash:   "abc123",
				TenantID:     "acme-corp",
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.IsEmpty(); got != tc.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCacheScopePrefix(t *testing.T) {
	tests := []struct {
		name  string
		scope CacheScope
		want  string
	}{
		{
			name:  "empty scope returns empty prefix",
			scope: CacheScope{},
			want:  "",
		},
		{
			name:  "listener only",
			scope: CacheScope{ListenerName: "go-proxy"},
			want:  "go-proxy///",
		},
		{
			name:  "tenant only",
			scope: CacheScope{TenantID: "acme-corp"},
			want:  "//acme-corp/",
		},
		{
			name: "all fields",
			scope: CacheScope{
				ListenerName: "go-proxy",
				PolicyHash:   "abc123",
				TenantID:     "acme-corp",
			},
			want: "go-proxy/abc123/acme-corp/",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.Prefix(); got != tc.want {
				t.Errorf("Prefix() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestCacheScopeScopedKey(t *testing.T) {
	tests := []struct {
		name  string
		scope CacheScope
		key   string
		want  string
	}{
		{
			name:  "empty scope returns original key",
			scope: CacheScope{},
			key:   "npm|lodash@4.17.21",
			want:  "npm|lodash@4.17.21",
		},
		{
			name:  "scoped key with tenant",
			scope: CacheScope{TenantID: "acme"},
			key:   "npm|lodash@4.17.21",
			want:  "//acme/npm|lodash@4.17.21",
		},
		{
			name: "full scope",
			scope: CacheScope{
				ListenerName: "npm-proxy",
				PolicyHash:   "hash",
				TenantID:     "acme",
			},
			key:  "npm|lodash@4.17.21",
			want: "npm-proxy/hash/acme/npm|lodash@4.17.21",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.scope.ScopedKey(tc.key); got != tc.want {
				t.Errorf("ScopedKey(%q) = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}

func TestHashPolicyPaths(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
	}{
		{
			name:  "empty paths returns empty hash",
			paths: nil,
		},
		{
			name:  "single path",
			paths: []string{"policy/security.yaml"},
		},
		{
			name:  "multiple paths",
			paths: []string{"policy/security.yaml", "policy/licenses.yaml"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hash := HashPolicyPaths(tc.paths)
			if len(tc.paths) == 0 {
				if hash != "" {
					t.Errorf("expected empty hash for empty paths, got %q", hash)
				}
				return
			}
			// Hash should be 16 hex characters (8 bytes)
			if len(hash) != 16 {
				t.Errorf("expected hash length 16, got %d (%q)", len(hash), hash)
			}
		})
	}

	// Verify different paths produce different hashes
	hash1 := HashPolicyPaths([]string{"a.yaml"})
	hash2 := HashPolicyPaths([]string{"b.yaml"})
	if hash1 == hash2 {
		t.Error("different paths should produce different hashes")
	}

	// Verify same paths produce same hash
	hash3 := HashPolicyPaths([]string{"a.yaml", "b.yaml"})
	hash4 := HashPolicyPaths([]string{"a.yaml", "b.yaml"})
	if hash3 != hash4 {
		t.Error("same paths should produce same hash")
	}

	// Verify order matters
	hash5 := HashPolicyPaths([]string{"b.yaml", "a.yaml"})
	if hash3 == hash5 {
		t.Error("different order should produce different hashes")
	}
}

func TestScopedOSVCacheIsolation(t *testing.T) {
	// Create a shared underlying cache
	inner := memory.NewTTLCache[string, []osv.Vulnerability](100, 0)

	// Create two scoped caches for different tenants
	scope1 := CacheScope{TenantID: "tenant-a"}
	scope2 := CacheScope{TenantID: "tenant-b"}

	cache1 := NewScopedOSVCache(scope1, inner)
	cache2 := NewScopedOSVCache(scope2, inner)

	// Create test vulnerabilities
	vulns1 := []osv.Vulnerability{{ID: "CVE-2024-001"}}
	vulns2 := []osv.Vulnerability{{ID: "CVE-2024-002"}}

	// Set value in tenant-a's cache
	cache1.Set("npm|lodash@4.17.21", vulns1)

	// Set different value in tenant-b's cache for same key
	cache2.Set("npm|lodash@4.17.21", vulns2)

	// Verify tenant-a sees their vulns
	got1, ok := cache1.Get("npm|lodash@4.17.21")
	if !ok {
		t.Fatal("expected cache hit for tenant-a")
	}
	if len(got1) != 1 || got1[0].ID != "CVE-2024-001" {
		t.Errorf("tenant-a got wrong vulns: %v", got1)
	}

	// Verify tenant-b sees their vulns (not tenant-a's)
	got2, ok := cache2.Get("npm|lodash@4.17.21")
	if !ok {
		t.Fatal("expected cache hit for tenant-b")
	}
	if len(got2) != 1 || got2[0].ID != "CVE-2024-002" {
		t.Errorf("tenant-b got wrong vulns: %v", got2)
	}

	// Verify tenant isolation - tenant-a cannot see tenant-b's entry directly
	// by using a different scope
	scopeEmpty := CacheScope{}
	cacheEmpty := NewScopedOSVCache(scopeEmpty, inner)
	_, ok = cacheEmpty.Get("npm|lodash@4.17.21")
	if ok {
		t.Error("unscoped cache should not see scoped entries")
	}
}

func TestScopedImageScanCacheIsolation(t *testing.T) {
	// Create a shared underlying cache
	inner := memory.NewTTLCache[string, ImageScanResult](100, 0)

	// Create two scoped caches for different tenants
	scope1 := CacheScope{ListenerName: "oci-proxy", TenantID: "tenant-a"}
	scope2 := CacheScope{ListenerName: "oci-proxy", TenantID: "tenant-b"}

	cache1 := NewScopedImageScanCache(scope1, inner)
	cache2 := NewScopedImageScanCache(scope2, inner)

	// Create test scan results
	result1 := ImageScanResult{
		Vulnerabilities: []string{"CVE-2024-001"},
		ImageInfo:       map[string]any{"owner": "tenant-a"},
	}
	result2 := ImageScanResult{
		Vulnerabilities: []string{"CVE-2024-002"},
		ImageInfo:       map[string]any{"owner": "tenant-b"},
	}

	key := "gcr.io|project/app@sha256:abc123"

	// Set value in tenant-a's cache
	cache1.Set(key, result1)

	// Set different value in tenant-b's cache for same key
	cache2.Set(key, result2)

	// Verify tenant-a sees their result
	got1, ok := cache1.Get(key)
	if !ok {
		t.Fatal("expected cache hit for tenant-a")
	}
	if got1.ImageInfo["owner"] != "tenant-a" {
		t.Errorf("tenant-a got wrong image info: %v", got1.ImageInfo)
	}

	// Verify tenant-b sees their result (not tenant-a's)
	got2, ok := cache2.Get(key)
	if !ok {
		t.Fatal("expected cache hit for tenant-b")
	}
	if got2.ImageInfo["owner"] != "tenant-b" {
		t.Errorf("tenant-b got wrong image info: %v", got2.ImageInfo)
	}
}

func TestScopedLicenseCacheIsolation(t *testing.T) {
	inner := memory.NewTTLCache[string, []string](100, 0)

	scope1 := CacheScope{TenantID: "tenant-a"}
	scope2 := CacheScope{TenantID: "tenant-b"}

	cache1 := NewScopedLicenseCache(scope1, inner)
	cache2 := NewScopedLicenseCache(scope2, inner)

	// Different tenants might have different license data due to enrichment
	cache1.Set("npm|lodash@4.17.21", []string{"MIT"})
	cache2.Set("npm|lodash@4.17.21", []string{"MIT", "Apache-2.0"})

	got1, ok := cache1.Get("npm|lodash@4.17.21")
	if !ok {
		t.Fatal("expected cache hit for tenant-a")
	}
	if len(got1) != 1 {
		t.Errorf("tenant-a expected 1 license, got %d", len(got1))
	}

	got2, ok := cache2.Get("npm|lodash@4.17.21")
	if !ok {
		t.Fatal("expected cache hit for tenant-b")
	}
	if len(got2) != 2 {
		t.Errorf("tenant-b expected 2 licenses, got %d", len(got2))
	}
}

func TestScopedDigestResolutionCacheIsolation(t *testing.T) {
	inner := memory.NewTTLCache[string, string](100, 0)

	scope1 := CacheScope{TenantID: "tenant-a"}
	scope2 := CacheScope{TenantID: "tenant-b"}

	cache1 := NewScopedDigestResolutionCache(scope1, inner)
	cache2 := NewScopedDigestResolutionCache(scope2, inner)

	key := "gcr.io|project/app:latest"

	// Different tenants might see different digests for same tag
	// (e.g., different registries with same path)
	cache1.Set(key, "sha256:aaa")
	cache2.Set(key, "sha256:bbb")

	got1, ok := cache1.Get(key)
	if !ok {
		t.Fatal("expected cache hit for tenant-a")
	}
	if got1 != "sha256:aaa" {
		t.Errorf("tenant-a got wrong digest: %s", got1)
	}

	got2, ok := cache2.Get(key)
	if !ok {
		t.Fatal("expected cache hit for tenant-b")
	}
	if got2 != "sha256:bbb" {
		t.Errorf("tenant-b got wrong digest: %s", got2)
	}
}

func TestNewScopedCacheEmptyScope(t *testing.T) {
	// When scope is empty, the wrapper should return the inner cache directly
	// for efficiency (no overhead of key prefixing)

	emptyScope := CacheScope{}

	t.Run("OSVCache", func(t *testing.T) {
		inner := memory.NewTTLCache[string, []osv.Vulnerability](100, 0)
		scoped := NewScopedOSVCache(emptyScope, inner)
		// Should return the inner cache directly
		if _, ok := scoped.(*ScopedOSVCache); ok {
			t.Error("empty scope should not create a ScopedOSVCache wrapper")
		}
	})

	t.Run("LicenseCache", func(t *testing.T) {
		inner := memory.NewTTLCache[string, []string](100, 0)
		scoped := NewScopedLicenseCache(emptyScope, inner)
		if _, ok := scoped.(*ScopedLicenseCache); ok {
			t.Error("empty scope should not create a ScopedLicenseCache wrapper")
		}
	})

	t.Run("ImageScanCache", func(t *testing.T) {
		inner := memory.NewTTLCache[string, ImageScanResult](100, 0)
		scoped := NewScopedImageScanCache(emptyScope, inner)
		if _, ok := scoped.(*ScopedImageScanCache); ok {
			t.Error("empty scope should not create a ScopedImageScanCache wrapper")
		}
	})

	t.Run("DigestResolutionCache", func(t *testing.T) {
		inner := memory.NewTTLCache[string, string](100, 0)
		scoped := NewScopedDigestResolutionCache(emptyScope, inner)
		if _, ok := scoped.(*ScopedDigestResolutionCache); ok {
			t.Error("empty scope should not create a ScopedDigestResolutionCache wrapper")
		}
	})
}

func TestCacheScopeFromContext(t *testing.T) {
	tests := []struct {
		name         string
		claims       *jwt.Claims
		listenerName string
		policyHash   string
		wantTenant   string
	}{
		{
			name:         "no claims",
			claims:       nil,
			listenerName: "go-proxy",
			policyHash:   "abc123",
			wantTenant:   "",
		},
		{
			name: "tenant claim",
			claims: &jwt.Claims{
				Subject: "user123",
				Custom:  map[string]any{"tenant": "acme-corp"},
			},
			listenerName: "go-proxy",
			policyHash:   "abc123",
			wantTenant:   "acme-corp",
		},
		{
			name: "org_id claim (no tenant)",
			claims: &jwt.Claims{
				Subject: "user123",
				Custom:  map[string]any{"org_id": "org-456"},
			},
			listenerName: "go-proxy",
			policyHash:   "abc123",
			wantTenant:   "org-456",
		},
		{
			name: "subject fallback (no tenant or org_id)",
			claims: &jwt.Claims{
				Subject: "service-account-1",
			},
			listenerName: "go-proxy",
			policyHash:   "abc123",
			wantTenant:   "service-account-1",
		},
		{
			name: "tenant takes precedence over org_id",
			claims: &jwt.Claims{
				Subject: "user123",
				Custom: map[string]any{
					"tenant": "primary-tenant",
					"org_id": "org-456",
				},
			},
			listenerName: "go-proxy",
			policyHash:   "abc123",
			wantTenant:   "primary-tenant",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.claims != nil {
				ctx = jwt.ContextWithClaims(ctx, tc.claims)
			}

			scope := CacheScopeFromContext(ctx, tc.listenerName, tc.policyHash)

			if scope.ListenerName != tc.listenerName {
				t.Errorf("ListenerName = %q, want %q", scope.ListenerName, tc.listenerName)
			}
			if scope.PolicyHash != tc.policyHash {
				t.Errorf("PolicyHash = %q, want %q", scope.PolicyHash, tc.policyHash)
			}
			if scope.TenantID != tc.wantTenant {
				t.Errorf("TenantID = %q, want %q", scope.TenantID, tc.wantTenant)
			}
		})
	}
}

func TestCacheIsolationByListener(t *testing.T) {
	// Test that different listeners have isolated caches
	inner := memory.NewTTLCache[string, []osv.Vulnerability](100, 0)

	scope1 := CacheScope{ListenerName: "go-proxy-prod"}
	scope2 := CacheScope{ListenerName: "go-proxy-staging"}

	cache1 := NewScopedOSVCache(scope1, inner)
	cache2 := NewScopedOSVCache(scope2, inner)

	vulns1 := []osv.Vulnerability{{ID: "CVE-2024-PROD"}}
	vulns2 := []osv.Vulnerability{{ID: "CVE-2024-STAGING"}}

	cache1.Set("go|example.com/pkg@v1.0.0", vulns1)
	cache2.Set("go|example.com/pkg@v1.0.0", vulns2)

	got1, _ := cache1.Get("go|example.com/pkg@v1.0.0")
	if got1[0].ID != "CVE-2024-PROD" {
		t.Errorf("prod listener got wrong vuln: %s", got1[0].ID)
	}

	got2, _ := cache2.Get("go|example.com/pkg@v1.0.0")
	if got2[0].ID != "CVE-2024-STAGING" {
		t.Errorf("staging listener got wrong vuln: %s", got2[0].ID)
	}
}

func TestCacheIsolationByPolicyHash(t *testing.T) {
	// Test that different policy versions have isolated caches
	inner := memory.NewTTLCache[string, []osv.Vulnerability](100, 0)

	scope1 := CacheScope{ListenerName: "go-proxy", PolicyHash: "v1-hash"}
	scope2 := CacheScope{ListenerName: "go-proxy", PolicyHash: "v2-hash"}

	cache1 := NewScopedOSVCache(scope1, inner)
	cache2 := NewScopedOSVCache(scope2, inner)

	// V1 policy might have filtered some vulns differently
	vulns1 := []osv.Vulnerability{{ID: "CVE-2024-001"}}
	// V2 policy shows more vulns
	vulns2 := []osv.Vulnerability{{ID: "CVE-2024-001"}, {ID: "CVE-2024-002"}}

	cache1.Set("go|example.com/pkg@v1.0.0", vulns1)
	cache2.Set("go|example.com/pkg@v1.0.0", vulns2)

	got1, _ := cache1.Get("go|example.com/pkg@v1.0.0")
	if len(got1) != 1 {
		t.Errorf("v1 policy expected 1 vuln, got %d", len(got1))
	}

	got2, _ := cache2.Get("go|example.com/pkg@v1.0.0")
	if len(got2) != 2 {
		t.Errorf("v2 policy expected 2 vulns, got %d", len(got2))
	}
}

// Tests for RequestScoped*Cache (context-aware tenant isolation)

func TestRequestScopedOSVCacheIsolation(t *testing.T) {
	inner := memory.NewTTLCache[string, []osv.Vulnerability](100, 0)

	// Base scope with listener/policy (shared across all requests)
	baseScope := CacheScope{ListenerName: "go-proxy", PolicyHash: "policy-v1"}

	// Create request-scoped cache
	cache := NewRequestScopedOSVCache(baseScope, inner)

	// Verify it implements ContextAwareOSVCache
	if _, ok := any(cache).(ContextAwareOSVCache); !ok {
		t.Fatal("RequestScopedOSVCache should implement ContextAwareOSVCache")
	}

	// Create contexts with different tenant claims
	ctxTenantA := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Subject: "user1",
		Custom:  map[string]any{"tenant": "tenant-a"},
	})
	ctxTenantB := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Subject: "user2",
		Custom:  map[string]any{"tenant": "tenant-b"},
	})

	vulnsA := []osv.Vulnerability{{ID: "CVE-TENANT-A"}}
	vulnsB := []osv.Vulnerability{{ID: "CVE-TENANT-B"}}

	// Set values with different tenant contexts
	cache.SetWithContext(ctxTenantA, "go|pkg@v1.0.0", vulnsA)
	cache.SetWithContext(ctxTenantB, "go|pkg@v1.0.0", vulnsB)

	// Verify tenant-a sees their data
	gotA, ok := cache.GetWithContext(ctxTenantA, "go|pkg@v1.0.0")
	if !ok {
		t.Fatal("expected cache hit for tenant-a")
	}
	if len(gotA) != 1 || gotA[0].ID != "CVE-TENANT-A" {
		t.Errorf("tenant-a got wrong vulns: %v", gotA)
	}

	// Verify tenant-b sees their data (not tenant-a's)
	gotB, ok := cache.GetWithContext(ctxTenantB, "go|pkg@v1.0.0")
	if !ok {
		t.Fatal("expected cache hit for tenant-b")
	}
	if len(gotB) != 1 || gotB[0].ID != "CVE-TENANT-B" {
		t.Errorf("tenant-b got wrong vulns: %v", gotB)
	}

	// Verify anonymous context (no tenant) uses base scope only
	ctxAnon := context.Background()
	_, ok = cache.GetWithContext(ctxAnon, "go|pkg@v1.0.0")
	if ok {
		t.Error("anonymous context should not see tenant-scoped entries")
	}
}

func TestRequestScopedImageScanCacheIsolation(t *testing.T) {
	inner := memory.NewTTLCache[string, ImageScanResult](100, 0)

	baseScope := CacheScope{ListenerName: "oci-proxy", PolicyHash: "policy-v1"}
	cache := NewRequestScopedImageScanCache(baseScope, inner)

	// Verify it implements ContextAwareImageScanCache
	if _, ok := any(cache).(ContextAwareImageScanCache); !ok {
		t.Fatal("RequestScopedImageScanCache should implement ContextAwareImageScanCache")
	}

	ctxTenantA := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Custom: map[string]any{"tenant": "tenant-a"},
	})
	ctxTenantB := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Custom: map[string]any{"tenant": "tenant-b"},
	})

	resultA := ImageScanResult{ImageInfo: map[string]any{"owner": "tenant-a"}}
	resultB := ImageScanResult{ImageInfo: map[string]any{"owner": "tenant-b"}}

	cacheKey := "gcr.io|app@sha256:abc"

	cache.SetWithContext(ctxTenantA, cacheKey, resultA)
	cache.SetWithContext(ctxTenantB, cacheKey, resultB)

	gotA, ok := cache.GetWithContext(ctxTenantA, cacheKey)
	if !ok || gotA.ImageInfo["owner"] != "tenant-a" {
		t.Errorf("tenant-a got wrong result: %v", gotA)
	}

	gotB, ok := cache.GetWithContext(ctxTenantB, cacheKey)
	if !ok || gotB.ImageInfo["owner"] != "tenant-b" {
		t.Errorf("tenant-b got wrong result: %v", gotB)
	}
}

func TestRequestScopedLicenseCacheIsolation(t *testing.T) {
	inner := memory.NewTTLCache[string, []string](100, 0)

	baseScope := CacheScope{ListenerName: "npm-proxy"}
	cache := NewRequestScopedLicenseCache(baseScope, inner)

	// Verify it implements ContextAwareLicenseCache
	if _, ok := any(cache).(ContextAwareLicenseCache); !ok {
		t.Fatal("RequestScopedLicenseCache should implement ContextAwareLicenseCache")
	}

	ctxTenantA := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Custom: map[string]any{"org_id": "org-a"},
	})
	ctxTenantB := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Custom: map[string]any{"org_id": "org-b"},
	})

	cache.SetWithContext(ctxTenantA, "npm|lodash@4.17.21", []string{"MIT"})
	cache.SetWithContext(ctxTenantB, "npm|lodash@4.17.21", []string{"MIT", "Apache-2.0"})

	gotA, ok := cache.GetWithContext(ctxTenantA, "npm|lodash@4.17.21")
	if !ok || len(gotA) != 1 {
		t.Errorf("org-a got wrong licenses: %v", gotA)
	}

	gotB, ok := cache.GetWithContext(ctxTenantB, "npm|lodash@4.17.21")
	if !ok || len(gotB) != 2 {
		t.Errorf("org-b got wrong licenses: %v", gotB)
	}
}

func TestRequestScopedDigestResolutionCacheIsolation(t *testing.T) {
	inner := memory.NewTTLCache[string, string](100, 0)

	baseScope := CacheScope{ListenerName: "oci-proxy"}
	cache := NewRequestScopedDigestResolutionCache(baseScope, inner)

	// Verify it implements ContextAwareDigestResolutionCache
	if _, ok := any(cache).(ContextAwareDigestResolutionCache); !ok {
		t.Fatal("RequestScopedDigestResolutionCache should implement ContextAwareDigestResolutionCache")
	}

	ctxTenantA := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Subject: "sa-tenant-a",
	})
	ctxTenantB := jwt.ContextWithClaims(context.Background(), &jwt.Claims{
		Subject: "sa-tenant-b",
	})

	key := "gcr.io|app:latest"

	cache.SetWithContext(ctxTenantA, key, "sha256:aaa")
	cache.SetWithContext(ctxTenantB, key, "sha256:bbb")

	gotA, ok := cache.GetWithContext(ctxTenantA, key)
	if !ok || gotA != "sha256:aaa" {
		t.Errorf("tenant-a got wrong digest: %s", gotA)
	}

	gotB, ok := cache.GetWithContext(ctxTenantB, key)
	if !ok || gotB != "sha256:bbb" {
		t.Errorf("tenant-b got wrong digest: %s", gotB)
	}
}

func TestTenantIDFromContext(t *testing.T) {
	tests := []struct {
		name       string
		claims     *jwt.Claims
		wantTenant string
	}{
		{
			name:       "no claims returns empty",
			claims:     nil,
			wantTenant: "",
		},
		{
			name: "tenant claim takes precedence",
			claims: &jwt.Claims{
				Subject: "user1",
				Custom: map[string]any{
					"tenant": "my-tenant",
					"org_id": "my-org",
				},
			},
			wantTenant: "my-tenant",
		},
		{
			name: "org_id used when no tenant",
			claims: &jwt.Claims{
				Subject: "user1",
				Custom:  map[string]any{"org_id": "my-org"},
			},
			wantTenant: "my-org",
		},
		{
			name: "sub used as fallback",
			claims: &jwt.Claims{
				Subject: "service-account",
			},
			wantTenant: "service-account",
		},
		{
			name: "empty strings are skipped",
			claims: &jwt.Claims{
				Subject: "fallback-sub",
				Custom:  map[string]any{"tenant": "", "org_id": ""},
			},
			wantTenant: "fallback-sub",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.claims != nil {
				ctx = jwt.ContextWithClaims(ctx, tc.claims)
			}

			got := TenantIDFromContext(ctx)
			if got != tc.wantTenant {
				t.Errorf("TenantIDFromContext() = %q, want %q", got, tc.wantTenant)
			}
		})
	}
}

func TestWithTenant(t *testing.T) {
	base := CacheScope{
		ListenerName: "go-proxy",
		PolicyHash:   "abc123",
		TenantID:     "", // no tenant in base
	}

	// Add tenant
	withTenant := base.WithTenant("acme-corp")

	if withTenant.ListenerName != base.ListenerName {
		t.Errorf("ListenerName changed: %q != %q", withTenant.ListenerName, base.ListenerName)
	}
	if withTenant.PolicyHash != base.PolicyHash {
		t.Errorf("PolicyHash changed: %q != %q", withTenant.PolicyHash, base.PolicyHash)
	}
	if withTenant.TenantID != "acme-corp" {
		t.Errorf("TenantID not set: %q != acme-corp", withTenant.TenantID)
	}

	// Original should be unchanged
	if base.TenantID != "" {
		t.Error("original scope should not be modified")
	}
}
