package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
)

func TestJWKSCache_BasicFetch(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, err := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jwkValue[jwk.KeyID] = "test-key-1"
		jwkValue[jwk.Algorithm] = string(jwa.ES256)

		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	// Create JWKS cache
	cache, err := NewJWKSCache(&JWKSConfig{
		URL:             jwksServer.URL,
		RefreshInterval: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// Get key from cache
	key, err := cache.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}

	ecdsaPub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}

	// Verify it's the same key
	if ecdsaPub.X.Cmp(privateKey.PublicKey.X) != 0 || ecdsaPub.Y.Cmp(privateKey.PublicKey.Y) != 0 {
		t.Error("retrieved key does not match original key")
	}
}

func TestJWKSCache_RSAKey(t *testing.T) {
	// Generate RSA key for testing
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Create JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, err := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jwkValue[jwk.KeyID] = "rsa-key-1"
		jwkValue[jwk.Algorithm] = string(jwa.RS256)

		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{
		URL:             jwksServer.URL,
		RefreshInterval: 1 * time.Hour,
	})
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	key, err := cache.GetKey(context.Background(), "rsa-key-1")
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}

	if _, ok := key.(*rsa.PublicKey); !ok {
		t.Fatalf("expected *rsa.PublicKey, got %T", key)
	}
}

func TestJWKSCache_KeyNotFound(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, _ := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		jwkValue[jwk.KeyID] = "existing-key"
		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{URL: jwksServer.URL})
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// Try to get a non-existent key
	_, err = cache.GetKey(context.Background(), "non-existent-key")
	if err == nil {
		t.Error("expected error for non-existent key")
	}
}

func TestJWKSCache_EmptyURL(t *testing.T) {
	_, err := NewJWKSCache(&JWKSConfig{URL: ""})
	if err == nil {
		t.Error("expected error for empty URL")
	}
}

func TestJWKSCache_NilConfig(t *testing.T) {
	_, err := NewJWKSCache(nil)
	if err == nil {
		t.Error("expected error for nil config")
	}
}

func TestJWKSCache_DoubleClose(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, _ := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		jwkValue[jwk.KeyID] = "test-key"
		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{URL: jwksServer.URL})
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}

	// Should not panic on multiple closes
	err1 := cache.Close()
	err2 := cache.Close()
	err3 := cache.Close()

	if err1 != nil || err2 != nil || err3 != nil {
		t.Error("Close() should always return nil")
	}
}

func TestJWKSCache_ConcurrentAccess(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var requestCount atomic.Int64
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		jwkValue, _ := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		jwkValue[jwk.KeyID] = "concurrent-key"
		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{URL: jwksServer.URL})
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// Concurrent reads should all succeed
	var wg sync.WaitGroup
	errors := make(chan error, 100)

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := cache.GetKey(context.Background(), "concurrent-key")
			if err != nil {
				errors <- err
			}
		}()
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Errorf("concurrent access error: %v", err)
	}
}

func TestJWKSCache_OIDCDiscovery(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Create JWKS server
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, _ := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		jwkValue[jwk.KeyID] = "oidc-key"
		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	// Create discovery server that returns JWKS URL
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]string{
				"jwks_uri": jwksServer.URL,
			}
			json.NewEncoder(w).Encode(config)
			return
		}
		http.NotFound(w, r)
	}))
	defer discoveryServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{
		URL:           discoveryServer.URL,
		OIDCDiscovery: true,
	})
	if err != nil {
		t.Fatalf("failed to create JWKS cache with OIDC discovery: %v", err)
	}
	defer cache.Close()

	// Should be able to get key
	_, err = cache.GetKey(context.Background(), "oidc-key")
	if err != nil {
		t.Errorf("failed to get key via OIDC discovery: %v", err)
	}
}

func TestJWKSCache_OIDCDiscoveryMissingJWKSURI(t *testing.T) {
	// Create discovery server that returns empty JWKS URI
	discoveryServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/openid-configuration" {
			config := map[string]string{
				"issuer": "https://example.com",
				// jwks_uri intentionally missing
			}
			json.NewEncoder(w).Encode(config)
			return
		}
		http.NotFound(w, r)
	}))
	defer discoveryServer.Close()

	_, err := NewJWKSCache(&JWKSConfig{
		URL:           discoveryServer.URL,
		OIDCDiscovery: true,
	})
	if err == nil {
		t.Error("expected error when jwks_uri is missing")
	}
}

func TestJWKSCache_LastRefreshAndError(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, _ := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		jwkValue[jwk.KeyID] = "test-key"
		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{URL: jwksServer.URL})
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// Last refresh should be recent
	if time.Since(cache.LastRefresh()) > 5*time.Second {
		t.Error("last refresh should be recent")
	}

	// No error on successful fetch
	if cache.LastError() != nil {
		t.Errorf("unexpected last error: %v", cache.LastError())
	}
}

func TestJWKSCache_ForceRefresh(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	var refreshCount atomic.Int64
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		refreshCount.Add(1)
		jwkValue, _ := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		jwkValue[jwk.KeyID] = "test-key"
		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{URL: jwksServer.URL})
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	initialCount := refreshCount.Load()

	// Force refresh should be rate-limited (within minJWKSRefreshInterval)
	err = cache.ForceRefresh(context.Background())
	if err != nil {
		t.Errorf("ForceRefresh returned error: %v", err)
	}

	// Count shouldn't increase because it's too soon
	if refreshCount.Load() != initialCount {
		t.Error("ForceRefresh should be rate-limited")
	}
}

func TestJWKSCache_WithMetrics(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, _ := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		jwkValue[jwk.KeyID] = "metrics-key"
		keySet := jwk.Set{Keys: []jwk.Value{jwkValue}}
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	// Create a simple test metrics recorder
	var refreshSuccess, keyLookups, keyMisses atomic.Int64
	metrics := &testMetrics{
		onRefresh: func(success bool) {
			if success {
				refreshSuccess.Add(1)
			}
		},
		onKeyLookup: func(found bool) {
			keyLookups.Add(1)
			if !found {
				keyMisses.Add(1)
			}
		},
	}

	cache, err := NewJWKSCache(&JWKSConfig{URL: jwksServer.URL}, WithJWKSMetrics(metrics))
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// Initial refresh should have been recorded
	if refreshSuccess.Load() < 1 {
		t.Error("expected at least one refresh success")
	}

	// Key lookup
	_, _ = cache.GetKey(context.Background(), "metrics-key")
	if keyLookups.Load() < 1 {
		t.Error("expected key lookup to be recorded")
	}

	// Key miss
	_, _ = cache.GetKey(context.Background(), "non-existent")
	if keyMisses.Load() < 1 {
		t.Error("expected key miss to be recorded")
	}
}

// testMetrics is a simple MetricsRecorder for testing
type testMetrics struct {
	onRefresh   func(success bool)
	onKeyLookup func(found bool)
}

func (m *testMetrics) RecordSuccess()           {}
func (m *testMetrics) RecordAnonymous()         {}
func (m *testMetrics) RecordError(code string)  {}
func (m *testMetrics) RecordJWKSRefresh(success bool) {
	if m.onRefresh != nil {
		m.onRefresh(success)
	}
}
func (m *testMetrics) RecordJWKSKeyLookup(found bool) {
	if m.onKeyLookup != nil {
		m.onKeyLookup(found)
	}
}
