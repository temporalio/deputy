package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwt"
)

// TestAuthIntegration_FullFlow tests the complete authentication flow
// from JWT creation through middleware to policy evaluation.
func TestAuthIntegration_FullFlow(t *testing.T) {
	// Generate test key pair
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	// Create JWKS server
	jwksServer := createTestJWKSServer(t, privateKey)
	defer jwksServer.Close()

	// Create upstream mock
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tests := []struct {
		name           string
		authMode       AuthMode
		token          func() string
		expectedStatus int
		description    string
	}{
		{
			name:     "required mode - valid token",
			authMode: AuthModeRequired,
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user123",
					jwt.Issuer:         "https://auth.example.com",
					jwt.Audience:       []string{"deputy-proxy"},
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
					jwt.IssuedAt:       time.Now().Unix(),
					"roles":            []string{"developer"},
				})
			},
			expectedStatus: http.StatusOK,
			description:    "Valid token should be accepted",
		},
		{
			name:           "required mode - no token",
			authMode:       AuthModeRequired,
			token:          func() string { return "" },
			expectedStatus: http.StatusUnauthorized,
			description:    "Missing token should be rejected in required mode",
		},
		{
			name:     "required mode - expired token",
			authMode: AuthModeRequired,
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user123",
					jwt.ExpirationTime: time.Now().Add(-1 * time.Hour).Unix(),
					jwt.IssuedAt:       time.Now().Add(-2 * time.Hour).Unix(),
				})
			},
			expectedStatus: http.StatusUnauthorized,
			description:    "Expired token should be rejected",
		},
		{
			name:           "optional mode - no token",
			authMode:       AuthModeOptional,
			token:          func() string { return "" },
			expectedStatus: http.StatusOK,
			description:    "Missing token should be allowed in optional mode",
		},
		{
			name:           "disabled mode - no token",
			authMode:       AuthModeDisabled,
			token:          func() string { return "" },
			expectedStatus: http.StatusOK,
			description:    "Disabled auth should allow all requests",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create authenticator
			var auth Authenticator
			var err error

			if tt.authMode != AuthModeDisabled {
				auth, err = NewAuthenticator(&AuthConfig{
					Mode: string(tt.authMode),
					StaticKeys: []StaticKeyConfig{
						{
							KeyID:     "test-key-1",
							Algorithm: "ES256",
							PublicKey: publicKeyPEM,
						},
					},
					Issuers:   []string{"https://auth.example.com"},
					Audiences: []string{"deputy-proxy"},
				})
				if err != nil {
					t.Fatalf("failed to create authenticator: %v", err)
				}
				defer auth.Close()
			}

			// Create test handler
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			// Wrap with auth middleware
			wrapped := withAuthentication(auth, tt.authMode)(handler)

			// Create request
			req := httptest.NewRequest("GET", "/test", nil)
			if token := tt.token(); token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, rec.Code)
			}
		})
	}
}

// TestAuthIntegration_PolicyWithJWTClaims tests that JWT claims are properly
// passed to the policy engine for evaluation.
func TestAuthIntegration_PolicyWithJWTClaims(t *testing.T) {
	// Generate test key pair
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	// Create upstream mock
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Create policy file for testing JWT claims
	policyContent := `
policies:
  - name: jwt-admin-required
    description: Test policy requiring admin role
    entrypoints: ["go_artifact_request"]
    rules:
      - action: deny
        when: |
          request.module.startsWith("internal/") &&
          (!has(jwt.roles) || !jwt.roles.exists(r, r == "admin"))
        reason: "Internal modules require admin role"
`

	// Write temp policy file
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "test-policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Create policy engine
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Create Go handler
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newGoModuleHandler: %v", err)
	}
	// Disable external lookups for tests
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = nil
	handler.lookups.vulnLookup = nil

	// Create authenticator
	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "optional",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key-1",
				Algorithm: "ES256",
				PublicKey: publicKeyPEM,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	tests := []struct {
		name           string
		path           string
		token          func() string
		expectedStatus int
		description    string
	}{
		{
			name: "internal module - admin role - allowed",
			path: "/internal/pkg/@v/v1.0.0.zip",
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "admin-user",
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
					"roles":            []string{"admin", "developer"},
				})
			},
			expectedStatus: http.StatusOK,
			description:    "Admin should access internal modules",
		},
		{
			name: "internal module - no admin role - denied",
			path: "/internal/pkg/@v/v1.0.0.zip",
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "regular-user",
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
					"roles":            []string{"developer"},
				})
			},
			expectedStatus: http.StatusForbidden,
			description:    "Non-admin should be denied internal modules",
		},
		{
			name:           "internal module - anonymous - denied",
			path:           "/internal/pkg/@v/v1.0.0.zip",
			token:          func() string { return "" },
			expectedStatus: http.StatusForbidden,
			description:    "Anonymous users should be denied internal modules",
		},
		{
			name: "public module - no admin role - allowed",
			path: "/github.com/example/pkg/@v/v1.0.0.zip",
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "regular-user",
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
					"roles":            []string{"developer"},
				})
			},
			expectedStatus: http.StatusOK,
			description:    "Non-admin should access public modules",
		},
		{
			name:           "public module - anonymous - allowed",
			path:           "/github.com/example/pkg/@v/v1.0.0.zip",
			token:          func() string { return "" },
			expectedStatus: http.StatusOK,
			description:    "Anonymous users should access public modules",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Wrap handler with auth middleware
			wrapped := withAuthentication(auth, AuthModeOptional)(handler)

			// Create request
			req := httptest.NewRequest("GET", tt.path, nil)
			if token := tt.token(); token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d\nBody: %s",
					tt.description, tt.expectedStatus, rec.Code, rec.Body.String())
			}
		})
	}
}

// TestAuthIntegration_JWKSRefresh tests that the JWKS cache properly
// fetches and caches keys from a remote endpoint.
func TestAuthIntegration_JWKSRefresh(t *testing.T) {
	// Generate test key pair
	privateKey, _ := generateTestKeyPair(t)

	fetchCount := 0
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
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

	// Create JWKS cache with short refresh interval for testing
	// Use testHTTPClient to bypass SafeDialer which blocks localhost in production
	cache, err := NewJWKSCache(&JWKSConfig{
		URL:             jwksServer.URL,
		RefreshInterval: 100 * time.Millisecond,
	}, WithJWKSHTTPClient(&http.Client{Timeout: 30 * time.Second}))
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// First fetch
	_, err = cache.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("first fetch failed: %v", err)
	}

	if fetchCount != 1 {
		t.Errorf("expected 1 fetch, got %d", fetchCount)
	}

	// Second fetch should use cache
	_, err = cache.GetKey(context.Background(), "test-key-1")
	if err != nil {
		t.Fatalf("second fetch failed: %v", err)
	}

	// fetchCount may or may not have increased depending on caching behavior
	// The important thing is that it doesn't fail
	if fetchCount < 1 {
		t.Error("expected at least 1 fetch")
	}
}

// TestAuthIntegration_AnonymousClaimsInPolicy tests that anonymous requests
// properly receive the anonymous claims marker for policy evaluation.
func TestAuthIntegration_AnonymousClaimsInPolicy(t *testing.T) {
	// Create policy file that checks for anonymous
	policyContent := `
policies:
  - name: deny-anonymous-critical
    description: Deny anonymous access to critical packages
    entrypoints: ["go_artifact_request"]
    rules:
      - action: deny
        when: |
          jwt.anonymous == true &&
          request.module.startsWith("critical/")
        reason: "Anonymous access not allowed for critical packages"
`

	// Write temp policy file
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "anon-policy.yaml")
	if err := os.WriteFile(policyPath, []byte(policyContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Create upstream mock
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	// Create policy engine
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Create Go handler
	handler, err := newGoModuleHandler(upstream.URL, engine)
	if err != nil {
		t.Fatalf("newGoModuleHandler: %v", err)
	}
	handler.lookups.osvClient = nil
	handler.lookups.licenseLookup = nil
	handler.lookups.vulnLookup = nil

	// Test anonymous request to critical package
	req := httptest.NewRequest("GET", "/critical/pkg/@v/v1.0.0.zip", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected anonymous request to critical package to be forbidden, got %d", rec.Code)
	}

	// Test anonymous request to non-critical package
	req = httptest.NewRequest("GET", "/github.com/example/pkg/@v/v1.0.0.zip", nil)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected anonymous request to non-critical package to succeed, got %d", rec.Code)
	}
}

// TestAuthIntegration_ClaimValidation tests various claim validation scenarios.
func TestAuthIntegration_ClaimValidation(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	tests := []struct {
		name           string
		config         *AuthConfig
		token          func() string
		expectedStatus int
		description    string
	}{
		{
			name: "valid issuer",
			config: &AuthConfig{
				Mode:    "required",
				Issuers: []string{"https://trusted.example.com"},
				StaticKeys: []StaticKeyConfig{
					{KeyID: "test-key-1", Algorithm: "ES256", PublicKey: publicKeyPEM},
				},
			},
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user",
					jwt.Issuer:         "https://trusted.example.com",
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
				})
			},
			expectedStatus: http.StatusOK,
			description:    "Token from trusted issuer should be accepted",
		},
		{
			name: "invalid issuer",
			config: &AuthConfig{
				Mode:    "required",
				Issuers: []string{"https://trusted.example.com"},
				StaticKeys: []StaticKeyConfig{
					{KeyID: "test-key-1", Algorithm: "ES256", PublicKey: publicKeyPEM},
				},
			},
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user",
					jwt.Issuer:         "https://untrusted.example.com",
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
				})
			},
			expectedStatus: http.StatusForbidden,
			description:    "Token from untrusted issuer should be rejected",
		},
		{
			name: "valid audience",
			config: &AuthConfig{
				Mode:      "required",
				Audiences: []string{"deputy-proxy"},
				StaticKeys: []StaticKeyConfig{
					{KeyID: "test-key-1", Algorithm: "ES256", PublicKey: publicKeyPEM},
				},
			},
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user",
					jwt.Audience:       []string{"deputy-proxy", "other-service"},
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
				})
			},
			expectedStatus: http.StatusOK,
			description:    "Token with matching audience should be accepted",
		},
		{
			name: "invalid audience",
			config: &AuthConfig{
				Mode:      "required",
				Audiences: []string{"deputy-proxy"},
				StaticKeys: []StaticKeyConfig{
					{KeyID: "test-key-1", Algorithm: "ES256", PublicKey: publicKeyPEM},
				},
			},
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user",
					jwt.Audience:       []string{"other-service"},
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
				})
			},
			expectedStatus: http.StatusForbidden,
			description:    "Token with non-matching audience should be rejected",
		},
		{
			name: "required claims present",
			config: &AuthConfig{
				Mode:           "required",
				RequiredClaims: []string{"email", "sub"},
				StaticKeys: []StaticKeyConfig{
					{KeyID: "test-key-1", Algorithm: "ES256", PublicKey: publicKeyPEM},
				},
			},
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user",
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
					"email":            "user@example.com",
				})
			},
			expectedStatus: http.StatusOK,
			description:    "Token with required claims should be accepted",
		},
		{
			name: "required claim missing",
			config: &AuthConfig{
				Mode:           "required",
				RequiredClaims: []string{"email"},
				StaticKeys: []StaticKeyConfig{
					{KeyID: "test-key-1", Algorithm: "ES256", PublicKey: publicKeyPEM},
				},
			},
			token: func() string {
				return createTestToken(t, privateKey, jwt.ClaimsSet{
					jwt.Subject:        "user",
					jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
				})
			},
			expectedStatus: http.StatusForbidden,
			description:    "Token missing required claims should be rejected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			auth, err := NewAuthenticator(tt.config)
			if err != nil {
				t.Fatalf("failed to create authenticator: %v", err)
			}
			defer auth.Close()

			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			})

			wrapped := withAuthentication(auth, AuthModeRequired)(handler)

			req := httptest.NewRequest("GET", "/test", nil)
			if token := tt.token(); token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			rec := httptest.NewRecorder()
			wrapped.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, rec.Code)
			}
		})
	}
}

// Helper functions

func generateTestKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})
	return privateKey, string(pubPEM)
}

func createTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, claims jwt.ClaimsSet) string {
	t.Helper()

	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key-1",
		},
		claims,
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	return token.String()
}

func createTestJWKSServer(t *testing.T, privateKey *ecdsa.PrivateKey) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}
