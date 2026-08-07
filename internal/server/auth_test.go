package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	josejwt "github.com/picatz/jose/pkg/jwt"

	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	"github.com/temporalio/deputy/gen/deputy/list/v1/listv1connect"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
)

// Test helpers

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

	publicKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}))

	return privateKey, publicKeyPEM
}

func createTestToken(t *testing.T, privateKey *ecdsa.PrivateKey, claims josejwt.ClaimsSet) string {
	t.Helper()

	token, err := josejwt.New(
		header.Parameters{
			header.Type:      josejwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key",
		},
		claims,
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	return token.String()
}

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return srv
}

// Auth mode tests

func TestServerAuthModeDisabled(t *testing.T) {
	// With auth disabled, requests without tokens should succeed
	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "disabled",
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := listv1connect.NewListServiceClient(http.DefaultClient, ts.URL)

	// Request without auth should succeed
	resp, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		t.Fatalf("request should succeed with auth disabled: %v", err)
	}
	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("expected at least one ecosystem")
	}
}

func TestServerAuthModeRequired_NoToken(t *testing.T) {
	// With auth required, requests without tokens should fail
	privateKey, publicKeyPEM := generateTestKeyPair(t)
	_ = privateKey // Not used in this test

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	client := listv1connect.NewListServiceClient(http.DefaultClient, ts.URL)

	// Request without auth should fail
	_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err == nil {
		t.Fatal("expected error for unauthenticated request when auth required")
	}

	connectErr, ok := err.(*connect.Error)
	if !ok {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("expected CodeUnauthenticated, got %v", connectErr.Code())
	}
}

func TestServerAuthModeRequired_ValidToken(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create a valid token
	token := createTestToken(t, privateKey, josejwt.ClaimsSet{
		josejwt.Subject:        "user:alice@example.com",
		josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
	})

	// Create client with auth header
	httpClient := &http.Client{
		Transport: &authTransport{
			transport: http.DefaultTransport,
			token:     token,
		},
	}
	client := listv1connect.NewListServiceClient(httpClient, ts.URL)

	// Request with valid token should succeed
	resp, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err != nil {
		t.Fatalf("request with valid token should succeed: %v", err)
	}
	if len(resp.Msg.Ecosystems) == 0 {
		t.Error("expected at least one ecosystem")
	}
}

func TestServerAuthModeRequired_ExpiredToken(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create an expired token
	token := createTestToken(t, privateKey, josejwt.ClaimsSet{
		josejwt.Subject:        "user:alice@example.com",
		josejwt.ExpirationTime: time.Now().Add(-time.Hour).Unix(),
	})

	httpClient := &http.Client{
		Transport: &authTransport{
			transport: http.DefaultTransport,
			token:     token,
		},
	}
	client := listv1connect.NewListServiceClient(httpClient, ts.URL)

	// Request with expired token should fail
	_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err == nil {
		t.Fatal("expected error for expired token")
	}

	connectErr, ok := err.(*connect.Error)
	if !ok {
		t.Fatalf("expected connect.Error, got %T", err)
	}
	if connectErr.Code() != connect.CodeUnauthenticated {
		t.Errorf("expected CodeUnauthenticated, got %v", connectErr.Code())
	}
}

// Issuer/audience validation tests

func TestServerAuthIssuerValidation(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		Issuers: []string{"https://auth.example.com"},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("valid issuer", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@example.com",
			josejwt.Issuer:         "https://auth.example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := listv1connect.NewListServiceClient(httpClient, ts.URL)

		_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
		if err != nil {
			t.Fatalf("request with valid issuer should succeed: %v", err)
		}
	})

	t.Run("invalid issuer", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@example.com",
			josejwt.Issuer:         "https://evil.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := listv1connect.NewListServiceClient(httpClient, ts.URL)

		_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
		if err == nil {
			t.Fatal("expected error for invalid issuer")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		// Invalid issuer returns Unauthenticated (401) - token is invalid
		// This is correct HTTP semantics: 401 = "I don't know who you are"
		if connectErr.Code() != connect.CodeUnauthenticated {
			t.Errorf("expected CodeUnauthenticated, got %v", connectErr.Code())
		}
	})
}

func TestServerAuthAudienceValidation(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		Audiences: []string{"deputy-server"},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("valid audience", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@example.com",
			josejwt.Audience:       []string{"deputy-server"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := listv1connect.NewListServiceClient(httpClient, ts.URL)

		_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
		if err != nil {
			t.Fatalf("request with valid audience should succeed: %v", err)
		}
	})

	t.Run("invalid audience", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@example.com",
			josejwt.Audience:       []string{"wrong-audience"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := listv1connect.NewListServiceClient(httpClient, ts.URL)

		_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
		if err == nil {
			t.Fatal("expected error for invalid audience")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		// Invalid audience returns Unauthenticated (401) - token is invalid
		// This is correct HTTP semantics: 401 = "I don't know who you are"
		if connectErr.Code() != connect.CodeUnauthenticated {
			t.Errorf("expected CodeUnauthenticated, got %v", connectErr.Code())
		}
	})
}

// Multi-tenant scenarios

func TestServerMultiTenantIdentities(t *testing.T) {
	// Test various identity types that might be used in multi-tenant deployments
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		Issuers:   []string{"https://auth.example.com"},
		Audiences: []string{"deputy-server"},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	testCases := []struct {
		name     string
		claims   josejwt.ClaimsSet
		wantErr  bool
		errCode  connect.Code
		scenario string
	}{
		{
			name: "human identity with tenant",
			claims: josejwt.ClaimsSet{
				josejwt.Subject:        "user:alice@acme.com",
				josejwt.Issuer:         "https://auth.example.com",
				josejwt.Audience:       []string{"deputy-server"},
				josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
				"tenant":               "acme-corp",
				"roles":                []string{"developer", "scanner"},
				"teams":                []string{"platform"},
			},
			wantErr:  false,
			scenario: "Human user from Acme Corp with developer/scanner roles",
		},
		{
			name: "service account with scopes",
			claims: josejwt.ClaimsSet{
				josejwt.Subject:        "sa:ci-scanner@acme-corp.iam",
				josejwt.Issuer:         "https://auth.example.com",
				josejwt.Audience:       []string{"deputy-server"},
				josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
				"tenant":               "acme-corp",
				"scopes":               []string{"scan", "sbom"},
			},
			wantErr:  false,
			scenario: "Service account for CI/CD with scan and sbom scopes",
		},
		{
			name: "admin identity",
			claims: josejwt.ClaimsSet{
				josejwt.Subject:        "user:admin@example.com",
				josejwt.Issuer:         "https://auth.example.com",
				josejwt.Audience:       []string{"deputy-server"},
				josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
				"roles":                []string{"admin"},
			},
			wantErr:  false,
			scenario: "Admin user with full access",
		},
		{
			name: "GitHub Actions OIDC token structure",
			claims: josejwt.ClaimsSet{
				josejwt.Subject:        "repo:owner/repo:ref:refs/heads/main",
				josejwt.Issuer:         "https://auth.example.com", // Would be https://token.actions.githubusercontent.com
				josejwt.Audience:       []string{"deputy-server"},
				josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
				"repository":           "owner/repo",
				"repository_owner":     "owner",
				"workflow":             "ci.yml",
				"ref":                  "refs/heads/main",
				"actor":                "github-actions[bot]",
			},
			wantErr:  false,
			scenario: "GitHub Actions OIDC workload identity",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			token := createTestToken(t, privateKey, tc.claims)

			httpClient := &http.Client{
				Transport: &authTransport{transport: http.DefaultTransport, token: token},
			}
			client := listv1connect.NewListServiceClient(httpClient, ts.URL)

			_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error for %s", tc.scenario)
				}
				if connectErr, ok := err.(*connect.Error); ok {
					if connectErr.Code() != tc.errCode {
						t.Errorf("expected %v, got %v for %s", tc.errCode, connectErr.Code(), tc.scenario)
					}
				}
			} else {
				if err != nil {
					t.Fatalf("%s should succeed: %v", tc.scenario, err)
				}
			}
		})
	}
}

// Health endpoints should work without auth

func TestHealthEndpointsNoAuth(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)
	_ = privateKey

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)

	// Health endpoints should still work without auth
	endpoints := []string{"/health", "/ready", "/version"}

	for _, ep := range endpoints {
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		rec := httptest.NewRecorder()

		srv.Handler().ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("endpoint %s should return 200 without auth, got %d", ep, rec.Code)
		}
	}
}

// Config builder tests

func TestGetAuthMode(t *testing.T) {
	tests := []struct {
		name     string
		config   *AuthConfig
		expected string
		wantErr  bool
	}{
		{"nil config", nil, "disabled", false},
		{"empty mode", &AuthConfig{Mode: ""}, "disabled", false},
		{"disabled mode", &AuthConfig{Mode: "disabled"}, "disabled", false},
		{"required mode", &AuthConfig{Mode: "required"}, "required", false},
		{"case insensitive", &AuthConfig{Mode: "REQUIRED"}, "required", false},
		{"unknown mode errors", &AuthConfig{Mode: "optional"}, "disabled", true},
		{"deprecated Enabled field", &AuthConfig{Enabled: true}, "required", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := getAuthMode(tt.config)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestBuildJWTConfig(t *testing.T) {
	t.Run("nil config", func(t *testing.T) {
		cfg := buildJWTConfig(nil)
		if cfg != nil {
			t.Error("expected nil config")
		}
	})

	t.Run("full config", func(t *testing.T) {
		authCfg := &AuthConfig{
			Mode: "required",
			JWKS: &JWKSConfig{
				URL:             "https://auth.example.com/.well-known/jwks.json",
				OIDCDiscovery:   true,
				RefreshInterval: time.Hour,
			},
			StaticKeys: []StaticKeyConfig{
				{KeyID: "key1", Algorithm: "ES256", PublicKey: "pem-data"},
			},
			Issuers:        []string{"https://auth.example.com"},
			Audiences:      []string{"deputy-server"},
			RequiredClaims: []string{"sub", "tenant"},
			ClockSkew:      30 * time.Second,
		}

		jwtCfg := buildJWTConfig(authCfg)
		if jwtCfg == nil {
			t.Fatal("expected non-nil config")
		}
		if jwtCfg.JWKS == nil {
			t.Error("expected JWKS config")
		}
		if jwtCfg.JWKS.URL != "https://auth.example.com/.well-known/jwks.json" {
			t.Errorf("unexpected JWKS URL: %s", jwtCfg.JWKS.URL)
		}
		if len(jwtCfg.StaticKeys) != 1 {
			t.Errorf("expected 1 static key, got %d", len(jwtCfg.StaticKeys))
		}
		if len(jwtCfg.Issuers) != 1 || jwtCfg.Issuers[0] != "https://auth.example.com" {
			t.Error("unexpected issuers")
		}
	})

	t.Run("deprecated JWKSURL field", func(t *testing.T) {
		authCfg := &AuthConfig{
			Mode:    "required",
			JWKSURL: "https://legacy.example.com/jwks",
		}

		jwtCfg := buildJWTConfig(authCfg)
		if jwtCfg.JWKS == nil {
			t.Error("expected JWKS config from deprecated field")
		}
		if jwtCfg.JWKS.URL != "https://legacy.example.com/jwks" {
			t.Errorf("unexpected JWKS URL: %s", jwtCfg.JWKS.URL)
		}
	})
}

// Test that scan service also respects auth

func TestScanServiceAuth(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("unauthenticated scan request rejected", func(t *testing.T) {
		client := scanv1connect.NewScanServiceClient(http.DefaultClient, ts.URL)

		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "github.com/test/repo",
		}))
		if err == nil {
			t.Fatal("expected error for unauthenticated request")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		if connectErr.Code() != connect.CodeUnauthenticated {
			t.Errorf("expected CodeUnauthenticated, got %v", connectErr.Code())
		}
	})

	t.Run("authenticated scan request proceeds to validation", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := scanv1connect.NewScanServiceClient(httpClient, ts.URL)

		// Request should pass auth, but may fail on scan validation
		// (that's fine - we're testing auth, not scan logic)
		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "", // Empty target should cause InvalidArgument, not Unauthenticated
		}))

		if err == nil {
			t.Fatal("expected error for empty target")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		// Should NOT be Unauthenticated - auth passed
		if connectErr.Code() == connect.CodeUnauthenticated {
			t.Error("request should have passed authentication")
		}
	})
}

// authTransport is an http.RoundTripper that adds Bearer token auth
type authTransport struct {
	transport http.RoundTripper
	token     string
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.transport.RoundTrip(req)
}

// Integration test with policy evaluation

func TestServerAuthWithPolicy(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	// Create a temporary policy file
	policyContent := `
policies:
  - name: require-scanner-role
    entrypoints:
      - service_scan_request
    rules:
      - action: deny
        when: |
          !jwt.anonymous &&
          !jwt.?roles.orValue([]).exists(r, r in ["scanner", "admin"])
        reason: "Scanner or admin role required"
`
	policyFile := t.TempDir() + "/test-policy.yaml"
	if err := writeTestFile(policyFile, policyContent); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}
	cfg.Policies = []string{policyFile}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("user without scanner role denied", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"roles":                []string{"developer"}, // Not scanner or admin
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := scanv1connect.NewScanServiceClient(httpClient, ts.URL)

		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "github.com/test/repo",
		}))
		if err == nil {
			t.Fatal("expected error for user without scanner role")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		if connectErr.Code() != connect.CodePermissionDenied {
			t.Errorf("expected CodePermissionDenied, got %v", connectErr.Code())
		}
	})

	t.Run("user with scanner role allowed", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:bob@example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"roles":                []string{"scanner"},
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := scanv1connect.NewScanServiceClient(httpClient, ts.URL)

		// Request should pass policy, but may fail on scan validation
		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "", // Empty target - auth and policy passed
		}))

		if err != nil {
			connectErr, ok := err.(*connect.Error)
			if ok && connectErr.Code() == connect.CodePermissionDenied {
				t.Error("scanner role should pass policy check")
			}
			// Other errors (like InvalidArgument) are expected
		}
	})

	t.Run("admin role also allowed", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:admin@example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"roles":                []string{"admin"},
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := scanv1connect.NewScanServiceClient(httpClient, ts.URL)

		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "",
		}))

		if err != nil {
			connectErr, ok := err.(*connect.Error)
			if ok && connectErr.Code() == connect.CodePermissionDenied {
				t.Error("admin role should pass policy check")
			}
		}
	})
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0600)
}

// =============================================================================
// Security Tests
// =============================================================================

func TestServerSecurity_AlgorithmConfusion(t *testing.T) {
	// Security test: Ensure algorithm confusion attacks are prevented.
	// An attacker cannot forge tokens by switching RS256 to HS256 and using
	// the public key as the HMAC secret.
	//
	// References:
	// - https://portswigger.net/web-security/jwt/algorithm-confusion
	// - https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/

	_, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Try to send a token with alg=none (classic JWT bypass)
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoidGVzdC1rZXkifQ.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0."

	httpClient := &http.Client{
		Transport: &authTransport{transport: http.DefaultTransport, token: noneToken},
	}
	client := listv1connect.NewListServiceClient(httpClient, ts.URL)

	_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err == nil {
		t.Fatal("SECURITY VULNERABILITY: Server accepted alg=none token")
	}

	// Try to send a token with alg=HS256 (algorithm confusion attack)
	hs256Token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJzdWIiOiJhdHRhY2tlciIsImV4cCI6OTk5OTk5OTk5OX0.fake_signature"

	httpClient2 := &http.Client{
		Transport: &authTransport{transport: http.DefaultTransport, token: hs256Token},
	}
	client2 := listv1connect.NewListServiceClient(httpClient2, ts.URL)

	_, err = client2.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err == nil {
		t.Fatal("SECURITY VULNERABILITY: Server accepted HS256 token when ES256 expected")
	}
}

func TestServerSecurity_TokenReplay(t *testing.T) {
	// Security test: Verify expired tokens are rejected even if previously valid.
	// This ensures token replay attacks with stale tokens fail.

	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create an expired token
	expiredToken := createTestToken(t, privateKey, josejwt.ClaimsSet{
		josejwt.Subject:        "user:alice@example.com",
		josejwt.ExpirationTime: time.Now().Add(-1 * time.Hour).Unix(), // Expired 1 hour ago
	})

	httpClient := &http.Client{
		Transport: &authTransport{transport: http.DefaultTransport, token: expiredToken},
	}
	client := listv1connect.NewListServiceClient(httpClient, ts.URL)

	_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err == nil {
		t.Fatal("SECURITY: Server accepted expired token")
	}
}

func TestServerSecurity_WrongKeyID(t *testing.T) {
	// Security test: Tokens signed with unknown keys are rejected.

	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "correct-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Create a token with a different key ID
	token, err := josejwt.New(
		header.Parameters{
			header.Type:      josejwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "wrong-key", // Different from configured "correct-key"
		},
		josejwt.ClaimsSet{
			josejwt.Subject:        "attacker",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	httpClient := &http.Client{
		Transport: &authTransport{transport: http.DefaultTransport, token: token.String()},
	}
	client := listv1connect.NewListServiceClient(httpClient, ts.URL)

	_, err = client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
	if err == nil {
		t.Fatal("SECURITY: Server accepted token with unknown key ID")
	}
}

// E2E test simulating GitHub Actions OIDC flow
func TestServerOIDC_GitHubActionsE2E(t *testing.T) {
	// This test simulates the end-to-end flow of a GitHub Actions workflow
	// authenticating to Deputy server using OIDC.
	//
	// In production:
	// 1. GitHub Actions workflow requests OIDC token from actions runtime
	// 2. Token contains claims like repository, repository_owner, workflow, ref
	// 3. Deputy server validates token against GitHub's JWKS
	// 4. CEL policies authorize based on claims

	privateKey, publicKeyPEM := generateTestKeyPair(t)

	// Create a test policy that restricts access based on GitHub Actions claims
	policyContent := `
policies:
  - name: github-actions-org-restriction
    entrypoints:
      - service_scan_request
    rules:
      - action: deny
        when: |
          jwt.?iss.orValue("") == "https://token.actions.githubusercontent.com" &&
          jwt.?repository_owner.orValue("") != "trusted-org"
        reason: "Only trusted-org workflows are allowed"

  - name: github-actions-allow
    entrypoints:
      - service_scan_request
      - service_list_request
    rules:
      - action: allow
        when: |
          jwt.?iss.orValue("") == "https://token.actions.githubusercontent.com" &&
          jwt.?repository_owner.orValue("") == "trusted-org"
        reason: "Trusted GitHub Actions workflow"
`
	policyFile := t.TempDir() + "/github-policy.yaml"
	if err := writeTestFile(policyFile, policyContent); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		Issuers:   []string{"https://token.actions.githubusercontent.com"},
		Audiences: []string{"deputy-server"},
	}
	cfg.Policies = []string{policyFile}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("trusted organization allowed", func(t *testing.T) {
		// Simulate GitHub Actions token from trusted org
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "repo:trusted-org/my-repo:ref:refs/heads/main",
			josejwt.Issuer:         "https://token.actions.githubusercontent.com",
			josejwt.Audience:       []string{"deputy-server"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"repository":           "trusted-org/my-repo",
			"repository_owner":     "trusted-org",
			"workflow":             "ci.yml",
			"ref":                  "refs/heads/main",
			"actor":                "developer",
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := listv1connect.NewListServiceClient(httpClient, ts.URL)

		_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
		if err != nil {
			t.Fatalf("trusted org should be allowed: %v", err)
		}
	})

	t.Run("untrusted organization denied", func(t *testing.T) {
		// Simulate GitHub Actions token from untrusted org
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "repo:evil-org/malicious-repo:ref:refs/heads/main",
			josejwt.Issuer:         "https://token.actions.githubusercontent.com",
			josejwt.Audience:       []string{"deputy-server"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"repository":           "evil-org/malicious-repo",
			"repository_owner":     "evil-org",
			"workflow":             "attack.yml",
			"ref":                  "refs/heads/main",
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := scanv1connect.NewScanServiceClient(httpClient, ts.URL)

		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "github.com/test/repo",
		}))
		if err == nil {
			t.Fatal("untrusted org should be denied")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		if connectErr.Code() != connect.CodePermissionDenied {
			t.Errorf("expected CodePermissionDenied, got %v", connectErr.Code())
		}
	})

	t.Run("wrong issuer denied", func(t *testing.T) {
		// Token from wrong issuer should be rejected
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:attacker",
			josejwt.Issuer:         "https://evil-issuer.com",
			josejwt.Audience:       []string{"deputy-server"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := listv1connect.NewListServiceClient(httpClient, ts.URL)

		_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
		if err == nil {
			t.Fatal("wrong issuer should be denied")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		// Wrong issuer returns Unauthenticated (401) - token is invalid
		// This is correct HTTP semantics: 401 = "I don't know who you are"
		if connectErr.Code() != connect.CodeUnauthenticated {
			t.Errorf("expected CodeUnauthenticated for wrong issuer, got %v", connectErr.Code())
		}
	})

	t.Run("wrong audience denied", func(t *testing.T) {
		// Token for wrong audience should be rejected
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "repo:trusted-org/my-repo:ref:refs/heads/main",
			josejwt.Issuer:         "https://token.actions.githubusercontent.com",
			josejwt.Audience:       []string{"wrong-audience"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"repository_owner":     "trusted-org",
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := listv1connect.NewListServiceClient(httpClient, ts.URL)

		_, err := client.ListEcosystems(t.Context(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
		if err == nil {
			t.Fatal("wrong audience should be denied")
		}
	})
}

// Test for CEL policy with tenant isolation
func TestServerPolicy_TenantIsolation(t *testing.T) {
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	// Create tenant isolation policy
	policyContent := `
policies:
  - name: tenant-isolation
    entrypoints:
      - service_scan_request
    rules:
      - action: deny
        when: |
          !jwt.anonymous &&
          has(jwt.tenant) &&
          has(request.target) &&
          request.target != "" &&
          !request.target.contains(jwt.tenant)
        reason: "Cross-tenant access denied"
`
	policyFile := t.TempDir() + "/tenant-policy.yaml"
	if err := writeTestFile(policyFile, policyContent); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	cfg := DefaultConfig()
	cfg.Auth = &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}
	cfg.Policies = []string{policyFile}

	srv := newTestServer(t, cfg)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	t.Run("same tenant allowed", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@acme.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"tenant":               "acme",
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := scanv1connect.NewScanServiceClient(httpClient, ts.URL)

		// Scanning a target in the same tenant should pass policy (fail on validation)
		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "github.com/acme/internal-app",
		}))

		// Should NOT be permission denied
		if err != nil {
			connectErr, ok := err.(*connect.Error)
			if ok && connectErr.Code() == connect.CodePermissionDenied {
				t.Error("same tenant should not be denied by policy")
			}
		}
	})

	t.Run("cross tenant denied", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user:alice@acme.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"tenant":               "acme",
		})

		httpClient := &http.Client{
			Transport: &authTransport{transport: http.DefaultTransport, token: token},
		}
		client := scanv1connect.NewScanServiceClient(httpClient, ts.URL)

		// Scanning a target from different tenant should be denied
		_, err := client.Scan(t.Context(), connect.NewRequest(&scanv1.ScanRequest{
			Target: "github.com/other-company/secret-app",
		}))
		if err == nil {
			t.Fatal("cross-tenant access should be denied")
		}

		connectErr, ok := err.(*connect.Error)
		if !ok {
			t.Fatalf("expected connect.Error, got %T", err)
		}
		if connectErr.Code() != connect.CodePermissionDenied {
			t.Errorf("expected CodePermissionDenied, got %v", connectErr.Code())
		}
	})
}
