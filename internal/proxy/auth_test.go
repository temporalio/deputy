package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwk"
	"github.com/picatz/jose/pkg/jwt"
)

// testHTTPClient returns an HTTP client without SSRF protection for tests that use httptest servers.
// The SafeDialer blocks localhost by default, which is correct for production but breaks tests.
func testHTTPClient() *http.Client {
	return &http.Client{Timeout: 30 * time.Second}
}

func TestAuthConfig_GetMode(t *testing.T) {
	tests := []struct {
		name     string
		config   *AuthConfig
		expected AuthMode
	}{
		{
			name:     "nil config",
			config:   nil,
			expected: AuthModeDisabled,
		},
		{
			name:     "empty mode",
			config:   &AuthConfig{Mode: ""},
			expected: AuthModeDisabled,
		},
		{
			name:     "disabled mode",
			config:   &AuthConfig{Mode: "disabled"},
			expected: AuthModeDisabled,
		},
		{
			name:     "optional mode",
			config:   &AuthConfig{Mode: "optional"},
			expected: AuthModeOptional,
		},
		{
			name:     "required mode",
			config:   &AuthConfig{Mode: "required"},
			expected: AuthModeRequired,
		},
		{
			name:     "case insensitive",
			config:   &AuthConfig{Mode: "REQUIRED"},
			expected: AuthModeRequired,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetMode()
			if got != tt.expected {
				t.Errorf("GetMode() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAuthConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *AuthConfig
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid disabled mode",
			config:  &AuthConfig{Mode: "disabled"},
			wantErr: false,
		},
		{
			name:    "invalid mode",
			config:  &AuthConfig{Mode: "invalid"},
			wantErr: true,
			errMsg:  "mode",
		},
		{
			name: "required mode without keys",
			config: &AuthConfig{
				Mode: "required",
			},
			wantErr: true,
			errMsg:  "jwks or static_keys",
		},
		{
			name: "valid required mode with JWKS",
			config: &AuthConfig{
				Mode: "required",
				JWKS: &JWKSConfig{URL: "https://example.com/.well-known/jwks.json"},
			},
			wantErr: false,
		},
		{
			name: "valid required mode with static keys",
			config: &AuthConfig{
				Mode: "required",
				StaticKeys: []StaticKeyConfig{
					{KeyID: "key1", Algorithm: "RS256", PublicKey: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"},
				},
			},
			wantErr: false,
		},
		{
			name: "JWKS without URL",
			config: &AuthConfig{
				Mode: "required",
				JWKS: &JWKSConfig{},
			},
			wantErr: true,
			errMsg:  "JWKS URL is required",
		},
		{
			name: "static key without kid",
			config: &AuthConfig{
				Mode: "required",
				StaticKeys: []StaticKeyConfig{
					{Algorithm: "RS256", PublicKey: "key"},
				},
			},
			wantErr: true,
			errMsg:  "key ID is required",
		},
		{
			name: "static key without algorithm",
			config: &AuthConfig{
				Mode: "required",
				StaticKeys: []StaticKeyConfig{
					{KeyID: "key1", PublicKey: "key"},
				},
			},
			wantErr: true,
			errMsg:  "algorithm is required",
		},
		{
			name: "static key without public key",
			config: &AuthConfig{
				Mode: "required",
				StaticKeys: []StaticKeyConfig{
					{KeyID: "key1", Algorithm: "RS256"},
				},
			},
			wantErr: true,
			errMsg:  "public key is required",
		},
		{
			name: "negative clock skew",
			config: &AuthConfig{
				Mode:      "required",
				JWKS:      &JWKSConfig{URL: "https://example.com/.well-known/jwks.json"},
				ClockSkew: -1 * time.Second,
			},
			wantErr: true,
			errMsg:  "clock skew must be non-negative",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use the standalone validation function since AuthConfig is now a type alias
			err := validateAuthConfig(tt.config, "test")
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAuthConfig() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("validateAuthConfig() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestJWTClaims_ToMap(t *testing.T) {
	claims := &JWTClaims{
		Subject:   "user123",
		Issuer:    "https://auth.example.com",
		Audience:  []string{"deputy-proxy"},
		ExpiresAt: 1700000000,
		IssuedAt:  1699990000,
		NotBefore: 1699990000,
		JWTID:     "jti123",
		Custom: map[string]any{
			"roles":  []string{"admin", "user"},
			"email":  "user@example.com",
			"tenant": "acme",
		},
	}

	m := claims.ToMap()

	if m["anonymous"] != false {
		t.Error("expected anonymous to be false")
	}
	if m["sub"] != "user123" {
		t.Errorf("expected sub to be 'user123', got %v", m["sub"])
	}
	if m["iss"] != "https://auth.example.com" {
		t.Errorf("expected iss to be 'https://auth.example.com', got %v", m["iss"])
	}

	roles, ok := m["roles"].([]string)
	if !ok {
		t.Errorf("expected roles to be []string, got %T", m["roles"])
	} else if len(roles) != 2 {
		t.Errorf("expected 2 roles, got %d", len(roles))
	}

	if m["email"] != "user@example.com" {
		t.Errorf("expected email to be 'user@example.com', got %v", m["email"])
	}
}

func TestAnonymousClaims(t *testing.T) {
	m := AnonymousClaims()

	if m["anonymous"] != true {
		t.Error("expected anonymous to be true")
	}
}

func TestAuthError_HTTPStatus(t *testing.T) {
	tests := []struct {
		code     string
		expected int
	}{
		{AuthCodeMissingToken, http.StatusUnauthorized},
		{AuthCodeInvalidToken, http.StatusUnauthorized},
		{AuthCodeExpiredToken, http.StatusUnauthorized},
		{AuthCodeSignatureInvalid, http.StatusUnauthorized},
		{AuthCodeKeyNotFound, http.StatusUnauthorized},
		{AuthCodeInvalidIssuer, http.StatusForbidden},
		{AuthCodeInvalidAudience, http.StatusForbidden},
		{AuthCodeMissingClaim, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			err := &AuthError{Code: tt.code, Message: "test"}
			if got := err.HTTPStatus(); got != tt.expected {
				t.Errorf("HTTPStatus() = %d, want %d", got, tt.expected)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	// Generate RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	rsaPubBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal RSA public key: %v", err)
	}

	rsaPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: rsaPubBytes,
	})

	// Generate ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}

	ecdsaPubBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal ECDSA public key: %v", err)
	}

	ecdsaPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: ecdsaPubBytes,
	})

	tests := []struct {
		name    string
		pem     string
		wantErr bool
	}{
		{
			name:    "valid RSA public key",
			pem:     string(rsaPEM),
			wantErr: false,
		},
		{
			name:    "valid ECDSA public key",
			pem:     string(ecdsaPEM),
			wantErr: false,
		},
		{
			name:    "invalid PEM",
			pem:     "not a pem",
			wantErr: true,
		},
		{
			name:    "empty PEM",
			pem:     "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parsePublicKey(tt.pem)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePublicKey() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestWithAuthentication_Disabled(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Test with nil authenticator
	wrapped := withAuthentication(nil, AuthModeDisabled)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestWithAuthentication_RequiredNoToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	// Create a mock authenticator that returns nil claims (no token)
	auth := &mockAuthenticator{claims: nil, err: nil}
	wrapped := withAuthentication(auth, AuthModeRequired)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Error("expected WWW-Authenticate header")
	}
}

func TestWithAuthentication_OptionalNoToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := JWTClaimsFromContext(r.Context())
		if claims != nil {
			t.Error("expected nil claims for anonymous request")
		}
		w.WriteHeader(http.StatusOK)
	})

	auth := &mockAuthenticator{claims: nil, err: nil}
	wrapped := withAuthentication(auth, AuthModeOptional)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestWithAuthentication_ValidToken(t *testing.T) {
	expectedClaims := &JWTClaims{
		Subject: "user123",
		Issuer:  "https://auth.example.com",
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := JWTClaimsFromContext(r.Context())
		if claims == nil {
			t.Error("expected claims in context")
			return
		}
		if claims.Subject != expectedClaims.Subject {
			t.Errorf("expected subject %q, got %q", expectedClaims.Subject, claims.Subject)
		}
		w.WriteHeader(http.StatusOK)
	})

	auth := &mockAuthenticator{claims: expectedClaims, err: nil}
	wrapped := withAuthentication(auth, AuthModeRequired)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer test-token")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestWithAuthentication_InvalidToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler should not be called for invalid token")
	})

	auth := &mockAuthenticator{
		claims: nil,
		err:    &AuthError{Code: AuthCodeInvalidToken, Message: "invalid token"},
	}
	wrapped := withAuthentication(auth, AuthModeRequired)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token")
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}

	if rec.Header().Get("X-Deputy-Auth-Error") != AuthCodeInvalidToken {
		t.Errorf("expected X-Deputy-Auth-Error header to be %q", AuthCodeInvalidToken)
	}
}

func TestJWKSServer(t *testing.T) {
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

	// Create JWKS cache with test HTTP client to bypass SafeDialer
	cache, err := NewJWKSCache(&JWKSConfig{
		URL:             jwksServer.URL,
		RefreshInterval: 1 * time.Hour,
	}, WithJWKSHTTPClient(testHTTPClient()))
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// Get key from cache
	key, err := cache.GetKey(t.Context(), "test-key-1")
	if err != nil {
		t.Fatalf("failed to get key: %v", err)
	}

	ecdsaPub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}

	// Verify it's the same key
	if !ecdsaPub.Equal(&privateKey.PublicKey) {
		t.Error("retrieved key does not match original key")
	}
}

func TestAuthenticator_WithStaticKey(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Create authenticator with static key
	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
		Issuers:   []string{"https://auth.example.com"},
		Audiences: []string{"deputy-proxy"},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create a valid JWT
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key",
		},
		jwt.ClaimsSet{
			jwt.Subject:        "user123",
			jwt.Issuer:         "https://auth.example.com",
			jwt.Audience:       []string{"deputy-proxy"},
			jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
			jwt.IssuedAt:       time.Now().Unix(),
			"email":            "user@example.com",
			"roles":            []string{"admin"},
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Create request with token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token.String())

	// Authenticate
	claims, err := auth.Authenticate(t.Context(), req)
	if err != nil {
		t.Fatalf("authentication failed: %v", err)
	}

	if claims.Subject != "user123" {
		t.Errorf("expected subject 'user123', got %q", claims.Subject)
	}
	if claims.Issuer != "https://auth.example.com" {
		t.Errorf("expected issuer 'https://auth.example.com', got %q", claims.Issuer)
	}
	if claims.Custom["email"] != "user@example.com" {
		t.Errorf("expected email 'user@example.com', got %v", claims.Custom["email"])
	}
}

func TestAuthenticator_ExpiredToken(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Create authenticator with static key
	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create an expired JWT
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key",
		},
		jwt.ClaimsSet{
			jwt.Subject:        "user123",
			jwt.ExpirationTime: time.Now().Add(-1 * time.Hour).Unix(), // Expired
			jwt.IssuedAt:       time.Now().Add(-2 * time.Hour).Unix(),
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Create request with token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token.String())

	// Authenticate should fail
	_, err = auth.Authenticate(t.Context(), req)
	if err == nil {
		t.Fatal("expected authentication to fail for expired token")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	// The jose library may reject expired tokens during signature verification
	// or our validateClaims may catch it. Both are acceptable outcomes.
	if authErr.Code != AuthCodeExpiredToken && authErr.Code != AuthCodeSignatureInvalid {
		t.Errorf("expected error code %q or %q, got %q", AuthCodeExpiredToken, AuthCodeSignatureInvalid, authErr.Code)
	}
}

func TestAuthenticator_InvalidIssuer(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Create authenticator with issuer validation
	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
		Issuers: []string{"https://trusted.example.com"},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create JWT with wrong issuer
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key",
		},
		jwt.ClaimsSet{
			jwt.Subject:        "user123",
			jwt.Issuer:         "https://untrusted.example.com",
			jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Create request with token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token.String())

	// Authenticate should fail
	_, err = auth.Authenticate(t.Context(), req)
	if err == nil {
		t.Fatal("expected authentication to fail for invalid issuer")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Code != AuthCodeInvalidIssuer {
		t.Errorf("expected error code %q, got %q", AuthCodeInvalidIssuer, authErr.Code)
	}
}

func TestAuthenticator_NoToken(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Create authenticator
	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create request without token
	req := httptest.NewRequest("GET", "/test", nil)

	// Authenticate should return nil claims (anonymous)
	claims, err := auth.Authenticate(t.Context(), req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if claims != nil {
		t.Error("expected nil claims for request without token")
	}
}

// mockAuthenticator is a mock implementation of Authenticator for testing.
type mockAuthenticator struct {
	claims *JWTClaims
	err    error
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*JWTClaims, error) {
	return m.claims, m.err
}

func (m *mockAuthenticator) Close() error {
	return nil
}

func TestAuthenticator_AllowedAlgorithms(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Create authenticator that only allows RS256 (not ES256)
	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
		AllowedAlgorithms: []string{"RS256"}, // Only allow RS256, not ES256
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create valid JWT with ES256 (which is not in allowed list)
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key",
		},
		jwt.ClaimsSet{
			jwt.Subject:        "user123",
			jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Create request with token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token.String())

	// Authenticate should fail due to algorithm restriction
	_, err = auth.Authenticate(t.Context(), req)
	if err == nil {
		t.Fatal("expected authentication to fail for disallowed algorithm")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Code != AuthCodeSignatureInvalid {
		t.Errorf("expected error code %q, got %q", AuthCodeSignatureInvalid, authErr.Code)
	}
	// Note: the user-facing message is generic for security; detailed error is in Cause
	if authErr.Message != "token signature verification failed" {
		t.Errorf("expected generic error message, got %q", authErr.Message)
	}
	// The underlying cause should contain the specific algorithm error
	if authErr.Cause == nil || !strings.Contains(authErr.Cause.Error(), "not allowed") {
		t.Errorf("expected underlying cause to contain 'not allowed', got %v", authErr.Cause)
	}
}

func TestAuthenticator_DefaultAllowedAlgorithms(t *testing.T) {
	// Verify that default allowed algorithms include common secure asymmetric algorithms
	expected := []string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "EdDSA", "PS256", "PS384", "PS512"}
	for _, alg := range expected {
		found := slices.Contains(DefaultAllowedAlgorithms, alg)
		if !found {
			t.Errorf("expected %q in DefaultAllowedAlgorithms", alg)
		}
	}

	// Verify that insecure algorithms like "none" and HS256 are NOT in defaults
	// (HS256 is symmetric and susceptible to key confusion attacks with public keys)
	insecure := []string{"none", "HS256", "HS384", "HS512"}
	for _, alg := range insecure {
		for _, defaultAlg := range DefaultAllowedAlgorithms {
			if alg == defaultAlg {
				t.Errorf("%q should not be in DefaultAllowedAlgorithms (insecure)", alg)
			}
		}
	}
}

func TestAuthenticator_NotBeforeToken(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Create authenticator with static key (no clock skew)
	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create a token that is not yet valid (nbf in the future)
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key",
		},
		jwt.ClaimsSet{
			jwt.Subject:        "user123",
			jwt.ExpirationTime: time.Now().Add(2 * time.Hour).Unix(),
			jwt.NotBefore:      time.Now().Add(1 * time.Hour).Unix(), // Not valid yet
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Create request with token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token.String())

	// Authenticate should fail
	_, err = auth.Authenticate(t.Context(), req)
	if err == nil {
		t.Fatal("expected authentication to fail for not-yet-valid token")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	// The token should be rejected for nbf violation
	if authErr.Code != AuthCodeExpiredToken && authErr.Code != AuthCodeSignatureInvalid {
		t.Errorf("expected error code %q or %q, got %q", AuthCodeExpiredToken, AuthCodeSignatureInvalid, authErr.Code)
	}
}

func TestAuthenticator_NotBeforeValid(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create a token with nbf in the past (should be valid)
	token, err := jwt.New(
		header.Parameters{
			header.Type:      jwt.Type,
			header.Algorithm: jwa.ES256,
			header.KeyID:     "test-key",
		},
		jwt.ClaimsSet{
			jwt.Subject:        "user123",
			jwt.ExpirationTime: time.Now().Add(1 * time.Hour).Unix(),
			jwt.NotBefore:      time.Now().Add(-1 * time.Minute).Unix(), // 1 min in past, valid
		},
		privateKey,
	)
	if err != nil {
		t.Fatalf("failed to create token: %v", err)
	}

	// Create request with token
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token.String())

	// Authenticate should succeed
	claims, err := auth.Authenticate(t.Context(), req)
	if err != nil {
		t.Fatalf("expected authentication to succeed, got error: %v", err)
	}
	if claims == nil {
		t.Fatal("expected claims to be non-nil")
	}
	if claims.Subject != "user123" {
		t.Errorf("expected subject 'user123', got %q", claims.Subject)
	}
}

func TestJWKSCache_ConcurrentAccess(t *testing.T) {
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

	// Create JWKS cache with test HTTP client to bypass SafeDialer
	cache, err := NewJWKSCache(&JWKSConfig{
		URL:             jwksServer.URL,
		RefreshInterval: 100 * time.Millisecond,
	}, WithJWKSHTTPClient(testHTTPClient()))
	if err != nil {
		t.Fatalf("failed to create JWKS cache: %v", err)
	}
	defer cache.Close()

	// Pre-warm the cache so we're testing concurrent reads from memory
	_, err = cache.GetKey(t.Context(), "test-key-1")
	if err != nil {
		t.Fatalf("failed to pre-warm cache: %v", err)
	}

	// Use synctest for deterministic concurrent testing of in-memory operations
	synctest.Test(t, func(t *testing.T) {
		const goroutines = 10
		const iterations = 100

		var errorCount atomic.Int64

		for range goroutines {
			go func() {
				for range iterations {
					// Access the already-cached key (no network I/O)
					_, err := cache.GetKey(t.Context(), "test-key-1")
					if err != nil {
						errorCount.Add(1)
					}
				}
			}()
		}

		// Wait for all goroutines to complete
		synctest.Wait()

		if errors := errorCount.Load(); errors > 0 {
			t.Errorf("concurrent access produced %d errors", errors)
		}
	})
}

func TestAuthMetrics_ConcurrentAccess(t *testing.T) {
	// Use synctest for deterministic concurrent testing
	synctest.Test(t, func(t *testing.T) {
		metrics := &AuthMetrics{}

		const goroutines = 10
		const iterations = 100

		// Concurrent success recording
		for range goroutines {
			go func() {
				for range iterations {
					metrics.RecordSuccess()
				}
			}()
		}

		// Concurrent anonymous recording
		for range goroutines {
			go func() {
				for range iterations {
					metrics.RecordAnonymous()
				}
			}()
		}

		// Concurrent error recording
		for range goroutines {
			go func() {
				for range iterations {
					metrics.RecordError(AuthCodeInvalidToken)
				}
			}()
		}

		// Wait for all goroutines to complete
		synctest.Wait()

		// Verify counts (each type: goroutines * iterations)
		expected := int64(goroutines * iterations)

		if got := metrics.Authenticated.Load(); got != expected {
			t.Errorf("Authenticated = %d, want %d", got, expected)
		}
		if got := metrics.Anonymous.Load(); got != expected {
			t.Errorf("Anonymous = %d, want %d", got, expected)
		}
		if got := metrics.Rejected.InvalidToken.Load(); got != expected {
			t.Errorf("Rejected.InvalidToken = %d, want %d", got, expected)
		}

		// Total should be 3x (success + anonymous + error)
		expectedTotal := expected * 3
		if got := metrics.TotalRequests.Load(); got != expectedTotal {
			t.Errorf("TotalRequests = %d, want %d", got, expectedTotal)
		}
	})
}

func TestJWTClaimsFromContext(t *testing.T) {
	t.Run("context without claims", func(t *testing.T) {
		ctx := t.Context()
		claims := JWTClaimsFromContext(ctx)
		if claims != nil {
			t.Error("expected nil claims for context without claims")
		}
	})

	t.Run("context with claims", func(t *testing.T) {
		expected := &JWTClaims{Subject: "user123"}
		ctx := ContextWithJWTClaims(t.Context(), expected)
		claims := JWTClaimsFromContext(ctx)
		if claims == nil {
			t.Fatal("expected non-nil claims")
		}
		if claims.Subject != expected.Subject {
			t.Errorf("expected subject %q, got %q", expected.Subject, claims.Subject)
		}
	})
}

func TestAuthenticator_MalformedToken(t *testing.T) {
	// Generate ECDSA key for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Encode public key as PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	auth, err := NewAuthenticator(&AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "test-key",
				Algorithm: "ES256",
				PublicKey: string(pubPEM),
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "not a JWT",
			token: "not-a-jwt-at-all",
		},
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "only two parts",
			token: "header.payload",
		},
		{
			name:  "invalid base64",
			token: "!!!.!!!.!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", nil)
			req.Header.Set("Authorization", "Bearer "+tt.token)

			_, err := auth.Authenticate(t.Context(), req)
			if err == nil {
				t.Fatal("expected authentication to fail for malformed token")
			}

			authErr, ok := err.(*AuthError)
			if !ok {
				t.Fatalf("expected *AuthError, got %T", err)
			}
			if authErr.Code != AuthCodeInvalidToken {
				t.Errorf("expected error code %q, got %q", AuthCodeInvalidToken, authErr.Code)
			}
		})
	}
}

// TestNewAuthenticator_CleanupOnStaticKeyError verifies that JWKS cache is properly
// closed if static key parsing fails after cache creation (prevents goroutine leak).
func TestNewAuthenticator_CleanupOnStaticKeyError(t *testing.T) {
	// Create a test JWKS server
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, err := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jwkValue[jwk.KeyID] = "test-key"
		keySet := &jwk.Set{Keys: []jwk.Value{jwkValue}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	// This config has a valid JWKS URL but an invalid static key
	cfg := &AuthConfig{
		Mode: "required",
		JWKS: &JWKSConfig{
			URL: jwksServer.URL,
		},
		StaticKeys: []StaticKeyConfig{
			{
				KeyID:     "invalid-key",
				Algorithm: "RS256",
				PublicKey: "not-a-valid-pem-key", // Invalid PEM
			},
		},
	}

	// NewAuthenticator should fail but should NOT leak the JWKS cache goroutine
	// Use testHTTPClient to bypass SafeDialer which blocks localhost in production
	auth, err := NewAuthenticator(cfg, WithJWKSCacheOptions(WithJWKSHTTPClient(testHTTPClient())))
	if err == nil {
		auth.Close()
		t.Fatal("expected error for invalid static key")
	}

	if !strings.Contains(err.Error(), "parse static key") {
		t.Errorf("expected parse static key error, got: %v", err)
	}

	// The JWKS cache should have been closed; we can't directly verify the goroutine
	// is stopped, but the fix ensures Close() is called on error paths.
}

// TestJWKSCache_EmptyURL verifies that an empty URL returns an error instead of panicking.
func TestJWKSCache_EmptyURL(t *testing.T) {
	_, err := NewJWKSCache(&JWKSConfig{URL: ""})
	if err == nil {
		t.Fatal("expected error for empty URL")
	}

	if !strings.Contains(err.Error(), "JWKS URL is required") {
		t.Errorf("expected 'JWKS URL is required' error, got: %v", err)
	}
}

// TestJWKSCache_EmptyURLWithOIDCDiscovery verifies that OIDC discovery with empty URL
// returns an error instead of panicking.
func TestJWKSCache_EmptyURLWithOIDCDiscovery(t *testing.T) {
	// This would previously panic in discoverJWKSURL when checking url[len(url)-1]
	_, err := NewJWKSCache(&JWKSConfig{
		URL:           "",
		OIDCDiscovery: true,
	})
	if err == nil {
		t.Fatal("expected error for empty URL with OIDC discovery")
	}
}

// TestAuthenticator_TokenSizeLimit verifies that oversized tokens are rejected.
func TestAuthenticator_TokenSizeLimit(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	auth, err := NewAuthenticator(&AuthConfig{
		Mode:         "required",
		MaxTokenSize: 100, // Very small limit for testing
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "RS256", PublicKey: string(pubKeyPEM)},
		},
	})
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Create a request with a large token
	largeToken := strings.Repeat("x", 200) // Exceeds 100 byte limit
	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+largeToken)

	_, err = auth.Authenticate(t.Context(), req)
	if err == nil {
		t.Fatal("expected authentication to fail for oversized token")
	}

	authErr, ok := err.(*AuthError)
	if !ok {
		t.Fatalf("expected *AuthError, got %T", err)
	}
	if authErr.Code != AuthCodeInvalidToken {
		t.Errorf("expected error code %q, got %q", AuthCodeInvalidToken, authErr.Code)
	}
	if !strings.Contains(authErr.Message, "maximum allowed size") {
		t.Errorf("expected error message about size, got %q", authErr.Message)
	}
}

// TestNewAuthenticator_ClockSkewLimit verifies that excessive clock skew is rejected.
func TestNewAuthenticator_ClockSkewLimit(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes})

	// Should fail with clock skew exceeding maximum
	_, err = NewAuthenticator(&AuthConfig{
		Mode:      "required",
		ClockSkew: 10 * time.Minute, // Exceeds 5 minute maximum
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "RS256", PublicKey: string(pubKeyPEM)},
		},
	})
	if err == nil {
		t.Fatal("expected error for excessive clock skew")
	}
	if !strings.Contains(err.Error(), "clock_skew") {
		t.Errorf("expected error about clock_skew, got %q", err.Error())
	}

	// Should succeed with acceptable clock skew
	auth, err := NewAuthenticator(&AuthConfig{
		Mode:      "required",
		ClockSkew: 30 * time.Second, // Within 5 minute maximum
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "RS256", PublicKey: string(pubKeyPEM)},
		},
	})
	if err != nil {
		t.Fatalf("expected no error for acceptable clock skew, got %v", err)
	}
	auth.Close()
}

// TestJWKSCache_DoubleClose verifies that calling Close() multiple times is safe.
func TestJWKSCache_DoubleClose(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		jwkValue, err := jwk.ValueFromPublicKey(&privateKey.PublicKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		jwkValue[jwk.KeyID] = "test-key"
		keySet := &jwk.Set{Keys: []jwk.Value{jwkValue}}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(keySet)
	}))
	defer jwksServer.Close()

	cache, err := NewJWKSCache(&JWKSConfig{URL: jwksServer.URL}, WithJWKSHTTPClient(testHTTPClient()))
	if err != nil {
		t.Fatalf("failed to create cache: %v", err)
	}

	// First close should succeed
	if err := cache.Close(); err != nil {
		t.Errorf("first Close() failed: %v", err)
	}

	// Second close should not panic
	if err := cache.Close(); err != nil {
		t.Errorf("second Close() failed: %v", err)
	}

	// Third close should also be safe
	if err := cache.Close(); err != nil {
		t.Errorf("third Close() failed: %v", err)
	}
}
