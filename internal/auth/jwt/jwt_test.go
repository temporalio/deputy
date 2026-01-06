package jwt

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	josejwt "github.com/picatz/jose/pkg/jwt"
)

func TestConfig_GetMode(t *testing.T) {
	tests := []struct {
		name     string
		config   *Config
		expected Mode
	}{
		{"nil config", nil, ModeDisabled},
		{"empty mode", &Config{Mode: ""}, ModeDisabled},
		{"disabled mode", &Config{Mode: "disabled"}, ModeDisabled},
		{"optional mode", &Config{Mode: "optional"}, ModeOptional},
		{"required mode", &Config{Mode: "required"}, ModeRequired},
		{"case insensitive", &Config{Mode: "REQUIRED"}, ModeRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetMode()
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{"nil config", nil, false},
		{"disabled mode without keys", &Config{Mode: "disabled"}, false},
		{"clock skew too large", &Config{ClockSkew: 10 * time.Minute}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestClaims_ToMap(t *testing.T) {
	claims := &Claims{
		Subject:   "user123",
		Issuer:    "https://issuer.example.com",
		Audience:  []string{"aud1", "aud2"},
		ExpiresAt: 1234567890,
		IssuedAt:  1234567800,
		NotBefore: 1234567800,
		JWTID:     "jti123",
		Custom: map[string]any{
			"role":  "admin",
			"email": "user@example.com",
		},
	}

	m := claims.ToMap()

	if m["anonymous"] != false {
		t.Error("expected anonymous=false")
	}
	if m["sub"] != "user123" {
		t.Errorf("expected sub='user123', got %v", m["sub"])
	}
	if m["iss"] != "https://issuer.example.com" {
		t.Errorf("expected iss='https://issuer.example.com', got %v", m["iss"])
	}
	if m["role"] != "admin" {
		t.Errorf("expected role='admin', got %v", m["role"])
	}
}

func TestClaims_Get(t *testing.T) {
	claims := &Claims{
		Subject: "user123",
		Custom: map[string]any{
			"role": "admin",
		},
	}

	if claims.Get("sub") != "user123" {
		t.Error("expected to get subject")
	}
	if claims.Get("role") != "admin" {
		t.Error("expected to get custom claim")
	}
	if claims.Get("missing") != nil {
		t.Error("expected nil for missing claim")
	}
}

func TestClaims_Has(t *testing.T) {
	claims := &Claims{
		Subject: "user123",
		Custom: map[string]any{
			"role": "admin",
		},
	}

	if !claims.Has("sub") {
		t.Error("expected Has('sub') to be true")
	}
	if !claims.Has("role") {
		t.Error("expected Has('role') to be true")
	}
	if claims.Has("missing") {
		t.Error("expected Has('missing') to be false")
	}
}

func TestAnonymousClaims(t *testing.T) {
	claims := AnonymousClaims()
	if claims == nil {
		t.Fatal("expected non-nil claims")
	}
	anonymous, ok := claims["anonymous"].(bool)
	if !ok || !anonymous {
		t.Error("expected anonymous=true")
	}
}

func TestError_HTTPStatus(t *testing.T) {
	tests := []struct {
		code           string
		expectedStatus int
	}{
		{CodeMissingToken, http.StatusUnauthorized},
		{CodeInvalidToken, http.StatusUnauthorized},
		{CodeExpiredToken, http.StatusUnauthorized},
		{CodeSignatureInvalid, http.StatusUnauthorized},
		{CodeKeyNotFound, http.StatusUnauthorized},
		{CodeInvalidIssuer, http.StatusForbidden},
		{CodeInvalidAudience, http.StatusForbidden},
		{CodeMissingClaim, http.StatusForbidden},
	}

	for _, tt := range tests {
		t.Run(tt.code, func(t *testing.T) {
			err := &Error{Code: tt.code, Message: "test"}
			if err.HTTPStatus() != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, err.HTTPStatus())
			}
		})
	}
}

func TestError_Error(t *testing.T) {
	err := &Error{Code: CodeInvalidToken, Message: "bad token"}
	expected := "invalid_token: bad token"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestMiddleware_Disabled(t *testing.T) {
	mw := Middleware(nil, MiddlewareConfig{Mode: ModeDisabled})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw(handler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestSimpleMiddleware(t *testing.T) {
	// Test SimpleMiddleware is equivalent to Middleware with default config
	mw := SimpleMiddleware(nil, ModeDisabled)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw(handler)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestClaimsFromContext(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		// Intentionally testing nil context handling - ClaimsFromContext guards against this
		claims := ClaimsFromContext(nil) //nolint:staticcheck // testing nil context behavior
		if claims != nil {
			t.Error("expected nil claims for nil context")
		}
	})

	t.Run("context without claims", func(t *testing.T) {
		ctx := context.Background()
		claims := ClaimsFromContext(ctx)
		if claims != nil {
			t.Error("expected nil claims")
		}
	})

	t.Run("context with claims", func(t *testing.T) {
		expected := &Claims{Subject: "user123"}
		ctx := ContextWithClaims(context.Background(), expected)
		claims := ClaimsFromContext(ctx)
		if claims == nil {
			t.Fatal("expected non-nil claims")
		}
		if claims.Subject != expected.Subject {
			t.Errorf("expected subject %q, got %q", expected.Subject, claims.Subject)
		}
	})
}

func TestDefaultErrorHandler(t *testing.T) {
	t.Run("401 error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := &Error{Code: CodeMissingToken, Message: "authentication required"}

		DefaultErrorHandler(rec, req, err)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rec.Code)
		}
		if rec.Header().Get("WWW-Authenticate") == "" {
			t.Error("expected WWW-Authenticate header")
		}
	})

	t.Run("403 error", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		err := &Error{Code: CodeInvalidIssuer, Message: "invalid issuer"}

		DefaultErrorHandler(rec, req, err)

		if rec.Code != http.StatusForbidden {
			t.Errorf("expected status 403, got %d", rec.Code)
		}
	})
}

func TestNoopMetrics(t *testing.T) {
	// Just ensure NoopMetrics implements the interface and doesn't panic
	var m MetricsRecorder = NoopMetrics{}
	m.RecordSuccess()
	m.RecordAnonymous()
	m.RecordError("test")
	m.RecordJWKSRefresh(true)
	m.RecordJWKSKeyLookup(true)
}

func TestParsePublicKey(t *testing.T) {
	// Generate a test key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	pemData := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}))

	t.Run("valid PEM", func(t *testing.T) {
		key, err := ParsePublicKey(pemData)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if key == nil {
			t.Error("expected non-nil key")
		}
	})

	t.Run("invalid PEM", func(t *testing.T) {
		_, err := ParsePublicKey("not a valid PEM")
		if err == nil {
			t.Error("expected error for invalid PEM")
		}
	})
}

func TestAuthenticator_StaticKeys(t *testing.T) {
	// Generate test key pair
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := &Config{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	t.Run("valid token", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims == nil {
			t.Error("expected non-nil claims")
		} else if claims.Subject != "user123" {
			t.Errorf("expected subject 'user123', got %q", claims.Subject)
		}
	})

	t.Run("no token - returns nil", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)

		claims, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims != nil {
			t.Error("expected nil claims for no token")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(-time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Error("expected error for expired token")
		}
	})
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

func TestAuthenticator_RejectsNoneAlgorithm(t *testing.T) {
	// Security test: Ensure the 'none' algorithm is rejected.
	// The 'none' algorithm is a well-known JWT attack vector that allows
	// attackers to forge tokens without a valid signature.

	_, publicKeyPEM := generateTestKeyPair(t)

	cfg := &Config{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Construct a token with alg=none manually (can't use jose library for this)
	// Format: base64url({"alg":"none","typ":"JWT","kid":"test-key"}).base64url({"sub":"attacker"}).
	noneToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIiwia2lkIjoidGVzdC1rZXkifQ.eyJzdWIiOiJhdHRhY2tlciJ9."

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+noneToken)

	_, err = auth.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for 'none' algorithm token, got nil - SECURITY VULNERABILITY")
	}

	// Verify it's rejected for the right reason
	authErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if authErr.Code != CodeSignatureInvalid {
		t.Errorf("expected error code %q, got %q", CodeSignatureInvalid, authErr.Code)
	}
}

func TestAuthenticator_RejectsSymmetricAlgorithms(t *testing.T) {
	// Security test: Ensure symmetric algorithms (HS256, HS384, HS512) are rejected.
	// Symmetric algorithms require shared secrets and are not secure for
	// distributed systems where multiple parties verify tokens.

	_, publicKeyPEM := generateTestKeyPair(t)

	cfg := &Config{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	// Test that HS256 tokens are rejected
	// Format: base64url({"alg":"HS256","typ":"JWT","kid":"test-key"}).base64url({"sub":"attacker"}).signature
	// The signature is fake but we should reject based on algorithm before signature verification
	hs256Token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2V5In0.eyJzdWIiOiJhdHRhY2tlciJ9.fake_signature"

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+hs256Token)

	_, err = auth.Authenticate(context.Background(), req)
	if err == nil {
		t.Fatal("expected error for HS256 algorithm token, got nil - SECURITY VULNERABILITY")
	}

	// The error should indicate signature verification failed (algorithm not allowed)
	authErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected *Error, got %T", err)
	}
	if authErr.Code != CodeSignatureInvalid {
		t.Errorf("expected error code %q, got %q", CodeSignatureInvalid, authErr.Code)
	}
}

func TestDefaultAllowedAlgorithms_NoSymmetricOrNone(t *testing.T) {
	// Security test: Verify DefaultAllowedAlgorithms doesn't include insecure algorithms.

	insecureAlgorithms := []string{
		"none", "None", "NONE", // Algorithm bypass
		"HS256", "HS384", "HS512", // Symmetric algorithms
	}

	for _, alg := range insecureAlgorithms {
		for _, allowed := range DefaultAllowedAlgorithms {
			if strings.EqualFold(alg, allowed) {
				t.Errorf("SECURITY: DefaultAllowedAlgorithms contains insecure algorithm %q", alg)
			}
		}
	}

	// Verify we have expected secure algorithms
	expectedSecure := []string{"RS256", "ES256", "EdDSA", "PS256"}
	for _, expected := range expectedSecure {
		found := false
		for _, allowed := range DefaultAllowedAlgorithms {
			if allowed == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected secure algorithm %q not in DefaultAllowedAlgorithms", expected)
		}
	}
}
