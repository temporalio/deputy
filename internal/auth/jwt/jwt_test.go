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
	"slices"
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
		found := slices.Contains(DefaultAllowedAlgorithms, expected)
		if !found {
			t.Errorf("expected secure algorithm %q not in DefaultAllowedAlgorithms", expected)
		}
	}
}

func TestAuthenticator_IssuerValidation(t *testing.T) {
	// Security test: Verify issuer validation works correctly.
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := &Config{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		Issuers: []string{"https://trusted.example.com", "https://also-trusted.example.com"},
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	t.Run("trusted issuer allowed", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.Issuer:         "https://trusted.example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("unexpected error for trusted issuer: %v", err)
		}
		if claims == nil || claims.Issuer != "https://trusted.example.com" {
			t.Errorf("expected issuer claim to be preserved")
		}
	})

	t.Run("untrusted issuer rejected", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "attacker",
			josejwt.Issuer:         "https://evil.example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for untrusted issuer")
		}
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
		if authErr.Code != CodeInvalidIssuer {
			t.Errorf("expected error code %q, got %q", CodeInvalidIssuer, authErr.Code)
		}
	})

	t.Run("empty issuer when required rejected", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			// No issuer claim
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for missing issuer when issuers configured")
		}
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
		if authErr.Code != CodeInvalidIssuer {
			t.Errorf("expected error code %q, got %q", CodeInvalidIssuer, authErr.Code)
		}
	})
}

func TestAuthenticator_AudienceValidation(t *testing.T) {
	// Security test: Verify audience validation works correctly.
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := &Config{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		Audiences: []string{"https://deputy.example.com", "deputy-api"},
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	t.Run("single matching audience allowed", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.Audience:       "https://deputy.example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("unexpected error for matching audience: %v", err)
		}
		if claims == nil {
			t.Error("expected non-nil claims")
		}
	})

	t.Run("multiple audiences with one matching allowed", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.Audience:       []string{"other-service", "deputy-api", "another-service"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("unexpected error when one audience matches: %v", err)
		}
		if claims == nil {
			t.Error("expected non-nil claims")
		}
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.Audience:       "https://other-service.example.com",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for wrong audience")
		}
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
		if authErr.Code != CodeInvalidAudience {
			t.Errorf("expected error code %q, got %q", CodeInvalidAudience, authErr.Code)
		}
	})

	t.Run("empty audience when required rejected", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			// No audience claim
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for missing audience when audiences configured")
		}
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
		if authErr.Code != CodeInvalidAudience {
			t.Errorf("expected error code %q, got %q", CodeInvalidAudience, authErr.Code)
		}
	})
}

func TestAuthenticator_RequiredClaims(t *testing.T) {
	// Security test: Verify required claims validation.
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := &Config{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		RequiredClaims: []string{"email", "groups"},
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	t.Run("all required claims present", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"email":                "user@example.com",
			"groups":               []string{"developers"},
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if claims == nil {
			t.Error("expected non-nil claims")
		}
	})

	t.Run("missing required claim rejected", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"email":                "user@example.com",
			// Missing 'groups' claim
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for missing required claim")
		}
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
		if authErr.Code != CodeMissingClaim {
			t.Errorf("expected error code %q, got %q", CodeMissingClaim, authErr.Code)
		}
	})
}

func TestAuthenticator_TokenSizeLimit(t *testing.T) {
	// Security test: Verify token size limits prevent DoS attacks.
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := &Config{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		MaxTokenSize: 1024, // 1KB limit for testing
	}

	auth, err := NewAuthenticator(cfg)
	if err != nil {
		t.Fatalf("failed to create authenticator: %v", err)
	}
	defer auth.Close()

	t.Run("oversized token rejected", func(t *testing.T) {
		// Create a token with a large custom claim to exceed the limit
		largeClaim := strings.Repeat("x", 2048) // 2KB string
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
			"large_data":           largeClaim,
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for oversized token")
		}
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
		if authErr.Code != CodeInvalidToken {
			t.Errorf("expected error code %q, got %q", CodeInvalidToken, authErr.Code)
		}
	})
}

func TestAuthenticator_ClockSkew(t *testing.T) {
	// Security test: Verify clock skew is properly bounded.
	_, publicKeyPEM := generateTestKeyPair(t)

	t.Run("excessive clock skew rejected at config", func(t *testing.T) {
		cfg := &Config{
			Mode: "required",
			StaticKeys: []StaticKeyConfig{
				{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
			},
			ClockSkew: 10 * time.Minute, // Exceeds MaxClockSkew (5 minutes)
		}

		_, err := NewAuthenticator(cfg)
		if err == nil {
			t.Fatal("expected error for excessive clock skew")
		}
	})

	t.Run("max clock skew boundary", func(t *testing.T) {
		cfg := &Config{
			Mode: "required",
			StaticKeys: []StaticKeyConfig{
				{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
			},
			ClockSkew: MaxClockSkew, // Exactly at the limit (5 minutes)
		}

		auth, err := NewAuthenticator(cfg)
		if err != nil {
			t.Fatalf("max clock skew should be accepted: %v", err)
		}
		auth.Close()
	})

	t.Run("slightly over max clock skew rejected", func(t *testing.T) {
		cfg := &Config{
			Mode: "required",
			StaticKeys: []StaticKeyConfig{
				{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
			},
			ClockSkew: MaxClockSkew + time.Second, // Just over the limit
		}

		_, err := NewAuthenticator(cfg)
		if err == nil {
			t.Fatal("expected error for clock skew exceeding max")
		}
	})
}

func TestAuthenticator_NotBeforeValidation(t *testing.T) {
	// Security test: Verify nbf (not before) claim is validated.
	// Note: The jose library validates nbf during token verification, so the
	// error comes from signature verification (which includes time checks).
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

	t.Run("future nbf rejected", func(t *testing.T) {
		// Token not valid for another hour
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.NotBefore:      time.Now().Add(time.Hour).Unix(),
			josejwt.ExpirationTime: time.Now().Add(2 * time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		_, err := auth.Authenticate(context.Background(), req)
		if err == nil {
			t.Fatal("expected error for token not yet valid")
		}
		// The jose library validates nbf during verification, so the error
		// comes back as signature_invalid (which includes time validation)
		authErr, ok := err.(*Error)
		if !ok {
			t.Fatalf("expected *Error, got %T", err)
		}
		// Accept either signature_invalid (jose lib validation) or invalid_token (our validation)
		if authErr.Code != CodeSignatureInvalid && authErr.Code != CodeInvalidToken {
			t.Errorf("expected error code %q or %q, got %q", CodeSignatureInvalid, CodeInvalidToken, authErr.Code)
		}
	})

	t.Run("valid nbf accepted", func(t *testing.T) {
		// Token valid from past time
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.NotBefore:      time.Now().Add(-time.Hour).Unix(),
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		claims, err := auth.Authenticate(context.Background(), req)
		if err != nil {
			t.Errorf("token with past nbf should be accepted: %v", err)
		}
		if claims == nil {
			t.Error("expected non-nil claims")
		}
	})
}

func TestTenantFromContext(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		// Intentionally testing nil context handling
		tenant := TenantFromContext(nil) //nolint:staticcheck // testing nil context behavior
		if tenant != "" {
			t.Errorf("expected empty string for nil context, got %q", tenant)
		}
	})

	t.Run("context without claims (anonymous)", func(t *testing.T) {
		ctx := context.Background()
		tenant := TenantFromContext(ctx)
		if tenant != "" {
			t.Errorf("expected empty string for context without claims, got %q", tenant)
		}
	})

	t.Run("claims without tenant", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom:  map[string]any{},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContext(ctx)
		if tenant != "" {
			t.Errorf("expected empty string for claims without tenant, got %q", tenant)
		}
	})

	t.Run("claims with string tenant", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom: map[string]any{
				"tenant": "acme-corp",
			},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContext(ctx)
		if tenant != "acme-corp" {
			t.Errorf("expected tenant 'acme-corp', got %q", tenant)
		}
	})

	t.Run("claims with bytes tenant", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom: map[string]any{
				"tenant": []byte("byte-tenant"),
			},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContext(ctx)
		if tenant != "byte-tenant" {
			t.Errorf("expected tenant 'byte-tenant', got %q", tenant)
		}
	})

	t.Run("claims with non-string tenant", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom: map[string]any{
				"tenant": 12345, // integer, not string
			},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContext(ctx)
		if tenant != "" {
			t.Errorf("expected empty string for non-string tenant, got %q", tenant)
		}
	})

	t.Run("claims with nil tenant value", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom: map[string]any{
				"tenant": nil,
			},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContext(ctx)
		if tenant != "" {
			t.Errorf("expected empty string for nil tenant value, got %q", tenant)
		}
	})
}

func TestTenantFromContextWithKey(t *testing.T) {
	t.Run("nil context", func(t *testing.T) {
		// Intentionally testing nil context handling
		tenant := TenantFromContextWithKey(nil, "org_id") //nolint:staticcheck // testing nil context behavior
		if tenant != "" {
			t.Errorf("expected empty string for nil context, got %q", tenant)
		}
	})

	t.Run("custom claim key", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom: map[string]any{
				"org_id": "organization-456",
			},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContextWithKey(ctx, "org_id")
		if tenant != "organization-456" {
			t.Errorf("expected tenant 'organization-456', got %q", tenant)
		}
	})

	t.Run("missing custom claim key", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom: map[string]any{
				"tenant": "acme-corp",
			},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContextWithKey(ctx, "org_id")
		if tenant != "" {
			t.Errorf("expected empty string for missing key, got %q", tenant)
		}
	})

	t.Run("empty claim key", func(t *testing.T) {
		claims := &Claims{
			Subject: "user123",
			Custom: map[string]any{
				"tenant": "acme-corp",
			},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContextWithKey(ctx, "")
		if tenant != "" {
			t.Errorf("expected empty string for empty key, got %q", tenant)
		}
	})

	t.Run("standard claim as tenant key", func(t *testing.T) {
		// Some systems use 'sub' as tenant identifier
		claims := &Claims{
			Subject: "tenant-from-subject",
			Custom:  map[string]any{},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContextWithKey(ctx, "sub")
		if tenant != "tenant-from-subject" {
			t.Errorf("expected tenant 'tenant-from-subject', got %q", tenant)
		}
	})

	t.Run("issuer as tenant key", func(t *testing.T) {
		// Some systems use issuer to determine tenant
		claims := &Claims{
			Subject: "user123",
			Issuer:  "https://acme.auth.com",
			Custom:  map[string]any{},
		}
		ctx := ContextWithClaims(context.Background(), claims)
		tenant := TenantFromContextWithKey(ctx, "iss")
		if tenant != "https://acme.auth.com" {
			t.Errorf("expected tenant 'https://acme.auth.com', got %q", tenant)
		}
	})
}

func TestDefaultTenantClaimKey(t *testing.T) {
	if DefaultTenantClaimKey != "tenant" {
		t.Errorf("expected DefaultTenantClaimKey to be 'tenant', got %q", DefaultTenantClaimKey)
	}
}
