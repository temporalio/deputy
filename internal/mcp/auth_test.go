package mcp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/temporalio/deputy/internal/auth/jwt"
	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	josejwt "github.com/picatz/jose/pkg/jwt"
)

func TestAuthConfig_TypeAlias(t *testing.T) {
	// Test that AuthConfig is a type alias for jwt.Config
	// This verifies the type alias relationship works correctly
	t.Run("config fields accessible", func(t *testing.T) {
		cfg := &AuthConfig{
			Mode: "required",
			JWKS: &JWKSConfig{
				URL:             "https://example.com/.well-known/jwks.json",
				OIDCDiscovery:   true,
				RefreshInterval: 2 * time.Hour,
			},
			StaticKeys: []StaticKeyConfig{
				{KeyID: "key1", Algorithm: "RS256", PublicKey: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"},
			},
			Issuers:           []string{"https://issuer.example.com"},
			Audiences:         []string{"deputy-mcp"},
			RequiredClaims:    []string{"sub", "email"},
			ClockSkew:         30 * time.Second,
			AllowedAlgorithms: []string{"RS256", "ES256"},
			MaxTokenSize:      8192,
		}

		// Verify fields are accessible (type alias works)
		if cfg.Mode != "required" {
			t.Errorf("expected mode 'required', got %q", cfg.Mode)
		}
		if cfg.JWKS == nil {
			t.Fatal("expected non-nil JWKS config")
		}
		if cfg.JWKS.URL != "https://example.com/.well-known/jwks.json" {
			t.Errorf("unexpected JWKS URL: %q", cfg.JWKS.URL)
		}
		if len(cfg.StaticKeys) != 1 {
			t.Errorf("expected 1 static key, got %d", len(cfg.StaticKeys))
		}
		if len(cfg.Issuers) != 1 {
			t.Errorf("expected 1 issuer, got %d", len(cfg.Issuers))
		}
		if cfg.ClockSkew != 30*time.Second {
			t.Errorf("expected clock skew 30s, got %v", cfg.ClockSkew)
		}

		// Verify the jwt.Config methods are available
		mode := cfg.GetMode()
		if mode != jwt.ModeRequired {
			t.Errorf("expected mode Required, got %v", mode)
		}
	})
}

func TestGetMode(t *testing.T) {
	tests := []struct {
		name     string
		cfg      *AuthConfig
		expected jwt.Mode
	}{
		{"nil config", nil, jwt.ModeDisabled},
		{"empty mode", &AuthConfig{}, jwt.ModeDisabled},
		{"disabled mode", &AuthConfig{Mode: "disabled"}, jwt.ModeDisabled},
		{"optional mode", &AuthConfig{Mode: "optional"}, jwt.ModeOptional},
		{"required mode", &AuthConfig{Mode: "required"}, jwt.ModeRequired},
		{"case insensitive", &AuthConfig{Mode: "REQUIRED"}, jwt.ModeRequired},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getMode(tt.cfg)
			if got != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, got)
			}
		})
	}
}

func TestAuthMiddleware_Disabled(t *testing.T) {
	// Test that nil config returns passthrough middleware
	mw, closer, err := authMiddleware(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer closer()

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

func TestAuthMiddleware_RequiredMode(t *testing.T) {
	// Generate test key pair
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := &AuthConfig{
		Mode: "required",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
		Audiences: []string{"deputy-mcp"},
	}

	mw, closer, err := authMiddleware(cfg)
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}
	defer closer()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			t.Error("expected claims in context")
		}
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw(handler)

	t.Run("no token - rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rec.Code)
		}

		// Check WWW-Authenticate header
		wwwAuth := rec.Header().Get("WWW-Authenticate")
		if wwwAuth == "" {
			t.Error("expected WWW-Authenticate header")
		}
	})

	t.Run("valid token - allowed", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.Audience:       []string{"deputy-mcp"},
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("expired token - rejected", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.Audience:       []string{"deputy-mcp"},
			josejwt.ExpirationTime: time.Now().Add(-time.Hour).Unix(), // expired
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("expected status 401, got %d", rec.Code)
		}
	})
}

func TestAuthMiddleware_OptionalMode(t *testing.T) {
	// Generate test key pair
	privateKey, publicKeyPEM := generateTestKeyPair(t)

	cfg := &AuthConfig{
		Mode: "optional",
		StaticKeys: []StaticKeyConfig{
			{KeyID: "test-key", Algorithm: "ES256", PublicKey: publicKeyPEM},
		},
	}

	mw, closer, err := authMiddleware(cfg)
	if err != nil {
		t.Fatalf("failed to create middleware: %v", err)
	}
	defer closer()

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrapped := mw(handler)

	t.Run("no token - allowed (anonymous)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})

	t.Run("valid token - allowed with claims", func(t *testing.T) {
		token := createTestToken(t, privateKey, josejwt.ClaimsSet{
			josejwt.Subject:        "user123",
			josejwt.ExpirationTime: time.Now().Add(time.Hour).Unix(),
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		wrapped.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", rec.Code)
		}
	})
}

func TestClaimsFromContext(t *testing.T) {
	t.Run("no claims", func(t *testing.T) {
		ctx := context.Background()
		claims := ClaimsFromContext(ctx)
		if claims != nil {
			t.Error("expected nil claims")
		}
	})

	t.Run("with claims", func(t *testing.T) {
		expected := &Claims{Subject: "test-user"}
		ctx := jwt.ContextWithClaims(context.Background(), expected)
		claims := ClaimsFromContext(ctx)
		if claims == nil {
			t.Fatal("expected non-nil claims")
		}
		if claims.Subject != expected.Subject {
			t.Errorf("expected subject %q, got %q", expected.Subject, claims.Subject)
		}
	})
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
