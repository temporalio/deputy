package jwt_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/authn"
	"github.com/temporalio/deputy/internal/auth/jwt"
)

// mockAuthenticator implements jwt.Authenticator for testing.
type mockAuthenticator struct {
	claims *jwt.Claims
	err    error
}

func (m *mockAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*jwt.Claims, error) {
	return m.claims, m.err
}

func (m *mockAuthenticator) Close() error {
	return nil
}

func TestAuthnFunc_Required_WithValidToken(t *testing.T) {
	claims := &jwt.Claims{
		Subject: "user:alice",
		Issuer:  "https://auth.example.com",
	}
	auth := &mockAuthenticator{claims: claims}
	authFunc := jwt.AuthnFunc(auth, jwt.ModeRequired)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer valid-token")

	info, err := authFunc(t.Context(), req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	resultClaims, ok := info.(*jwt.Claims)
	if !ok {
		t.Fatalf("expected *jwt.Claims, got %T", info)
	}

	if resultClaims.Subject != "user:alice" {
		t.Errorf("expected subject 'user:alice', got %q", resultClaims.Subject)
	}
}

func TestAuthnFunc_Required_NoToken(t *testing.T) {
	// No claims returned means no token was provided
	auth := &mockAuthenticator{claims: nil, err: nil}
	authFunc := jwt.AuthnFunc(auth, jwt.ModeRequired)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	_, err := authFunc(t.Context(), req)
	if err == nil {
		t.Fatal("expected error for missing token in required mode")
	}

	// Should be an authn error with CodeUnauthenticated
	// The error message should indicate authentication is required
}

func TestAuthnFunc_Optional_NoToken(t *testing.T) {
	// No claims returned means no token was provided - allowed in optional mode
	auth := &mockAuthenticator{claims: nil, err: nil}
	authFunc := jwt.AuthnFunc(auth, jwt.ModeOptional)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	info, err := authFunc(t.Context(), req)
	if err != nil {
		t.Fatalf("expected no error in optional mode, got %v", err)
	}

	// Info should be nil for anonymous requests
	// Note: info is typed as `any`, and we return `nil` (untyped nil), which is correct
	if info != nil {
		t.Errorf("expected nil info for anonymous, got %T: %v", info, info)
	}
}

func TestAuthnFunc_Disabled(t *testing.T) {
	// Even with valid claims available, disabled mode should pass through
	claims := &jwt.Claims{Subject: "user:alice"}
	auth := &mockAuthenticator{claims: claims}
	authFunc := jwt.AuthnFunc(auth, jwt.ModeDisabled)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	info, err := authFunc(t.Context(), req)
	if err != nil {
		t.Fatalf("expected no error in disabled mode, got %v", err)
	}

	// Disabled mode returns nil info regardless of token
	if info != nil {
		t.Errorf("expected nil info in disabled mode, got %v", info)
	}
}

func TestAuthnFunc_NilAuthenticator(t *testing.T) {
	authFunc := jwt.AuthnFunc(nil, jwt.ModeRequired)

	req := httptest.NewRequest(http.MethodGet, "/", nil)

	info, err := authFunc(t.Context(), req)
	if err != nil {
		t.Fatalf("expected no error with nil authenticator, got %v", err)
	}

	if info != nil {
		t.Errorf("expected nil info with nil authenticator, got %v", info)
	}
}

func TestAuthnFunc_AuthError(t *testing.T) {
	authErr := &jwt.Error{
		Code:    jwt.CodeExpiredToken,
		Message: "token has expired",
	}
	auth := &mockAuthenticator{err: authErr}
	authFunc := jwt.AuthnFunc(auth, jwt.ModeRequired)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer expired-token")

	_, err := authFunc(t.Context(), req)
	if err == nil {
		t.Fatal("expected error for expired token")
	}

	// Error should contain the message
	if err.Error() == "" {
		t.Error("error message should not be empty")
	}
}

func TestClaimsFromAuthn(t *testing.T) {
	claims := &jwt.Claims{
		Subject: "user:bob",
		Issuer:  "https://issuer.example.com",
	}

	// Set up context with authn info
	ctx := authn.SetInfo(t.Context(), claims)

	// Retrieve claims using our helper
	result := jwt.ClaimsFromAuthn(ctx)
	if result == nil {
		t.Fatal("expected claims, got nil")
	}

	if result.Subject != "user:bob" {
		t.Errorf("expected subject 'user:bob', got %q", result.Subject)
	}
}

func TestClaimsFromAuthn_NoInfo(t *testing.T) {
	ctx := t.Context()

	result := jwt.ClaimsFromAuthn(ctx)
	if result != nil {
		t.Errorf("expected nil claims, got %v", result)
	}
}

func TestClaimsFromAuthn_WrongType(t *testing.T) {
	// Set up context with non-Claims info
	ctx := authn.SetInfo(t.Context(), "not-claims")

	result := jwt.ClaimsFromAuthn(ctx)
	if result != nil {
		t.Errorf("expected nil claims for wrong type, got %v", result)
	}
}

func TestIsAnonymousAuthn(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		expected bool
	}{
		{
			name:     "no info",
			ctx:      t.Context(),
			expected: true,
		},
		{
			name:     "with claims",
			ctx:      authn.SetInfo(t.Context(), &jwt.Claims{Subject: "user:alice"}),
			expected: false,
		},
		{
			name:     "with nil info explicitly set",
			ctx:      authn.SetInfo(t.Context(), nil),
			expected: true, // nil is treated as anonymous
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := jwt.IsAnonymousAuthn(tt.ctx)
			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestAuthnMiddlewareIntegration(t *testing.T) {
	claims := &jwt.Claims{
		Subject:  "user:charlie",
		Issuer:   "https://auth.example.com",
		Audience: []string{"deputy"},
	}
	auth := &mockAuthenticator{claims: claims}
	authFunc := jwt.AuthnFunc(auth, jwt.ModeRequired)

	// Create authn middleware
	middleware := authn.NewMiddleware(authFunc)

	// Create a test handler that checks for claims
	var capturedClaims *jwt.Claims
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedClaims = jwt.ClaimsFromAuthn(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	// Wrap handler with middleware
	wrapped := middleware.Wrap(handler)

	// Make request
	req := httptest.NewRequest(http.MethodPost, "/deputy.scan.v1.ScanService/Scan", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	req.Header.Set("Content-Type", "application/connect+proto")

	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}

	if capturedClaims == nil {
		t.Fatal("expected claims to be captured")
	}

	if capturedClaims.Subject != "user:charlie" {
		t.Errorf("expected subject 'user:charlie', got %q", capturedClaims.Subject)
	}
}
