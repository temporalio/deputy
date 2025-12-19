package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTokenSource(t *testing.T) {
	provider := NewStaticProvider(
		&TokenCredential{Token: "gh_token", AllowedHosts: []string{"api.github.com"}},
	)
	store := NewStore(WithProvider(provider))
	ctx := context.Background()

	t.Run("returns token source for valid host", func(t *testing.T) {
		ts, err := store.TokenSource(ctx, "api.github.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts == nil {
			t.Fatal("expected token source, got nil")
		}

		token, err := ts.Token()
		if err != nil {
			t.Fatalf("unexpected error getting token: %v", err)
		}
		if token.AccessToken != "gh_token" {
			t.Errorf("got token %q, want %q", token.AccessToken, "gh_token")
		}
		if token.TokenType != "Bearer" {
			t.Errorf("got token type %q, want %q", token.TokenType, "Bearer")
		}
	})

	t.Run("returns nil for unknown host", func(t *testing.T) {
		ts, err := store.TokenSource(ctx, "unknown.com")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ts != nil {
			t.Error("expected nil token source for unknown host")
		}
	})
}

func TestTokenSourceWithBasicCredential(t *testing.T) {
	provider := NewStaticProvider(
		&BasicCredential{
			Username:     "user",
			Password:     "pass",
			AllowedHosts: []string{"custom.registry.io"},
		},
	)
	store := NewStore(WithProvider(provider))
	ctx := context.Background()

	ts, err := store.TokenSource(ctx, "custom.registry.io")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == nil {
		t.Fatal("expected token source, got nil")
	}

	token, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error getting token: %v", err)
	}
	// BasicCredential uses password as access token
	if token.AccessToken != "pass" {
		t.Errorf("got token %q, want %q", token.AccessToken, "pass")
	}
}

// refreshable credential for testing
type refreshableToken struct {
	*TokenCredential
	newToken string
	called   *int
}

// ExpiresAt is inherited from TokenCredential via embedding.

func (r *refreshableToken) Refresh(ctx context.Context) (Credential, error) {
	if r.called != nil {
		*r.called++
	}
	future := time.Now().Add(time.Hour)
	return &TokenCredential{
		Token:        r.newToken,
		AllowedHosts: r.AllowedHosts,
		Expiry:       &future,
	}, nil
}

func TestTokenSourceExpiredNonRefreshable(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	provider := NewStaticProvider(
		&TokenCredential{Token: "old", AllowedHosts: []string{"api.github.com"}, Expiry: &past},
	)
	store := NewStore(WithProvider(provider))
	ctx := context.Background()

	ts, err := store.TokenSource(ctx, "api.github.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	_, err = ts.Token()
	if err == nil {
		t.Fatal("expected error for expired non-refreshable credential")
	}
	// Should be ErrCredentialExpired
	if !errors.Is(err, ErrCredentialExpired) {
		t.Errorf("expected ErrCredentialExpired, got %v", err)
	}
}

func TestTokenSourceExpiredRefreshable(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	called := 0
	ref := &refreshableToken{
		TokenCredential: &TokenCredential{Token: "old", AllowedHosts: []string{"api.github.com"}, Expiry: &past},
		newToken:        "newtoken",
		called:          &called,
	}
	provider := NewStaticProvider(ref)
	store := NewStore(WithProvider(provider))
	ctx := context.Background()

	ts, err := store.TokenSource(ctx, "api.github.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tok, err := ts.Token()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok.AccessToken != "newtoken" {
		t.Fatalf("expected refreshed token, got %q", tok.AccessToken)
	}
	if called != 1 {
		t.Fatalf("expected refresh called once, got %d", called)
	}
	if tok.Expiry.IsZero() {
		t.Fatalf("expected expiry to be set on refreshed token")
	}
}

func TestTokenSourceRejectsSSHCredential(t *testing.T) {
	provider := NewStaticProvider(
		&SSHCredential{
			User:         "git",
			PrivateKey:   []byte("fake-key"),
			AllowedHosts: []string{"github.com"},
		},
	)
	store := NewStore(WithProvider(provider))
	ctx := context.Background()

	ts, err := store.TokenSource(ctx, "github.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ts == nil {
		t.Fatal("expected token source, got nil")
	}

	// Should error when trying to get token from SSH credential
	_, err = ts.Token()
	if err == nil {
		t.Error("expected error converting SSH credential to oauth2.Token")
	}
	// Should be ErrUnsupportedCredentialType
	if !errors.Is(err, ErrUnsupportedCredentialType) {
		t.Errorf("expected ErrUnsupportedCredentialType, got %v", err)
	}
}

func TestRoundTripper(t *testing.T) {
	// Create a test server to capture the request
	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	// Explicitly allow any host for the test (insecure by design)
	provider := NewStaticProvider(
		&TokenCredential{Token: "bearer_token", AllowedHosts: InsecureAllowAnyHosts()},
	)
	store := NewStore(WithProvider(provider), WithoutHTTPSRequirement())

	rt := store.RoundTripper(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	if capturedAuth != "Bearer bearer_token" {
		t.Errorf("got auth header %q, want %q", capturedAuth, "Bearer bearer_token")
	}
}

// strict mode should surface ConfigureHTTPRequest errors
func TestRoundTripperStrictErrors(t *testing.T) {
	// Provider that returns an unsupported credential type to force an error
	provider := NewStaticProvider(&SSHCredential{AllowedHosts: InsecureAllowAnyHosts()})
	store := NewStore(WithProvider(provider), WithStrictAuthErrors(), WithoutHTTPSRequirement())

	// Dummy server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rt := store.RoundTripper(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequest("GET", server.URL, nil)
	_, err := client.Do(req)
	if err == nil {
		t.Fatal("expected error in strict mode, got nil")
	}
}

func TestRoundTripperNoCredentials(t *testing.T) {
	// Empty provider
	store := NewStore(WithProvider(NullProvider{}))

	var capturedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	rt := store.RoundTripper(http.DefaultTransport)
	client := &http.Client{Transport: rt}

	req, _ := http.NewRequest("GET", server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()

	// Should continue without auth, not error
	if capturedAuth != "" {
		t.Errorf("expected no auth header, got %q", capturedAuth)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("got status %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

func TestHTTPClient(t *testing.T) {
	provider := NewStaticProvider(
		&TokenCredential{Token: "client_token", AllowedHosts: []string{"*"}},
	)
	store := NewStore(WithProvider(provider), WithoutHTTPSRequirement())

	client := store.HTTPClient(nil)
	if client == nil {
		t.Fatal("expected http client, got nil")
	}

	// Client should have our round tripper
	_, ok := client.Transport.(*authRoundTripper)
	if !ok {
		t.Error("expected client to have authRoundTripper transport")
	}
}

func TestGitAuthMethod(t *testing.T) {
	cred := &TokenCredential{Token: "git_token", AllowedHosts: []string{"github.com"}}
	gam := &GitAuthMethod{cred: cred, host: "github.com"}

	if gam.Name() != "http-basic-auth" {
		t.Errorf("got name %q, want %q", gam.Name(), "http-basic-auth")
	}

	if gam.String() != "http-basic-auth (host: github.com)" {
		t.Errorf("got string %q, want %q", gam.String(), "http-basic-auth (host: github.com)")
	}

	auth, err := gam.ToTransportAuth()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if auth == nil {
		t.Fatal("expected auth method, got nil")
	}
}
