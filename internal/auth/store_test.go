package auth

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
)

func TestStore_Lookup(t *testing.T) {
	cred := &TokenCredential{
		Token:        "test_token",
		AllowedHosts: []string{"github.com"},
		Source:       "test",
	}

	store := NewStore(WithProvider(NewStaticProvider(cred)))

	ctx := context.Background()
	scope := Scope{Host: "github.com"}

	got, err := store.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if got == nil {
		t.Fatal("expected credential, got nil")
	}
	if got != cred {
		t.Error("expected same credential instance")
	}
}

func TestStore_LookupHostMismatch(t *testing.T) {
	cred := &TokenCredential{
		Token:        "test_token",
		AllowedHosts: []string{"github.com"},
		Source:       "test",
	}

	store := NewStore(WithProvider(NewStaticProvider(cred)))

	ctx := context.Background()
	scope := Scope{Host: "gitlab.com"}

	got, err := store.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if got != nil {
		t.Error("expected nil credential for non-matching host")
	}
}

func TestStore_GitAuth(t *testing.T) {
	env := make(map[string]string)
	env["GITHUB_TOKEN"] = "ghp_test_token_12345678"

	provider := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}
	store := NewStore(WithProvider(provider))

	ctx := context.Background()
	auth, err := store.GitAuth(ctx, "https://github.com/user/repo.git")
	if err != nil {
		t.Fatalf("GitAuth failed: %v", err)
	}
	if auth == nil {
		t.Fatal("expected auth, got nil")
	}

	basicAuth, ok := auth.(*githttp.BasicAuth)
	if !ok {
		t.Fatalf("expected BasicAuth, got %T", auth)
	}
	if basicAuth.Username != "oauth2" {
		t.Errorf("expected username 'oauth2', got %s", basicAuth.Username)
	}
	if basicAuth.Password != "ghp_test_token_12345678" {
		t.Error("unexpected password value")
	}
}

func TestStore_GitAuthNoCredential(t *testing.T) {
	store := NewStore(WithProvider(NullProvider{}))

	ctx := context.Background()
	auth, err := store.GitAuth(ctx, "https://github.com/user/repo.git")
	if err != nil {
		t.Fatalf("GitAuth failed: %v", err)
	}
	if auth != nil {
		t.Error("expected nil auth when no credentials")
	}
}

func TestStore_HTTPBearerToken(t *testing.T) {
	cred := &TokenCredential{
		Token:        "api_token_xyz",
		AllowedHosts: []string{"api.example.com"},
	}
	store := NewStore(WithProvider(NewStaticProvider(cred)))

	ctx := context.Background()
	token, err := store.HTTPBearerToken(ctx, "api.example.com")
	if err != nil {
		t.Fatalf("HTTPBearerToken failed: %v", err)
	}
	if token != "api_token_xyz" {
		t.Errorf("unexpected token: %s", token)
	}
}

func TestStore_HTTPBasicAuth(t *testing.T) {
	cred := &BasicCredential{
		Username:     "myuser",
		Password:     "mypass",
		AllowedHosts: []string{"registry.example.com"},
	}
	store := NewStore(WithProvider(NewStaticProvider(cred)))

	ctx := context.Background()
	user, pass, err := store.HTTPBasicAuth(ctx, "registry.example.com")
	if err != nil {
		t.Fatalf("HTTPBasicAuth failed: %v", err)
	}
	if user != "myuser" {
		t.Errorf("unexpected username: %s", user)
	}
	if pass != "mypass" {
		t.Errorf("unexpected password")
	}
}

func TestStore_ConfigureHTTPRequest(t *testing.T) {
	cred := &TokenCredential{
		Token:        "bearer_token",
		AllowedHosts: []string{"api.example.com"},
	}
	store := NewStore(WithProvider(NewStaticProvider(cred)))

	req := httptest.NewRequest(http.MethodGet, "https://api.example.com/v1/data", nil)
	ctx := context.Background()

	err := store.ConfigureHTTPRequest(ctx, req)
	if err != nil {
		t.Fatalf("ConfigureHTTPRequest failed: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader != "Bearer bearer_token" {
		t.Errorf("unexpected Authorization header: %s", authHeader)
	}
}

func TestStore_ConfigureHTTPRequestNoHTTPS(t *testing.T) {
	cred := &TokenCredential{
		Token:        "bearer_token",
		AllowedHosts: []string{"api.example.com"},
	}
	store := NewStore(WithProvider(NewStaticProvider(cred)))

	// HTTP (not HTTPS) - should NOT add credentials by default
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1/data", nil)
	ctx := context.Background()

	err := store.ConfigureHTTPRequest(ctx, req)
	if err != nil {
		t.Fatalf("ConfigureHTTPRequest failed: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader != "" {
		t.Error("should not add credentials to non-HTTPS requests")
	}
}

func TestStore_ConfigureHTTPRequestNoHTTPSDisabled(t *testing.T) {
	cred := &TokenCredential{
		Token:        "bearer_token",
		AllowedHosts: []string{"api.example.com"},
	}
	store := NewStore(
		WithProvider(NewStaticProvider(cred)),
		WithoutHTTPSRequirement(),
	)

	// HTTP (not HTTPS) - should add credentials when HTTPS check disabled
	req := httptest.NewRequest(http.MethodGet, "http://api.example.com/v1/data", nil)
	ctx := context.Background()

	err := store.ConfigureHTTPRequest(ctx, req)
	if err != nil {
		t.Fatalf("ConfigureHTTPRequest failed: %v", err)
	}

	authHeader := req.Header.Get("Authorization")
	if authHeader == "" {
		t.Error("should add credentials when HTTPS requirement disabled")
	}
}

func TestStore_ContainerAuth(t *testing.T) {
	cred := &DockerCredential{
		Username:      "dockeruser",
		Password:      "dockerpass",
		ServerAddress: "https://ghcr.io",
	}
	store := NewStore(WithProvider(NewStaticProvider(cred)))

	ctx := context.Background()
	docker, err := store.ContainerAuth(ctx, "ghcr.io")
	if err != nil {
		t.Fatalf("ContainerAuth failed: %v", err)
	}
	if docker == nil {
		t.Fatal("expected credential, got nil")
	}
	if docker.Username != "dockeruser" {
		t.Errorf("unexpected username: %s", docker.Username)
	}
}

func TestStore_LLMAPIKey(t *testing.T) {
	env := make(map[string]string)
	env["ANTHROPIC_API_KEY"] = "sk-ant-xxx"

	provider := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}
	store := NewStore(WithProvider(provider))

	ctx := context.Background()
	key, err := store.LLMAPIKey(ctx, "api.anthropic.com")
	if err != nil {
		t.Fatalf("LLMAPIKey failed: %v", err)
	}
	if key != "sk-ant-xxx" {
		t.Errorf("unexpected key: %s", key)
	}
}

func TestChainProvider(t *testing.T) {
	cred1 := &TokenCredential{
		Token:        "token1",
		AllowedHosts: []string{"host1.com"},
	}
	cred2 := &TokenCredential{
		Token:        "token2",
		AllowedHosts: []string{"host2.com"},
	}

	chain := NewChainProvider(
		NewStaticProvider(cred1),
		NewStaticProvider(cred2),
	)

	ctx := context.Background()

	// Should find cred1
	scope1 := Scope{Host: "host1.com"}
	got1, err := chain.Lookup(ctx, scope1)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if got1 != cred1 {
		t.Error("expected cred1")
	}

	// Should find cred2
	scope2 := Scope{Host: "host2.com"}
	got2, err := chain.Lookup(ctx, scope2)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if got2 != cred2 {
		t.Error("expected cred2")
	}

	// Should find nothing
	scope3 := Scope{Host: "host3.com"}
	got3, err := chain.Lookup(ctx, scope3)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if got3 != nil {
		t.Error("expected nil for unknown host")
	}
}

func TestDefaultStore(t *testing.T) {
	store := DefaultStore()
	if store == nil {
		t.Fatal("DefaultStore returned nil")
	}
}

func TestStore_Logger(t *testing.T) {
	// Default store should have a logger (even if no-op)
	store := NewStore()
	if store.Logger() == nil {
		t.Fatal("Logger() returned nil")
	}
}

func TestStore_WithLogger(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	store := NewStore(
		WithProvider(NewStaticProvider(&TokenCredential{
			Token:        "test",
			AllowedHosts: []string{"github.com"},
		})),
		WithLogger(logger),
	)

	ctx := context.Background()
	_, _ = store.Lookup(ctx, Scope{Host: "github.com"})

	// Logger should have logged something
	if buf.Len() == 0 {
		t.Error("expected log output")
	}
}

func TestTokenUsernameForHost(t *testing.T) {
	tests := []struct {
		host string
		want string
	}{
		{"github.com", "oauth2"},
		{"api.github.com", "oauth2"},
		{"gitlab.com", "oauth2"},
		{"sub.gitlab.com", "oauth2"},
		{"bitbucket.org", "x-token-auth"},
		{"unknown.com", "x-access-token"},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			got := tokenUsernameForHost(tt.host)
			if got != tt.want {
				t.Errorf("tokenUsernameForHost(%q) = %q, want %q", tt.host, got, tt.want)
			}
		})
	}
}

// Verify that returned auth implements the expected interface
func TestCredentialToGitAuth_Interface(t *testing.T) {
	cred := &TokenCredential{
		Token:        "test",
		AllowedHosts: []string{"github.com"},
	}

	auth, err := credentialToGitAuth(cred, "github.com")
	if err != nil {
		t.Fatalf("credentialToGitAuth failed: %v", err)
	}

	// Should implement transport.AuthMethod
	var _ transport.AuthMethod = auth
}
