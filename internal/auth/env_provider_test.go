package auth

import (
	"testing"
)

func TestEnvProvider_GitHub(t *testing.T) {
	env := make(map[string]string)
	env["GITHUB_TOKEN"] = "ghp_test_token_12345678"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "github.com", Hint: "git"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}

	token, ok := cred.(*TokenCredential)
	if !ok {
		t.Fatalf("expected TokenCredential, got %T", cred)
	}
	if token.Token != "ghp_test_token_12345678" {
		t.Errorf("unexpected token value")
	}
	if token.Source != "GITHUB_TOKEN" {
		t.Errorf("unexpected source: %s", token.Source)
	}

	// Should also work for api.github.com
	scope.Host = "api.github.com"
	cred, err = p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup for api.github.com failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential for api.github.com, got nil")
	}
}

func TestEnvProvider_GitLab(t *testing.T) {
	env := make(map[string]string)
	env["GITLAB_TOKEN"] = "glpat-xxxxxxxxxxxx"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "gitlab.com", Hint: "git"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}

	token, ok := cred.(*TokenCredential)
	if !ok {
		t.Fatalf("expected TokenCredential, got %T", cred)
	}
	if token.Token != "glpat-xxxxxxxxxxxx" {
		t.Errorf("unexpected token value")
	}
}

func TestEnvProvider_Anthropic(t *testing.T) {
	env := make(map[string]string)
	env["ANTHROPIC_API_KEY"] = "sk-ant-api03-xxx"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "api.anthropic.com", Hint: "llm"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}

	token, ok := cred.(*TokenCredential)
	if !ok {
		t.Fatalf("expected TokenCredential, got %T", cred)
	}
	if token.Token != "sk-ant-api03-xxx" {
		t.Errorf("unexpected token value")
	}

	// Should NOT return this token for other hosts
	scope.Host = "evil.com"
	cred, err = p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup for evil.com failed: %v", err)
	}
	if cred != nil {
		t.Error("should not return Anthropic key for evil.com")
	}
}

func TestEnvProvider_NoToken(t *testing.T) {
	p := &EnvProvider{
		getenv: func(key string) string { return "" },
	}

	ctx := t.Context()
	scope := Scope{Host: "github.com", Hint: "git"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred != nil {
		t.Error("expected nil credential when no token set")
	}
}

func TestEnvProvider_Prefix(t *testing.T) {
	env := make(map[string]string)
	env["MY_GITHUB_TOKEN"] = "ghp_prefixed_token"

	p := &EnvProvider{
		Prefix: "MY_",
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "github.com", Hint: "git"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential with prefix, got nil")
	}
}

func TestEnvProvider_GitHubEnterprise(t *testing.T) {
	env := make(map[string]string)
	env["DEPUTY_AUTH_GITHUB_ENTERPRISE_HOST"] = "github.mycompany.com"
	env["DEPUTY_AUTH_GITHUB_ENTERPRISE_TOKEN"] = "ghp_enterprise_token"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "github.mycompany.com", Hint: "git"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential for GHE, got nil")
	}

	token, ok := cred.(*TokenCredential)
	if !ok {
		t.Fatalf("expected TokenCredential, got %T", cred)
	}
	if !token.ValidForHost("github.mycompany.com") {
		t.Error("token should be valid for configured GHE host")
	}
	if token.ValidForHost("github.com") {
		t.Error("token should NOT be valid for public GitHub")
	}
}

func TestEnvProvider_NPM(t *testing.T) {
	env := make(map[string]string)
	env["NPM_TOKEN"] = "npm_xxxxxxxxxxxx"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "registry.npmjs.org", Hint: "registry"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}
}

func TestEnvProvider_DockerHub(t *testing.T) {
	env := make(map[string]string)
	env["DOCKER_USERNAME"] = "myuser"
	env["DOCKER_PASSWORD"] = "mypass"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "index.docker.io", Hint: "container"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}

	docker, ok := cred.(*DockerCredential)
	if !ok {
		t.Fatalf("expected DockerCredential, got %T", cred)
	}
	if docker.Username != "myuser" {
		t.Errorf("unexpected username: %s", docker.Username)
	}
}

func TestEnvProvider_GHCR(t *testing.T) {
	env := make(map[string]string)
	env["GITHUB_TOKEN"] = "ghp_container_token"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "ghcr.io", Hint: "container"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}

	docker, ok := cred.(*DockerCredential)
	if !ok {
		t.Fatalf("expected DockerCredential, got %T", cred)
	}
	if docker.Password != "ghp_container_token" {
		t.Errorf("unexpected password/token")
	}
}

func TestEnvProvider_InvalidScope(t *testing.T) {
	p := NewEnvProvider()
	ctx := t.Context()
	scope := Scope{} // missing Host

	_, err := p.Lookup(ctx, scope)
	if err == nil {
		t.Error("expected error for invalid scope")
	}
}

func TestEnvProvider_GHToken(t *testing.T) {
	// Test GH_TOKEN (GitHub CLI convention)
	env := make(map[string]string)
	env["GH_TOKEN"] = "ghp_cli_token"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "github.com", Hint: "git"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential from GH_TOKEN, got nil")
	}

	token, ok := cred.(*TokenCredential)
	if !ok {
		t.Fatalf("expected TokenCredential, got %T", cred)
	}
	if token.Source != "GH_TOKEN" {
		t.Errorf("expected source GH_TOKEN, got %s", token.Source)
	}
}

func TestEnvProvider_GitHubTokenPrecedence(t *testing.T) {
	// GITHUB_TOKEN should take precedence over GH_TOKEN
	env := make(map[string]string)
	env["GITHUB_TOKEN"] = "ghp_primary"
	env["GH_TOKEN"] = "ghp_secondary"

	p := &EnvProvider{
		getenv: func(key string) string { return env[key] },
	}

	ctx := t.Context()
	scope := Scope{Host: "github.com", Hint: "git"}

	cred, err := p.Lookup(ctx, scope)
	if err != nil {
		t.Fatalf("Lookup failed: %v", err)
	}
	if cred == nil {
		t.Fatal("expected credential, got nil")
	}

	token, ok := cred.(*TokenCredential)
	if !ok {
		t.Fatalf("expected TokenCredential, got %T", cred)
	}
	if token.Token != "ghp_primary" {
		t.Error("GITHUB_TOKEN should take precedence over GH_TOKEN")
	}
}
