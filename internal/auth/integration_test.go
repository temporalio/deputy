package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/picatz/deputy/internal/auth"
)

// TestIntegration_ConfusedDeputyPrevention verifies that credentials
// are not sent to unintended hosts (confused deputy attack prevention).
func TestIntegration_ConfusedDeputyPrevention(t *testing.T) {
	// Create a store with a GitHub token
	githubCred := &auth.TokenCredential{
		Token:        "ghp_secret_token",
		AllowedHosts: []string{"github.com", "api.github.com"},
		Source:       "test",
	}

	store := auth.NewStore(auth.WithProvider(auth.NewStaticProvider(githubCred)))
	ctx := context.Background()

	tests := []struct {
		name     string
		host     string
		wantAuth bool
		desc     string
	}{
		{
			name:     "github.com should get credentials",
			host:     "github.com",
			wantAuth: true,
			desc:     "GitHub host should receive credentials",
		},
		{
			name:     "api.github.com should get credentials",
			host:     "api.github.com",
			wantAuth: true,
			desc:     "GitHub API should receive credentials",
		},
		{
			name:     "evil.com should NOT get credentials",
			host:     "evil.com",
			wantAuth: false,
			desc:     "Attacker host must not receive GitHub token",
		},
		{
			name:     "github.com.evil.com should NOT get credentials",
			host:     "github.com.evil.com",
			wantAuth: false,
			desc:     "Subdomain impersonation must not receive token",
		},
		{
			name:     "gitlab.com should NOT get credentials",
			host:     "gitlab.com",
			wantAuth: false,
			desc:     "Other git hosts must not receive GitHub token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "https://"+tt.host+"/api/v1", nil)
			err := store.ConfigureHTTPRequest(ctx, req)
			if err != nil {
				t.Fatalf("ConfigureHTTPRequest error: %v", err)
			}

			hasAuth := req.Header.Get("Authorization") != ""
			if hasAuth != tt.wantAuth {
				if tt.wantAuth {
					t.Errorf("%s: expected credentials but got none", tt.desc)
				} else {
					t.Errorf("%s: credentials were leaked to %s", tt.desc, tt.host)
				}
			}
		})
	}
}

// TestIntegration_ServiceIsolation verifies that credentials for one service
// type don't leak to another service type inappropriately.
func TestIntegration_ServiceIsolation(t *testing.T) {
	// Set up credentials for different services
	env := map[string]string{
		"GITHUB_TOKEN":      "ghp_github_token",
		"ANTHROPIC_API_KEY": "sk-ant-anthropic-key",
	}

	// Create separate providers for different services
	githubCred := &auth.TokenCredential{
		Token:        env["GITHUB_TOKEN"],
		AllowedHosts: auth.GitHubHosts(),
		Source:       "GITHUB_TOKEN",
	}

	anthropicCred := &auth.TokenCredential{
		Token:        env["ANTHROPIC_API_KEY"],
		AllowedHosts: []string{"api.anthropic.com"},
		Source:       "ANTHROPIC_API_KEY",
	}

	chain := auth.NewChainProvider(
		auth.NewStaticProvider(githubCred),
		auth.NewStaticProvider(anthropicCred),
	)

	store := auth.NewStore(auth.WithProvider(chain))
	ctx := context.Background()

	// Anthropic API key should only go to api.anthropic.com
	t.Run("anthropic key isolation", func(t *testing.T) {
		token, err := store.LLMAPIKey(ctx, "api.anthropic.com")
		if err != nil {
			t.Fatalf("LLMAPIKey error: %v", err)
		}
		if token != env["ANTHROPIC_API_KEY"] {
			t.Error("expected Anthropic key for api.anthropic.com")
		}

		// Should NOT return Anthropic key for other hosts
		token, err = store.LLMAPIKey(ctx, "evil.com")
		if err != nil {
			t.Fatalf("LLMAPIKey error: %v", err)
		}
		if token != "" {
			t.Error("Anthropic key leaked to evil.com")
		}
	})

	// GitHub token should only go to GitHub hosts
	t.Run("github token isolation", func(t *testing.T) {
		gitAuth, err := store.GitAuth(ctx, "https://github.com/user/repo.git")
		if err != nil {
			t.Fatalf("GitAuth error: %v", err)
		}
		if gitAuth == nil {
			t.Error("expected auth for github.com")
		}

		// Should NOT return GitHub token for other hosts
		gitAuth, err = store.GitAuth(ctx, "https://gitlab.com/user/repo.git")
		if err != nil {
			t.Fatalf("GitAuth error: %v", err)
		}
		if gitAuth != nil {
			t.Error("GitHub token leaked to gitlab.com")
		}
	})
}

// TestIntegration_HTTPSRequirement verifies that credentials are not sent
// over non-HTTPS connections by default.
func TestIntegration_HTTPSRequirement(t *testing.T) {
	cred := &auth.TokenCredential{
		Token:        "secret_token",
		AllowedHosts: []string{"api.example.com"},
	}

	store := auth.NewStore(auth.WithProvider(auth.NewStaticProvider(cred)))
	ctx := context.Background()

	t.Run("HTTPS gets credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "https://api.example.com/data", nil)
		err := store.ConfigureHTTPRequest(ctx, req)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if req.Header.Get("Authorization") == "" {
			t.Error("HTTPS request should have credentials")
		}
	})

	t.Run("HTTP does NOT get credentials", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "http://api.example.com/data", nil)
		err := store.ConfigureHTTPRequest(ctx, req)
		if err != nil {
			t.Fatalf("error: %v", err)
		}
		if req.Header.Get("Authorization") != "" {
			t.Error("HTTP request should NOT have credentials (security)")
		}
	})
}

// TestIntegration_WildcardHostMatching tests wildcard patterns for
// GitHub Enterprise and similar self-hosted scenarios.
func TestIntegration_WildcardHostMatching(t *testing.T) {
	// Enterprise GitHub with wildcard
	cred := &auth.TokenCredential{
		Token:        "ghp_enterprise",
		AllowedHosts: []string{"*.enterprise.example.com"},
	}

	store := auth.NewStore(auth.WithProvider(auth.NewStaticProvider(cred)))
	ctx := context.Background()

	tests := []struct {
		host     string
		wantAuth bool
	}{
		{"github.enterprise.example.com", true},
		{"api.enterprise.example.com", true},
		{"enterprise.example.com", false}, // wildcard doesn't match root
		{"evil.enterprise.example.com.attacker.com", false},
		{"github.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.host, func(t *testing.T) {
			scope := auth.Scope{Host: tt.host, Hint: "git"}
			cred, err := store.Lookup(ctx, scope)
			if err != nil {
				t.Fatalf("Lookup error: %v", err)
			}

			hasAuth := cred != nil
			if hasAuth != tt.wantAuth {
				t.Errorf("host %s: got auth=%v, want auth=%v", tt.host, hasAuth, tt.wantAuth)
			}
		})
	}
}
