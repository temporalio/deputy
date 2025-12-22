package proxy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	deperrors "github.com/picatz/deputy/internal/errors"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.yaml")
	configYAML := `
listeners:
  - name: go
    bind: ":8080"
    ecosystems: ["go"]
    upstream: https://proxy.golang.org
    policies:
      - policy.go.yaml
`
	if err := os.WriteFile(path, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(cfg.Listeners))
	}
	if cfg.Listeners[0].Bind != ":8080" {
		t.Fatalf("unexpected bind %q", cfg.Listeners[0].Bind)
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantErr   bool
		wantField string
	}{
		{
			name:      "empty listeners",
			config:    Config{},
			wantErr:   true,
			wantField: "listeners",
		},
		{
			name: "missing name",
			config: Config{
				Listeners: []ListenerConfig{{
					Bind:       ":8080",
					Ecosystems: []string{"go"},
					Upstream:   "https://proxy.golang.org",
				}},
			},
			wantErr:   true,
			wantField: "listeners[0].name",
		},
		{
			name: "missing bind",
			config: Config{
				Listeners: []ListenerConfig{{
					Name:       "test",
					Ecosystems: []string{"go"},
					Upstream:   "https://proxy.golang.org",
				}},
			},
			wantErr:   true,
			wantField: "listeners[0].bind",
		},
		{
			name: "missing ecosystems",
			config: Config{
				Listeners: []ListenerConfig{{
					Name:     "test",
					Bind:     ":8080",
					Upstream: "https://proxy.golang.org",
				}},
			},
			wantErr:   true,
			wantField: "listeners[0].ecosystems",
		},
		{
			name: "invalid ecosystem",
			config: Config{
				Listeners: []ListenerConfig{{
					Name:       "test",
					Bind:       ":8080",
					Ecosystems: []string{"invalid"},
					Upstream:   "https://proxy.golang.org",
				}},
			},
			wantErr:   true,
			wantField: "listeners[0].ecosystems",
		},
		{
			name: "missing upstream",
			config: Config{
				Listeners: []ListenerConfig{{
					Name:       "test",
					Bind:       ":8080",
					Ecosystems: []string{"go"},
				}},
			},
			wantErr:   true,
			wantField: "listeners[0].upstream",
		},
		{
			name: "duplicate listener name",
			config: Config{
				Listeners: []ListenerConfig{
					{Name: "test", Bind: ":8080", Ecosystems: []string{"go"}, Upstream: "https://proxy.golang.org"},
					{Name: "test", Bind: ":8081", Ecosystems: []string{"npm"}, Upstream: "https://registry.npmjs.org"},
				},
			},
			wantErr:   true,
			wantField: "listeners[1].name",
		},
		{
			name: "valid config",
			config: Config{
				Listeners: []ListenerConfig{{
					Name:       "test",
					Bind:       ":8080",
					Ecosystems: []string{"go"},
					Upstream:   "https://proxy.golang.org",
				}},
			},
			wantErr: false,
		},
		{
			name: "valid multi-listener config",
			config: Config{
				Listeners: []ListenerConfig{
					{Name: "go-proxy", Bind: ":8080", Ecosystems: []string{"go"}, Upstream: "https://proxy.golang.org"},
					{Name: "npm-proxy", Bind: ":8081", Ecosystems: []string{"npm"}, Upstream: "https://registry.npmjs.org"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.wantField != "" {
				var valErr *deperrors.ValidationError
				if !errors.As(err, &valErr) {
					t.Errorf("expected ValidationError, got %T", err)
					return
				}
				if !strings.Contains(valErr.Field, tt.wantField) {
					t.Errorf("expected field containing %q, got %q", tt.wantField, valErr.Field)
				}
			}
		})
	}
}

func TestConfig_ValidateAuth(t *testing.T) {
	baseListener := func(auth *AuthConfig) Config {
		return Config{
			Listeners: []ListenerConfig{{
				Name:       "test",
				Bind:       ":8080",
				Ecosystems: []string{"go"},
				Upstream:   "https://proxy.golang.org",
				Auth:       auth,
			}},
		}
	}

	validStaticKey := StaticKeyConfig{
		KeyID:     "test-key",
		Algorithm: "RS256",
		PublicKey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANB...test\n-----END PUBLIC KEY-----",
	}

	tests := []struct {
		name      string
		config    Config
		wantErr   bool
		wantField string
	}{
		{
			name:    "nil auth config",
			config:  baseListener(nil),
			wantErr: false,
		},
		{
			name:    "disabled auth mode",
			config:  baseListener(&AuthConfig{Mode: "disabled"}),
			wantErr: false,
		},
		{
			name:    "empty mode defaults to disabled",
			config:  baseListener(&AuthConfig{Mode: ""}),
			wantErr: false,
		},
		{
			name: "invalid auth mode",
			config: baseListener(&AuthConfig{
				Mode: "invalid",
			}),
			wantErr:   true,
			wantField: "auth.mode",
		},
		{
			name: "required mode without keys",
			config: baseListener(&AuthConfig{
				Mode: "required",
			}),
			wantErr:   true,
			wantField: "auth",
		},
		{
			name: "optional mode without keys",
			config: baseListener(&AuthConfig{
				Mode: "optional",
			}),
			wantErr:   true,
			wantField: "auth",
		},
		{
			name: "required mode with JWKS",
			config: baseListener(&AuthConfig{
				Mode: "required",
				JWKS: &JWKSConfig{URL: "https://auth.example.com/.well-known/jwks.json"},
			}),
			wantErr: false,
		},
		{
			name: "required mode with static keys",
			config: baseListener(&AuthConfig{
				Mode:       "required",
				StaticKeys: []StaticKeyConfig{validStaticKey},
			}),
			wantErr: false,
		},
		{
			name: "JWKS without URL",
			config: baseListener(&AuthConfig{
				Mode: "required",
				JWKS: &JWKSConfig{},
			}),
			wantErr:   true,
			wantField: "jwks.url",
		},
		{
			name: "JWKS with negative refresh interval",
			config: baseListener(&AuthConfig{
				Mode: "required",
				JWKS: &JWKSConfig{
					URL:             "https://auth.example.com/.well-known/jwks.json",
					RefreshInterval: -1,
				},
			}),
			wantErr:   true,
			wantField: "refresh_interval",
		},
		{
			name: "static key without key ID",
			config: baseListener(&AuthConfig{
				Mode: "required",
				StaticKeys: []StaticKeyConfig{{
					Algorithm: "RS256",
					PublicKey: "key",
				}},
			}),
			wantErr:   true,
			wantField: "static_keys[0].kid",
		},
		{
			name: "static key without algorithm",
			config: baseListener(&AuthConfig{
				Mode: "required",
				StaticKeys: []StaticKeyConfig{{
					KeyID:     "test",
					PublicKey: "key",
				}},
			}),
			wantErr:   true,
			wantField: "static_keys[0].alg",
		},
		{
			name: "static key without public key",
			config: baseListener(&AuthConfig{
				Mode: "required",
				StaticKeys: []StaticKeyConfig{{
					KeyID:     "test",
					Algorithm: "RS256",
				}},
			}),
			wantErr:   true,
			wantField: "static_keys[0].public_key",
		},
		{
			name: "negative clock skew",
			config: baseListener(&AuthConfig{
				Mode:       "required",
				StaticKeys: []StaticKeyConfig{validStaticKey},
				ClockSkew:  -1,
			}),
			wantErr:   true,
			wantField: "clock_skew",
		},
		{
			name: "valid full auth config",
			config: baseListener(&AuthConfig{
				Mode:           "required",
				JWKS:           &JWKSConfig{URL: "https://auth.example.com/.well-known/jwks.json"},
				StaticKeys:     []StaticKeyConfig{validStaticKey},
				Issuers:        []string{"https://auth.example.com"},
				Audiences:      []string{"deputy-proxy"},
				RequiredClaims: []string{"sub", "email"},
				ClockSkew:      30000000000, // 30s in nanoseconds
			}),
			wantErr: false,
		},
		{
			name: "optional mode with JWKS and issuers",
			config: baseListener(&AuthConfig{
				Mode:    "optional",
				JWKS:    &JWKSConfig{URL: "https://auth.example.com/.well-known/jwks.json"},
				Issuers: []string{"https://auth.example.com", "https://backup.example.com"},
			}),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.wantField != "" {
				var valErr *deperrors.ValidationError
				if !errors.As(err, &valErr) {
					t.Errorf("expected ValidationError, got %T", err)
					return
				}
				if !strings.Contains(valErr.Field, tt.wantField) {
					t.Errorf("expected field containing %q, got %q", tt.wantField, valErr.Field)
				}
			}
		})
	}
}

func TestLoadConfig_WithAuth(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "proxy.yaml")
	configYAML := `
listeners:
  - name: go-secure
    bind: ":8080"
    ecosystems: ["go"]
    upstream: https://proxy.golang.org
    policies:
      - policy.yaml
    auth:
      mode: required
      jwks:
        url: https://auth.example.com/.well-known/jwks.json
        refresh_interval: 1h
      issuers:
        - https://auth.example.com
      audiences:
        - deputy-proxy
      required_claims:
        - sub
        - email
      clock_skew: 30s
`
	if err := os.WriteFile(path, []byte(configYAML), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if len(cfg.Listeners) != 1 {
		t.Fatalf("expected 1 listener, got %d", len(cfg.Listeners))
	}

	auth := cfg.Listeners[0].Auth
	if auth == nil {
		t.Fatal("expected auth config to be present")
	}
	if auth.Mode != "required" {
		t.Errorf("expected mode 'required', got %q", auth.Mode)
	}
	if auth.JWKS == nil {
		t.Fatal("expected JWKS config to be present")
	}
	if auth.JWKS.URL != "https://auth.example.com/.well-known/jwks.json" {
		t.Errorf("unexpected JWKS URL %q", auth.JWKS.URL)
	}
	if len(auth.Issuers) != 1 || auth.Issuers[0] != "https://auth.example.com" {
		t.Errorf("unexpected issuers %v", auth.Issuers)
	}
	if len(auth.Audiences) != 1 || auth.Audiences[0] != "deputy-proxy" {
		t.Errorf("unexpected audiences %v", auth.Audiences)
	}
	if len(auth.RequiredClaims) != 2 {
		t.Errorf("expected 2 required claims, got %d", len(auth.RequiredClaims))
	}
}
