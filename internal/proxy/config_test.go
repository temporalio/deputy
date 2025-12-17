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
