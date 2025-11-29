package proxy

import (
	"os"
	"path/filepath"
	"testing"
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
