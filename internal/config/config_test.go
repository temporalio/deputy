package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	if cfg.Logging.Level != "info" {
		t.Errorf("expected default log level 'info', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "text" {
		t.Errorf("expected default log format 'text', got %q", cfg.Logging.Format)
	}
	if cfg.Proxy.ListenAddr != ":8080" {
		t.Errorf("expected default proxy addr ':8080', got %q", cfg.Proxy.ListenAddr)
	}
	if cfg.Policy.Mode != "enforce" {
		t.Errorf("expected default policy mode 'enforce', got %q", cfg.Policy.Mode)
	}
}

func TestConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     defaultConfig(),
			wantErr: false,
		},
		{
			name: "invalid log level",
			cfg: &Config{
				Logging: LogConfig{Level: "invalid", Format: "text"},
			},
			wantErr: true,
		},
		{
			name: "invalid log format",
			cfg: &Config{
				Logging: LogConfig{Level: "info", Format: "invalid"},
			},
			wantErr: true,
		},
		{
			name: "invalid policy mode",
			cfg: &Config{
				Logging: LogConfig{Level: "info", Format: "text"},
				Policy:  PolicyConfig{Mode: "invalid"},
			},
			wantErr: true,
		},
		{
			name: "case insensitive log level",
			cfg: &Config{
				Logging: LogConfig{Level: "DEBUG", Format: "text"},
			},
			wantErr: false,
		},
		{
			name: "case insensitive format",
			cfg: &Config{
				Logging: LogConfig{Level: "info", Format: "JSON"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr && err == nil {
				t.Error("expected validation error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected validation error: %v", err)
			}
		})
	}
}

func TestLoadFromEnv(t *testing.T) {
	// Set up environment
	envVars := map[string]string{
		"DEPUTY_LOG_LEVEL":       "debug",
		"DEPUTY_LOG_FORMAT":      "json",
		"DEPUTY_LOG_COLOR":       "false",
		"DEPUTY_LOG_SOURCE":      "true",
		"DEPUTY_PROXY_ADDR":      ":9000",
		"DEPUTY_PROXY_POLICIES":  "policy1.yaml,policy2.yaml",
		"DEPUTY_SCAN_ECOSYSTEMS": "npm,pypi",
		"DEPUTY_SCAN_SKIP_CACHE": "true",
		"DEPUTY_POLICY_PATHS":    "policies/",
		"DEPUTY_POLICY_MODE":     "advisory",
	}

	// Set test env vars (cleanup is automatic)
	for k, v := range envVars {
		t.Setenv(k, v)
	}

	loader := NewLoader("")
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify env vars were applied
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected log level 'debug', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected log format 'json', got %q", cfg.Logging.Format)
	}
	if cfg.Logging.Color != false {
		t.Errorf("expected log color false, got true")
	}
	if cfg.Logging.Source != true {
		t.Errorf("expected log source true, got false")
	}
	if cfg.Proxy.ListenAddr != ":9000" {
		t.Errorf("expected proxy addr ':9000', got %q", cfg.Proxy.ListenAddr)
	}
	if len(cfg.Proxy.PolicyPaths) != 2 {
		t.Errorf("expected 2 policy paths, got %d", len(cfg.Proxy.PolicyPaths))
	}
	if len(cfg.Scan.Ecosystems) != 2 {
		t.Errorf("expected 2 ecosystems, got %d", len(cfg.Scan.Ecosystems))
	}
	if cfg.Scan.SkipCache != true {
		t.Errorf("expected skip cache true, got false")
	}
	if cfg.Policy.Mode != "advisory" {
		t.Errorf("expected policy mode 'advisory', got %q", cfg.Policy.Mode)
	}
}

func TestLoadFromFile(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "deputy.yaml")
	configData := []byte(`
logging:
  level: debug
  format: json
  color: false
  source: true
proxy:
  listen_addr: ":9090"
  policy_paths:
    - policy1.yaml
    - policy2.yaml
scan:
  ecosystems:
    - npm
    - pypi
  skip_cache: true
policy:
  paths:
    - policies/
  mode: advisory
`)

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	loader := NewLoader(configPath)
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify file values were loaded
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected log level 'debug', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected log format 'json', got %q", cfg.Logging.Format)
	}
	if cfg.Proxy.ListenAddr != ":9090" {
		t.Errorf("expected proxy addr ':9090', got %q", cfg.Proxy.ListenAddr)
	}
	if len(cfg.Proxy.PolicyPaths) != 2 {
		t.Errorf("expected 2 policy paths, got %d", len(cfg.Proxy.PolicyPaths))
	}
}

func TestLoadWithOverrides(t *testing.T) {
	loader := NewLoader("")
	overrides := map[string]string{
		"log-level":  "error",
		"log-format": "json",
		"log-color":  "false",
	}

	cfg, err := loader.LoadWithOverrides(overrides)
	if err != nil {
		t.Fatalf("LoadWithOverrides failed: %v", err)
	}

	if cfg.Logging.Level != "error" {
		t.Errorf("expected log level 'error', got %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" {
		t.Errorf("expected log format 'json', got %q", cfg.Logging.Format)
	}
	if cfg.Logging.Color != false {
		t.Errorf("expected log color false, got true")
	}
}

func TestPrecedence(t *testing.T) {
	// Create temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "deputy.yaml")
	configData := []byte(`
logging:
  level: warn
  format: json
`)
	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Set environment variable
	t.Setenv("DEPUTY_LOG_LEVEL", "error")

	loader := NewLoader(configPath)

	// Test env overrides file
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.Logging.Level != "error" {
		t.Errorf("expected env var to override file: got level %q", cfg.Logging.Level)
	}

	// Test flag overrides env
	overrides := map[string]string{"log-level": "debug"}
	cfg, err = loader.LoadWithOverrides(overrides)
	if err != nil {
		t.Fatalf("LoadWithOverrides failed: %v", err)
	}
	if cfg.Logging.Level != "debug" {
		t.Errorf("expected flag to override env: got level %q", cfg.Logging.Level)
	}
}

func TestToSlogLevel(t *testing.T) {
	tests := []struct {
		level    string
		expected string
	}{
		{"debug", "DEBUG"},
		{"DEBUG", "DEBUG"},
		{"info", "INFO"},
		{"INFO", "INFO"},
		{"warn", "WARN"},
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"unknown", "INFO"}, // default
	}

	for _, tt := range tests {
		t.Run(tt.level, func(t *testing.T) {
			lc := LogConfig{Level: tt.level}
			got := lc.ToSlogLevel().String()
			if got != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, got)
			}
		})
	}
}

func TestFindConfigFile(t *testing.T) {
	// Save original working directory
	origWd, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	defer os.Chdir(origWd)

	// Create temporary directory with config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, ".deputy.yaml")
	if err := os.WriteFile(configPath, []byte("logging:\n  level: info\n"), 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	// Change to temp directory
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to change directory: %v", err)
	}

	// Should find the file
	found := FindConfigFile()
	if found != ".deputy.yaml" {
		t.Errorf("expected to find '.deputy.yaml', got %q", found)
	}
}

func TestContains(t *testing.T) {
	slice := []string{"debug", "info", "warn", "error"}

	if !contains(slice, "debug") {
		t.Error("expected contains to find 'debug'")
	}
	if !contains(slice, "DEBUG") {
		t.Error("expected case-insensitive contains to find 'DEBUG'")
	}
	if contains(slice, "notfound") {
		t.Error("expected contains to not find 'notfound'")
	}
}
