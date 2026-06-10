package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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
		{
			name: "invalid egress cidr",
			cfg: func() *Config {
				cfg := defaultConfig()
				cfg.Egress = &EgressConfig{
					AllowedCIDRs: []string{"10.0.0.0/8", "not-a-cidr"},
				}
				return cfg
			}(),
			wantErr: true,
		},
		{
			name: "invalid server egress cidr",
			cfg: func() *Config {
				cfg := defaultConfig()
				cfg.Server.Egress = &ServerEgressConfig{
					AllowedCIDRs: []string{"bad-cidr"},
				}
				return cfg
			}(),
			wantErr: true,
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
		"DEPUTY_LOG_LEVEL":               "debug",
		"DEPUTY_LOG_FORMAT":              "json",
		"DEPUTY_LOG_COLOR":               "false",
		"DEPUTY_LOG_SOURCE":              "true",
		"DEPUTY_PROXY_ADDR":              ":9000",
		"DEPUTY_PROXY_POLICIES":          "policy1.yaml,policy2.yaml",
		"DEPUTY_SCAN_ECOSYSTEMS":         "npm,pypi",
		"DEPUTY_SCAN_SKIP_CACHE":         "true",
		"DEPUTY_POLICY_PATHS":            "policies/",
		"DEPUTY_POLICY_MODE":             "advisory",
		"DEPUTY_EGRESS_ALLOW_HOSTS":      ".corp.local,git.internal",
		"DEPUTY_EGRESS_ALLOW_CIDRS":      "10.0.0.0/8,192.168.0.0/16",
		"DEPUTY_EGRESS_ALLOW_LOOPBACK":   "true",
		"DEPUTY_EGRESS_ALLOW_LINK_LOCAL": "true",
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
	if cfg.Egress == nil {
		t.Fatal("expected egress config to be set")
	}
	if len(cfg.Egress.AllowedHosts) != 2 {
		t.Errorf("expected 2 egress hosts, got %d", len(cfg.Egress.AllowedHosts))
	}
	if len(cfg.Egress.AllowedCIDRs) != 2 {
		t.Errorf("expected 2 egress CIDRs, got %d", len(cfg.Egress.AllowedCIDRs))
	}
	if !cfg.Egress.AllowLoopback {
		t.Error("expected egress allow_loopback true, got false")
	}
	if !cfg.Egress.AllowLinkLocal {
		t.Error("expected egress allow_link_local true, got false")
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

func TestDefaultHTTPConfig(t *testing.T) {
	cfg := defaultConfig()

	// Verify HTTP defaults
	if cfg.HTTP.Timeout != 30*time.Second {
		t.Errorf("expected HTTP timeout 30s, got %v", cfg.HTTP.Timeout)
	}
	if cfg.HTTP.DialTimeout != 10*time.Second {
		t.Errorf("expected dial timeout 10s, got %v", cfg.HTTP.DialTimeout)
	}
	if cfg.HTTP.MaxIdleConns != 20 {
		t.Errorf("expected max idle conns 20, got %d", cfg.HTTP.MaxIdleConns)
	}
	if cfg.HTTP.MaxIdleConnsPerHost != 10 {
		t.Errorf("expected max idle conns per host 10, got %d", cfg.HTTP.MaxIdleConnsPerHost)
	}
	if cfg.HTTP.Retry.Max != 3 {
		t.Errorf("expected retry max 3, got %d", cfg.HTTP.Retry.Max)
	}
	if cfg.HTTP.Retry.WaitMin != 500*time.Millisecond {
		t.Errorf("expected retry wait min 500ms, got %v", cfg.HTTP.Retry.WaitMin)
	}
	if cfg.HTTP.Retry.WaitMax != 5*time.Second {
		t.Errorf("expected retry wait max 5s, got %v", cfg.HTTP.Retry.WaitMax)
	}
	if !cfg.HTTP.RetryEnabled() {
		t.Error("expected retry to be enabled by default")
	}
}

func TestDefaultPerformanceConfig(t *testing.T) {
	cfg := defaultConfig()

	// Verify performance defaults
	if cfg.Performance.OSVConcurrency != 10 {
		t.Errorf("expected OSV concurrency 10, got %d", cfg.Performance.OSVConcurrency)
	}
	if cfg.Performance.GraphConcurrency != 5 {
		t.Errorf("expected graph concurrency 5, got %d", cfg.Performance.GraphConcurrency)
	}
	if cfg.Performance.SBOMEnrichConcurrency != 4 {
		t.Errorf("expected SBOM enrich concurrency 4, got %d", cfg.Performance.SBOMEnrichConcurrency)
	}
	if cfg.Performance.ImageScanConcurrency != 4 {
		t.Errorf("expected image scan concurrency 4, got %d", cfg.Performance.ImageScanConcurrency)
	}

	// Verify cache defaults
	if cfg.Performance.Cache.TTL != 1*time.Hour {
		t.Errorf("expected cache TTL 1h, got %v", cfg.Performance.Cache.TTL)
	}
	if cfg.Performance.Cache.KEVTTL != 24*time.Hour {
		t.Errorf("expected KEV TTL 24h, got %v", cfg.Performance.Cache.KEVTTL)
	}
	if cfg.Performance.Cache.MaxSize != 1024 {
		t.Errorf("expected cache max size 1024, got %d", cfg.Performance.Cache.MaxSize)
	}
	if cfg.Performance.Cache.Disabled {
		t.Error("expected cache to be enabled by default")
	}
}

func TestHTTPConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     HTTPConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     defaultConfig().HTTP,
			wantErr: false,
		},
		{
			name: "negative timeout",
			cfg: HTTPConfig{
				Timeout: -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative dial timeout",
			cfg: HTTPConfig{
				DialTimeout: -1 * time.Second,
			},
			wantErr: true,
		},
		{
			name: "negative retry max",
			cfg: HTTPConfig{
				Retry: RetryConfig{Max: -1},
			},
			wantErr: true,
		},
		{
			name: "negative retry wait min",
			cfg: HTTPConfig{
				Retry: RetryConfig{
					WaitMin: -1 * time.Second,
					WaitMax: 5 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "wait max less than wait min",
			cfg: HTTPConfig{
				Retry: RetryConfig{
					WaitMin: 5 * time.Second,
					WaitMax: 1 * time.Second,
				},
			},
			wantErr: true,
		},
		{
			name: "zero timeout is valid",
			cfg: HTTPConfig{
				Timeout:     0,
				DialTimeout: 0,
				Retry: RetryConfig{
					Max:     0,
					WaitMin: 0,
					WaitMax: 0,
				},
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

func TestPerformanceConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		cfg     PerformanceConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			cfg:     defaultConfig().Performance,
			wantErr: false,
		},
		{
			name: "negative OSV concurrency",
			cfg: PerformanceConfig{
				OSVConcurrency: -1,
			},
			wantErr: true,
		},
		{
			name: "negative graph concurrency",
			cfg: PerformanceConfig{
				GraphConcurrency: -1,
			},
			wantErr: true,
		},
		{
			name: "negative cache max size",
			cfg: PerformanceConfig{
				Cache: CacheConfig{MaxSize: -1},
			},
			wantErr: true,
		},
		{
			name: "negative cache TTL",
			cfg: PerformanceConfig{
				Cache: CacheConfig{TTL: -1 * time.Second},
			},
			wantErr: true,
		},
		{
			name: "zero concurrency is valid",
			cfg: PerformanceConfig{
				OSVConcurrency:   0,
				GraphConcurrency: 0,
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

func TestRetryEnabled(t *testing.T) {
	tests := []struct {
		name     string
		cfg      HTTPConfig
		expected bool
	}{
		{
			name:     "nil defaults to true",
			cfg:      HTTPConfig{},
			expected: true,
		},
		{
			name: "explicit true",
			cfg: HTTPConfig{
				Retry: RetryConfig{Enabled: new(true)},
			},
			expected: true,
		},
		{
			name: "explicit false",
			cfg: HTTPConfig{
				Retry: RetryConfig{Enabled: new(false)},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.RetryEnabled(); got != tt.expected {
				t.Errorf("RetryEnabled() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLoadHTTPFromEnv(t *testing.T) {
	envVars := map[string]string{
		"DEPUTY_HTTP_TIMEOUT":                 "60s",
		"DEPUTY_HTTP_DIAL_TIMEOUT":            "15s",
		"DEPUTY_HTTP_TLS_TIMEOUT":             "20s",
		"DEPUTY_HTTP_RESPONSE_TIMEOUT":        "30s",
		"DEPUTY_HTTP_KEEPALIVE":               "45s",
		"DEPUTY_HTTP_IDLE_TIMEOUT":            "120s",
		"DEPUTY_HTTP_MAX_IDLE_CONNS":          "50",
		"DEPUTY_HTTP_MAX_IDLE_CONNS_PER_HOST": "20",
		"DEPUTY_HTTP_RETRY_MAX":               "5",
		"DEPUTY_HTTP_RETRY_WAIT_MIN":          "1s",
		"DEPUTY_HTTP_RETRY_WAIT_MAX":          "10s",
		"DEPUTY_HTTP_RETRY_ENABLED":           "false",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	loader := NewLoader("")
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.HTTP.Timeout != 60*time.Second {
		t.Errorf("expected HTTP timeout 60s, got %v", cfg.HTTP.Timeout)
	}
	if cfg.HTTP.DialTimeout != 15*time.Second {
		t.Errorf("expected dial timeout 15s, got %v", cfg.HTTP.DialTimeout)
	}
	if cfg.HTTP.TLSHandshakeTimeout != 20*time.Second {
		t.Errorf("expected TLS timeout 20s, got %v", cfg.HTTP.TLSHandshakeTimeout)
	}
	if cfg.HTTP.ResponseHeaderTimeout != 30*time.Second {
		t.Errorf("expected response header timeout 30s, got %v", cfg.HTTP.ResponseHeaderTimeout)
	}
	if cfg.HTTP.KeepAlive != 45*time.Second {
		t.Errorf("expected keep-alive 45s, got %v", cfg.HTTP.KeepAlive)
	}
	if cfg.HTTP.IdleConnTimeout != 120*time.Second {
		t.Errorf("expected idle conn timeout 120s, got %v", cfg.HTTP.IdleConnTimeout)
	}
	if cfg.HTTP.MaxIdleConns != 50 {
		t.Errorf("expected max idle conns 50, got %d", cfg.HTTP.MaxIdleConns)
	}
	if cfg.HTTP.MaxIdleConnsPerHost != 20 {
		t.Errorf("expected max idle conns per host 20, got %d", cfg.HTTP.MaxIdleConnsPerHost)
	}
	if cfg.HTTP.Retry.Max != 5 {
		t.Errorf("expected retry max 5, got %d", cfg.HTTP.Retry.Max)
	}
	if cfg.HTTP.Retry.WaitMin != 1*time.Second {
		t.Errorf("expected retry wait min 1s, got %v", cfg.HTTP.Retry.WaitMin)
	}
	if cfg.HTTP.Retry.WaitMax != 10*time.Second {
		t.Errorf("expected retry wait max 10s, got %v", cfg.HTTP.Retry.WaitMax)
	}
	if cfg.HTTP.RetryEnabled() {
		t.Error("expected retry to be disabled")
	}
}

func TestLoadPerformanceFromEnv(t *testing.T) {
	envVars := map[string]string{
		"DEPUTY_OSV_CONCURRENCY":         "20",
		"DEPUTY_GRAPH_CONCURRENCY":       "10",
		"DEPUTY_SBOM_ENRICH_CONCURRENCY": "8",
		"DEPUTY_IMAGE_SCAN_CONCURRENCY":  "6",
		"DEPUTY_CACHE_DIR":               "/tmp/deputy-cache",
		"DEPUTY_CACHE_TTL":               "2h",
		"DEPUTY_CACHE_KEV_TTL":           "48h",
		"DEPUTY_CACHE_EPSS_TTL":          "12h",
		"DEPUTY_CACHE_OSV_TTL":           "30m",
		"DEPUTY_CACHE_LICENSE_TTL":       "72h",
		"DEPUTY_CACHE_MAX_SIZE":          "2048",
		"DEPUTY_CACHE_DISABLED":          "true",
	}

	for k, v := range envVars {
		t.Setenv(k, v)
	}

	loader := NewLoader("")
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Performance.OSVConcurrency != 20 {
		t.Errorf("expected OSV concurrency 20, got %d", cfg.Performance.OSVConcurrency)
	}
	if cfg.Performance.GraphConcurrency != 10 {
		t.Errorf("expected graph concurrency 10, got %d", cfg.Performance.GraphConcurrency)
	}
	if cfg.Performance.SBOMEnrichConcurrency != 8 {
		t.Errorf("expected SBOM enrich concurrency 8, got %d", cfg.Performance.SBOMEnrichConcurrency)
	}
	if cfg.Performance.ImageScanConcurrency != 6 {
		t.Errorf("expected image scan concurrency 6, got %d", cfg.Performance.ImageScanConcurrency)
	}
	if cfg.Performance.Cache.Dir != "/tmp/deputy-cache" {
		t.Errorf("expected cache dir '/tmp/deputy-cache', got %q", cfg.Performance.Cache.Dir)
	}
	if cfg.Performance.Cache.TTL != 2*time.Hour {
		t.Errorf("expected cache TTL 2h, got %v", cfg.Performance.Cache.TTL)
	}
	if cfg.Performance.Cache.KEVTTL != 48*time.Hour {
		t.Errorf("expected KEV TTL 48h, got %v", cfg.Performance.Cache.KEVTTL)
	}
	if cfg.Performance.Cache.EPSSTTL != 12*time.Hour {
		t.Errorf("expected EPSS TTL 12h, got %v", cfg.Performance.Cache.EPSSTTL)
	}
	if cfg.Performance.Cache.OSVTTL != 30*time.Minute {
		t.Errorf("expected OSV TTL 30m, got %v", cfg.Performance.Cache.OSVTTL)
	}
	if cfg.Performance.Cache.LicenseTTL != 72*time.Hour {
		t.Errorf("expected license TTL 72h, got %v", cfg.Performance.Cache.LicenseTTL)
	}
	if cfg.Performance.Cache.MaxSize != 2048 {
		t.Errorf("expected cache max size 2048, got %d", cfg.Performance.Cache.MaxSize)
	}
	if !cfg.Performance.Cache.Disabled {
		t.Error("expected cache to be disabled")
	}
}

func TestLoadHTTPAndPerformanceFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "deputy.yaml")
	configData := []byte(`
logging:
  level: info
  format: text
http:
  timeout: 45s
  dial_timeout: 12s
  tls_handshake_timeout: 15s
  max_idle_conns: 30
  retry:
    max: 4
    wait_min: 750ms
    wait_max: 8s
performance:
  osv_concurrency: 15
  graph_concurrency: 8
  cache:
    ttl: 90m
    max_size: 512
`)

	if err := os.WriteFile(configPath, configData, 0644); err != nil {
		t.Fatalf("failed to write config file: %v", err)
	}

	loader := NewLoader(configPath)
	cfg, err := loader.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.HTTP.Timeout != 45*time.Second {
		t.Errorf("expected HTTP timeout 45s, got %v", cfg.HTTP.Timeout)
	}
	if cfg.HTTP.DialTimeout != 12*time.Second {
		t.Errorf("expected dial timeout 12s, got %v", cfg.HTTP.DialTimeout)
	}
	if cfg.HTTP.TLSHandshakeTimeout != 15*time.Second {
		t.Errorf("expected TLS timeout 15s, got %v", cfg.HTTP.TLSHandshakeTimeout)
	}
	if cfg.HTTP.MaxIdleConns != 30 {
		t.Errorf("expected max idle conns 30, got %d", cfg.HTTP.MaxIdleConns)
	}
	if cfg.HTTP.Retry.Max != 4 {
		t.Errorf("expected retry max 4, got %d", cfg.HTTP.Retry.Max)
	}
	if cfg.HTTP.Retry.WaitMin != 750*time.Millisecond {
		t.Errorf("expected retry wait min 750ms, got %v", cfg.HTTP.Retry.WaitMin)
	}
	if cfg.HTTP.Retry.WaitMax != 8*time.Second {
		t.Errorf("expected retry wait max 8s, got %v", cfg.HTTP.Retry.WaitMax)
	}
	if cfg.Performance.OSVConcurrency != 15 {
		t.Errorf("expected OSV concurrency 15, got %d", cfg.Performance.OSVConcurrency)
	}
	if cfg.Performance.GraphConcurrency != 8 {
		t.Errorf("expected graph concurrency 8, got %d", cfg.Performance.GraphConcurrency)
	}
	if cfg.Performance.Cache.TTL != 90*time.Minute {
		t.Errorf("expected cache TTL 90m, got %v", cfg.Performance.Cache.TTL)
	}
	if cfg.Performance.Cache.MaxSize != 512 {
		t.Errorf("expected cache max size 512, got %d", cfg.Performance.Cache.MaxSize)
	}
}
