// Package config provides unified configuration management for Deputy.
// It handles configuration from multiple sources with clear precedence:
// flags > environment variables > config file > defaults.
package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/picatz/deputy/internal/errors"
	"github.com/picatz/deputy/internal/otel"
	"gopkg.in/yaml.v3"
)

// Config represents the complete Deputy configuration.
type Config struct {
	// Logging configures log output behavior.
	Logging LogConfig `yaml:"logging"`

	// HTTP configures HTTP client behavior across all subsystems.
	HTTP HTTPConfig `yaml:"http,omitempty"`

	// Performance configures concurrency, caching, and resource limits.
	Performance PerformanceConfig `yaml:"performance,omitempty"`

	// Proxy configures the package proxy server.
	Proxy ProxyConfig `yaml:"proxy,omitempty"`

	// Scan configures vulnerability scanning behavior.
	Scan ScanConfig `yaml:"scan,omitempty"`

	// Policy configures policy evaluation.
	Policy PolicyConfig `yaml:"policy,omitempty"`

	// OTel configures OpenTelemetry instrumentation.
	OTel otel.Config `yaml:"otel,omitempty"`
}

// LogConfig configures logging behavior.
type LogConfig struct {
	// Level sets the minimum log level (debug, info, warn, error).
	Level string `yaml:"level"`

	// Format specifies output format (text, json).
	Format string `yaml:"format"`

	// Color enables ANSI color codes in text format.
	Color bool `yaml:"color"`

	// Source includes source file and line number in logs.
	Source bool `yaml:"source"`
}

// ProxyConfig configures the package proxy server.
type ProxyConfig struct {
	// ListenAddr is the address to bind the proxy server (e.g., ":8080").
	ListenAddr string `yaml:"listen_addr"`

	// PolicyPaths are paths to policy files to enforce.
	PolicyPaths []string `yaml:"policy_paths"`
}

// ScanConfig configures vulnerability scanning.
type ScanConfig struct {
	// Ecosystems limits scanning to specific ecosystems.
	Ecosystems []string `yaml:"ecosystems,omitempty"`

	// SkipCache disables result caching.
	SkipCache bool `yaml:"skip_cache"`
}

// PolicyConfig configures policy evaluation.
type PolicyConfig struct {
	// Paths are locations of policy files or directories.
	Paths []string `yaml:"paths"`

	// Mode sets the default policy mode (enforce, advisory).
	Mode string `yaml:"mode"`
}

// HTTPConfig configures HTTP client behavior across all subsystems.
// These settings apply to all HTTP clients created by Deputy unless
// explicitly overridden.
type HTTPConfig struct {
	// Timeout is the overall request timeout for HTTP operations.
	// Default: 30s
	Timeout time.Duration `yaml:"timeout"`

	// DialTimeout is the maximum time to establish a TCP connection.
	// Default: 10s
	DialTimeout time.Duration `yaml:"dial_timeout"`

	// TLSHandshakeTimeout is the maximum time for TLS handshake.
	// Default: 10s
	TLSHandshakeTimeout time.Duration `yaml:"tls_handshake_timeout"`

	// ResponseHeaderTimeout is the maximum time to wait for response headers.
	// Default: 20s
	ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout"`

	// KeepAlive is the interval between TCP keep-alive probes.
	// Default: 30s
	KeepAlive time.Duration `yaml:"keep_alive"`

	// IdleConnTimeout is how long idle connections remain in the pool.
	// Default: 90s
	IdleConnTimeout time.Duration `yaml:"idle_conn_timeout"`

	// MaxIdleConns is the maximum number of idle connections in the pool.
	// Default: 20
	MaxIdleConns int `yaml:"max_idle_conns"`

	// MaxIdleConnsPerHost is the maximum idle connections per host.
	// Default: 10
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host"`

	// Retry configures automatic retry behavior for transient failures.
	Retry RetryConfig `yaml:"retry,omitempty"`
}

// RetryConfig configures HTTP retry behavior.
type RetryConfig struct {
	// Max is the maximum number of retry attempts.
	// Default: 3
	Max int `yaml:"max"`

	// WaitMin is the minimum wait time between retries.
	// Default: 500ms
	WaitMin time.Duration `yaml:"wait_min"`

	// WaitMax is the maximum wait time between retries.
	// Default: 5s
	WaitMax time.Duration `yaml:"wait_max"`

	// Enabled controls whether retries are attempted at all.
	// Default: true
	Enabled *bool `yaml:"enabled,omitempty"`
}

// PerformanceConfig configures concurrency, caching, and resource limits.
type PerformanceConfig struct {
	// OSVConcurrency is the number of concurrent OSV API requests.
	// Default: 10
	OSVConcurrency int `yaml:"osv_concurrency"`

	// GraphConcurrency is the number of concurrent graph resolution operations.
	// Default: 5
	GraphConcurrency int `yaml:"graph_concurrency"`

	// SBOMEnrichConcurrency is the concurrency for SBOM enrichment operations.
	// Default: 4
	SBOMEnrichConcurrency int `yaml:"sbom_enrich_concurrency"`

	// ImageScanConcurrency is the concurrency for container image scanning.
	// Default: 4
	ImageScanConcurrency int `yaml:"image_scan_concurrency"`

	// Cache configures caching behavior.
	Cache CacheConfig `yaml:"cache,omitempty"`
}

// CacheConfig configures caching behavior.
type CacheConfig struct {
	// Dir is the directory for persistent cache storage.
	// Default: ~/.deputy/cache
	Dir string `yaml:"dir"`

	// TTL is the default time-to-live for cached entries.
	// Default: 1h
	TTL time.Duration `yaml:"ttl"`

	// KEVTTL is the TTL for CISA KEV catalog cache.
	// Default: 24h
	KEVTTL time.Duration `yaml:"kev_ttl"`

	// EPSSTTL is the TTL for EPSS scores cache.
	// Default: 24h
	EPSSTTL time.Duration `yaml:"epss_ttl"`

	// OSVTTL is the TTL for OSV vulnerability cache.
	// Default: 1h
	OSVTTL time.Duration `yaml:"osv_ttl"`

	// LicenseTTL is the TTL for license information cache.
	// Default: 24h
	LicenseTTL time.Duration `yaml:"license_ttl"`

	// MaxSize is the maximum number of entries in in-memory caches.
	// Default: 1024
	MaxSize int `yaml:"max_size"`

	// Disabled completely disables caching.
	// Default: false
	Disabled bool `yaml:"disabled"`
}

// Loader handles loading configuration from multiple sources.
type Loader struct {
	configPath string
	envPrefix  string
}

// NewLoader creates a configuration loader with optional config file path.
func NewLoader(configPath string) *Loader {
	return &Loader{
		configPath: configPath,
		envPrefix:  "DEPUTY_",
	}
}

// Load reads configuration from all sources and applies precedence rules.
// Precedence: explicit flags > environment variables > config file > defaults.
func (l *Loader) Load() (*Config, error) {
	cfg := defaultConfig()

	// 1. Load from config file if provided
	if l.configPath != "" {
		if err := l.loadFromFile(cfg); err != nil {
			return nil, err
		}
	}

	// 2. Override with environment variables
	l.loadFromEnv(cfg)

	// 3. Validate the final configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

// LoadWithOverrides loads config and applies explicit flag overrides.
func (l *Loader) LoadWithOverrides(overrides map[string]string) (*Config, error) {
	cfg, err := l.Load()
	if err != nil {
		return nil, err
	}

	// Apply explicit flag overrides (highest precedence)
	if level, ok := overrides["log-level"]; ok && level != "" {
		cfg.Logging.Level = level
	}
	if format, ok := overrides["log-format"]; ok && format != "" {
		cfg.Logging.Format = format
	}
	if color, ok := overrides["log-color"]; ok {
		cfg.Logging.Color = color == "true" || color == "1"
	}

	return cfg, nil
}

// loadFromFile reads configuration from a YAML file.
func (l *Loader) loadFromFile(cfg *Config) error {
	data, err := os.ReadFile(l.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // Config file is optional
		}
		return &errors.ConfigError{
			Path:    l.configPath,
			Message: "failed to read config file",
			Cause:   err,
		}
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return &errors.ConfigError{
			Path:    l.configPath,
			Message: "failed to parse config file",
			Cause:   err,
		}
	}

	return nil
}

// loadFromEnv reads configuration from environment variables.
func (l *Loader) loadFromEnv(cfg *Config) {
	// Logging configuration
	if val := os.Getenv(l.envPrefix + "LOG_LEVEL"); val != "" {
		cfg.Logging.Level = val
	}
	if val := os.Getenv(l.envPrefix + "LOG_FORMAT"); val != "" {
		cfg.Logging.Format = val
	}
	if val := os.Getenv(l.envPrefix + "LOG_COLOR"); val != "" {
		cfg.Logging.Color = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "LOG_SOURCE"); val != "" {
		cfg.Logging.Source = val == "true" || val == "1"
	}

	// HTTP configuration
	l.loadHTTPFromEnv(cfg)

	// Performance configuration
	l.loadPerformanceFromEnv(cfg)

	// Proxy configuration
	if val := os.Getenv(l.envPrefix + "PROXY_ADDR"); val != "" {
		cfg.Proxy.ListenAddr = val
	}
	if val := os.Getenv(l.envPrefix + "PROXY_POLICIES"); val != "" {
		cfg.Proxy.PolicyPaths = strings.Split(val, ",")
	}

	// Scan configuration
	if val := os.Getenv(l.envPrefix + "SCAN_ECOSYSTEMS"); val != "" {
		cfg.Scan.Ecosystems = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SCAN_SKIP_CACHE"); val != "" {
		cfg.Scan.SkipCache = val == "true" || val == "1"
	}

	// Policy configuration
	if val := os.Getenv(l.envPrefix + "POLICY_PATHS"); val != "" {
		cfg.Policy.Paths = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "POLICY_MODE"); val != "" {
		cfg.Policy.Mode = val
	}

	// OTel configuration
	if val := os.Getenv(l.envPrefix + "OTEL_ENABLED"); val != "" {
		cfg.OTel.Enabled = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "OTEL_SERVICE_NAME"); val != "" {
		cfg.OTel.ServiceName = val
	}
	// Standard OTel environment variables
	if val := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); val != "" {
		cfg.OTel.Exporter.Endpoint = val
	}
	if val := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL"); val != "" {
		cfg.OTel.Exporter.Protocol = val
	}
	if val := os.Getenv("OTEL_EXPORTER_OTLP_INSECURE"); val != "" {
		cfg.OTel.Exporter.Insecure = val == "true" || val == "1"
	}
	if val := os.Getenv("OTEL_TRACES_SAMPLER_ARG"); val != "" {
		if rate, err := strconv.ParseFloat(val, 64); err == nil {
			cfg.OTel.Traces.SampleRate = rate
		}
	}
	if val := os.Getenv("OTEL_EXPORTER_OTLP_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.OTel.Exporter.Timeout = d
		}
	}
}

// loadHTTPFromEnv loads HTTP configuration from environment variables.
func (l *Loader) loadHTTPFromEnv(cfg *Config) {
	if val := os.Getenv(l.envPrefix + "HTTP_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.Timeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_DIAL_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.DialTimeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_TLS_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.TLSHandshakeTimeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_RESPONSE_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.ResponseHeaderTimeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_KEEPALIVE"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.KeepAlive = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_IDLE_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.IdleConnTimeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_MAX_IDLE_CONNS"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.HTTP.MaxIdleConns = n
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_MAX_IDLE_CONNS_PER_HOST"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.HTTP.MaxIdleConnsPerHost = n
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_RETRY_MAX"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n >= 0 {
			cfg.HTTP.Retry.Max = n
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_RETRY_WAIT_MIN"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.Retry.WaitMin = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_RETRY_WAIT_MAX"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.HTTP.Retry.WaitMax = d
		}
	}
	if val := os.Getenv(l.envPrefix + "HTTP_RETRY_ENABLED"); val != "" {
		enabled := val == "true" || val == "1"
		cfg.HTTP.Retry.Enabled = &enabled
	}
}

// loadPerformanceFromEnv loads performance configuration from environment variables.
func (l *Loader) loadPerformanceFromEnv(cfg *Config) {
	if val := os.Getenv(l.envPrefix + "OSV_CONCURRENCY"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Performance.OSVConcurrency = n
		}
	}
	if val := os.Getenv(l.envPrefix + "GRAPH_CONCURRENCY"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Performance.GraphConcurrency = n
		}
	}
	if val := os.Getenv(l.envPrefix + "SBOM_ENRICH_CONCURRENCY"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Performance.SBOMEnrichConcurrency = n
		}
	}
	if val := os.Getenv(l.envPrefix + "IMAGE_SCAN_CONCURRENCY"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Performance.ImageScanConcurrency = n
		}
	}
	// Cache configuration
	if val := os.Getenv(l.envPrefix + "CACHE_DIR"); val != "" {
		cfg.Performance.Cache.Dir = val
	}
	if val := os.Getenv(l.envPrefix + "CACHE_TTL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Performance.Cache.TTL = d
		}
	}
	if val := os.Getenv(l.envPrefix + "CACHE_KEV_TTL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Performance.Cache.KEVTTL = d
		}
	}
	if val := os.Getenv(l.envPrefix + "CACHE_EPSS_TTL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Performance.Cache.EPSSTTL = d
		}
	}
	if val := os.Getenv(l.envPrefix + "CACHE_OSV_TTL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Performance.Cache.OSVTTL = d
		}
	}
	if val := os.Getenv(l.envPrefix + "CACHE_LICENSE_TTL"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Performance.Cache.LicenseTTL = d
		}
	}
	if val := os.Getenv(l.envPrefix + "CACHE_MAX_SIZE"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			cfg.Performance.Cache.MaxSize = n
		}
	}
	if val := os.Getenv(l.envPrefix + "CACHE_DISABLED"); val != "" {
		cfg.Performance.Cache.Disabled = val == "true" || val == "1"
	}
}

// defaultConfig returns a configuration with sensible defaults.
func defaultConfig() *Config {
	retryEnabled := true
	return &Config{
		Logging: LogConfig{
			Level:  "info",
			Format: "text",
			Color:  isTerminal(),
			Source: false,
		},
		HTTP: HTTPConfig{
			Timeout:               30 * time.Second,
			DialTimeout:           10 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 20 * time.Second,
			KeepAlive:             30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConns:          20,
			MaxIdleConnsPerHost:   10,
			Retry: RetryConfig{
				Max:     3,
				WaitMin: 500 * time.Millisecond,
				WaitMax: 5 * time.Second,
				Enabled: &retryEnabled,
			},
		},
		Performance: PerformanceConfig{
			OSVConcurrency:        10,
			GraphConcurrency:      5,
			SBOMEnrichConcurrency: 4,
			ImageScanConcurrency:  4,
			Cache: CacheConfig{
				Dir:        defaultCacheDir(),
				TTL:        1 * time.Hour,
				KEVTTL:     24 * time.Hour,
				EPSSTTL:    24 * time.Hour,
				OSVTTL:     1 * time.Hour,
				LicenseTTL: 24 * time.Hour,
				MaxSize:    1024,
				Disabled:   false,
			},
		},
		Proxy: ProxyConfig{
			ListenAddr: ":8080",
		},
		Scan: ScanConfig{
			SkipCache: false,
		},
		Policy: PolicyConfig{
			Mode: "enforce",
		},
		OTel: otel.DefaultConfig(),
	}
}

// defaultCacheDir returns the default cache directory path.
func defaultCacheDir() string {
	if dir := os.Getenv("DEPUTY_CACHE_DIR"); dir != "" {
		return dir
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ".deputy/cache"
	}
	return filepath.Join(home, ".deputy", "cache")
}

// Validate checks the configuration for invalid values.
func (c *Config) Validate() error {
	// Validate log level
	validLevels := []string{"debug", "info", "warn", "error"}
	if !contains(validLevels, strings.ToLower(c.Logging.Level)) {
		return &errors.ValidationError{
			Field:   "logging.level",
			Value:   c.Logging.Level,
			Message: fmt.Sprintf("must be one of: %s", strings.Join(validLevels, ", ")),
		}
	}

	// Validate log format
	validFormats := []string{"text", "json"}
	if !contains(validFormats, strings.ToLower(c.Logging.Format)) {
		return &errors.ValidationError{
			Field:   "logging.format",
			Value:   c.Logging.Format,
			Message: fmt.Sprintf("must be one of: %s", strings.Join(validFormats, ", ")),
		}
	}

	// Validate HTTP configuration
	if err := c.HTTP.Validate(); err != nil {
		return err
	}

	// Validate performance configuration
	if err := c.Performance.Validate(); err != nil {
		return err
	}

	// Validate policy mode
	if c.Policy.Mode != "" {
		validModes := []string{"enforce", "advisory"}
		if !contains(validModes, strings.ToLower(c.Policy.Mode)) {
			return &errors.ValidationError{
				Field:   "policy.mode",
				Value:   c.Policy.Mode,
				Message: fmt.Sprintf("must be one of: %s", strings.Join(validModes, ", ")),
			}
		}
	}

	// Validate OTel configuration
	if err := c.OTel.Validate(); err != nil {
		return err
	}

	return nil
}

// Validate checks HTTPConfig for invalid values.
func (h HTTPConfig) Validate() error {
	if h.Timeout < 0 {
		return &errors.ValidationError{
			Field:   "http.timeout",
			Value:   h.Timeout.String(),
			Message: "must be non-negative",
		}
	}
	if h.DialTimeout < 0 {
		return &errors.ValidationError{
			Field:   "http.dial_timeout",
			Value:   h.DialTimeout.String(),
			Message: "must be non-negative",
		}
	}
	if h.Retry.Max < 0 {
		return &errors.ValidationError{
			Field:   "http.retry.max",
			Value:   strconv.Itoa(h.Retry.Max),
			Message: "must be non-negative",
		}
	}
	if h.Retry.WaitMin < 0 {
		return &errors.ValidationError{
			Field:   "http.retry.wait_min",
			Value:   h.Retry.WaitMin.String(),
			Message: "must be non-negative",
		}
	}
	if h.Retry.WaitMax < h.Retry.WaitMin {
		return &errors.ValidationError{
			Field:   "http.retry.wait_max",
			Value:   h.Retry.WaitMax.String(),
			Message: "must be >= wait_min",
		}
	}
	return nil
}

// RetryEnabled returns whether retry is enabled (defaults to true).
func (h HTTPConfig) RetryEnabled() bool {
	if h.Retry.Enabled == nil {
		return true
	}
	return *h.Retry.Enabled
}

// WithDefaults returns a copy of HTTPConfig with zero values replaced by defaults.
// This is useful when loading partial configs from YAML where some fields may be omitted.
func (h HTTPConfig) WithDefaults() HTTPConfig {
	def := defaultHTTPConfig()
	if h.Timeout == 0 {
		h.Timeout = def.Timeout
	}
	if h.DialTimeout == 0 {
		h.DialTimeout = def.DialTimeout
	}
	if h.TLSHandshakeTimeout == 0 {
		h.TLSHandshakeTimeout = def.TLSHandshakeTimeout
	}
	if h.ResponseHeaderTimeout == 0 {
		h.ResponseHeaderTimeout = def.ResponseHeaderTimeout
	}
	if h.KeepAlive == 0 {
		h.KeepAlive = def.KeepAlive
	}
	if h.IdleConnTimeout == 0 {
		h.IdleConnTimeout = def.IdleConnTimeout
	}
	if h.MaxIdleConns == 0 {
		h.MaxIdleConns = def.MaxIdleConns
	}
	if h.MaxIdleConnsPerHost == 0 {
		h.MaxIdleConnsPerHost = def.MaxIdleConnsPerHost
	}
	if h.Retry.Max == 0 && h.Retry.Enabled == nil {
		h.Retry.Max = def.Retry.Max
	}
	if h.Retry.WaitMin == 0 {
		h.Retry.WaitMin = def.Retry.WaitMin
	}
	if h.Retry.WaitMax == 0 {
		h.Retry.WaitMax = def.Retry.WaitMax
	}
	if h.Retry.Enabled == nil {
		h.Retry.Enabled = def.Retry.Enabled
	}
	return h
}

// defaultHTTPConfig returns default HTTP configuration values.
func defaultHTTPConfig() HTTPConfig {
	retryEnabled := true
	return HTTPConfig{
		Timeout:               30 * time.Second,
		DialTimeout:           10 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		KeepAlive:             30 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          20,
		MaxIdleConnsPerHost:   10,
		Retry: RetryConfig{
			Max:     3,
			WaitMin: 500 * time.Millisecond,
			WaitMax: 5 * time.Second,
			Enabled: &retryEnabled,
		},
	}
}

// Validate checks PerformanceConfig for invalid values.
func (p PerformanceConfig) Validate() error {
	if p.OSVConcurrency < 0 {
		return &errors.ValidationError{
			Field:   "performance.osv_concurrency",
			Value:   strconv.Itoa(p.OSVConcurrency),
			Message: "must be non-negative",
		}
	}
	if p.GraphConcurrency < 0 {
		return &errors.ValidationError{
			Field:   "performance.graph_concurrency",
			Value:   strconv.Itoa(p.GraphConcurrency),
			Message: "must be non-negative",
		}
	}
	if p.Cache.MaxSize < 0 {
		return &errors.ValidationError{
			Field:   "performance.cache.max_size",
			Value:   strconv.Itoa(p.Cache.MaxSize),
			Message: "must be non-negative",
		}
	}
	if p.Cache.TTL < 0 {
		return &errors.ValidationError{
			Field:   "performance.cache.ttl",
			Value:   p.Cache.TTL.String(),
			Message: "must be non-negative",
		}
	}
	return nil
}

// ToSlogLevel converts the log level string to slog.Level.
func (lc LogConfig) ToSlogLevel() slog.Level {
	switch strings.ToLower(lc.Level) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// FindConfigFile searches for a config file in standard locations.
// Returns the path if found, empty string otherwise.
func FindConfigFile() string {
	// Check explicit DEPUTY_CONFIG env var first
	if path := os.Getenv("DEPUTY_CONFIG"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	// Check current directory
	candidates := []string{
		".deputy.yaml",
		".deputy.yml",
		"deputy.yaml",
		"deputy.yml",
	}

	for _, name := range candidates {
		if _, err := os.Stat(name); err == nil {
			return name
		}
	}

	// Check home directory
	if home, err := os.UserHomeDir(); err == nil {
		for _, name := range candidates {
			path := filepath.Join(home, name)
			if _, err := os.Stat(path); err == nil {
				return path
			}
		}
	}

	return ""
}

// contains checks if a string slice contains a value.
func contains(slice []string, val string) bool {
	return slices.ContainsFunc(slice, func(item string) bool {
		return strings.EqualFold(item, val)
	})
}

// isTerminal checks if stdout is a terminal (for auto-enabling colors).
func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}
