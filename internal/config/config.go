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
	"strings"

	"github.com/picatz/deputy/internal/errors"
	"gopkg.in/yaml.v3"
)

// Config represents the complete Deputy configuration.
type Config struct {
	// Logging configures log output behavior.
	Logging LogConfig `yaml:"logging"`

	// Proxy configures the package proxy server.
	Proxy ProxyConfig `yaml:"proxy,omitempty"`

	// Scan configures vulnerability scanning behavior.
	Scan ScanConfig `yaml:"scan,omitempty"`

	// Policy configures policy evaluation.
	Policy PolicyConfig `yaml:"policy,omitempty"`
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
}

// defaultConfig returns a configuration with sensible defaults.
func defaultConfig() *Config {
	return &Config{
		Logging: LogConfig{
			Level:  "info",
			Format: "text",
			Color:  isTerminal(),
			Source: false,
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
	}
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
