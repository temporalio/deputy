// Package config provides unified configuration management for Deputy.
// It handles configuration from multiple sources with clear precedence:
// flags > environment variables > config file > defaults.
package config

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/temporalio/deputy/internal/errors"
	"github.com/temporalio/deputy/internal/otel"
	"gopkg.in/yaml.v3"
)

// Config represents the complete Deputy configuration.
type Config struct {
	// Logging configures log output behavior.
	Logging LogConfig `yaml:"logging" json:"logging"`

	// HTTP configures HTTP client behavior across all subsystems.
	HTTP HTTPConfig `yaml:"http,omitempty" json:"http"`

	// Performance configures concurrency, caching, and resource limits.
	Performance PerformanceConfig `yaml:"performance,omitempty" json:"performance"`

	// Proxy configures the package proxy server.
	Proxy ProxyConfig `yaml:"proxy,omitempty" json:"proxy"`

	// Server configures the gRPC/Connect server.
	Server ServerConfig `yaml:"server,omitempty" json:"server"`

	// Egress configures outbound allowlists for local CLI mode.
	// These settings apply to in-process clients; use server.egress for remote servers.
	Egress *EgressConfig `yaml:"egress,omitempty" json:"egress,omitempty"`

	// Scan configures vulnerability scanning behavior.
	Scan ScanConfig `yaml:"scan,omitempty" json:"scan"`

	// AdvisorySources lists external advisory sources (threat feeds, vendor
	// databases) to aggregate with the built-in OSV source during vulnerability
	// scans. Loading is explicit opt-in; sources that fail to load are skipped
	// with a warning and the scan's coverage report shows which answered.
	AdvisorySources []AdvisorySourceConfig `yaml:"advisory_sources,omitempty" json:"advisory_sources,omitempty"`

	// Policy configures policy evaluation.
	Policy PolicyConfig `yaml:"policy,omitempty" json:"policy"`

	// AI configures AI/LLM providers for agentic features.
	AI AIConfig `yaml:"ai,omitempty" json:"ai"`

	// Agents configures agent plugin discovery and behavior.
	Agents AgentConfig `yaml:"agents,omitempty" json:"agents"`

	// OTel configures OpenTelemetry instrumentation.
	OTel otel.Config `yaml:"otel,omitempty" json:"otel"`
}

// AdvisorySourceConfig declares one external advisory source. Exactly one of
// Program or URL must be set.
type AdvisorySourceConfig struct {
	// Program is a pluginrpc advisory-source plugin executable, as a
	// PATH-resolved name or a path. Deputy executes it per query; it never
	// auto-executes binaries it merely finds on PATH.
	Program string `yaml:"program,omitempty" json:"program,omitempty"`
	// URL is the base URL of a ConnectRPC AdvisorySourceService: a persistent
	// local sidecar or shared remote service (e.g. an org-wide threat feed).
	URL string `yaml:"url,omitempty" json:"url,omitempty"`
}

// LogConfig configures logging behavior.
type LogConfig struct {
	// Level sets the minimum log level (debug, info, warn, error).
	Level string `yaml:"level" json:"level"`

	// Format specifies output format (text, json).
	Format string `yaml:"format" json:"format"`

	// Color enables ANSI color codes in text format.
	Color bool `yaml:"color" json:"color"`

	// Source includes source file and line number in logs.
	Source bool `yaml:"source" json:"source"`
}

// ProxyConfig configures the package proxy server.
type ProxyConfig struct {
	// ListenAddr is the address to bind the proxy server (e.g., ":8080").
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`

	// PolicyPaths are paths to policy files to enforce.
	PolicyPaths []string `yaml:"policy_paths" json:"policy_paths"`
}

// ServerConfig configures the gRPC/Connect server.
type ServerConfig struct {
	// Addr is the address to bind the server (e.g., ":8090", "localhost:8090").
	Addr string `yaml:"addr" json:"addr"`

	// ReadTimeout is the maximum duration for reading the request.
	ReadTimeout time.Duration `yaml:"read_timeout" json:"read_timeout"`

	// WriteTimeout is the maximum duration for writing the response.
	WriteTimeout time.Duration `yaml:"write_timeout" json:"write_timeout"`

	// IdleTimeout is the maximum duration to wait for the next request.
	IdleTimeout time.Duration `yaml:"idle_timeout" json:"idle_timeout"`

	// MaxRequestBodyBytes limits request body size.
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes" json:"max_request_body_bytes"`

	// TLS configures TLS for the server.
	TLS *ServerTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// CORS configures Cross-Origin Resource Sharing.
	CORS *ServerCORSConfig `yaml:"cors,omitempty" json:"cors,omitempty"`

	// Auth configures authentication.
	Auth *ServerAuthConfig `yaml:"auth,omitempty" json:"auth,omitempty"`

	// RateLimit configures rate limiting.
	RateLimit *ServerRateLimitConfig `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`

	// Security configures explicit security overrides for server mode.
	Security *ServerSecurityConfig `yaml:"security,omitempty" json:"security,omitempty"`

	// Egress configures outbound allowlists for remote server mode.
	Egress *ServerEgressConfig `yaml:"egress,omitempty" json:"egress,omitempty"`
}

// ServerTLSConfig configures TLS for the server.
type ServerTLSConfig struct {
	// CertFile is the path to the TLS certificate file.
	CertFile string `yaml:"cert_file" json:"cert_file"`

	// KeyFile is the path to the TLS private key file.
	KeyFile string `yaml:"key_file" json:"key_file"`

	// ClientCAFile is the path to the CA certificate for client verification.
	ClientCAFile string `yaml:"client_ca_file,omitempty" json:"client_ca_file,omitempty"`
}

// ServerCORSConfig configures Cross-Origin Resource Sharing.
type ServerCORSConfig struct {
	// AllowedOrigins is a list of allowed origins (* for all).
	AllowedOrigins []string `yaml:"allowed_origins" json:"allowed_origins"`

	// AllowedMethods is a list of allowed HTTP methods.
	AllowedMethods []string `yaml:"allowed_methods" json:"allowed_methods"`

	// AllowedHeaders is a list of allowed headers.
	AllowedHeaders []string `yaml:"allowed_headers" json:"allowed_headers"`

	// AllowCredentials indicates whether credentials are allowed.
	AllowCredentials bool `yaml:"allow_credentials" json:"allow_credentials"`

	// MaxAge is the max age for preflight cache in seconds.
	MaxAge int `yaml:"max_age" json:"max_age"`
}

// ServerAuthConfig configures authentication.
type ServerAuthConfig struct {
	// Enabled turns authentication on/off.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// Mode determines authentication enforcement ("required" or "disabled").
	Mode string `yaml:"mode,omitempty" json:"mode,omitempty"`

	// JWKSURL is the URL to fetch JSON Web Key Sets.
	JWKSURL string `yaml:"jwks_url,omitempty" json:"jwks_url,omitempty"`

	// OIDCDiscovery enables OIDC discovery for JWKS URL resolution.
	OIDCDiscovery bool `yaml:"oidc_discovery,omitempty" json:"oidc_discovery,omitempty"`

	// Issuers is a list of allowed token issuers.
	Issuers []string `yaml:"issuers,omitempty" json:"issuers,omitempty"`

	// Audiences is a list of allowed token audiences.
	Audiences []string `yaml:"audiences,omitempty" json:"audiences,omitempty"`

	// RequiredClaims specifies claims required in tokens.
	RequiredClaims []string `yaml:"required_claims,omitempty" json:"required_claims,omitempty"`

	// ClockSkew allows for clock drift when validating exp/nbf/iat.
	ClockSkew time.Duration `yaml:"clock_skew,omitempty" json:"clock_skew,omitempty"`
}

// ServerRateLimitConfig configures rate limiting.
type ServerRateLimitConfig struct {
	// Enabled turns rate limiting on/off.
	Enabled bool `yaml:"enabled" json:"enabled"`

	// RequestsPerSecond is the maximum requests per second per client.
	RequestsPerSecond float64 `yaml:"requests_per_second" json:"requests_per_second"`

	// Burst is the maximum burst size.
	Burst int `yaml:"burst" json:"burst"`
}

// ServerSecurityConfig configures explicit security overrides for server mode.
type ServerSecurityConfig struct {
	// AllowPublic permits binding to non-loopback addresses.
	AllowPublic bool `yaml:"allow_public,omitempty" json:"allow_public,omitempty"`

	// AllowInsecure permits insecure server modes (no TLS/auth, policy load errors).
	AllowInsecure bool `yaml:"allow_insecure,omitempty" json:"allow_insecure,omitempty"`
}

// EgressConfig configures outbound allowlists for local CLI mode.
// These settings apply to in-process clients; server mode has separate controls.
type EgressConfig struct {
	// AllowedHosts is a list of hostnames allowed to resolve to private IPs.
	AllowedHosts []string `yaml:"allowed_hosts,omitempty" json:"allowed_hosts,omitempty"`

	// AllowedCIDRs is a list of CIDR ranges allowed for outbound connections.
	AllowedCIDRs []string `yaml:"allowed_cidrs,omitempty" json:"allowed_cidrs,omitempty"`

	// AllowLoopback permits loopback targets (127.0.0.1, ::1).
	AllowLoopback bool `yaml:"allow_loopback,omitempty" json:"allow_loopback,omitempty"`

	// AllowLinkLocal permits link-local targets (169.254.0.0/16, fe80::/10).
	AllowLinkLocal bool `yaml:"allow_link_local,omitempty" json:"allow_link_local,omitempty"`
}

// Configured reports whether any egress allowlist settings are set.
func (e *EgressConfig) Configured() bool {
	if e == nil {
		return false
	}
	if e.AllowLoopback || e.AllowLinkLocal {
		return true
	}
	for _, host := range e.AllowedHosts {
		if strings.TrimSpace(host) != "" {
			return true
		}
	}
	for _, cidr := range e.AllowedCIDRs {
		if strings.TrimSpace(cidr) != "" {
			return true
		}
	}
	return false
}

// AllowedCIDRPrefixes parses the configured CIDR strings into netip prefixes.
func (e *EgressConfig) AllowedCIDRPrefixes() ([]netip.Prefix, error) {
	if e == nil {
		return nil, nil
	}
	return parseCIDRs(e.AllowedCIDRs)
}

// ServerEgressConfig configures outbound allowlists for remote server mode.
type ServerEgressConfig struct {
	// AllowedHosts is a list of hostnames allowed to resolve to private IPs.
	AllowedHosts []string `yaml:"allowed_hosts,omitempty" json:"allowed_hosts,omitempty"`

	// AllowedCIDRs is a list of CIDR ranges allowed for outbound connections.
	AllowedCIDRs []string `yaml:"allowed_cidrs,omitempty" json:"allowed_cidrs,omitempty"`

	// AllowSSH permits SSH-style git targets.
	AllowSSH bool `yaml:"allow_ssh,omitempty" json:"allow_ssh,omitempty"`

	// AllowLoopback permits loopback targets in remote server mode.
	AllowLoopback bool `yaml:"allow_loopback,omitempty" json:"allow_loopback,omitempty"`

	// AllowLinkLocal permits link-local targets in remote server mode.
	AllowLinkLocal bool `yaml:"allow_link_local,omitempty" json:"allow_link_local,omitempty"`
}

// ScanConfig configures vulnerability scanning.
type ScanConfig struct {
	// Ecosystems limits scanning to specific ecosystems.
	Ecosystems []string `yaml:"ecosystems,omitempty" json:"ecosystems,omitempty"`

	// SkipCache disables result caching.
	SkipCache bool `yaml:"skip_cache" json:"skip_cache"`

	// ExcludePaths lists glob patterns for directory paths to skip during the
	// filesystem walk (e.g., ".bin/**", "**/testdata"). Matching subtrees are
	// never inventoried, so they are absent from scan, diff, list, and SBOM
	// output. Honored by all commands that walk the source tree; the
	// --exclude-path flag is unioned with this list.
	ExcludePaths []string `yaml:"exclude_paths,omitempty" json:"exclude_paths,omitempty"`
}

// PolicyConfig configures policy evaluation.
type PolicyConfig struct {
	// Paths are locations of policy files or directories.
	Paths []string `yaml:"paths" json:"paths"`

	// Mode sets the default policy mode (enforce, advisory).
	Mode string `yaml:"mode" json:"mode"`
}

// AIConfig configures AI/LLM providers for agentic features.
type AIConfig struct {
	// DefaultProvider is used when no provider is explicitly specified.
	// Common values: "codex", "claude", "openai", "anthropic"
	DefaultProvider string `yaml:"default_provider" json:"default_provider"`

	// Providers contains per-provider configuration.
	Providers map[string]AIProviderConfig `yaml:"providers,omitempty" json:"providers,omitempty"`

	// Approval configures when user approval is required.
	Approval AIApprovalConfig `yaml:"approval,omitempty" json:"approval"`

	// Guardrails configures safety constraints for AI operations.
	// These are evaluated before approval checks and can block operations
	// outright or flag them as high-risk.
	Guardrails AIGuardrailsConfig `yaml:"guardrails,omitempty" json:"guardrails"`

	// Disabled completely disables AI features.
	Disabled bool `yaml:"disabled" json:"disabled"`
}

// AIProviderConfig contains settings for a specific AI provider.
type AIProviderConfig struct {
	// Model specifies the model to use.
	Model string `yaml:"model" json:"model"`

	// APIKey for API-based providers.
	// Supports ${ENV_VAR} syntax for environment variable expansion.
	APIKey string `yaml:"api_key,omitempty" json:"api_key,omitempty"`

	// BaseURL overrides the default API endpoint.
	BaseURL string `yaml:"base_url,omitempty" json:"base_url,omitempty"`

	// Sandbox sets the default sandbox mode for agentic providers.
	// Values: "read-only", "workspace-write", "full-access"
	Sandbox string `yaml:"sandbox,omitempty" json:"sandbox,omitempty"`

	// MaxTokens sets the default max tokens for completions.
	MaxTokens int `yaml:"max_tokens,omitempty" json:"max_tokens,omitempty"`

	// Temperature sets the default temperature (0.0-2.0).
	Temperature *float64 `yaml:"temperature,omitempty" json:"temperature,omitempty"`

	// Extra contains provider-specific additional configuration.
	Extra map[string]any `yaml:"extra,omitempty" json:"extra,omitempty"`
}

// AIApprovalConfig controls when user approval is required for AI operations.
type AIApprovalConfig struct {
	// Required makes all AI operations require approval.
	Required bool `yaml:"required" json:"required"`

	// Commands requires approval before shell command execution.
	Commands bool `yaml:"commands" json:"commands"`

	// FileWrites requires approval before file modifications.
	FileWrites bool `yaml:"file_writes" json:"file_writes"`
}

// AIGuardrailsConfig configures safety constraints for AI operations.
// Guardrails are evaluated before approval checks and can block operations
// outright or flag them as high-risk.
type AIGuardrailsConfig struct {
	// Preset selects a predefined guardrail configuration.
	// Values: "default", "strict", "permissive"
	// Default: "default"
	Preset string `yaml:"preset" json:"preset"`

	// Commands configures command execution guardrails.
	Commands AICommandGuardrails `yaml:"commands,omitempty" json:"commands"`

	// Files configures file operation guardrails.
	Files AIFileGuardrails `yaml:"files,omitempty" json:"files"`

	// WorkspaceOnly restricts all file operations to the workspace directory.
	// Default: true
	WorkspaceOnly *bool `yaml:"workspace_only,omitempty" json:"workspace_only,omitempty"`
}

// AICommandGuardrails configures command execution constraints.
type AICommandGuardrails struct {
	// DenyPatterns blocks commands matching these regex patterns.
	DenyPatterns []string `yaml:"deny_patterns,omitempty" json:"deny_patterns,omitempty"`

	// AllowPatterns permits only commands matching these patterns.
	// If non-empty, commands not matching any pattern are denied.
	AllowPatterns []string `yaml:"allow_patterns,omitempty" json:"allow_patterns,omitempty"`

	// HighRiskPatterns flags commands as high-risk (requiring approval).
	HighRiskPatterns []string `yaml:"high_risk_patterns,omitempty" json:"high_risk_patterns,omitempty"`

	// DenyCommands blocks specific command names (e.g., "rm", "sudo").
	DenyCommands []string `yaml:"deny_commands,omitempty" json:"deny_commands,omitempty"`

	// AllowCommands permits only these command names.
	// If non-empty, commands not in this list are denied.
	AllowCommands []string `yaml:"allow_commands,omitempty" json:"allow_commands,omitempty"`
}

// AIFileGuardrails configures file operation constraints.
type AIFileGuardrails struct {
	// DenyPaths blocks operations on paths matching these glob patterns.
	// Supports glob syntax (e.g., "/etc/**", "~/.ssh/*").
	DenyPaths []string `yaml:"deny_paths,omitempty" json:"deny_paths,omitempty"`

	// AllowPaths permits only operations on paths matching these patterns.
	AllowPaths []string `yaml:"allow_paths,omitempty" json:"allow_paths,omitempty"`

	// HighRiskPaths flags operations on these paths as high-risk.
	HighRiskPaths []string `yaml:"high_risk_paths,omitempty" json:"high_risk_paths,omitempty"`

	// DenyExtensions blocks operations on files with these extensions.
	DenyExtensions []string `yaml:"deny_extensions,omitempty" json:"deny_extensions,omitempty"`

	// AllowExtensions permits only operations on files with these extensions.
	AllowExtensions []string `yaml:"allow_extensions,omitempty" json:"allow_extensions,omitempty"`

	// DenyActions blocks specific actions (e.g., "delete", "execute").
	DenyActions []string `yaml:"deny_actions,omitempty" json:"deny_actions,omitempty"`
}

// AgentConfig configures agent plugin discovery and behavior.
type AgentConfig struct {
	// Default is the default agent to use when none is specified.
	// If empty, uses the first available builtin (typically "claude").
	Default string `yaml:"default,omitempty" json:"default,omitempty"`

	// DiscoverFromPath enables automatic discovery of plugins from PATH.
	// Looks for executables named "deputy-plugin-<name>".
	// Default: true
	DiscoverFromPath *bool `yaml:"discover_from_path,omitempty" json:"discover_from_path,omitempty"`

	// Plugins configures specific agent plugins.
	// Keys are plugin names, values are plugin-specific configuration.
	Plugins map[string]AgentPluginConfig `yaml:"plugins,omitempty" json:"plugins,omitempty"`

	// Remote configures remote agent plugin endpoints.
	// Keys are plugin names, values are server addresses.
	Remote map[string]string `yaml:"remote,omitempty" json:"remote,omitempty"`
}

// DiscoverFromPathEnabled returns whether PATH discovery is enabled (defaults to true).
func (a AgentConfig) DiscoverFromPathEnabled() bool {
	if a.DiscoverFromPath == nil {
		return true
	}
	return *a.DiscoverFromPath
}

// AgentPluginConfig contains settings for a specific agent plugin.
type AgentPluginConfig struct {
	// Enabled controls whether this plugin is available.
	// Default: true
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`

	// Path overrides automatic PATH discovery with a specific executable path.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`

	// Model specifies the default model for this agent.
	Model string `yaml:"model,omitempty" json:"model,omitempty"`

	// Sandbox sets the default sandbox mode for this agent.
	// Values: "read-only", "workspace-write", "full-access"
	Sandbox string `yaml:"sandbox,omitempty" json:"sandbox,omitempty"`

	// Extra contains plugin-specific additional configuration.
	Extra map[string]any `yaml:"extra,omitempty" json:"extra,omitempty"`
}

// IsEnabled returns whether the plugin is enabled (defaults to true).
func (p AgentPluginConfig) IsEnabled() bool {
	if p.Enabled == nil {
		return true
	}
	return *p.Enabled
}

// HTTPConfig configures HTTP client behavior across all subsystems.
// These settings apply to all HTTP clients created by Deputy unless
// explicitly overridden.
type HTTPConfig struct {
	// Timeout is the overall request timeout for HTTP operations.
	// Default: 30s
	Timeout time.Duration `yaml:"timeout" json:"timeout"`

	// DialTimeout is the maximum time to establish a TCP connection.
	// Default: 10s
	DialTimeout time.Duration `yaml:"dial_timeout" json:"dial_timeout"`

	// TLSHandshakeTimeout is the maximum time for TLS handshake.
	// Default: 10s
	TLSHandshakeTimeout time.Duration `yaml:"tls_handshake_timeout" json:"tls_handshake_timeout"`

	// ResponseHeaderTimeout is the maximum time to wait for response headers.
	// Default: 20s
	ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout" json:"response_header_timeout"`

	// KeepAlive is the interval between TCP keep-alive probes.
	// Default: 30s
	KeepAlive time.Duration `yaml:"keep_alive" json:"keep_alive"`

	// IdleConnTimeout is how long idle connections remain in the pool.
	// Default: 90s
	IdleConnTimeout time.Duration `yaml:"idle_conn_timeout" json:"idle_conn_timeout"`

	// MaxIdleConns is the maximum number of idle connections in the pool.
	// Default: 20
	MaxIdleConns int `yaml:"max_idle_conns" json:"max_idle_conns"`

	// MaxIdleConnsPerHost is the maximum idle connections per host.
	// Default: 10
	MaxIdleConnsPerHost int `yaml:"max_idle_conns_per_host" json:"max_idle_conns_per_host"`

	// Retry configures automatic retry behavior for transient failures.
	Retry RetryConfig `yaml:"retry,omitempty" json:"retry"`
}

// RetryConfig configures HTTP retry behavior.
type RetryConfig struct {
	// Max is the maximum number of retry attempts.
	// Default: 3
	Max int `yaml:"max" json:"max"`

	// WaitMin is the minimum wait time between retries.
	// Default: 500ms
	WaitMin time.Duration `yaml:"wait_min" json:"wait_min"`

	// WaitMax is the maximum wait time between retries.
	// Default: 5s
	WaitMax time.Duration `yaml:"wait_max" json:"wait_max"`

	// Enabled controls whether retries are attempted at all.
	// Default: true
	Enabled *bool `yaml:"enabled,omitempty" json:"enabled,omitempty"`
}

// PerformanceConfig configures concurrency, caching, and resource limits.
type PerformanceConfig struct {
	// OSVConcurrency is the number of concurrent OSV API requests.
	// Default: 10
	OSVConcurrency int `yaml:"osv_concurrency" json:"osv_concurrency"`

	// GraphConcurrency is the number of concurrent graph resolution operations.
	// Default: 5
	GraphConcurrency int `yaml:"graph_concurrency" json:"graph_concurrency"`

	// SBOMEnrichConcurrency is the concurrency for SBOM enrichment operations.
	// Default: 4
	SBOMEnrichConcurrency int `yaml:"sbom_enrich_concurrency" json:"sbom_enrich_concurrency"`

	// ImageScanConcurrency is the concurrency for container image scanning.
	// Default: 4
	ImageScanConcurrency int `yaml:"image_scan_concurrency" json:"image_scan_concurrency"`

	// Cache configures caching behavior.
	Cache CacheConfig `yaml:"cache,omitempty" json:"cache"`
}

// CacheConfig configures caching behavior.
type CacheConfig struct {
	// Dir is the directory for persistent cache storage.
	// Default: ~/.deputy/cache
	Dir string `yaml:"dir" json:"dir"`

	// TTL is the default time-to-live for cached entries.
	// Default: 1h
	TTL time.Duration `yaml:"ttl" json:"ttl"`

	// KEVTTL is the TTL for CISA KEV catalog cache.
	// Default: 24h
	KEVTTL time.Duration `yaml:"kev_ttl" json:"kev_ttl"`

	// EPSSTTL is the TTL for EPSS scores cache.
	// Default: 24h
	EPSSTTL time.Duration `yaml:"epss_ttl" json:"epss_ttl"`

	// OSVTTL is the TTL for OSV vulnerability cache.
	// Default: 1h
	OSVTTL time.Duration `yaml:"osv_ttl" json:"osv_ttl"`

	// LicenseTTL is the TTL for license information cache.
	// Default: 24h
	LicenseTTL time.Duration `yaml:"license_ttl" json:"license_ttl"`

	// MaxSize is the maximum number of entries in in-memory caches.
	// Default: 1024
	MaxSize int `yaml:"max_size" json:"max_size"`

	// Disabled completely disables caching.
	// Default: false
	Disabled bool `yaml:"disabled" json:"disabled"`
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

	// Local egress configuration
	if val := os.Getenv(l.envPrefix + "EGRESS_ALLOW_HOSTS"); val != "" {
		if cfg.Egress == nil {
			cfg.Egress = &EgressConfig{}
		}
		cfg.Egress.AllowedHosts = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "EGRESS_ALLOW_CIDRS"); val != "" {
		if cfg.Egress == nil {
			cfg.Egress = &EgressConfig{}
		}
		cfg.Egress.AllowedCIDRs = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "EGRESS_ALLOW_LOOPBACK"); val != "" {
		if cfg.Egress == nil {
			cfg.Egress = &EgressConfig{}
		}
		cfg.Egress.AllowLoopback = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "EGRESS_ALLOW_LINK_LOCAL"); val != "" {
		if cfg.Egress == nil {
			cfg.Egress = &EgressConfig{}
		}
		cfg.Egress.AllowLinkLocal = val == "true" || val == "1"
	}

	// Server configuration
	l.loadServerFromEnv(cfg)

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

// loadServerFromEnv loads server configuration from environment variables.
func (l *Loader) loadServerFromEnv(cfg *Config) {
	// Basic server settings
	if val := os.Getenv(l.envPrefix + "SERVER_ADDR"); val != "" {
		cfg.Server.Addr = val
	}
	if val := os.Getenv(l.envPrefix + "SERVER_READ_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Server.ReadTimeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "SERVER_WRITE_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Server.WriteTimeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "SERVER_IDLE_TIMEOUT"); val != "" {
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Server.IdleTimeout = d
		}
	}
	if val := os.Getenv(l.envPrefix + "SERVER_MAX_REQUEST_BODY_BYTES"); val != "" {
		if n, err := strconv.ParseInt(val, 10, 64); err == nil && n > 0 {
			cfg.Server.MaxRequestBodyBytes = n
		}
	}

	// TLS configuration
	tlsCert := os.Getenv(l.envPrefix + "SERVER_TLS_CERT")
	tlsKey := os.Getenv(l.envPrefix + "SERVER_TLS_KEY")
	if tlsCert != "" && tlsKey != "" {
		if cfg.Server.TLS == nil {
			cfg.Server.TLS = &ServerTLSConfig{}
		}
		cfg.Server.TLS.CertFile = tlsCert
		cfg.Server.TLS.KeyFile = tlsKey
	}
	if val := os.Getenv(l.envPrefix + "SERVER_TLS_CLIENT_CA"); val != "" {
		if cfg.Server.TLS == nil {
			cfg.Server.TLS = &ServerTLSConfig{}
		}
		cfg.Server.TLS.ClientCAFile = val
	}

	// CORS configuration
	if val := os.Getenv(l.envPrefix + "SERVER_CORS_ORIGINS"); val != "" {
		if cfg.Server.CORS == nil {
			cfg.Server.CORS = &ServerCORSConfig{}
		}
		cfg.Server.CORS.AllowedOrigins = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_CORS_METHODS"); val != "" {
		if cfg.Server.CORS == nil {
			cfg.Server.CORS = &ServerCORSConfig{}
		}
		cfg.Server.CORS.AllowedMethods = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_CORS_HEADERS"); val != "" {
		if cfg.Server.CORS == nil {
			cfg.Server.CORS = &ServerCORSConfig{}
		}
		cfg.Server.CORS.AllowedHeaders = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_CORS_CREDENTIALS"); val != "" {
		if cfg.Server.CORS == nil {
			cfg.Server.CORS = &ServerCORSConfig{}
		}
		cfg.Server.CORS.AllowCredentials = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "SERVER_CORS_MAX_AGE"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			if cfg.Server.CORS == nil {
				cfg.Server.CORS = &ServerCORSConfig{}
			}
			cfg.Server.CORS.MaxAge = n
		}
	}

	// Auth configuration
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_ENABLED"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		cfg.Server.Auth.Enabled = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_MODE"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		cfg.Server.Auth.Mode = val
	}
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_JWKS_URL"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		cfg.Server.Auth.JWKSURL = val
	}
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_OIDC_DISCOVERY"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		cfg.Server.Auth.OIDCDiscovery = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_ISSUERS"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		cfg.Server.Auth.Issuers = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_AUDIENCES"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		cfg.Server.Auth.Audiences = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_REQUIRED_CLAIMS"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		cfg.Server.Auth.RequiredClaims = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_AUTH_CLOCK_SKEW"); val != "" {
		if cfg.Server.Auth == nil {
			cfg.Server.Auth = &ServerAuthConfig{}
		}
		if d, err := time.ParseDuration(val); err == nil {
			cfg.Server.Auth.ClockSkew = d
		}
	}

	// Rate limit configuration
	if val := os.Getenv(l.envPrefix + "SERVER_RATE_LIMIT_ENABLED"); val != "" {
		if cfg.Server.RateLimit == nil {
			cfg.Server.RateLimit = &ServerRateLimitConfig{}
		}
		cfg.Server.RateLimit.Enabled = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "SERVER_RATE_LIMIT_RPS"); val != "" {
		if f, err := strconv.ParseFloat(val, 64); err == nil && f > 0 {
			if cfg.Server.RateLimit == nil {
				cfg.Server.RateLimit = &ServerRateLimitConfig{}
			}
			cfg.Server.RateLimit.RequestsPerSecond = f
		}
	}
	if val := os.Getenv(l.envPrefix + "SERVER_RATE_LIMIT_BURST"); val != "" {
		if n, err := strconv.Atoi(val); err == nil && n > 0 {
			if cfg.Server.RateLimit == nil {
				cfg.Server.RateLimit = &ServerRateLimitConfig{}
			}
			cfg.Server.RateLimit.Burst = n
		}
	}

	// Security configuration
	if val := os.Getenv(l.envPrefix + "SERVER_SECURITY_ALLOW_PUBLIC"); val != "" {
		if cfg.Server.Security == nil {
			cfg.Server.Security = &ServerSecurityConfig{}
		}
		cfg.Server.Security.AllowPublic = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "SERVER_SECURITY_ALLOW_INSECURE"); val != "" {
		if cfg.Server.Security == nil {
			cfg.Server.Security = &ServerSecurityConfig{}
		}
		cfg.Server.Security.AllowInsecure = val == "true" || val == "1"
	}

	// Egress configuration
	if val := os.Getenv(l.envPrefix + "SERVER_EGRESS_ALLOW_HOSTS"); val != "" {
		if cfg.Server.Egress == nil {
			cfg.Server.Egress = &ServerEgressConfig{}
		}
		cfg.Server.Egress.AllowedHosts = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_EGRESS_ALLOW_CIDRS"); val != "" {
		if cfg.Server.Egress == nil {
			cfg.Server.Egress = &ServerEgressConfig{}
		}
		cfg.Server.Egress.AllowedCIDRs = strings.Split(val, ",")
	}
	if val := os.Getenv(l.envPrefix + "SERVER_EGRESS_ALLOW_SSH"); val != "" {
		if cfg.Server.Egress == nil {
			cfg.Server.Egress = &ServerEgressConfig{}
		}
		cfg.Server.Egress.AllowSSH = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "SERVER_EGRESS_ALLOW_LOOPBACK"); val != "" {
		if cfg.Server.Egress == nil {
			cfg.Server.Egress = &ServerEgressConfig{}
		}
		cfg.Server.Egress.AllowLoopback = val == "true" || val == "1"
	}
	if val := os.Getenv(l.envPrefix + "SERVER_EGRESS_ALLOW_LINK_LOCAL"); val != "" {
		if cfg.Server.Egress == nil {
			cfg.Server.Egress = &ServerEgressConfig{}
		}
		cfg.Server.Egress.AllowLinkLocal = val == "true" || val == "1"
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

	// Validate local egress configuration
	if err := validateCIDRList("egress.allowed_cidrs", egressCIDRs(c.Egress)); err != nil {
		return err
	}

	// Validate server egress configuration
	if err := validateCIDRList("server.egress.allowed_cidrs", serverEgressCIDRs(c.Server.Egress)); err != nil {
		return err
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

// ResolveConfigFile reports which config file to load, and fails when one was
// explicitly requested but cannot be used. DEPUTY_CONFIG names a specific file,
// so a path that cannot be stated is an error rather than a cue to look
// elsewhere: discarding it silently hands the caller an auto-discovered file,
// or no configuration at all, in place of the one it asked for. An empty path
// with a nil error means no config file was requested and none was discovered,
// which is normal.
//
// FindConfigFile keeps the lenient behavior for callers that are reporting on
// configuration rather than acting on it.
func ResolveConfigFile() (string, error) {
	if path := os.Getenv("DEPUTY_CONFIG"); path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", &errors.ConfigError{
				Path:    path,
				Message: "config file named by DEPUTY_CONFIG is unavailable",
				Cause:   err,
			}
		}
		return path, nil
	}
	return FindConfigFile(), nil
}

// FindConfigFile searches for a config file in standard locations.
// Returns the path if found, empty string otherwise. An unusable DEPUTY_CONFIG
// is ignored here; use [ResolveConfigFile] when that must be an error.
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

func egressCIDRs(cfg *EgressConfig) []string {
	if cfg == nil {
		return nil
	}
	return cfg.AllowedCIDRs
}

func serverEgressCIDRs(cfg *ServerEgressConfig) []string {
	if cfg == nil {
		return nil
	}
	return cfg.AllowedCIDRs
}

func parseCIDRs(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		cidr := strings.TrimSpace(raw)
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func validateCIDRList(field string, values []string) error {
	if len(values) == 0 {
		return nil
	}
	if _, err := parseCIDRs(values); err != nil {
		return &errors.ValidationError{
			Field:   field,
			Value:   values,
			Message: "invalid CIDR",
			Cause:   err,
		}
	}
	return nil
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

// ToGuardrails converts the config to an ai.Guardrails instance.
// This method is in config to avoid circular imports.
func (g AIGuardrailsConfig) ToGuardrails() *AIGuardrailsResult {
	result := &AIGuardrailsResult{
		Commands: AIGuardrailsResultCommands{
			DenyPatterns:     g.Commands.DenyPatterns,
			AllowPatterns:    g.Commands.AllowPatterns,
			HighRiskPatterns: g.Commands.HighRiskPatterns,
			DenyCommands:     g.Commands.DenyCommands,
			AllowCommands:    g.Commands.AllowCommands,
		},
		Files: AIGuardrailsResultFiles{
			DenyPaths:       g.Files.DenyPaths,
			AllowPaths:      g.Files.AllowPaths,
			HighRiskPaths:   g.Files.HighRiskPaths,
			DenyExtensions:  g.Files.DenyExtensions,
			AllowExtensions: g.Files.AllowExtensions,
			DenyActions:     g.Files.DenyActions,
			WorkspaceOnly:   true, // Default to true
		},
		Preset: g.Preset,
	}

	// Override WorkspaceOnly if explicitly set
	if g.WorkspaceOnly != nil {
		result.Files.WorkspaceOnly = *g.WorkspaceOnly
	}

	return result
}

// AIGuardrailsResult is a transport struct for guardrails configuration.
// It avoids circular imports between config and ai packages.
type AIGuardrailsResult struct {
	Preset   string
	Commands AIGuardrailsResultCommands
	Files    AIGuardrailsResultFiles
}

// AIGuardrailsResultCommands contains command guardrail settings.
type AIGuardrailsResultCommands struct {
	DenyPatterns     []string
	AllowPatterns    []string
	HighRiskPatterns []string
	DenyCommands     []string
	AllowCommands    []string
}

// AIGuardrailsResultFiles contains file guardrail settings.
type AIGuardrailsResultFiles struct {
	DenyPaths       []string
	AllowPaths      []string
	HighRiskPaths   []string
	DenyExtensions  []string
	AllowExtensions []string
	DenyActions     []string
	WorkspaceOnly   bool
}
