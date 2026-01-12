package proxy

import (
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/picatz/deputy/internal/errors"
	"gopkg.in/yaml.v3"
)

// validEcosystems defines the supported ecosystem adapters.
var validEcosystems = []string{"go", "pypi", "npm", "rubygems", "oci"}

// Config describes one or more listeners exposed by the proxy server.
type Config struct {
	Listeners []ListenerConfig `yaml:"listeners"`
}

// ListenerConfig configures a single HTTP listener bound to an ecosystem adapter.
type ListenerConfig struct {
	Name       string   `yaml:"name"`
	Bind       string   `yaml:"bind"`
	Ecosystems []string `yaml:"ecosystems"`
	Upstream   string   `yaml:"upstream"`
	Policies   []string `yaml:"policies"`

	// Auth configures JWT-based authentication for this listener.
	// If nil or mode is "disabled", no authentication is performed.
	Auth *AuthConfig `yaml:"auth,omitempty"`

	// MaxConcurrentRequests caps in-flight HTTP requests for this listener.
	// A value <= 0 means unlimited.
	MaxConcurrentRequests int `yaml:"max_concurrent_requests,omitempty"`

	// ReadHeaderTimeout is the maximum amount of time to read request headers.
	// A value of 0 uses the proxy default.
	ReadHeaderTimeout time.Duration `yaml:"read_header_timeout,omitempty"`
	// WriteTimeout is the maximum duration before timing out writes of the response.
	// A value of 0 uses the proxy default.
	WriteTimeout time.Duration `yaml:"write_timeout,omitempty"`
	// IdleTimeout is the maximum amount of time to wait for the next request when keep-alives are enabled.
	// A value of 0 uses the proxy default.
	IdleTimeout time.Duration `yaml:"idle_timeout,omitempty"`
	// MaxRequestBodyBytes caps the request body size for this listener.
	// A value of 0 uses the proxy default; a value < 0 disables the cap.
	MaxRequestBodyBytes int64 `yaml:"max_request_body_bytes,omitempty"`

	// OCI configures OCI-specific proxy behavior.
	// Only used when "oci" is in the ecosystems list.
	OCI *OCIConfig `yaml:"oci,omitempty"`
}

// OCIConfig holds OCI registry proxy configuration.
type OCIConfig struct {
	// AllowMutableTags controls whether mutable tags (e.g., :latest) are allowed.
	// When false (default in strict mode), requests for mutable tags are blocked
	// unless the request is rewritten to use a digest.
	// This mitigates TOCTOU vulnerabilities where a tag's content can change
	// between policy evaluation and upstream fetch.
	AllowMutableTags bool `yaml:"allow_mutable_tags,omitempty"`

	// PinDigests enables automatic digest pinning for mutable tag requests.
	// When true (default), the proxy resolves tags to digests during policy
	// evaluation and rewrites upstream requests to use the pinned digest.
	// This ensures the content fetched matches what was scanned.
	// The resolved digest is returned in the X-Deputy-Pinned-Digest header.
	PinDigests bool `yaml:"pin_digests,omitempty"`

	// StrictMode enforces secure defaults: AllowMutableTags=false, PinDigests=true.
	// When set, it overrides individual settings.
	StrictMode bool `yaml:"strict_mode,omitempty"`
}

// EffectiveAllowMutableTags returns whether mutable tags are allowed,
// taking StrictMode into account.
func (c *OCIConfig) EffectiveAllowMutableTags() bool {
	if c == nil {
		return true // Default: allow mutable tags for backward compatibility
	}
	if c.StrictMode {
		return false // Strict mode disallows mutable tags
	}
	return c.AllowMutableTags
}

// EffectivePinDigests returns whether digest pinning is enabled,
// taking StrictMode into account.
func (c *OCIConfig) EffectivePinDigests() bool {
	if c == nil {
		return true // Default: pin digests for security
	}
	if c.StrictMode {
		return true // Strict mode always pins digests
	}
	return c.PinDigests
}

// LoadConfig loads YAML/JSON configuration from the provided path.
func LoadConfig(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parse config: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the configuration for invalid or missing values.
func (c *Config) Validate() error {
	if len(c.Listeners) == 0 {
		return &errors.ValidationError{
			Field:   "listeners",
			Message: "config must define at least one listener",
		}
	}
	seen := make(map[string]bool)
	for i, l := range c.Listeners {
		if err := l.Validate(i); err != nil {
			return err
		}
		if seen[l.Name] {
			return &errors.ValidationError{
				Field:   fmt.Sprintf("listeners[%d].name", i),
				Value:   l.Name,
				Message: "duplicate listener name",
			}
		}
		seen[l.Name] = true
	}
	return nil
}

// Validate checks a single listener configuration for invalid values.
func (l *ListenerConfig) Validate(index int) error {
	prefix := fmt.Sprintf("listeners[%d]", index)

	if strings.TrimSpace(l.Name) == "" {
		return &errors.ValidationError{
			Field:   prefix + ".name",
			Message: "listener name is required",
		}
	}
	if strings.TrimSpace(l.Bind) == "" {
		return &errors.ValidationError{
			Field:   prefix + ".bind",
			Message: "bind address is required",
		}
	}
	if len(l.Ecosystems) == 0 {
		return &errors.ValidationError{
			Field:   prefix + ".ecosystems",
			Message: "at least one ecosystem is required",
		}
	}
	for _, eco := range l.Ecosystems {
		ecoLower := strings.ToLower(strings.TrimSpace(eco))
		if !slices.Contains(validEcosystems, ecoLower) {
			return &errors.ValidationError{
				Field:   prefix + ".ecosystems",
				Value:   eco,
				Message: fmt.Sprintf("unsupported ecosystem; must be one of: %s", strings.Join(validEcosystems, ", ")),
			}
		}
	}
	if strings.TrimSpace(l.Upstream) == "" {
		return &errors.ValidationError{
			Field:   prefix + ".upstream",
			Message: "upstream URL is required",
		}
	}
	if l.ReadHeaderTimeout < 0 {
		return &errors.ValidationError{
			Field:   prefix + ".read_header_timeout",
			Value:   l.ReadHeaderTimeout,
			Message: "timeout must be non-negative",
		}
	}
	if l.WriteTimeout < 0 {
		return &errors.ValidationError{
			Field:   prefix + ".write_timeout",
			Value:   l.WriteTimeout,
			Message: "timeout must be non-negative",
		}
	}
	if l.IdleTimeout < 0 {
		return &errors.ValidationError{
			Field:   prefix + ".idle_timeout",
			Value:   l.IdleTimeout,
			Message: "timeout must be non-negative",
		}
	}
	if err := validateAuthConfig(l.Auth, prefix); err != nil {
		return err
	}
	return nil
}

// validateAuthConfig checks the authentication configuration for invalid values.
// This is a standalone function since AuthConfig is a type alias for jwt.Config.
func validateAuthConfig(a *AuthConfig, prefix string) error {
	if a == nil {
		return nil
	}
	prefix = prefix + ".auth"

	// Validate mode
	switch strings.ToLower(a.Mode) {
	case "", "disabled", "optional", "required":
		// valid
	default:
		return &errors.ValidationError{
			Field:   prefix + ".mode",
			Value:   a.Mode,
			Message: "must be one of: disabled, optional, required",
		}
	}

	// If auth is enabled, require at least one key source
	mode := strings.ToLower(a.Mode)
	if mode == "optional" || mode == "required" {
		if a.JWKS == nil && len(a.StaticKeys) == 0 {
			return &errors.ValidationError{
				Field:   prefix,
				Message: "either jwks or static_keys must be configured when auth is enabled",
			}
		}
	}

	// Validate JWKS config
	if a.JWKS != nil {
		if strings.TrimSpace(a.JWKS.URL) == "" {
			return &errors.ValidationError{
				Field:   prefix + ".jwks.url",
				Message: "JWKS URL is required",
			}
		}
		if a.JWKS.RefreshInterval < 0 {
			return &errors.ValidationError{
				Field:   prefix + ".jwks.refresh_interval",
				Value:   a.JWKS.RefreshInterval,
				Message: "refresh interval must be non-negative",
			}
		}
	}

	// Validate static keys
	for i, key := range a.StaticKeys {
		keyPrefix := fmt.Sprintf("%s.static_keys[%d]", prefix, i)
		if strings.TrimSpace(key.KeyID) == "" {
			return &errors.ValidationError{
				Field:   keyPrefix + ".kid",
				Message: "key ID is required",
			}
		}
		if strings.TrimSpace(key.Algorithm) == "" {
			return &errors.ValidationError{
				Field:   keyPrefix + ".alg",
				Message: "algorithm is required",
			}
		}
		if strings.TrimSpace(key.PublicKey) == "" {
			return &errors.ValidationError{
				Field:   keyPrefix + ".public_key",
				Message: "public key is required",
			}
		}
	}

	// Validate clock skew
	if a.ClockSkew < 0 {
		return &errors.ValidationError{
			Field:   prefix + ".clock_skew",
			Value:   a.ClockSkew,
			Message: "clock skew must be non-negative",
		}
	}

	return nil
}

// MarshalTemplate renders a starter configuration for the specified ecosystem.
func MarshalTemplate(ecosystem string) (string, error) {
	var cfg Config
	switch ecosystem {
	case "", "go":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "go-proxy",
					Bind:       ":8080",
					Ecosystems: []string{"go"},
					Upstream:   "https://proxy.golang.org",
					Policies:   []string{"policy/go-proxy.yaml"},
				},
			},
		}
	case "pypi":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "pypi-proxy",
					Bind:       ":8081",
					Ecosystems: []string{"pypi"},
					Upstream:   "https://pypi.org",
					Policies:   []string{"policy/pypi.yaml"},
				},
			},
		}
	case "npm":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "npm-proxy",
					Bind:       ":8082",
					Ecosystems: []string{"npm"},
					Upstream:   "https://registry.npmjs.org",
					Policies:   []string{"policy/npm.yaml"},
				},
			},
		}
	case "rubygems":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "rubygems-proxy",
					Bind:       ":8083",
					Ecosystems: []string{"rubygems"},
					Upstream:   "https://rubygems.org",
					Policies:   []string{"policy/rubygems.yaml"},
				},
			},
		}
	case "oci":
		cfg = Config{
			Listeners: []ListenerConfig{
				{
					Name:       "oci-proxy",
					Bind:       ":8084",
					Ecosystems: []string{"oci"},
					Upstream:   "https://registry-1.docker.io",
					Policies:   []string{"policy/oci.yaml"},
					OCI: &OCIConfig{
						StrictMode: true, // Secure defaults for OCI
					},
				},
			},
		}
	default:
		return "", fmt.Errorf("unknown ecosystem %q", ecosystem)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return "", err
	}

	// Append commented auth configuration example
	authExample := `
# Authentication (optional):
# Uncomment to enable JWT-based authentication.
# See: docs/commands/proxy.md#authentication-jwtoidc
#
# auth:
#   mode: required  # disabled | optional | required
#   jwks:
#     url: "https://auth.example.com/.well-known/jwks.json"
#     # oidc_discovery: true  # auto-discover from issuer
#     # refresh_interval: 1h
#   # static_keys:  # alternative to JWKS
#   #   - kid: "key-1"
#   #     alg: "RS256"
#   #     public_key: |
#   #       -----BEGIN PUBLIC KEY-----
#   #       ...
#   #       -----END PUBLIC KEY-----
#   issuers:
#     - "https://auth.example.com"
#   audiences:
#     - "deputy-proxy"
#   # required_claims: ["sub", "email"]
#   # clock_skew: 30s
#   # allowed_algorithms: ["RS256", "ES256"]
`

	// Append OCI-specific configuration example for OCI ecosystem
	ociExample := ""
	if ecosystem == "oci" {
		ociExample = `
# OCI Security (TOCTOU mitigation):
# The OCI proxy pins image digests during policy evaluation to prevent
# time-of-check-to-time-of-use vulnerabilities. StrictMode enforces:
# - pin_digests: true (rewrite tag requests to use resolved digest)
# - allow_mutable_tags: false (block :latest and other mutable tags)
#
# For production, keep strict_mode: true. For development/testing:
# oci:
#   strict_mode: false
#   pin_digests: true           # Still pin digests for security
#   allow_mutable_tags: true    # But allow :latest for convenience
`
	}

	return string(data) + authExample + ociExample, nil
}
