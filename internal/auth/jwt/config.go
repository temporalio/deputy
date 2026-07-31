package jwt

import (
	"strings"
	"time"
)

// Mode defines how authentication is enforced.
type Mode string

const (
	// ModeDisabled disables authentication entirely (default).
	ModeDisabled Mode = "disabled"
	// ModeOptional validates tokens if present but allows anonymous access.
	ModeOptional Mode = "optional"
	// ModeRequired rejects requests without valid tokens.
	ModeRequired Mode = "required"
)

// Config defines authentication settings.
type Config struct {
	// Mode determines how authentication is enforced.
	// - "required": requests without valid tokens are rejected (401)
	// - "optional": tokens are validated if present, anonymous access allowed
	// - "disabled": no authentication (default for backward compatibility)
	Mode string `yaml:"mode,omitempty"`

	// JWKS configures JSON Web Key Set endpoints for key discovery.
	JWKS *JWKSConfig `yaml:"jwks,omitempty"`

	// StaticKeys provides inline public keys for validation.
	// Useful for development, testing, or air-gapped environments.
	StaticKeys []StaticKeyConfig `yaml:"static_keys,omitempty"`

	// Issuers lists trusted token issuers (iss claim).
	// If empty, issuer validation is skipped.
	Issuers []string `yaml:"issuers,omitempty"`

	// Audiences lists expected audiences (aud claim).
	// If empty, audience validation is skipped.
	Audiences []string `yaml:"audiences,omitempty"`

	// RequiredClaims specifies claims that must be present in tokens.
	RequiredClaims []string `yaml:"required_claims,omitempty"`

	// ClockSkew allows for clock drift when validating exp/nbf/iat.
	// Defaults to 0 (no skew allowed). Must be non-negative. Maximum 5 minutes.
	ClockSkew time.Duration `yaml:"clock_skew,omitempty"`

	// AllowedAlgorithms restricts accepted signing algorithms.
	// If empty, defaults to secure asymmetric algorithms (RS256, ES256, EdDSA, etc).
	// Use this to reject weaker or unwanted algorithms.
	AllowedAlgorithms []string `yaml:"allowed_algorithms,omitempty"`

	// MaxTokenSize limits the maximum size of JWT tokens in bytes.
	// Defaults to 16KB. Use this to prevent DoS via oversized tokens.
	MaxTokenSize int `yaml:"max_token_size,omitempty"`
}

// JWKSConfig configures JWKS endpoint discovery.
type JWKSConfig struct {
	// URL is the JWKS endpoint (e.g., https://issuer/.well-known/jwks.json).
	URL string `yaml:"url"`

	// OIDCDiscovery enables OIDC discovery from issuer URL.
	// When true, URL should be the issuer URL; JWKS URI is auto-discovered.
	OIDCDiscovery bool `yaml:"oidc_discovery,omitempty"`

	// RefreshInterval controls background JWKS refresh (default: 1h).
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"`

	// CacheDuration controls how long keys are cached (default: 24h).
	// Deprecated: Use RefreshInterval instead.
	CacheDuration time.Duration `yaml:"cache_duration,omitempty"`
}

// StaticKeyConfig defines an inline public key.
type StaticKeyConfig struct {
	// KeyID is the key identifier (matches JWT header "kid").
	KeyID string `yaml:"kid"`

	// Algorithm specifies the signing algorithm (e.g., RS256, ES256, EdDSA).
	Algorithm string `yaml:"alg"`

	// PublicKey is the PEM-encoded public key.
	PublicKey string `yaml:"public_key"`
}

// Constants for configuration limits.
const (
	// DefaultMaxTokenSize is the default maximum JWT token size (16KB).
	DefaultMaxTokenSize = 16 * 1024
	// MaxClockSkew is the maximum allowed clock skew (5 minutes).
	MaxClockSkew = 5 * time.Minute
)

// DefaultAllowedAlgorithms are the signing algorithms allowed by default.
// These are all asymmetric algorithms; symmetric algorithms (HS256, etc.) are excluded
// for security since they require shared secrets.
var DefaultAllowedAlgorithms = []string{
	"RS256", "RS384", "RS512", // RSA with SHA-2
	"ES256", "ES384", "ES512", // ECDSA with SHA-2
	"EdDSA",                   // Ed25519
	"PS256", "PS384", "PS512", // RSA-PSS
}

// GetMode returns the auth mode, defaulting to disabled.
func (c *Config) GetMode() Mode {
	if c == nil {
		return ModeDisabled
	}
	switch strings.ToLower(c.Mode) {
	case "required":
		return ModeRequired
	case "optional":
		return ModeOptional
	default:
		return ModeDisabled
	}
}

// Validate checks the configuration for errors.
func (c *Config) Validate() error {
	if c == nil {
		return nil
	}

	// Validate clock skew
	if c.ClockSkew < 0 {
		return NewError(CodeInvalidToken, "clock_skew must be non-negative")
	}
	if c.ClockSkew > MaxClockSkew {
		return NewError(CodeInvalidToken, "clock_skew exceeds maximum allowed 5m")
	}

	// Must have at least one key source if auth is enabled
	mode := c.GetMode()
	if mode != ModeDisabled {
		if c.JWKS == nil && len(c.StaticKeys) == 0 {
			return NewError(CodeKeyNotFound, "no key sources configured: need jwks or static_keys")
		}
	}

	return nil
}
