package proxy

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

// AuthMode defines how authentication is enforced.
type AuthMode string

const (
	// AuthModeDisabled disables authentication entirely.
	AuthModeDisabled AuthMode = "disabled"
	// AuthModeOptional validates tokens if present but allows anonymous access.
	AuthModeOptional AuthMode = "optional"
	// AuthModeRequired rejects requests without valid tokens.
	AuthModeRequired AuthMode = "required"
)

// AuthConfig defines authentication settings for a listener.
type AuthConfig struct {
	// Mode determines how authentication is enforced.
	// - "required": requests without valid tokens are rejected (401)
	// - "optional": tokens are validated if present, anonymous access allowed
	// - "disabled": no authentication (default for backward compatibility)
	Mode string `yaml:"mode,omitempty"`

	// JWKS configures JSON Web Key Set endpoints for key discovery.
	JWKS *JWKSConfig `yaml:"jwks,omitempty"`

	// StaticKeys provides inline public keys for validation.
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
	// Defaults to 0 (no skew allowed). Maximum 5 minutes.
	ClockSkew time.Duration `yaml:"clock_skew,omitempty"`

	// AllowedAlgorithms restricts accepted signing algorithms.
	// If empty, defaults to secure asymmetric algorithms (RS256, ES256, EdDSA, etc).
	// Use this to reject weaker or unwanted algorithms.
	AllowedAlgorithms []string `yaml:"allowed_algorithms,omitempty"`

	// MaxTokenSize limits the maximum size of JWT tokens in bytes.
	// Defaults to 16KB. Use this to prevent DoS via oversized tokens.
	MaxTokenSize int `yaml:"max_token_size,omitempty"`
}

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
func (c *AuthConfig) GetMode() AuthMode {
	if c == nil {
		return AuthModeDisabled
	}
	switch strings.ToLower(c.Mode) {
	case "required":
		return AuthModeRequired
	case "optional":
		return AuthModeOptional
	default:
		return AuthModeDisabled
	}
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

// JWTClaims represents verified JWT claims exposed to policies.
type JWTClaims struct {
	// Standard claims
	Subject   string   `json:"sub,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	NotBefore int64    `json:"nbf,omitempty"`
	JWTID     string   `json:"jti,omitempty"`

	// Custom claims (all other claims from the token)
	Custom map[string]any `json:"-"`
}

// ToMap converts claims to a map suitable for CEL evaluation.
func (c *JWTClaims) ToMap() map[string]any {
	m := map[string]any{
		"anonymous": false,
	}

	// Add standard claims if present
	if c.Subject != "" {
		m["sub"] = c.Subject
	}
	if c.Issuer != "" {
		m["iss"] = c.Issuer
	}
	if len(c.Audience) > 0 {
		m["aud"] = c.Audience
	}
	if c.ExpiresAt != 0 {
		m["exp"] = c.ExpiresAt
	}
	if c.IssuedAt != 0 {
		m["iat"] = c.IssuedAt
	}
	if c.NotBefore != 0 {
		m["nbf"] = c.NotBefore
	}
	if c.JWTID != "" {
		m["jti"] = c.JWTID
	}

	// Merge custom claims at top level for easy access
	for k, v := range c.Custom {
		if _, reserved := m[k]; !reserved {
			m[k] = v
		}
	}

	return m
}

// AnonymousClaims returns a claims map indicating anonymous access.
func AnonymousClaims() map[string]any {
	return map[string]any{
		"anonymous": true,
	}
}

// Authenticator validates JWT tokens and extracts claims.
type Authenticator interface {
	// Authenticate validates the token and returns claims.
	// Returns nil claims and nil error for valid anonymous access (no token provided).
	// Returns AuthError for authentication failures.
	Authenticate(ctx context.Context, r *http.Request) (*JWTClaims, error)

	// Close releases any resources held by the authenticator.
	Close() error
}

// jwtAuthenticator implements Authenticator using the jose library.
type jwtAuthenticator struct {
	jwksCache         *JWKSCache
	staticKeys        map[string]crypto.PublicKey
	issuers           []string
	audiences         []string
	requiredClaims    []string
	clockSkew         time.Duration
	allowedAlgorithms []string
	maxTokenSize      int
}

// NewAuthenticator creates a new JWT authenticator from the given configuration.
func NewAuthenticator(cfg *AuthConfig) (Authenticator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	// Validate clock skew
	if cfg.ClockSkew > MaxClockSkew {
		return nil, fmt.Errorf("clock_skew %v exceeds maximum allowed %v", cfg.ClockSkew, MaxClockSkew)
	}

	// Use configured algorithms or defaults
	allowedAlgs := cfg.AllowedAlgorithms
	if len(allowedAlgs) == 0 {
		allowedAlgs = DefaultAllowedAlgorithms
	}

	// Use configured max token size or default
	maxTokenSize := cfg.MaxTokenSize
	if maxTokenSize <= 0 {
		maxTokenSize = DefaultMaxTokenSize
	}

	auth := &jwtAuthenticator{
		issuers:           cfg.Issuers,
		audiences:         cfg.Audiences,
		requiredClaims:    cfg.RequiredClaims,
		clockSkew:         cfg.ClockSkew,
		allowedAlgorithms: allowedAlgs,
		maxTokenSize:      maxTokenSize,
		staticKeys:        make(map[string]crypto.PublicKey),
	}

	// Initialize JWKS cache if configured
	if cfg.JWKS != nil && cfg.JWKS.URL != "" {
		cache, err := NewJWKSCache(cfg.JWKS)
		if err != nil {
			return nil, fmt.Errorf("create JWKS cache: %w", err)
		}
		auth.jwksCache = cache
	}

	// Parse static keys
	for i, keyCfg := range cfg.StaticKeys {
		key, err := parsePublicKey(keyCfg.PublicKey)
		if err != nil {
			// Clean up JWKS cache if we created one (prevent goroutine leak)
			if auth.jwksCache != nil {
				auth.jwksCache.Close()
			}
			return nil, fmt.Errorf("parse static key %d (%s): %w", i, keyCfg.KeyID, err)
		}
		auth.staticKeys[keyCfg.KeyID] = key
	}

	// Ensure at least one key source is configured
	if auth.jwksCache == nil && len(auth.staticKeys) == 0 {
		return nil, fmt.Errorf("no key sources configured: need jwks or static_keys")
	}

	return auth, nil
}

// Authenticate validates the JWT from the request and returns claims.
func (a *jwtAuthenticator) Authenticate(ctx context.Context, r *http.Request) (*JWTClaims, error) {
	// Extract bearer token from Authorization header
	tokenString, err := jwt.FromHTTPAuthorizationHeader(r)
	if err != nil {
		// No token present - this is not an error, just anonymous
		return nil, nil
	}

	// Check token size to prevent DoS via oversized tokens
	if len(tokenString) > a.maxTokenSize {
		return nil, &AuthError{
			Code:    AuthCodeInvalidToken,
			Message: "token exceeds maximum allowed size",
		}
	}

	// Parse the token to extract header (for kid) and claims
	token, err := jwt.Parse(tokenString)
	if err != nil {
		return nil, &AuthError{
			Code:    AuthCodeInvalidToken,
			Message: "failed to parse JWT",
			Cause:   err,
		}
	}

	// Get the key ID from the token header
	kid, _ := token.Header[header.KeyID].(string)

	// Look up the verification key
	key, err := a.getKey(ctx, kid)
	if err != nil {
		return nil, err
	}

	// Verify the token signature based on key type
	if err := a.verifyTokenSignature(token, kid, key); err != nil {
		// Log detailed error server-side, but don't expose to client
		slog.Debug("token signature verification failed", "kid", kid, "error", err)
		return nil, &AuthError{
			Code:    AuthCodeSignatureInvalid,
			Message: "token signature verification failed",
			Cause:   err,
		}
	}

	// Extract and validate claims
	claims, err := a.extractClaims(token)
	if err != nil {
		return nil, err
	}

	// Validate standard claims
	if err := a.validateClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// verifyTokenSignature verifies the token signature using the appropriate method for the key type.
func (a *jwtAuthenticator) verifyTokenSignature(token *jwt.Token, kid string, key crypto.PublicKey) error {
	// Get algorithm from token header
	alg, _ := token.Header[header.Algorithm].(string)
	if alg == "" {
		return fmt.Errorf("missing algorithm in token header")
	}

	// Check algorithm is allowed (security: prevent algorithm confusion attacks)
	if !slices.Contains(a.allowedAlgorithms, alg) {
		return fmt.Errorf("algorithm %q is not allowed", alg)
	}

	algOpt := jwt.WithAllowedAlgorithms(jwa.Algorithm(alg))

	// Verify with the key and algorithm constraint - need to type switch due to generics
	switch k := key.(type) {
	case *rsa.PublicKey:
		return token.Verify(algOpt, jwt.WithIdentifiableKey(kid, k))
	case *ecdsa.PublicKey:
		return token.Verify(algOpt, jwt.WithIdentifiableKey(kid, k))
	case ed25519.PublicKey:
		return token.Verify(algOpt, jwt.WithIdentifiableKey(kid, k))
	default:
		return fmt.Errorf("unsupported key type: %T", key)
	}
}

// Close releases resources held by the authenticator.
func (a *jwtAuthenticator) Close() error {
	if a.jwksCache != nil {
		return a.jwksCache.Close()
	}
	return nil
}

// getKey looks up the verification key by key ID.
func (a *jwtAuthenticator) getKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	// Try static keys first
	if key, ok := a.staticKeys[kid]; ok {
		return key, nil
	}

	// Try JWKS cache
	if a.jwksCache != nil {
		key, err := a.jwksCache.GetKey(ctx, kid)
		if err == nil {
			return key, nil
		}
		// If key not found, try refreshing the cache
		if refreshErr := a.jwksCache.ForceRefresh(ctx); refreshErr != nil {
			slog.Debug("JWKS cache refresh failed during key lookup", "kid", kid, "error", refreshErr)
		} else if key, err := a.jwksCache.GetKey(ctx, kid); err == nil {
			return key, nil
		}
	}

	return nil, &AuthError{
		Code:    AuthCodeKeyNotFound,
		Message: fmt.Sprintf("key %q not found", kid),
	}
}

// extractClaims extracts claims from a parsed JWT token.
func (a *jwtAuthenticator) extractClaims(token *jwt.Token) (*JWTClaims, error) {
	claims := &JWTClaims{
		Custom: make(map[string]any),
	}

	// Extract standard claims with type validation
	if sub, err := token.Claims.Get(jwt.Subject); err == nil {
		if s, ok := sub.(string); ok {
			claims.Subject = s
		} else if sub != nil {
			slog.Warn("JWT claim 'sub' has unexpected type", "type", fmt.Sprintf("%T", sub))
		}
	}

	if iss, err := token.Claims.Get(jwt.Issuer); err == nil {
		if s, ok := iss.(string); ok {
			claims.Issuer = s
		} else if iss != nil {
			slog.Warn("JWT claim 'iss' has unexpected type", "type", fmt.Sprintf("%T", iss))
		}
	}

	if aud, err := token.Claims.Get(jwt.Audience); err == nil {
		switch v := aud.(type) {
		case string:
			claims.Audience = []string{v}
		case []any:
			for _, a := range v {
				if s, ok := a.(string); ok {
					claims.Audience = append(claims.Audience, s)
				}
			}
		case []string:
			claims.Audience = v
		default:
			if aud != nil {
				slog.Warn("JWT claim 'aud' has unexpected type", "type", fmt.Sprintf("%T", aud))
			}
		}
	}

	if exp, err := token.Claims.Get(jwt.ExpirationTime); err == nil {
		claims.ExpiresAt = toInt64(exp)
	}

	if iat, err := token.Claims.Get(jwt.IssuedAt); err == nil {
		claims.IssuedAt = toInt64(iat)
	}

	if nbf, err := token.Claims.Get(jwt.NotBefore); err == nil {
		claims.NotBefore = toInt64(nbf)
	}

	if jti, err := token.Claims.Get(jwt.JWTID); err == nil {
		if s, ok := jti.(string); ok {
			claims.JWTID = s
		} else if jti != nil {
			slog.Warn("JWT claim 'jti' has unexpected type", "type", fmt.Sprintf("%T", jti))
		}
	}

	// Extract custom claims
	standardClaims := map[string]bool{
		"sub": true, "iss": true, "aud": true,
		"exp": true, "iat": true, "nbf": true, "jti": true,
	}

	for key, value := range token.Claims {
		if !standardClaims[key] {
			claims.Custom[key] = value
		}
	}

	return claims, nil
}

// validateClaims validates the token claims against configuration.
func (a *jwtAuthenticator) validateClaims(claims *JWTClaims) error {
	now := time.Now()

	// Validate expiration
	if claims.ExpiresAt != 0 {
		expTime := time.Unix(claims.ExpiresAt, 0).Add(a.clockSkew)
		if now.After(expTime) {
			return &AuthError{
				Code:    AuthCodeExpiredToken,
				Message: "token has expired",
			}
		}
	}

	// Validate not-before
	if claims.NotBefore != 0 {
		nbfTime := time.Unix(claims.NotBefore, 0).Add(-a.clockSkew)
		if now.Before(nbfTime) {
			return &AuthError{
				Code:    AuthCodeInvalidToken,
				Message: "token not yet valid",
			}
		}
	}

	// Validate issuer
	// Note: Not using constant-time comparison here. Issuer values are typically
	// public (from OIDC discovery), and timing attacks would require many requests
	// with network noise far exceeding comparison timing differences.
	if len(a.issuers) > 0 {
		if !slices.Contains(a.issuers, claims.Issuer) {
			return &AuthError{
				Code:    AuthCodeInvalidIssuer,
				Message: fmt.Sprintf("issuer %q not in allowed list", claims.Issuer),
			}
		}
	}

	// Validate audience (any match - per JWT spec)
	// Same timing consideration as issuer validation above.
	if len(a.audiences) > 0 {
		found := false
		for _, aud := range claims.Audience {
			if slices.Contains(a.audiences, aud) {
				found = true
				break
			}
		}
		if !found {
			return &AuthError{
				Code:    AuthCodeInvalidAudience,
				Message: "token audience not in allowed list",
			}
		}
	}

	// Validate required claims
	claimsMap := claims.ToMap()
	for _, claim := range a.requiredClaims {
		if _, ok := claimsMap[claim]; !ok {
			return &AuthError{
				Code:    AuthCodeMissingClaim,
				Message: fmt.Sprintf("required claim %q not present", claim),
			}
		}
	}

	return nil
}

// parsePublicKey parses a PEM-encoded public key.
func parsePublicKey(pemData string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	switch block.Type {
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	case "EC PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			return nil, fmt.Errorf("not an ECDSA public key")
		}
		return pub, nil
	default:
		// Try generic parsing
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported key type %q: %w", block.Type, err)
		}
		return pub, nil
	}
}

// toInt64 converts various numeric types to int64.
func toInt64(v any) int64 {
	switch n := v.(type) {
	case int64:
		return n
	case float64:
		return int64(n)
	case int:
		return int64(n)
	case int32:
		return int64(n)
	default:
		return 0
	}
}

// Verify key types are supported
var (
	_ crypto.PublicKey = (*rsa.PublicKey)(nil)
	_ crypto.PublicKey = (*ecdsa.PublicKey)(nil)
	_ crypto.PublicKey = (ed25519.PublicKey)(nil)
)
