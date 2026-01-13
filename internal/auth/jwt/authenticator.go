package jwt

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
	"time"

	"github.com/picatz/jose/pkg/header"
	"github.com/picatz/jose/pkg/jwa"
	"github.com/picatz/jose/pkg/jwt"
)

// Authenticator validates JWT tokens and extracts claims.
type Authenticator interface {
	// Authenticate validates the token and returns claims.
	// Returns nil claims and nil error for valid anonymous access (no token provided).
	// Returns *Error for authentication failures.
	Authenticate(ctx context.Context, r *http.Request) (*Claims, error)

	// Close releases any resources held by the authenticator.
	Close() error
}

// authenticator implements Authenticator using the jose library.
type authenticator struct {
	jwksCache         *JWKSCache
	jwksCacheOpts     []JWKSCacheOption
	staticKeys        map[string]crypto.PublicKey
	issuers           []string
	audiences         []string
	requiredClaims    []string
	clockSkew         time.Duration
	allowedAlgorithms []string
	maxTokenSize      int
	metrics           MetricsRecorder
}

// Option configures an Authenticator.
type Option func(*authenticator)

// WithMetrics sets the metrics recorder for the authenticator.
func WithMetrics(m MetricsRecorder) Option {
	return func(a *authenticator) {
		if m != nil {
			a.metrics = m
		}
	}
}

// WithJWKSCacheOptions sets additional options for the JWKS cache.
// This is primarily useful for testing to inject a custom HTTP client.
func WithJWKSCacheOptions(opts ...JWKSCacheOption) Option {
	return func(a *authenticator) {
		a.jwksCacheOpts = append(a.jwksCacheOpts, opts...)
	}
}

// NewAuthenticator creates a new JWT authenticator from the given configuration.
func NewAuthenticator(cfg *Config, opts ...Option) (Authenticator, error) {
	if cfg == nil {
		return nil, fmt.Errorf("auth config is nil")
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, err
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

	auth := &authenticator{
		issuers:           cfg.Issuers,
		audiences:         cfg.Audiences,
		requiredClaims:    cfg.RequiredClaims,
		clockSkew:         cfg.ClockSkew,
		allowedAlgorithms: allowedAlgs,
		maxTokenSize:      maxTokenSize,
		staticKeys:        make(map[string]crypto.PublicKey),
		metrics:           NoopMetrics{},
	}

	// Apply options
	for _, opt := range opts {
		opt(auth)
	}

	// Initialize JWKS cache if configured
	if cfg.JWKS != nil && cfg.JWKS.URL != "" {
		// Combine default metrics option with any user-provided options
		jwksCacheOpts := append([]JWKSCacheOption{WithJWKSMetrics(auth.metrics)}, auth.jwksCacheOpts...)
		cache, err := NewJWKSCache(cfg.JWKS, jwksCacheOpts...)
		if err != nil {
			return nil, fmt.Errorf("create JWKS cache: %w", err)
		}
		auth.jwksCache = cache
	}

	// Parse static keys
	for i, keyCfg := range cfg.StaticKeys {
		key, err := ParsePublicKey(keyCfg.PublicKey)
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
func (a *authenticator) Authenticate(ctx context.Context, r *http.Request) (*Claims, error) {
	// Extract bearer token from Authorization header
	tokenString, err := jwt.FromHTTPAuthorizationHeader(r)
	if err != nil {
		// No token present - this is not an error, just anonymous
		return nil, nil
	}

	// Check token size to prevent DoS via oversized tokens
	if len(tokenString) > a.maxTokenSize {
		return nil, &Error{
			Code:    CodeInvalidToken,
			Message: "token exceeds maximum allowed size",
		}
	}

	// Parse the token to extract header (for kid) and claims
	token, err := jwt.Parse(tokenString)
	if err != nil {
		return nil, &Error{
			Code:    CodeInvalidToken,
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
		return nil, &Error{
			Code:    CodeSignatureInvalid,
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
func (a *authenticator) verifyTokenSignature(token *jwt.Token, kid string, key crypto.PublicKey) error {
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
func (a *authenticator) Close() error {
	if a.jwksCache != nil {
		return a.jwksCache.Close()
	}
	return nil
}

// getKey looks up the verification key by key ID.
func (a *authenticator) getKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
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

	return nil, &Error{
		Code:    CodeKeyNotFound,
		Message: fmt.Sprintf("key %q not found", kid),
	}
}

// extractClaims extracts claims from a parsed JWT token.
func (a *authenticator) extractClaims(token *jwt.Token) (*Claims, error) {
	claims := &Claims{
		Custom: make(map[string]any),
	}

	// Extract standard claims with type validation
	if sub, err := token.Claims.Get(jwt.Subject); err == nil {
		if s, ok := sub.(string); ok {
			claims.Subject = s
		} else if sub != nil {
			slog.Debug("JWT claim 'sub' has unexpected type", "type", fmt.Sprintf("%T", sub))
		}
	}

	if iss, err := token.Claims.Get(jwt.Issuer); err == nil {
		if s, ok := iss.(string); ok {
			claims.Issuer = s
		} else if iss != nil {
			slog.Debug("JWT claim 'iss' has unexpected type", "type", fmt.Sprintf("%T", iss))
		}
	}

	if aud, err := token.Claims.Get(jwt.Audience); err == nil {
		switch v := aud.(type) {
		case string:
			claims.Audience = []string{v}
		case []any:
			for _, audVal := range v {
				if s, ok := audVal.(string); ok {
					claims.Audience = append(claims.Audience, s)
				}
			}
		case []string:
			claims.Audience = v
		default:
			if aud != nil {
				slog.Debug("JWT claim 'aud' has unexpected type", "type", fmt.Sprintf("%T", aud))
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
			slog.Debug("JWT claim 'jti' has unexpected type", "type", fmt.Sprintf("%T", jti))
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
func (a *authenticator) validateClaims(claims *Claims) error {
	now := time.Now()

	// Validate expiration
	if claims.ExpiresAt != 0 {
		expTime := time.Unix(claims.ExpiresAt, 0).Add(a.clockSkew)
		if now.After(expTime) {
			return &Error{
				Code:    CodeExpiredToken,
				Message: "token has expired",
			}
		}
	}

	// Validate not-before
	if claims.NotBefore != 0 {
		nbfTime := time.Unix(claims.NotBefore, 0).Add(-a.clockSkew)
		if now.Before(nbfTime) {
			return &Error{
				Code:    CodeInvalidToken,
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
			return &Error{
				Code:    CodeInvalidIssuer,
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
			return &Error{
				Code:    CodeInvalidAudience,
				Message: "token audience not in allowed list",
			}
		}
	}

	// Validate required claims
	for _, claim := range a.requiredClaims {
		if !claims.Has(claim) {
			return &Error{
				Code:    CodeMissingClaim,
				Message: fmt.Sprintf("required claim %q not present", claim),
			}
		}
	}

	return nil
}

// ParsePublicKey parses a PEM-encoded public key.
func ParsePublicKey(pemData string) (crypto.PublicKey, error) {
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

// Verify key types are supported at compile time.
var (
	_ crypto.PublicKey = (*rsa.PublicKey)(nil)
	_ crypto.PublicKey = (*ecdsa.PublicKey)(nil)
	_ crypto.PublicKey = (ed25519.PublicKey)(nil)
)
