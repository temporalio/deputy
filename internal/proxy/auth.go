package proxy

import (
	"context"
	"net/http"

	"github.com/picatz/deputy/internal/auth/jwt"
)

// Type aliases for backward compatibility.
// These allow existing code to use proxy.AuthConfig, proxy.JWKSConfig, etc.
// while the actual types are defined in the shared jwt package.
type (
	// AuthConfig defines authentication settings for a listener.
	// This is a type alias for jwt.Config.
	AuthConfig = jwt.Config

	// JWKSConfig configures JWKS endpoint discovery.
	// This is a type alias for jwt.JWKSConfig.
	JWKSConfig = jwt.JWKSConfig

	// StaticKeyConfig defines an inline public key.
	// This is a type alias for jwt.StaticKeyConfig.
	StaticKeyConfig = jwt.StaticKeyConfig

	// AuthMode defines how authentication is enforced.
	// This is a type alias for jwt.Mode.
	AuthMode = jwt.Mode
)

// Mode constants for backward compatibility.
const (
	// AuthModeDisabled disables authentication entirely.
	AuthModeDisabled = jwt.ModeDisabled
	// AuthModeOptional validates tokens if present but allows anonymous access.
	AuthModeOptional = jwt.ModeOptional
	// AuthModeRequired rejects requests without valid tokens.
	AuthModeRequired = jwt.ModeRequired
)

// Configuration constants - aliases for backward compatibility.
const (
	// DefaultMaxTokenSize is the default maximum JWT token size (16KB).
	DefaultMaxTokenSize = jwt.DefaultMaxTokenSize
	// MaxClockSkew is the maximum allowed clock skew (5 minutes).
	MaxClockSkew = jwt.MaxClockSkew
)

// DefaultAllowedAlgorithms are the signing algorithms allowed by default.
// These are all asymmetric algorithms; symmetric algorithms (HS256, etc.) are excluded
// for security since they require shared secrets.
var DefaultAllowedAlgorithms = jwt.DefaultAllowedAlgorithms

// JWTClaims represents verified JWT claims exposed to policies.
// This is a type alias for the shared jwt.Claims for backward compatibility.
type JWTClaims = jwt.Claims

// AnonymousClaims returns a claims map indicating anonymous access.
func AnonymousClaims() map[string]any {
	return jwt.AnonymousClaims()
}

// Authenticator validates JWT tokens and extracts claims.
// This is a type alias for the shared jwt.Authenticator.
type Authenticator = jwt.Authenticator

// NewAuthenticator creates a new JWT authenticator from the given configuration.
// Since AuthConfig is now a type alias for jwt.Config, no conversion is needed.
func NewAuthenticator(cfg *AuthConfig) (Authenticator, error) {
	return jwt.NewAuthenticator(cfg, jwt.WithMetrics(authMetrics))
}

// JWTClaimsFromContext retrieves verified JWT claims from the request context.
// Returns nil if no claims are present (anonymous request or auth disabled).
func JWTClaimsFromContext(ctx context.Context) *JWTClaims {
	return jwt.ClaimsFromContext(ctx)
}

// JWKSCache is a type alias for the shared jwt.JWKSCache.
type JWKSCache = jwt.JWKSCache

// NewJWKSCache creates a new JWKS cache with the given configuration.
// Since JWKSConfig is now a type alias for jwt.JWKSConfig, no conversion is needed.
func NewJWKSCache(cfg *JWKSConfig) (*JWKSCache, error) {
	return jwt.NewJWKSCache(cfg, jwt.WithJWKSMetrics(authMetrics))
}

// parsePublicKey parses a PEM-encoded public key.
// This is an alias to jwt.ParsePublicKey for backward compatibility.
var parsePublicKey = jwt.ParsePublicKey

// ContextWithJWTClaims returns a new context with the given claims.
// This is useful for testing and for manually setting claims.
func ContextWithJWTClaims(ctx context.Context, claims *JWTClaims) context.Context {
	return jwt.ContextWithClaims(ctx, claims)
}

// withAuthentication returns middleware that validates JWT tokens.
// It should be placed after withRequestID and before withRequestLogging
// for proper correlation and logging.
func withAuthentication(auth Authenticator, mode AuthMode) func(http.Handler) http.Handler {
	if auth == nil || mode == AuthModeDisabled {
		return func(next http.Handler) http.Handler { return next }
	}

	// Register metrics on first use
	registerAuthMetrics()

	return jwt.Middleware(auth, jwt.MiddlewareConfig{
		Mode:    mode, // AuthMode is now a type alias for jwt.Mode
		Metrics: authMetrics,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err *jwt.Error) {
			handleAuthError(w, r, err)
		},
		OnSuccess: func(ctx context.Context, claims *jwt.Claims) {
			RecordAuthSuccess(ctx, traceSpanFromContext(ctx), claims.Subject)
		},
		OnAnonymous: func(ctx context.Context) {
			RecordAuthAnonymous(ctx, traceSpanFromContext(ctx))
		},
		OnRejected: func(ctx context.Context, code string) {
			RecordAuthRejected(ctx, traceSpanFromContext(ctx), code)
		},
		RequestIDFunc: requestIDFromContext,
	})
}
