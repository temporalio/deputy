package mcp

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/temporalio/deputy/internal/auth/jwt"
)

// Type aliases for configuration types.
// These allow MCP-specific documentation while using the shared jwt package types.
type (
	// AuthConfig defines authentication settings for the MCP HTTP server.
	// This is a type alias for jwt.Config.
	AuthConfig = jwt.Config

	// JWKSConfig configures JWKS endpoint discovery.
	// This is a type alias for jwt.JWKSConfig.
	JWKSConfig = jwt.JWKSConfig

	// StaticKeyConfig defines an inline public key.
	// This is a type alias for jwt.StaticKeyConfig.
	StaticKeyConfig = jwt.StaticKeyConfig
)

// getMode returns the auth mode for a config, defaulting to disabled.
func getMode(c *AuthConfig) jwt.Mode {
	if c == nil {
		return jwt.ModeDisabled
	}
	return c.GetMode()
}

// Claims is a type alias for jwt.Claims for convenience.
type Claims = jwt.Claims

// ClaimsFromContext retrieves verified JWT claims from the request context.
// Returns nil if no claims are present (anonymous request or auth disabled).
func ClaimsFromContext(ctx context.Context) *Claims {
	return jwt.ClaimsFromContext(ctx)
}

// AnonymousClaims returns a claims map indicating anonymous access.
func AnonymousClaims() map[string]any {
	return jwt.AnonymousClaims()
}

// authMiddleware creates JWT authentication middleware for the MCP server.
func authMiddleware(cfg *AuthConfig) (func(http.Handler) http.Handler, func() error, error) {
	mode := getMode(cfg)
	if cfg == nil || mode == jwt.ModeDisabled {
		return func(next http.Handler) http.Handler { return next }, func() error { return nil }, nil
	}

	// Register metrics on first use
	registerMCPAuthMetrics()

	// Since AuthConfig is now a type alias for jwt.Config, pass directly
	// Pass metrics to both authenticator and middleware
	auth, err := jwt.NewAuthenticator(cfg, jwt.WithMetrics(mcpMetrics))
	if err != nil {
		return nil, nil, err
	}

	middleware := jwt.Middleware(auth, jwt.MiddlewareConfig{
		Mode:    mode,
		Metrics: mcpMetrics,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err *jwt.Error) {
			handleAuthError(w, r, err)
		},
		OnSuccess: func(ctx context.Context, claims *jwt.Claims) {
			slog.Debug("MCP auth success", "subject", claims.Subject)
		},
		OnAnonymous: func(ctx context.Context) {
			slog.Debug("MCP anonymous request")
		},
		OnRejected: func(ctx context.Context, code string) {
			slog.Debug("MCP auth rejected", "code", code)
		},
	})

	return middleware, auth.Close, nil
}

// handleAuthError writes an authentication error response for MCP.
// Note: Logging is handled by the jwt middleware's logAuthError function
// to avoid duplicate log entries.
func handleAuthError(w http.ResponseWriter, r *http.Request, err *jwt.Error) {
	status := err.HTTPStatus()

	// Set WWW-Authenticate header for 401 responses
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="deputy-mcp"`)
	}

	// Add error details in headers
	w.Header().Set("X-MCP-Auth-Error", err.Code)
	if err.Message != "" {
		w.Header().Set("X-MCP-Auth-Message", err.Message)
	}

	http.Error(w, err.Message, status)
}
