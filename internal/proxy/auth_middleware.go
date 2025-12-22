package proxy

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// jwtClaimsKey is the context key for storing verified JWT claims.
type jwtClaimsKey struct{}

// JWTClaimsFromContext retrieves verified JWT claims from the request context.
// Returns nil if no claims are present (anonymous request or auth disabled).
func JWTClaimsFromContext(ctx context.Context) *JWTClaims {
	if ctx == nil {
		return nil
	}
	claims, _ := ctx.Value(jwtClaimsKey{}).(*JWTClaims)
	return claims
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

	required := mode == AuthModeRequired

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, err := auth.Authenticate(r.Context(), r)

			if err != nil {
				var authErr *AuthError
				if errors.As(err, &authErr) {
					authMetrics.RecordError(authErr.Code)
					handleAuthError(w, r, authErr)
					return
				}
				// Unexpected error
				authMetrics.RecordError("internal_error")
				slog.Error("authentication failed",
					"request_id", requestIDFromContext(r.Context()),
					"error", err,
				)
				http.Error(w, "authentication error", http.StatusInternalServerError)
				return
			}

			if claims == nil && required {
				// No token provided but auth is required
				authMetrics.RecordError(AuthCodeMissingToken)
				handleAuthError(w, r, &AuthError{
					Code:    AuthCodeMissingToken,
					Message: "authentication required",
				})
				return
			}

			// Record success or anonymous
			if claims != nil {
				authMetrics.RecordSuccess()
			} else {
				authMetrics.RecordAnonymous()
			}

			// Store claims in context (may be nil for anonymous)
			ctx := context.WithValue(r.Context(), jwtClaimsKey{}, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// handleAuthError writes an authentication error response.
func handleAuthError(w http.ResponseWriter, r *http.Request, err *AuthError) {
	status := err.HTTPStatus()

	// Set WWW-Authenticate header for 401 responses
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="deputy-proxy"`)
	}

	// Add error details in headers
	w.Header().Set("X-Deputy-Auth-Error", err.Code)
	if err.Message != "" {
		w.Header().Set("X-Deputy-Auth-Message", err.Message)
	}

	// Log authentication failures (except missing token which is expected)
	if err.Code != AuthCodeMissingToken {
		slog.Warn("authentication failed",
			"request_id", requestIDFromContext(r.Context()),
			"code", err.Code,
			"message", err.Message,
			"path", r.URL.Path,
		)
	}

	http.Error(w, err.Message, status)
}
