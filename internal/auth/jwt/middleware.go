package jwt

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
)

// claimsKey is the context key for storing verified JWT claims.
type claimsKey struct{}

// ClaimsFromContext retrieves verified JWT claims from the request context.
// Returns nil if no claims are present (anonymous request or auth disabled).
func ClaimsFromContext(ctx context.Context) *Claims {
	if ctx == nil {
		return nil
	}
	claims, _ := ctx.Value(claimsKey{}).(*Claims)
	return claims
}

// ContextWithClaims returns a new context with the given claims.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// MiddlewareConfig configures the authentication middleware.
type MiddlewareConfig struct {
	// Mode determines how authentication is enforced.
	Mode Mode

	// Metrics records authentication metrics.
	Metrics MetricsRecorder

	// ErrorHandler handles authentication errors.
	// If nil, DefaultErrorHandler is used.
	ErrorHandler ErrorHandler

	// OnSuccess is called after successful authentication.
	// Use this for custom OTel span events or additional logging.
	OnSuccess func(ctx context.Context, claims *Claims)

	// OnAnonymous is called when no token is provided (and mode is optional).
	OnAnonymous func(ctx context.Context)

	// OnRejected is called when authentication fails.
	OnRejected func(ctx context.Context, code string)

	// RequestIDFunc extracts a request ID from context for logging.
	// If nil, no request ID is logged.
	RequestIDFunc func(ctx context.Context) string
}

// ErrorHandler handles authentication errors and writes the HTTP response.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, err *Error)

// DefaultErrorHandler is the default error handler for authentication failures.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err *Error) {
	status := err.HTTPStatus()

	// Set WWW-Authenticate header for 401 responses
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="deputy"`)
	}

	// Add error details in headers
	w.Header().Set("X-Auth-Error", err.Code)
	if err.Message != "" {
		w.Header().Set("X-Auth-Message", err.Message)
	}

	http.Error(w, err.Message, status)
}

// Middleware returns HTTP middleware that validates JWT tokens.
// It should be placed early in the middleware chain for proper correlation.
//
// When auth is nil or mode is ModeDisabled, the middleware passes through without modification.
func Middleware(auth Authenticator, cfg MiddlewareConfig) func(http.Handler) http.Handler {
	if auth == nil || cfg.Mode == ModeDisabled {
		return func(next http.Handler) http.Handler { return next }
	}

	// Use defaults for nil callbacks
	metrics := cfg.Metrics
	if metrics == nil {
		metrics = NoopMetrics{}
	}

	errorHandler := cfg.ErrorHandler
	if errorHandler == nil {
		errorHandler = DefaultErrorHandler
	}

	required := cfg.Mode == ModeRequired

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()
			claims, err := auth.Authenticate(ctx, r)

			if err != nil {
				var authErr *Error
				if errors.As(err, &authErr) {
					metrics.RecordError(authErr.Code)
					if cfg.OnRejected != nil {
						cfg.OnRejected(ctx, authErr.Code)
					}
					logAuthError(ctx, authErr, r.URL.Path, cfg.RequestIDFunc)
					errorHandler(w, r, authErr)
					return
				}
				// Unexpected error
				metrics.RecordError("internal_error")
				if cfg.OnRejected != nil {
					cfg.OnRejected(ctx, "internal_error")
				}
				slog.Error("authentication failed",
					"error", err,
					"path", r.URL.Path,
				)
				http.Error(w, "authentication error", http.StatusInternalServerError)
				return
			}

			if claims == nil && required {
				// No token provided but auth is required
				authErr := &Error{
					Code:    CodeMissingToken,
					Message: "authentication required",
				}
				metrics.RecordError(CodeMissingToken)
				if cfg.OnRejected != nil {
					cfg.OnRejected(ctx, CodeMissingToken)
				}
				errorHandler(w, r, authErr)
				return
			}

			// Record success or anonymous
			if claims != nil {
				metrics.RecordSuccess()
				if cfg.OnSuccess != nil {
					cfg.OnSuccess(ctx, claims)
				}
			} else {
				metrics.RecordAnonymous()
				if cfg.OnAnonymous != nil {
					cfg.OnAnonymous(ctx)
				}
			}

			// Store claims in context (may be nil for anonymous)
			ctx = ContextWithClaims(ctx, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// logAuthError logs authentication failures with appropriate level.
func logAuthError(ctx context.Context, err *Error, path string, requestIDFunc func(context.Context) string) {
	// Don't log missing token at warn level - it's expected for anonymous endpoints
	if err.Code == CodeMissingToken {
		return
	}

	attrs := []any{
		"code", err.Code,
		"message", err.Message,
		"path", path,
	}

	if requestIDFunc != nil {
		if reqID := requestIDFunc(ctx); reqID != "" {
			attrs = append(attrs, "request_id", reqID)
		}
	}

	slog.Warn("authentication failed", attrs...)
}

// SimpleMiddleware returns a simplified middleware with default configuration.
// For more control, use Middleware with MiddlewareConfig.
func SimpleMiddleware(auth Authenticator, mode Mode) func(http.Handler) http.Handler {
	return Middleware(auth, MiddlewareConfig{Mode: mode})
}
