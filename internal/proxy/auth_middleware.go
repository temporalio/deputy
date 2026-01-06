package proxy

import (
	"context"
	"net/http"

	"go.opentelemetry.io/otel/trace"
)

// handleAuthError writes an authentication error response.
// This is proxy-specific (includes deputy-proxy realm).
// Note: Logging is handled by the jwt middleware's logAuthError function
// to avoid duplicate log entries.
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

	http.Error(w, err.Message, status)
}

// traceSpanFromContext gets the trace span from context.
func traceSpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}
