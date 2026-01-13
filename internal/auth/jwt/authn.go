package jwt

import (
	"context"
	"net/http"

	"connectrpc.com/authn"
	"connectrpc.com/connect"
)

// AuthnFunc creates an authn.AuthFunc that wraps the given Authenticator.
// This enables using Deputy's JWT authenticator with connectrpc/authn-go middleware.
//
// The returned AuthFunc returns *Claims as the authentication info, which can be
// retrieved downstream via authn.GetInfo(ctx).(*jwt.Claims).
//
// When mode is ModeRequired, missing tokens return authn.Errorf (connect.CodeUnauthenticated).
// When mode is ModeOptional, missing tokens return (nil, nil) for anonymous access.
// When mode is ModeDisabled, all requests pass through with nil info.
//
// Example usage with authn.NewMiddleware:
//
//	authenticator, _ := jwt.NewAuthenticator(cfg)
//	authFunc := jwt.AuthnFunc(authenticator, jwt.ModeRequired)
//	middleware := authn.NewMiddleware(authFunc, handlerOptions...)
//	handler := middleware.Wrap(mux)
func AuthnFunc(auth Authenticator, mode Mode) authn.AuthFunc {
	if auth == nil || mode == ModeDisabled {
		return func(ctx context.Context, req *http.Request) (any, error) {
			return nil, nil
		}
	}

	required := mode == ModeRequired

	return func(ctx context.Context, req *http.Request) (any, error) {
		claims, err := auth.Authenticate(ctx, req)
		if err != nil {
			// Convert our error to authn error for proper Connect error handling
			if authErr, ok := err.(*Error); ok {
				connectErr := authn.Errorf("%s", authErr.Message)
				// Set WWW-Authenticate header for 401 responses
				if authErr.HTTPStatus() == http.StatusUnauthorized {
					connectErr.Meta().Set("WWW-Authenticate", `Bearer realm="deputy"`)
				}
				connectErr.Meta().Set("X-Auth-Error", authErr.Code)
				return nil, connectErr
			}
			// Unexpected error - return as internal
			return nil, connect.NewError(connect.CodeInternal, err)
		}

		if claims == nil {
			if required {
				// No token provided but auth is required
				connectErr := authn.Errorf("authentication required")
				connectErr.Meta().Set("WWW-Authenticate", `Bearer realm="deputy"`)
				connectErr.Meta().Set("X-Auth-Error", CodeMissingToken)
				return nil, connectErr
			}
			// Anonymous access allowed - return untyped nil (not (*Claims)(nil))
			return nil, nil
		}

		// Return claims as the auth info
		return claims, nil
	}
}

// ClaimsFromAuthn retrieves JWT claims from a context populated by authn middleware.
// This is a convenience wrapper around authn.GetInfo that handles type assertion.
//
// Returns nil if:
//   - No auth info is present (anonymous request)
//   - Auth info is not *Claims (different auth provider)
//   - Auth is disabled
func ClaimsFromAuthn(ctx context.Context) *Claims {
	info := authn.GetInfo(ctx)
	if info == nil {
		return nil
	}
	claims, _ := info.(*Claims)
	return claims
}

// IsAnonymousAuthn returns true if the request has no authentication info.
// Use this to check for anonymous access when using authn middleware.
func IsAnonymousAuthn(ctx context.Context) bool {
	return authn.GetInfo(ctx) == nil
}
