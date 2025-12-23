package proxy

import (
	"fmt"
	"net/http"
)

// Authentication error codes.
const (
	AuthCodeMissingToken     = "missing_token"
	AuthCodeInvalidToken     = "invalid_token"
	AuthCodeExpiredToken     = "expired_token"
	AuthCodeInvalidIssuer    = "invalid_issuer"
	AuthCodeInvalidAudience  = "invalid_audience"
	AuthCodeMissingClaim     = "missing_claim"
	AuthCodeKeyNotFound      = "key_not_found"
	AuthCodeSignatureInvalid = "signature_invalid"
)

// AuthError represents an authentication or authorization failure.
type AuthError struct {
	Code    string // Machine-readable error code
	Message string // Human-readable message
	Cause   error  // Underlying error, if any
}

func (e *AuthError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

func (e *AuthError) Unwrap() error {
	return e.Cause
}

// HTTPStatus returns the appropriate HTTP status code for the error.
// Authentication failures (identity unknown) return 401.
// Authorization failures (identity known but insufficient) return 403.
func (e *AuthError) HTTPStatus() int {
	switch e.Code {
	case AuthCodeMissingToken, AuthCodeInvalidToken, AuthCodeExpiredToken, AuthCodeSignatureInvalid, AuthCodeKeyNotFound:
		return http.StatusUnauthorized // 401 - identity unknown or unverifiable
	case AuthCodeInvalidIssuer, AuthCodeInvalidAudience, AuthCodeMissingClaim:
		return http.StatusForbidden // 403 - identity known but insufficient permissions
	default:
		return http.StatusUnauthorized
	}
}
