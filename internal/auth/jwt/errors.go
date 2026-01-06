package jwt

import (
	"fmt"
	"net/http"
)

// Error codes for authentication failures.
// These are machine-readable codes that can be used for metrics,
// logging, and programmatic error handling.
const (
	// CodeMissingToken indicates no Authorization header was provided.
	CodeMissingToken = "missing_token"
	// CodeInvalidToken indicates the token could not be parsed or is malformed.
	CodeInvalidToken = "invalid_token"
	// CodeExpiredToken indicates the token's exp claim is in the past.
	CodeExpiredToken = "expired_token"
	// CodeInvalidIssuer indicates the token's iss claim is not in the allowed list.
	CodeInvalidIssuer = "invalid_issuer"
	// CodeInvalidAudience indicates the token's aud claim is not in the allowed list.
	CodeInvalidAudience = "invalid_audience"
	// CodeMissingClaim indicates a required claim is not present in the token.
	CodeMissingClaim = "missing_claim"
	// CodeKeyNotFound indicates the signing key (kid) was not found in JWKS or static keys.
	CodeKeyNotFound = "key_not_found"
	// CodeSignatureInvalid indicates the token signature verification failed.
	CodeSignatureInvalid = "signature_invalid"
)

// Error represents an authentication or authorization failure.
// It contains both a machine-readable Code and a human-readable Message.
type Error struct {
	// Code is a machine-readable error code from the Code* constants.
	Code string
	// Message is a human-readable description of the error.
	Message string
	// Cause is the underlying error, if any.
	Cause error
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error for use with errors.Is/As.
func (e *Error) Unwrap() error {
	return e.Cause
}

// HTTPStatus returns the appropriate HTTP status code for the error.
//
// Authentication failures (identity unknown/unverifiable) return 401 Unauthorized:
//   - missing_token, invalid_token, expired_token, signature_invalid, key_not_found
//
// Authorization failures (identity known but insufficient) return 403 Forbidden:
//   - invalid_issuer, invalid_audience, missing_claim
func (e *Error) HTTPStatus() int {
	switch e.Code {
	case CodeMissingToken, CodeInvalidToken, CodeExpiredToken, CodeSignatureInvalid, CodeKeyNotFound:
		return http.StatusUnauthorized // 401 - identity unknown or unverifiable
	case CodeInvalidIssuer, CodeInvalidAudience, CodeMissingClaim:
		return http.StatusForbidden // 403 - identity known but insufficient permissions
	default:
		return http.StatusUnauthorized
	}
}

// NewError creates a new Error with the given code and message.
func NewError(code, message string) *Error {
	return &Error{Code: code, Message: message}
}

// WrapError creates a new Error that wraps an underlying error.
func WrapError(code, message string, cause error) *Error {
	return &Error{Code: code, Message: message, Cause: cause}
}
