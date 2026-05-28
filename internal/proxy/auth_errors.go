package proxy

import (
	"github.com/temporalio/deputy/internal/auth/jwt"
)

// Authentication error codes - aliases to shared jwt package for backward compatibility.
const (
	AuthCodeMissingToken     = jwt.CodeMissingToken
	AuthCodeInvalidToken     = jwt.CodeInvalidToken
	AuthCodeExpiredToken     = jwt.CodeExpiredToken
	AuthCodeInvalidIssuer    = jwt.CodeInvalidIssuer
	AuthCodeInvalidAudience  = jwt.CodeInvalidAudience
	AuthCodeMissingClaim     = jwt.CodeMissingClaim
	AuthCodeKeyNotFound      = jwt.CodeKeyNotFound
	AuthCodeSignatureInvalid = jwt.CodeSignatureInvalid
)

// AuthError represents an authentication or authorization failure.
// This is a type alias for the shared jwt.Error for backward compatibility.
type AuthError = jwt.Error
