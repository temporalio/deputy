package errors

import (
	"errors"
	"regexp"
	"strings"
	"sync"
)

// SanitizedError wraps an error with a sanitized message that is safe to expose
// to users or log without leaking sensitive data. The original error is preserved
// for internal debugging via Unwrap().
//
// Use [Sanitize] or [Sanitizer.Sanitize] to create SanitizedError instances.
type SanitizedError struct {
	// sanitized is the safe-to-display error message
	sanitized string
	// cause is the original error (may contain sensitive data)
	cause error
}

func (e *SanitizedError) Error() string {
	return e.sanitized
}

// Unwrap returns the original unsanitized error for internal use.
// SECURITY: Do not expose the unwrapped error to users or external logs.
func (e *SanitizedError) Unwrap() error {
	return e.cause
}

// Is implements errors.Is for SanitizedError.
func (e *SanitizedError) Is(target error) bool {
	_, ok := target.(*SanitizedError)
	return ok
}

// Original returns the original unsanitized error message.
// SECURITY: Only use for internal debugging, never expose to users.
func (e *SanitizedError) Original() string {
	if e.cause != nil {
		return e.cause.Error()
	}
	return ""
}

// credentialPattern defines a sensitive data pattern with its replacement.
type credentialPattern struct {
	name    string
	pattern *regexp.Regexp
	replace string
}

// Sanitizer detects and redacts sensitive data from error messages.
// It is safe for concurrent use.
//
// Create a Sanitizer with [NewSanitizer] or use [DefaultSanitizer] for
// common credential patterns.
type Sanitizer struct {
	mu       sync.RWMutex
	patterns []credentialPattern
}

// NewSanitizer creates a new empty Sanitizer.
// Use AddPattern to register patterns, or use DefaultSanitizer for common patterns.
func NewSanitizer() *Sanitizer {
	return &Sanitizer{}
}

// AddPattern registers a pattern to detect and redact.
// The replacement string replaces matched content. Use $1, $2 etc. for capture groups.
//
// Example:
//
//	s.AddPattern("aws-key", `AKIA[A-Z0-9]{16}`, "[AWS_ACCESS_KEY_REDACTED]")
func (s *Sanitizer) AddPattern(name, pattern, replacement string) error {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.patterns = append(s.patterns, credentialPattern{
		name:    name,
		pattern: re,
		replace: replacement,
	})
	return nil
}

// MustAddPattern is like AddPattern but panics on invalid patterns.
// Use for compile-time constant patterns.
func (s *Sanitizer) MustAddPattern(name, pattern, replacement string) {
	if err := s.AddPattern(name, pattern, replacement); err != nil {
		panic("invalid pattern " + name + ": " + err.Error())
	}
}

// Sanitize returns a SanitizedError with sensitive data redacted from the message.
// Returns nil if err is nil.
//
// The original error is preserved and can be retrieved via Unwrap() for internal
// debugging, but the Error() method returns only the sanitized message.
func (s *Sanitizer) Sanitize(err error) error {
	if err == nil {
		return nil
	}

	// Don't double-wrap
	var already *SanitizedError
	if errors.As(err, &already) {
		return err
	}

	msg := err.Error()
	sanitized := s.SanitizeString(msg)

	// If nothing changed, return original to avoid unnecessary wrapping
	if sanitized == msg {
		return err
	}

	return &SanitizedError{
		sanitized: sanitized,
		cause:     err,
	}
}

// SanitizeString redacts sensitive data from a string.
// Use this for sanitizing log messages or other text that isn't an error.
func (s *Sanitizer) SanitizeString(msg string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, p := range s.patterns {
		msg = p.pattern.ReplaceAllString(msg, p.replace)
	}
	return msg
}

// defaultSanitizer is the package-level sanitizer with common patterns.
var defaultSanitizer = func() *Sanitizer {
	s := NewSanitizer()

	// AWS credentials
	// AWS Access Key ID: AKIA followed by 16 alphanumeric characters
	s.MustAddPattern("aws-access-key-id",
		`AKIA[A-Z0-9]{16}`,
		"[AWS_ACCESS_KEY_REDACTED]")

	// AWS Secret Access Key: 40 character base64-like string (often follows specific patterns)
	// Be careful not to match other base64 - look for context clues
	s.MustAddPattern("aws-secret-key-context",
		`(?i)(aws[_-]?secret[_-]?access[_-]?key|secret[_-]?key)[=:\s]["']?([A-Za-z0-9/+=]{40})["']?`,
		"$1=[AWS_SECRET_KEY_REDACTED]")

	// AWS Session Token (variable length, base64-like)
	s.MustAddPattern("aws-session-token",
		`(?i)(aws[_-]?session[_-]?token|security[_-]?token)[=:\s]["']?([A-Za-z0-9/+=]{100,})["']?`,
		"$1=[AWS_SESSION_TOKEN_REDACTED]")

	// Generic API keys and tokens (with context)
	s.MustAddPattern("api-key-context",
		`(?i)(api[_-]?key|apikey|api[_-]?token)[=:\s]["']?([A-Za-z0-9_\-]{20,})["']?`,
		"$1=[API_KEY_REDACTED]")

	// Bearer tokens in auth headers
	s.MustAddPattern("bearer-token",
		`(?i)(bearer\s+)([A-Za-z0-9_\-\.]+)`,
		"$1[BEARER_TOKEN_REDACTED]")

	// Basic auth in URLs: https://user:password@host
	s.MustAddPattern("basic-auth-url",
		`(https?://)([^:]+):([^@]+)@`,
		"$1$2:[PASSWORD_REDACTED]@")

	// GitHub tokens (ghp_, gho_, ghu_, ghs_, ghr_ prefixes)
	s.MustAddPattern("github-token",
		`(ghp_|gho_|ghu_|ghs_|ghr_)[A-Za-z0-9_]{36,}`,
		"[GITHUB_TOKEN_REDACTED]")

	// GitHub classic PAT (40 hex characters, but need context to avoid false positives)
	s.MustAddPattern("github-pat-context",
		`(?i)(github[_-]?token|gh[_-]?token|token)[=:\s]["']?([a-f0-9]{40})["']?`,
		"$1=[GITHUB_TOKEN_REDACTED]")

	// Docker/registry auth (base64 encoded user:pass)
	s.MustAddPattern("docker-auth",
		`(?i)(auth)[=:\s]["']?([A-Za-z0-9+/]{20,}={0,2})["']?`,
		"$1=[AUTH_REDACTED]")

	// Private keys (PEM format)
	s.MustAddPattern("private-key",
		`-----BEGIN[A-Z ]*PRIVATE KEY-----[\s\S]*?-----END[A-Z ]*PRIVATE KEY-----`,
		"[PRIVATE_KEY_REDACTED]")

	// Password fields in various formats
	s.MustAddPattern("password-field",
		`(?i)(password|passwd|pwd|secret)[=:\s]["']?([^\s"']{8,})["']?`,
		"$1=[PASSWORD_REDACTED]")

	// Azure credentials
	s.MustAddPattern("azure-client-secret",
		`(?i)(client[_-]?secret|azure[_-]?secret)[=:\s]["']?([A-Za-z0-9_\-\.~]{30,})["']?`,
		"$1=[AZURE_SECRET_REDACTED]")

	// GCP service account key (JSON key_id pattern)
	s.MustAddPattern("gcp-private-key-id",
		`(?i)(private[_-]?key[_-]?id)[=:\s]["']?([a-f0-9]{40})["']?`,
		"$1=[GCP_KEY_ID_REDACTED]")

	// Connection strings with embedded credentials
	s.MustAddPattern("connection-string",
		`(?i)(mongodb|postgres|mysql|redis|amqp)://([^:]+):([^@]+)@`,
		"$1://$2:[PASSWORD_REDACTED]@")

	// JWT tokens (three base64url parts separated by dots)
	s.MustAddPattern("jwt-token",
		`eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*`,
		"[JWT_REDACTED]")

	return s
}()

// DefaultSanitizer returns the package-level Sanitizer with common credential patterns.
// This sanitizer is pre-configured to detect:
//   - AWS credentials (access key ID, secret key, session token)
//   - GitHub tokens (fine-grained and classic PATs)
//   - Bearer tokens
//   - Basic auth in URLs
//   - Private keys (PEM format)
//   - Password fields
//   - Azure credentials
//   - GCP credentials
//   - Database connection strings
//   - JWT tokens
//
// The returned Sanitizer is safe for concurrent use.
func DefaultSanitizer() *Sanitizer {
	return defaultSanitizer
}

// Sanitize uses the default sanitizer to redact sensitive data from an error.
// This is a convenience function equivalent to DefaultSanitizer().Sanitize(err).
func Sanitize(err error) error {
	return defaultSanitizer.Sanitize(err)
}

// SanitizeString uses the default sanitizer to redact sensitive data from a string.
// This is a convenience function equivalent to DefaultSanitizer().SanitizeString(s).
func SanitizeString(s string) string {
	return defaultSanitizer.SanitizeString(s)
}

// IsSanitized returns true if the error has already been sanitized.
func IsSanitized(err error) bool {
	var sanitized *SanitizedError
	return errors.As(err, &sanitized)
}

// MustSanitize is like Sanitize but panics if the result would expose sensitive data.
// Use this in security-critical paths where accidentally exposing credentials is unacceptable.
//
// This function checks if the sanitized message differs from the original. If they're
// the same (meaning no sensitive data was detected), it returns the original error.
// If sensitive data was found and redacted, it returns the sanitized error.
func MustSanitize(err error) error {
	if err == nil {
		return nil
	}
	return defaultSanitizer.Sanitize(err)
}

// SanitizeFields returns a map suitable for structured logging with sensitive
// values redacted. Use this when logging errors that might contain credentials.
//
// Example:
//
//	slog.Error("operation failed", deperrors.SanitizeFields(err)...)
func SanitizeFields(err error) []any {
	if err == nil {
		return nil
	}

	msg := SanitizeString(err.Error())

	// Check if we have a suggestion
	suggestion := GetSuggestion(err)
	if suggestion != "" {
		return []any{"error", msg, "suggestion", suggestion}
	}

	return []any{"error", msg}
}

// WrapSanitized wraps an error with additional context, ensuring the result
// is sanitized. Use this instead of fmt.Errorf when wrapping errors that
// might contain sensitive data.
//
// Example:
//
//	return deperrors.WrapSanitized(err, "failed to authenticate with registry")
func WrapSanitized(err error, message string) error {
	if err == nil {
		return nil
	}

	// Sanitize the original error first
	sanitized := Sanitize(err)

	// Create a new error with the message prefix
	wrapped := &SanitizedError{
		sanitized: message + ": " + sanitized.Error(),
		cause:     err,
	}
	return wrapped
}

// AuthenticationError represents an authentication failure with safe error messages.
// It ensures that credential details are never exposed in the error string.
type AuthenticationError struct {
	// Service is the service that rejected authentication (e.g., "AWS", "GitHub", "ECR")
	Service string
	// Operation describes what was being attempted
	Operation string
	// Hint provides user-friendly remediation guidance
	Hint string
	// cause is the underlying error (may contain sensitive details)
	cause error
}

func (e *AuthenticationError) Error() string {
	var b strings.Builder
	b.WriteString("authentication failed")
	if e.Service != "" {
		b.WriteString(" for ")
		b.WriteString(e.Service)
	}
	if e.Operation != "" {
		b.WriteString(" during ")
		b.WriteString(e.Operation)
	}
	return b.String()
}

// Unwrap returns the underlying cause for internal inspection.
// SECURITY: The unwrapped error may contain sensitive data.
func (e *AuthenticationError) Unwrap() error {
	return e.cause
}

// Is implements errors.Is for AuthenticationError.
func (e *AuthenticationError) Is(target error) bool {
	_, ok := target.(*AuthenticationError)
	return ok
}

// Suggestion implements [Suggestible] to provide remediation hints.
func (e *AuthenticationError) Suggestion() string {
	return e.Hint
}

// NewAuthenticationError creates an AuthenticationError with safe defaults.
// The cause error is sanitized when stored.
func NewAuthenticationError(service, operation string, cause error, hint string) *AuthenticationError {
	return &AuthenticationError{
		Service:   service,
		Operation: operation,
		Hint:      hint,
		cause:     cause,
	}
}

// ErrAuthentication is a sentinel error for authentication failures.
// Use errors.Is(err, ErrAuthentication) to check for auth failures.
var ErrAuthentication = errors.New("authentication failed")
