// Package errors provides domain-specific error types for Deputy.
// These errors enable robust error handling using errors.Is and errors.As,
// allowing callers to distinguish between different failure modes and handle
// them appropriately.
package errors

import (
	"errors"
	"fmt"
	"strings"
)

// Sentinel errors for common failure modes
var (
	// ErrNotFound indicates a requested resource does not exist.
	ErrNotFound = errors.New("not found")

	// ErrInvalidInput indicates user input failed validation.
	ErrInvalidInput = errors.New("invalid input")

	// ErrNetwork indicates a network operation failed.
	ErrNetwork = errors.New("network error")

	// ErrConfiguration indicates invalid or missing configuration.
	ErrConfiguration = errors.New("configuration error")

	// ErrPermission indicates insufficient permissions.
	ErrPermission = errors.New("permission denied")
)

// SilentError indicates an error that should cause a non-zero exit but should
// not be printed by the CLI framework (because the command already explained it).
type SilentError struct {
	Cause error
}

func (e *SilentError) Error() string {
	if e == nil || e.Cause == nil {
		return ""
	}
	return e.Cause.Error()
}

func (e *SilentError) Unwrap() error { return e.Cause }

// Silent wraps err so the CLI framework can suppress printing while still
// returning a non-zero exit status.
func Silent(err error) error {
	if err == nil {
		return nil
	}
	return &SilentError{Cause: err}
}

// ExitError carries a specific exit code for the CLI to use.
// This allows commands to signal different exit codes (e.g., 130 for SIGINT,
// or custom codes for partial success/failure scenarios).
type ExitError struct {
	Code  int   // Exit code to use (0 = success, 1 = error, 130 = interrupted, etc.)
	Cause error // Underlying error (may be nil for non-error exit codes)
}

func (e *ExitError) Error() string {
	if e == nil || e.Cause == nil {
		return fmt.Sprintf("exit code %d", e.Code)
	}
	return e.Cause.Error()
}

func (e *ExitError) Unwrap() error { return e.Cause }

// ExitCode returns the exit code from an error chain if present.
// Returns 1 if error is non-nil but has no ExitError, or 0 if error is nil.
func ExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *ExitError
	if errors.As(err, &exitErr) {
		return exitErr.Code
	}
	return 1
}

// WithExitCode wraps an error with a specific exit code.
// Returns nil if both err is nil and code is 0.
func WithExitCode(err error, code int) error {
	if err == nil && code == 0 {
		return nil
	}
	return &ExitError{Code: code, Cause: err}
}

// PolicyError represents a policy evaluation or compilation failure.
type PolicyError struct {
	PolicyName string
	Source     string
	Line       int
	Cause      error
}

func (e *PolicyError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("policy %q at %s:%d: %v", e.PolicyName, e.Source, e.Line, e.Cause)
	}
	if e.Source != "" {
		return fmt.Sprintf("policy %q at %s: %v", e.PolicyName, e.Source, e.Cause)
	}
	return fmt.Sprintf("policy %q: %v", e.PolicyName, e.Cause)
}

func (e *PolicyError) Unwrap() error { return e.Cause }

func (e *PolicyError) Is(target error) bool {
	_, ok := target.(*PolicyError)
	return ok
}

// ValidationError represents input validation failures with detailed field information.
type ValidationError struct {
	Field   string
	Value   any
	Message string
	Cause   error
}

func (e *ValidationError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("validation failed for %s: %s: %v", e.Field, e.Message, e.Cause)
	}
	return fmt.Sprintf("validation failed for %s: %s", e.Field, e.Message)
}

func (e *ValidationError) Unwrap() error { return e.Cause }

func (e *ValidationError) Is(target error) bool {
	_, ok := target.(*ValidationError)
	return ok || errors.Is(e.Cause, target)
}

// PluginFailure represents a single plugin failure with context.
type PluginFailure struct {
	Name   string
	Reason string
	Err    error
}

// PluginError represents one or more plugin failures during scanning.
type PluginError struct {
	Failures []PluginFailure
}

func (e *PluginError) Error() string {
	if len(e.Failures) == 0 {
		return "plugin failures occurred"
	}
	if len(e.Failures) == 1 {
		f := e.Failures[0]
		if f.Err != nil {
			return fmt.Sprintf("plugin %s failed: %s: %v", f.Name, f.Reason, f.Err)
		}
		return fmt.Sprintf("plugin %s failed: %s", f.Name, f.Reason)
	}
	parts := make([]string, len(e.Failures))
	for i, f := range e.Failures {
		if f.Err != nil {
			parts[i] = fmt.Sprintf("%s: %s: %v", f.Name, f.Reason, f.Err)
		} else {
			parts[i] = fmt.Sprintf("%s: %s", f.Name, f.Reason)
		}
	}
	return fmt.Sprintf("%d plugin failures: %s", len(e.Failures), strings.Join(parts, "; "))
}

func (e *PluginError) Is(target error) bool {
	_, ok := target.(*PluginError)
	return ok
}

// Unwrap returns the first plugin error for compatibility with errors.Unwrap.
func (e *PluginError) Unwrap() error {
	if len(e.Failures) > 0 && e.Failures[0].Err != nil {
		return e.Failures[0].Err
	}
	return nil
}

// NetworkError represents network operation failures with retry context.
type NetworkError struct {
	Operation string
	URL       string
	Attempt   int
	Cause     error
}

func (e *NetworkError) Error() string {
	if e.Attempt > 1 {
		return fmt.Sprintf("%s failed for %s (attempt %d): %v", e.Operation, e.URL, e.Attempt, e.Cause)
	}
	return fmt.Sprintf("%s failed for %s: %v", e.Operation, e.URL, e.Cause)
}

func (e *NetworkError) Unwrap() error { return e.Cause }

func (e *NetworkError) Is(target error) bool {
	if errors.Is(target, ErrNetwork) {
		return true
	}
	_, ok := target.(*NetworkError)
	return ok
}

func (e *NetworkError) Temporary() bool {
	// Check if the underlying error is temporary
	type temporary interface {
		Temporary() bool
	}
	if t, ok := e.Cause.(temporary); ok {
		return t.Temporary()
	}
	return false
}

// ConfigError represents configuration-related failures.
type ConfigError struct {
	Path    string
	Field   string
	Message string
	Cause   error
}

func (e *ConfigError) Error() string {
	if e.Field != "" {
		return fmt.Sprintf("config error in %s at %s: %s", e.Path, e.Field, e.Message)
	}
	return fmt.Sprintf("config error in %s: %s", e.Path, e.Message)
}

func (e *ConfigError) Unwrap() error { return e.Cause }

func (e *ConfigError) Is(target error) bool {
	if errors.Is(target, ErrConfiguration) {
		return true
	}
	_, ok := target.(*ConfigError)
	return ok
}

// ScanError represents failures during dependency scanning.
type ScanError struct {
	Target  string
	Phase   string // "inventory", "query", "analysis"
	Message string
	Cause   error
}

func (e *ScanError) Error() string {
	return fmt.Sprintf("scan failed for %s during %s: %s: %v", e.Target, e.Phase, e.Message, e.Cause)
}

func (e *ScanError) Unwrap() error { return e.Cause }

func (e *ScanError) Is(target error) bool {
	_, ok := target.(*ScanError)
	return ok
}

// Suggestible is an interface for errors that can provide remediation suggestions.
type Suggestible interface {
	error
	Suggestion() string
}

// WithSuggestion wraps an error with a remediation suggestion.
// The suggestion appears in CLI output to help users resolve the issue.
type WithSuggestion struct {
	Err        error
	suggestion string
}

func (e *WithSuggestion) Error() string {
	return e.Err.Error()
}

func (e *WithSuggestion) Unwrap() error { return e.Err }

func (e *WithSuggestion) Suggestion() string {
	return e.suggestion
}

// Suggest wraps an error with a suggestion for how to fix it.
// Returns nil if err is nil.
func Suggest(err error, suggestion string) error {
	if err == nil {
		return nil
	}
	return &WithSuggestion{Err: err, suggestion: suggestion}
}

// GetSuggestion extracts a suggestion from an error chain.
// Returns empty string if no suggestion is found.
func GetSuggestion(err error) string {
	var s Suggestible
	if errors.As(err, &s) {
		return s.Suggestion()
	}
	return ""
}

// CommonSuggestions provides standard remediation suggestions for common errors.
var CommonSuggestions = map[string]string{
	"no go.mod":          "Run 'go mod init' to initialize a Go module in this directory",
	"no package.json":    "Run 'npm init' to create a package.json file",
	"network":            "Check your internet connection and try again. If behind a proxy, set HTTP_PROXY/HTTPS_PROXY",
	"auth":               "Check your credentials. For GitHub, ensure GITHUB_TOKEN is set correctly",
	"rate limit":         "Wait a few minutes or authenticate to increase rate limits",
	"not found":          "Verify the path or URL is correct and the resource exists",
	"permission denied":  "Check file permissions or run with appropriate privileges",
	"invalid format":     "Check the input format matches expected format (JSON, YAML, etc.)",
	"policy syntax":      "Run 'deputy policy lint' to validate your policy files",
	"no vulnerabilities": "No action needed - your dependencies appear secure",
}

// SuggestFor returns a standard suggestion for a given error category.
// Falls back to empty string if no match is found.
func SuggestFor(category string) string {
	return CommonSuggestions[category]
}

// TargetError represents failures related to target resolution (repos, images, etc.).
type TargetError struct {
	Target     string
	Message    string
	Cause      error
	suggestion string
}

func (e *TargetError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("target %q: %s: %v", e.Target, e.Message, e.Cause)
	}
	return fmt.Sprintf("target %q: %s", e.Target, e.Message)
}

func (e *TargetError) Unwrap() error { return e.Cause }

func (e *TargetError) Suggestion() string {
	return e.suggestion
}

func (e *TargetError) Is(target error) bool {
	_, ok := target.(*TargetError)
	return ok
}

// NewTargetError creates a TargetError with an optional suggestion.
func NewTargetError(target, message string, cause error, suggestion string) *TargetError {
	return &TargetError{
		Target:     target,
		Message:    message,
		Cause:      cause,
		suggestion: suggestion,
	}
}
