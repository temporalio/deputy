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
