package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestPolicyError(t *testing.T) {
	base := fmt.Errorf("CEL compilation failed")
	policyErr := &PolicyError{
		PolicyName: "test-policy",
		Source:     "policy.yaml",
		Line:       42,
		Cause:      base,
	}

	// Test Error() formatting
	msg := policyErr.Error()
	if msg != `policy "test-policy" at policy.yaml:42: CEL compilation failed` {
		t.Errorf("unexpected error message: %s", msg)
	}

	// Test Unwrap
	if errors.Unwrap(policyErr) != base {
		t.Error("Unwrap should return base error")
	}

	// Test Is
	if !errors.Is(policyErr, policyErr) {
		t.Error("errors.Is should match same type")
	}
}

func TestValidationError(t *testing.T) {
	valErr := &ValidationError{
		Field:   "ecosystems",
		Value:   []string{"invalid"},
		Message: "unsupported ecosystem",
	}

	if !errors.Is(valErr, valErr) {
		t.Error("errors.Is should match ValidationError")
	}
}

func TestPluginError(t *testing.T) {
	tests := []struct {
		name     string
		failures []PluginFailure
		wantMsg  string
	}{
		{
			name: "single failure",
			failures: []PluginFailure{
				{Name: "npm", Reason: "parse error", Err: fmt.Errorf("invalid JSON")},
			},
			wantMsg: "plugin npm failed: parse error: invalid JSON",
		},
		{
			name: "multiple failures",
			failures: []PluginFailure{
				{Name: "npm", Reason: "parse error"},
				{Name: "go", Reason: "missing go.mod"},
			},
			wantMsg: "2 plugin failures: npm: parse error; go: missing go.mod",
		},
		{
			name:     "empty failures",
			failures: []PluginFailure{},
			wantMsg:  "plugin failures occurred",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &PluginError{Failures: tt.failures}
			if err.Error() != tt.wantMsg {
				t.Errorf("got %q, want %q", err.Error(), tt.wantMsg)
			}
		})
	}
}

func TestNetworkError(t *testing.T) {
	base := fmt.Errorf("connection timeout")
	netErr := &NetworkError{
		Operation: "GET",
		URL:       "https://api.osv.dev",
		Attempt:   2,
		Cause:     base,
	}

	// Test Is with sentinel error
	if !errors.Is(netErr, ErrNetwork) {
		t.Error("NetworkError should match ErrNetwork sentinel")
	}

	// Test Unwrap
	if errors.Unwrap(netErr) != base {
		t.Error("Unwrap should return base error")
	}
}

func TestConfigError(t *testing.T) {
	configErr := &ConfigError{
		Path:    "config.yaml",
		Field:   "listeners[0].bind",
		Message: "invalid address format",
	}

	if !errors.Is(configErr, ErrConfiguration) {
		t.Error("ConfigError should match ErrConfiguration sentinel")
	}
}

func TestScanError(t *testing.T) {
	scanErr := &ScanError{
		Target:  "/path/to/repo",
		Phase:   "inventory",
		Message: "no manifest files found",
		Cause:   ErrNotFound,
	}

	// Test error chain
	if !errors.Is(scanErr, ErrNotFound) {
		t.Error("should unwrap to ErrNotFound")
	}
}

func TestErrorWrapping(t *testing.T) {
	// Test that our custom errors work with standard error wrapping
	baseErr := fmt.Errorf("base error")
	policyErr := &PolicyError{
		PolicyName: "test",
		Source:     "test.yaml",
		Cause:      baseErr,
	}

	wrapped := fmt.Errorf("failed to evaluate: %w", policyErr)

	// Should be able to unwrap through multiple layers
	if !errors.Is(wrapped, baseErr) {
		t.Error("should unwrap through custom error to base")
	}

	// Should be able to extract our custom error type
	var pe *PolicyError
	if !errors.As(wrapped, &pe) {
		t.Error("errors.As should extract PolicyError")
	}
	if pe.PolicyName != "test" {
		t.Errorf("got PolicyName %q, want %q", pe.PolicyName, "test")
	}
}
