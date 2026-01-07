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

func TestSuggest(t *testing.T) {
	baseErr := fmt.Errorf("file not found")
	suggestion := "Check if the file exists and you have read permissions"

	// Test wrapping with suggestion
	suggested := Suggest(baseErr, suggestion)
	if suggested == nil {
		t.Fatal("Suggest should not return nil for non-nil error")
	}

	// Test error message is preserved
	if suggested.Error() != baseErr.Error() {
		t.Errorf("Error() = %q, want %q", suggested.Error(), baseErr.Error())
	}

	// Test suggestion is retrievable
	got := GetSuggestion(suggested)
	if got != suggestion {
		t.Errorf("GetSuggestion() = %q, want %q", got, suggestion)
	}

	// Test Suggestible interface
	var s Suggestible
	if !errors.As(suggested, &s) {
		t.Error("suggested error should implement Suggestible")
	}
	if s.Suggestion() != suggestion {
		t.Errorf("Suggestion() = %q, want %q", s.Suggestion(), suggestion)
	}
}

func TestSuggestNil(t *testing.T) {
	suggested := Suggest(nil, "some suggestion")
	if suggested != nil {
		t.Error("Suggest(nil, ...) should return nil")
	}
}

func TestGetSuggestionNoSuggestion(t *testing.T) {
	baseErr := fmt.Errorf("plain error")
	got := GetSuggestion(baseErr)
	if got != "" {
		t.Errorf("GetSuggestion for plain error = %q, want empty", got)
	}
}

func TestGetSuggestionWrapped(t *testing.T) {
	baseErr := fmt.Errorf("file not found")
	suggested := Suggest(baseErr, "Check the path")
	wrapped := fmt.Errorf("operation failed: %w", suggested)

	// Should find suggestion through wrapping
	got := GetSuggestion(wrapped)
	if got != "Check the path" {
		t.Errorf("GetSuggestion through wrapping = %q, want %q", got, "Check the path")
	}
}

func TestTargetError(t *testing.T) {
	targetErr := NewTargetError(
		"nginx:latest",
		"failed to resolve image",
		fmt.Errorf("network timeout"),
		"Check your network connection or try a different registry",
	)

	// Test error message
	wantMsg := `target "nginx:latest": failed to resolve image: network timeout`
	if targetErr.Error() != wantMsg {
		t.Errorf("Error() = %q, want %q", targetErr.Error(), wantMsg)
	}

	// Test suggestion
	got := targetErr.Suggestion()
	if got != "Check your network connection or try a different registry" {
		t.Errorf("Suggestion() = %q", got)
	}

	// Test Suggestible interface
	var s Suggestible
	if !errors.As(targetErr, &s) {
		t.Error("TargetError should implement Suggestible")
	}

	// Test GetSuggestion works
	gotSuggestion := GetSuggestion(targetErr)
	if gotSuggestion != targetErr.Suggestion() {
		t.Errorf("GetSuggestion() = %q, want %q", gotSuggestion, targetErr.Suggestion())
	}
}

func TestTargetErrorNoCause(t *testing.T) {
	targetErr := NewTargetError("./myapp", "not a valid target", nil, "")

	wantMsg := `target "./myapp": not a valid target`
	if targetErr.Error() != wantMsg {
		t.Errorf("Error() = %q, want %q", targetErr.Error(), wantMsg)
	}
}

func TestSuggestFor(t *testing.T) {
	tests := []struct {
		category string
		wantNot  string
	}{
		{"network", ""},
		{"auth", ""},
		{"not found", ""},
		{"unknown category", ""},
	}

	for _, tt := range tests {
		got := SuggestFor(tt.category)
		if tt.category == "unknown category" {
			if got != "" {
				t.Errorf("SuggestFor(%q) = %q, want empty", tt.category, got)
			}
		} else {
			if got == "" {
				t.Errorf("SuggestFor(%q) returned empty, want suggestion", tt.category)
			}
		}
	}
}

func TestCommonSuggestions(t *testing.T) {
	// Verify common suggestions are populated
	if len(CommonSuggestions) == 0 {
		t.Error("CommonSuggestions should not be empty")
	}

	// Verify expected categories exist
	expectedCategories := []string{"network", "auth", "rate limit", "not found", "permission denied"}
	for _, cat := range expectedCategories {
		if _, ok := CommonSuggestions[cat]; !ok {
			t.Errorf("CommonSuggestions missing category %q", cat)
		}
	}
}

func TestExitError(t *testing.T) {
	t.Run("with cause", func(t *testing.T) {
		cause := fmt.Errorf("command failed")
		exitErr := &ExitError{Code: 1, Cause: cause}

		if exitErr.Error() != "command failed" {
			t.Errorf("Error() = %q, want %q", exitErr.Error(), "command failed")
		}

		if errors.Unwrap(exitErr) != cause {
			t.Error("Unwrap should return cause")
		}
	})

	t.Run("without cause", func(t *testing.T) {
		exitErr := &ExitError{Code: 130, Cause: nil}

		if exitErr.Error() != "exit code 130" {
			t.Errorf("Error() = %q, want %q", exitErr.Error(), "exit code 130")
		}
	})
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{"nil error", nil, 0},
		{"plain error", fmt.Errorf("fail"), 1},
		{"ExitError code 0", &ExitError{Code: 0}, 0},
		{"ExitError code 1", &ExitError{Code: 1}, 1},
		{"ExitError code 130", &ExitError{Code: 130}, 130},
		{"wrapped ExitError", fmt.Errorf("wrapped: %w", &ExitError{Code: 42}), 42},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExitCode(tt.err)
			if got != tt.wantCode {
				t.Errorf("ExitCode() = %d, want %d", got, tt.wantCode)
			}
		})
	}
}

func TestWithExitCode(t *testing.T) {
	t.Run("nil error with zero code", func(t *testing.T) {
		err := WithExitCode(nil, 0)
		if err != nil {
			t.Errorf("WithExitCode(nil, 0) = %v, want nil", err)
		}
	})

	t.Run("nil error with non-zero code", func(t *testing.T) {
		err := WithExitCode(nil, 1)
		if err == nil {
			t.Error("WithExitCode(nil, 1) should not be nil")
		}
		if ExitCode(err) != 1 {
			t.Errorf("ExitCode() = %d, want 1", ExitCode(err))
		}
	})

	t.Run("error with code", func(t *testing.T) {
		cause := fmt.Errorf("partial failure")
		err := WithExitCode(cause, 2)

		if ExitCode(err) != 2 {
			t.Errorf("ExitCode() = %d, want 2", ExitCode(err))
		}

		// Should be able to unwrap to cause
		if !errors.Is(err, cause) {
			t.Error("should unwrap to cause")
		}
	})
}
