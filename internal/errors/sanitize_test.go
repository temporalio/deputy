package errors

import (
	"errors"
	"fmt"
	"testing"
)

func TestSanitizer_AWSCredentials(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		contains string // what the output should NOT contain
		redacted string // what it should contain instead
	}{
		{
			name:     "AWS access key ID",
			input:    "failed to auth with AKIAIOSFODNN7EXAMPLE",
			contains: "AKIAIOSFODNN7EXAMPLE",
			redacted: "[AWS_ACCESS_KEY_REDACTED]",
		},
		{
			name:     "AWS secret key with context",
			input:    "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			contains: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			redacted: "[AWS_SECRET_KEY_REDACTED]",
		},
		{
			name:     "AWS session token",
			input:    "aws_session_token=" + "AQoDYXdzEJr" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			contains: "AQoDYXdzEJr",
			redacted: "[AWS_SESSION_TOKEN_REDACTED]",
		},
	}

	s := DefaultSanitizer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := s.SanitizeString(tt.input)
			if result == tt.input {
				t.Errorf("SanitizeString did not modify input")
			}
			if tt.contains != "" && containsString(result, tt.contains) {
				t.Errorf("SanitizeString output still contains sensitive data: %q", tt.contains)
			}
			if tt.redacted != "" && !containsString(result, tt.redacted) {
				t.Errorf("SanitizeString output missing redaction marker %q, got: %q", tt.redacted, result)
			}
		})
	}
}

func TestSanitizer_GitHubTokens(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "fine-grained PAT ghp_",
			input:    "token: ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1234",
			contains: "ghp_",
		},
		{
			name:     "OAuth token gho_",
			input:    "auth failed: gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx5678",
			contains: "gho_",
		},
		{
			name:     "classic PAT with context",
			input:    "GITHUB_TOKEN=a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			contains: "a1b2c3d4",
		},
	}

	s := DefaultSanitizer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := s.SanitizeString(tt.input)
			if containsString(result, tt.contains) {
				t.Errorf("SanitizeString output still contains: %q\nGot: %q", tt.contains, result)
			}
		})
	}
}

func TestSanitizer_URLs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		contains string
	}{
		{
			name:     "basic auth in HTTPS URL",
			input:    "connecting to https://user:supersecret@registry.example.com/v2/",
			contains: "supersecret",
		},
		{
			name:     "basic auth in HTTP URL",
			input:    "failed: http://admin:password123@internal.corp:8080/api",
			contains: "password123",
		},
		{
			name:     "mongodb connection string",
			input:    "mongodb://dbuser:dbpassword@cluster.mongodb.net/db",
			contains: "dbpassword",
		},
		{
			name:     "postgres connection string",
			input:    "postgres://postgres:secretpw@localhost:5432/mydb",
			contains: "secretpw",
		},
	}

	s := DefaultSanitizer()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := s.SanitizeString(tt.input)
			if containsString(result, tt.contains) {
				t.Errorf("SanitizeString output still contains: %q\nGot: %q", tt.contains, result)
			}
		})
	}
}

func TestSanitizer_PrivateKeys(t *testing.T) {
	t.Parallel()

	privateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
...key content...
-----END RSA PRIVATE KEY-----`

	s := DefaultSanitizer()
	result := s.SanitizeString("Error loading key: " + privateKey)

	if containsString(result, "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn") {
		t.Errorf("Private key content not redacted")
	}
	if !containsString(result, "[PRIVATE_KEY_REDACTED]") {
		t.Errorf("Missing redaction marker for private key")
	}
}

func TestSanitizer_JWT(t *testing.T) {
	t.Parallel()

	// Example JWT (expired, not a real secret)
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"

	s := DefaultSanitizer()
	result := s.SanitizeString("auth header: Bearer " + jwt)

	if containsString(result, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9") {
		t.Errorf("JWT not redacted")
	}
}

func TestSanitize_Error(t *testing.T) {
	t.Parallel()

	originalErr := fmt.Errorf("AWS error: AccessDenied with key AKIAIOSFODNN7EXAMPLE")
	sanitized := Sanitize(originalErr)

	// Check that Error() is sanitized
	if containsString(sanitized.Error(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Sanitized error still contains sensitive data: %q", sanitized.Error())
	}

	// Check that Unwrap() preserves the original
	unwrapped := errors.Unwrap(sanitized)
	if unwrapped == nil {
		t.Fatal("Unwrap returned nil")
	}
	if !containsString(unwrapped.Error(), "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Unwrapped error should contain original data")
	}
}

func TestSanitize_NilError(t *testing.T) {
	t.Parallel()

	result := Sanitize(nil)
	if result != nil {
		t.Errorf("Sanitize(nil) = %v, want nil", result)
	}
}

func TestSanitize_NoSensitiveData(t *testing.T) {
	t.Parallel()

	originalErr := errors.New("simple error with no credentials")
	result := Sanitize(originalErr)

	// Should return original error unchanged (not wrapped)
	if result != originalErr {
		t.Errorf("Sanitize should return original error when no sensitive data found")
	}
}

func TestSanitize_DoesNotDoubleWrap(t *testing.T) {
	t.Parallel()

	originalErr := fmt.Errorf("error with AKIAIOSFODNN7EXAMPLE")
	firstSanitize := Sanitize(originalErr)
	secondSanitize := Sanitize(firstSanitize)

	// Should be the same object
	if firstSanitize != secondSanitize {
		t.Errorf("Sanitize double-wrapped an already sanitized error")
	}
}

func TestSanitizedError_Is(t *testing.T) {
	t.Parallel()

	originalErr := fmt.Errorf("error with AKIAIOSFODNN7EXAMPLE")
	sanitized := Sanitize(originalErr)

	// Check Is() works
	var target *SanitizedError
	if !errors.As(sanitized, &target) {
		t.Error("errors.As should match SanitizedError")
	}
}

func TestSanitizedError_Original(t *testing.T) {
	t.Parallel()

	originalErr := fmt.Errorf("secret: AKIAIOSFODNN7EXAMPLE")
	sanitized := Sanitize(originalErr)

	se, ok := sanitized.(*SanitizedError)
	if !ok {
		t.Fatal("Expected SanitizedError type")
	}

	original := se.Original()
	if !containsString(original, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("Original() should return unsanitized message")
	}
}

func TestIsSanitized(t *testing.T) {
	t.Parallel()

	regularErr := errors.New("regular error")
	sanitizedErr := Sanitize(fmt.Errorf("key: AKIAIOSFODNN7EXAMPLE"))

	if IsSanitized(regularErr) {
		t.Error("IsSanitized should return false for regular errors")
	}
	if !IsSanitized(sanitizedErr) {
		t.Error("IsSanitized should return true for sanitized errors")
	}
}

func TestWrapSanitized(t *testing.T) {
	t.Parallel()

	originalErr := fmt.Errorf("connection failed: password=secret123")
	wrapped := WrapSanitized(originalErr, "registry authentication failed")

	// Error message should be sanitized and have prefix
	msg := wrapped.Error()
	if containsString(msg, "secret123") {
		t.Errorf("WrapSanitized should sanitize credentials: %q", msg)
	}
	if !containsString(msg, "registry authentication failed") {
		t.Errorf("WrapSanitized should include message prefix: %q", msg)
	}
}

func TestWrapSanitized_NilError(t *testing.T) {
	t.Parallel()

	result := WrapSanitized(nil, "some context")
	if result != nil {
		t.Errorf("WrapSanitized(nil) = %v, want nil", result)
	}
}

func TestSanitizeFields(t *testing.T) {
	t.Parallel()

	err := fmt.Errorf("auth failed: api_key=sk-1234567890abcdef1234")
	fields := SanitizeFields(err)

	if len(fields) < 2 {
		t.Fatalf("Expected at least 2 fields, got %d", len(fields))
	}

	// First field should be "error"
	if fields[0] != "error" {
		t.Errorf("First field should be 'error', got %v", fields[0])
	}

	// Second field should be sanitized message
	msg, ok := fields[1].(string)
	if !ok {
		t.Fatalf("Second field should be string, got %T", fields[1])
	}
	if containsString(msg, "sk-1234567890abcdef1234") {
		t.Errorf("SanitizeFields should sanitize error message: %q", msg)
	}
}

func TestAuthenticationError(t *testing.T) {
	t.Parallel()

	cause := fmt.Errorf("AWS returned: InvalidAccessKeyId - Key AKIAIOSFODNN7EXAMPLE not found")
	authErr := NewAuthenticationError("AWS ECR", "GetAuthorizationToken", cause, "run 'aws configure' to set credentials")

	// Error() should not contain sensitive data
	msg := authErr.Error()
	if containsString(msg, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("AuthenticationError.Error() should not expose credentials: %q", msg)
	}
	if !containsString(msg, "AWS ECR") {
		t.Errorf("AuthenticationError.Error() should include service: %q", msg)
	}

	// Unwrap should give us the cause
	unwrapped := errors.Unwrap(authErr)
	if unwrapped == nil {
		t.Error("Unwrap should return cause")
	}

	// Suggestion should work
	suggestion := authErr.Suggestion()
	if suggestion != "run 'aws configure' to set credentials" {
		t.Errorf("Unexpected suggestion: %q", suggestion)
	}

	// errors.Is should work
	if !errors.Is(authErr, &AuthenticationError{}) {
		t.Error("errors.Is should match AuthenticationError")
	}
}

func TestCustomSanitizer(t *testing.T) {
	t.Parallel()

	s := NewSanitizer()
	err := s.AddPattern("custom-secret", `SECRET_[A-Z0-9]{10}`, "[CUSTOM_REDACTED]")
	if err != nil {
		t.Fatalf("AddPattern failed: %v", err)
	}

	input := "error: SECRET_ABC1234567 not found"
	result := s.SanitizeString(input)

	if containsString(result, "SECRET_ABC1234567") {
		t.Errorf("Custom pattern not applied: %q", result)
	}
	if !containsString(result, "[CUSTOM_REDACTED]") {
		t.Errorf("Custom replacement not found: %q", result)
	}
}

func TestSanitizer_InvalidPattern(t *testing.T) {
	t.Parallel()

	s := NewSanitizer()
	err := s.AddPattern("invalid", `[invalid(`, "replacement")
	if err == nil {
		t.Error("AddPattern should fail for invalid regex")
	}
}

func TestMustAddPattern_Panics(t *testing.T) {
	t.Parallel()

	s := NewSanitizer()

	defer func() {
		if r := recover(); r == nil {
			t.Error("MustAddPattern should panic on invalid pattern")
		}
	}()

	s.MustAddPattern("invalid", `[invalid(`, "replacement")
}

// containsString is a simple helper to check substring presence
func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && searchString(s, substr)))
}

func searchString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
