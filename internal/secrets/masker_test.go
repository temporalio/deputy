package secrets

import (
	"testing"
)

func TestMasker_Mask(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	masker := NewMasker(engine)

	input := `Here is my config:
token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789
database: postgres://localhost/mydb
`

	masked := masker.Mask(input)

	// Should not contain the original token
	if contains(masked, "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789") {
		t.Error("masked output should not contain the original token")
	}

	// Should contain redacted marker
	if !contains(masked, "[REDACTED:") {
		t.Error("masked output should contain redaction marker")
	}

	// Should preserve non-secret content
	if !contains(masked, "database: postgres://localhost/mydb") {
		t.Error("masked output should preserve non-secret content")
	}
}

func TestMasker_MaskKnown(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	masker := NewMasker(engine)

	// First, learn a secret
	input := "token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789"
	_ = masker.Mask(input)

	// Now mask known secrets in different text
	output := "The response contained ghp_ABCDEFghijklmnopqrstuvwxyz0123456789 in the body"
	masked := masker.MaskKnown(output)

	if contains(masked, "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789") {
		t.Error("MaskKnown should mask previously learned secrets")
	}
}

func TestMasker_AddSecret(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	masker := NewMasker(engine)

	// Manually add a secret
	masker.AddSecret("my-custom-secret-value", TypeGenericAPIKey)

	// Mask text containing that secret
	input := "The secret is my-custom-secret-value"
	masked := masker.MaskKnown(input)

	if contains(masked, "my-custom-secret-value") {
		t.Error("AddSecret should enable masking of custom secrets")
	}
}

func TestMasker_Stats(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	masker := NewMasker(engine)

	// Learn some secrets
	masker.AddSecret("secret1", TypeGitHubToken)
	masker.AddSecret("secret2", TypeGitHubToken)
	masker.AddSecret("secret3", TypeAWSAccessKey)

	stats := masker.Stats()

	if stats[TypeGitHubToken] != 2 {
		t.Errorf("expected 2 GitHub tokens, got %d", stats[TypeGitHubToken])
	}
	if stats[TypeAWSAccessKey] != 1 {
		t.Errorf("expected 1 AWS access key, got %d", stats[TypeAWSAccessKey])
	}
}

func TestMasker_Clear(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	masker := NewMasker(engine)

	// Add and then clear
	masker.AddSecret("secret1", TypeGitHubToken)
	masker.Clear()

	stats := masker.Stats()
	if len(stats) != 0 {
		t.Error("Clear should remove all secrets")
	}
}

func TestMasker_MaskAndLearn(t *testing.T) {
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	masker := NewMasker(engine)

	input := "token: ghp_ABCDEFghijklmnopqrstuvwxyz0123456789"
	masked, findings := masker.MaskAndLearn(input)

	// Should have findings
	if len(findings) == 0 {
		t.Error("expected findings from MaskAndLearn")
	}

	// Should be masked
	if contains(masked, "ghp_ABCDEFghijklmnopqrstuvwxyz0123456789") {
		t.Error("output should be masked")
	}

	// Should have learned the secret
	stats := masker.Stats()
	if stats[TypeGitHubToken] == 0 {
		t.Error("should have learned the GitHub token")
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
