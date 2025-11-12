package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractPolicyName(t *testing.T) {
	src := `//! policy.name = "foo-policy"
true`
	if got := extractPolicyName(src); got != "foo-policy" {
		t.Fatalf("extractPolicyName() = %q, want foo-policy", got)
	}
}

func TestBuildBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.cel")
	source := `//! policy.name = "bundle-policy"
true`
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	bundle, err := BuildBundle([]string{path})
	if err != nil {
		t.Fatalf("BuildBundle() error = %v", err)
	}
	if bundle.SchemaVersion == "" {
		t.Fatalf("expected schema version, got empty")
	}
	if len(bundle.Policies) != 1 {
		t.Fatalf("expected 1 policy in bundle, got %d", len(bundle.Policies))
	}
	if bundle.Policies[0].Name != "bundle-policy" {
		t.Fatalf("unexpected policy name %q", bundle.Policies[0].Name)
	}
	if bundle.Policies[0].Source == "" {
		t.Fatalf("expected policy source to be stored")
	}
}
