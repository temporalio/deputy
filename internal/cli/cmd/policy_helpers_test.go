package cmd

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/temporalio/deputy/internal/policy"
)

// helper to locate the example policy from CLI package.
func examplePolicyPath(name string) string {
	return filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", name))
}

func TestEvaluatePoliciesForCommand_SbomComponentLicenses(t *testing.T) {
	pol := examplePolicyPath("license-allowlist.yaml")
	// Proto-first: pkg is the canonical variable for package info
	payload := map[string]any{
		"pkg": map[string]any{
			"licenses": []any{"GPL-3.0"},
		},
	}
	_, err := evaluatePoliciesForCommand(t.Context(), []string{pol}, payload, "sbom", policy.EntrypointSBOMComponent, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected policy denial error, got nil")
	}
}

func TestEvaluatePoliciesForCommand_Scan_NoPanic(t *testing.T) {
	pol := examplePolicyPath("license-allowlist.yaml")
	// Proto-first: pkg must be present with empty licenses for the policy to evaluate
	payload := map[string]any{
		"pkg": map[string]any{
			"licenses": []any{}, // empty licenses - should trigger warn, not deny
		},
	}
	actions, err := evaluatePoliciesForCommand(t.Context(), []string{pol}, payload, "scan", policy.EntrypointScanReport, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("evaluatePoliciesForCommand: %v", err)
	}
	for _, act := range actions {
		if act.Type == "deny" {
			t.Fatalf("unexpected deny for scan payload: %+v", act)
		}
	}
}
