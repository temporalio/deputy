package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/picatz/deputy/internal/policy"
)

// helper to locate the example policy from CLI package.
func examplePolicyPath(name string) string {
	return filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", name))
}

func TestEvaluatePoliciesForCommand_SbomComponentLicenses(t *testing.T) {
	pol := examplePolicyPath("license-allowlist.yaml")
	payload := map[string]any{
		"component": map[string]any{
			"licenses": []any{"GPL-3.0"},
		},
	}
	_, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "sbom", policy.EntrypointSBOMComponent, &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected policy denial error, got nil")
	}
}

func TestEvaluatePoliciesForCommand_Scan_NoPanic(t *testing.T) {
	pol := examplePolicyPath("license-allowlist.yaml")
	payload := map[string]any{} // no licenses present
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", policy.EntrypointScanReport, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("evaluatePoliciesForCommand: %v", err)
	}
	for _, act := range actions {
		if act.Type == "deny" {
			t.Fatalf("unexpected deny for scan payload: %+v", act)
		}
	}
}
