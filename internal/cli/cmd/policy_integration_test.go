package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"
)

// End-to-end style check: load the composed example bundle and execute the sbom entrypoint payload path.
func TestPolicyIntegration_ComposedBundleSbomComponent(t *testing.T) {
	bundlePath := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "license-allowlist-composed.yaml"))
	payload := map[string]any{
		"component": map[string]any{
			"licenses": []any{"AgPl-3.0-only", "MIT"},
		},
	}
	_, err := evaluatePoliciesForCommand(context.Background(), []string{bundlePath}, payload, "sbom", "sbom_component", &bytes.Buffer{})
	if err == nil {
		t.Fatalf("expected denial error from composed bundle, got nil")
	}
}

func TestPolicyIntegration_ComposedBundleSbomComponent_AllowsPermissive(t *testing.T) {
	bundlePath := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "license-allowlist-composed.yaml"))
	payload := map[string]any{
		"component": map[string]any{
			"licenses": []any{"MIT"},
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{bundlePath}, payload, "sbom", "sbom_component", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("evaluatePoliciesForCommand: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" {
			t.Fatalf("did not expect deny: %+v", a)
		}
	}
}

// Ensure scan command (no licenses) is not denied by the composed bundle.
func TestPolicyIntegration_ComposedBundleScanReport_NoDeny(t *testing.T) {
	bundlePath := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "license-allowlist-composed.yaml"))
	payload := map[string]any{} // no licenses present
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{bundlePath}, payload, "scan", "scan_report", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("evaluatePoliciesForCommand: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" {
			t.Fatalf("did not expect deny for scan payload: %+v", a)
		}
	}
}

func TestPolicyIntegration_FixStepCommandAllowlist_Deny(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "fix-step-command-allowlist.yaml"))
	payload := map[string]any{
		"step": map[string]any{
			"command":    "rm -rf /",
			"executable": true,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "fix", "fix_plan_step", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for unsafe fix step")
	}
}

func TestPolicyIntegration_NewDependencyReview_Deny(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "new-dependency-review.yaml"))
	payload := map[string]any{
		"change": map[string]any{
			"type": "added",
			"name": "github.com/unknown/mod",
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", "diff_dependency_change", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for unapproved dependency addition")
	}
}

func TestPolicyIntegration_PypiPrefixAllowlist(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "pypi-prefix-allowlist.yaml"))
	denyPayload := map[string]any{
		"request": map[string]any{
			"ecosystem": "pypi",
			"package":   "randompkg",
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, denyPayload, "proxy", "pypi_artifact_request", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for unapproved pypi package")
	}

	allowPayload := map[string]any{
		"request": map[string]any{
			"ecosystem": "pypi",
			"package":   "acme_toolkit",
		},
	}
	if actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, allowPayload, "proxy", "pypi_artifact_request", &bytes.Buffer{}); err != nil {
		t.Fatalf("unexpected error for approved pypi package: %v", err)
	} else {
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for approved prefix: %+v", actions)
			}
		}
	}
}
