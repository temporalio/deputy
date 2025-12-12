package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"slices"
	"testing"

	"github.com/picatz/deputy/internal/policy"
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

func TestPolicyIntegration_RuntimeCriticalBaseline(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "runtime-critical-baseline.yaml"))
	payload := map[string]any{
		"change": map[string]any{
			"type": "removed",
			"name": "github.com/sirupsen/logrus",
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", "diff_dependency_change", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for removing critical module")
	}
}

func TestPolicyIntegration_ExploitAvailableBlocker(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "exploit-available-blocker.yaml"))
	payload := map[string]any{
		"vulnerability": map[string]any{
			"severity":   "CRITICAL",
			"references": []any{"https://exploit-db.com/awesome-poc"},
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", "scan_vulnerability", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for exploit-available vulnerability")
	}
}

func TestPolicyIntegration_DeprecatedModuleBlock(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "deprecated-module-block.yaml"))
	payload := map[string]any{
		"vulnerability": map[string]any{
			"summary": "Module is deprecated and unmaintained",
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", "scan_vulnerability", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for deprecated module")
	}
}

func TestPolicyIntegration_DependencyCountGuard(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "dependency-count-guard.yaml"))
	payload := map[string]any{
		"changes": make([]any, 80),
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", "diff_report", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for oversized diff change set")
	}
}

func TestPolicyIntegration_LicensePresentBlocker(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "license-present-blocker.yaml"))
	payload := map[string]any{
		"pkg": map[string]any{
			"licenses": []any{},
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", "go_artifact_request", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for missing license metadata")
	}
}

func TestPolicyIntegration_NoFixEscalator(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "no-fix-escalator.yaml"))
	payload := map[string]any{
		"vulnerability": map[string]any{
			"severity":      "HIGH",
			"isDirect":      true,
			"fixedVersions": []any{},
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", "scan_vulnerability", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a policy.Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for no-fix vuln, got %+v", actions)
	}
}

func TestPolicyIntegration_ProdManifestGate(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "prod-manifest-gate.yaml"))
	payload := map[string]any{
		"vulnerability": map[string]any{
			"severity": "CRITICAL",
			"manifestRefs": []any{
				map[string]any{"groups": []any{"prod"}},
			},
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", "scan_vulnerability", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for prod manifest vuln")
	}
}

func TestPolicyIntegration_DomainBrandedPackageGuard(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "domain-branded-package-guard.yaml"))
	payload := map[string]any{
		"request": map[string]any{
			"package": "aws-helper",
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", "npm_artifact_request", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for branded package name")
	}
}

func TestPolicyIntegration_CriticalRuntimePinning(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "critical-runtime-pinning.yaml"))
	payload := map[string]any{
		"change": map[string]any{
			"name":          "golang.org/x/crypto",
			"baseVersion":   "v0.24.0",
			"targetVersion": "v0.24.0",
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", "diff_dependency_change", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a policy.Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for unchanged critical module, got %+v", actions)
	}
}

func TestPolicyIntegration_SbomSizeShapeSanity(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "sbom-size-shape-sanity.yaml"))
	packages := make([]any, 12000)
	payload := map[string]any{
		"packages": packages,
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "sbom", "sbom_report", &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a policy.Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for oversized SBOM, got %+v", actions)
	}
}

func TestPolicyIntegration_CriticalTransitiveSpotlight(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "critical-transitive-spotlight.yaml"))
	payload := map[string]any{
		"vulnerability": map[string]any{
			"severity": "CRITICAL",
			"isDirect": false,
		},
	}
	if actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", "scan_vulnerability", &bytes.Buffer{}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	} else {
		if !slices.ContainsFunc(actions, func(a policy.Action) bool { return a.Type == "warn" }) {
			t.Fatalf("expected warn for critical indirect vuln, got %+v", actions)
		}
	}
}

func TestPolicyIntegration_TyposquatLevenshteinGuard(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "typosquat-levenshtein-guard.yaml"))
	payload := map[string]any{
		"request": map[string]any{
			"package":   "lodas",
			"ecosystem": "npm",
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", "npm_artifact_request", &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for typosquat package")
	}

	allowPayload := map[string]any{
		"request": map[string]any{
			"package":   "teamlib",
			"ecosystem": "npm",
		},
	}
	if actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, allowPayload, "proxy", "npm_artifact_request", &bytes.Buffer{}); err != nil {
		t.Fatalf("did not expect error for safe package: %v", err)
	} else {
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for safe package: %+v", actions)
			}
		}
	}
}
