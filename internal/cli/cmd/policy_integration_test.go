package cmd

import (
	"bytes"
	"context"
	"os"
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
	_, err := evaluatePoliciesForCommand(context.Background(), []string{bundlePath}, payload, "sbom", policy.EntrypointSBOMComponent, &bytes.Buffer{})
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
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{bundlePath}, payload, "sbom", policy.EntrypointSBOMComponent, &bytes.Buffer{})
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
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{bundlePath}, payload, "scan", policy.EntrypointScanReport, &bytes.Buffer{})
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "fix", policy.EntrypointFixPlanStep, &bytes.Buffer{}); err == nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", policy.EntrypointDiffDependencyChange, &bytes.Buffer{}); err == nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, denyPayload, "proxy", policy.EntrypointPypiArtifactRequest, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for unapproved pypi package")
	}

	allowPayload := map[string]any{
		"request": map[string]any{
			"ecosystem": "pypi",
			"package":   "acme_toolkit",
		},
	}
	if actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, allowPayload, "proxy", policy.EntrypointPypiArtifactRequest, &bytes.Buffer{}); err != nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", policy.EntrypointDiffDependencyChange, &bytes.Buffer{}); err == nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for deprecated module")
	}
}

func TestPolicyIntegration_DependencyCountGuard(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "dependency-count-guard.yaml"))
	payload := map[string]any{
		"changes": make([]any, 80),
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", policy.EntrypointDiffReport, &bytes.Buffer{}); err == nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", policy.EntrypointGoArtifactRequest, &bytes.Buffer{}); err == nil {
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
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", policy.EntrypointNpmArtifactRequest, &bytes.Buffer{}); err == nil {
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
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "diff", policy.EntrypointDiffDependencyChange, &bytes.Buffer{})
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
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "sbom", policy.EntrypointSBOMReport, &bytes.Buffer{})
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
	if actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err != nil {
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
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", policy.EntrypointNpmArtifactRequest, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for typosquat package")
	}

	allowPayload := map[string]any{
		"request": map[string]any{
			"package":   "teamlib",
			"ecosystem": "npm",
		},
	}
	if actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, allowPayload, "proxy", policy.EntrypointNpmArtifactRequest, &bytes.Buffer{}); err != nil {
		t.Fatalf("did not expect error for safe package: %v", err)
	} else {
		for _, a := range actions {
			if a.Type == "deny" {
				t.Fatalf("did not expect deny for safe package: %+v", actions)
			}
		}
	}
}

func TestPolicyIntegration_CWEBlocker(t *testing.T) {
	// Test that CWEs are accessible in vulnerability policies
	polContent := `
policies:
  - name: block-injection-cwes
    entrypoints: [scan_vulnerability]
    rules:
      - action: deny
        when: |
          has(vulnerability.cwes) &&
          vulnerability.cwes.exists(c, c in ["CWE-89", "CWE-79", "CWE-78"])
        reason: "Injection vulnerability (SQL/XSS/Command)"
`
	pol := filepath.Join(t.TempDir(), "cwe-blocker.yaml")
	if err := os.WriteFile(pol, []byte(polContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Vulnerability with SQL injection CWE should be denied
	payloadWithCWE := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-1234",
			"severity": "HIGH",
			"cwes":     []any{"CWE-89", "CWE-20"}, // SQL injection
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadWithCWE, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for vulnerability with injection CWE")
	}

	// Vulnerability without injection CWEs should pass
	payloadSafeCWE := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-5678",
			"severity": "MEDIUM",
			"cwes":     []any{"CWE-20", "CWE-400"}, // Input validation, resource consumption
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadSafeCWE, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for safe CWEs: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" {
			t.Fatalf("did not expect deny for vulnerability without injection CWE: %+v", actions)
		}
	}

	// Vulnerability without CWEs should pass
	payloadNoCWE := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-9999",
			"severity": "LOW",
		},
	}
	actions, err = evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadNoCWE, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for vulnerability without CWEs: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" {
			t.Fatalf("did not expect deny for vulnerability without CWEs: %+v", actions)
		}
	}
}

func TestPolicyIntegration_KEVBlocker(t *testing.T) {
	// Test that KEV status is accessible in vulnerability policies
	polContent := `
policies:
  - name: block-kev
    entrypoints: [scan_vulnerability]
    rules:
      - action: deny
        when: |
          has(vulnerability.inKEV) &&
          vulnerability.inKEV == true
        reason: "CVE is in CISA's Known Exploited Vulnerabilities catalog"
`
	pol := filepath.Join(t.TempDir(), "kev-blocker.yaml")
	if err := os.WriteFile(pol, []byte(polContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Vulnerability in KEV should be denied
	payloadInKEV := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-1234",
			"severity": "HIGH",
			"inKEV":    true,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadInKEV, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for vulnerability in KEV")
	}

	// Vulnerability not in KEV should pass
	payloadNotInKEV := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-5678",
			"severity": "MEDIUM",
			"inKEV":    false,
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadNotInKEV, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for vulnerability not in KEV: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" {
			t.Fatalf("did not expect deny for vulnerability not in KEV: %+v", actions)
		}
	}

	// Vulnerability without KEV status should pass (field not present)
	payloadNoKEV := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-9999",
			"severity": "LOW",
		},
	}
	actions, err = evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadNoKEV, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for vulnerability without KEV status: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" {
			t.Fatalf("did not expect deny for vulnerability without KEV status: %+v", actions)
		}
	}
}

func TestPolicyIntegration_EPSSThreshold(t *testing.T) {
	// Test that EPSS scores are accessible in vulnerability policies
	polContent := `
policies:
  - name: block-high-epss
    entrypoints: [scan_vulnerability]
    vars:
      deny_threshold: 0.1
      warn_threshold: 0.05
    rules:
      - action: deny
        when: |
          has(vulnerability.epss) &&
          vulnerability.epss >= deny_threshold
        reason: "High EPSS score (>= 10% exploitation probability)"
      - action: warn
        when: |
          has(vulnerability.epss) &&
          vulnerability.epss >= warn_threshold &&
          vulnerability.epss < deny_threshold
        reason: "Elevated EPSS score (5-10% exploitation probability)"
`
	pol := filepath.Join(t.TempDir(), "epss-threshold.yaml")
	if err := os.WriteFile(pol, []byte(polContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Vulnerability with high EPSS should be denied
	payloadHighEPSS := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-1234",
			"severity": "HIGH",
			"epss":     0.15, // 15% exploitation probability
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadHighEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for vulnerability with high EPSS")
	}

	// Vulnerability with medium EPSS should warn
	payloadMediumEPSS := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-5678",
			"severity": "MEDIUM",
			"epss":     0.07, // 7% exploitation probability
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadMediumEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for vulnerability with medium EPSS: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a policy.Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for vulnerability with medium EPSS, got %+v", actions)
	}

	// Vulnerability with low EPSS should pass
	payloadLowEPSS := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-9999",
			"severity": "LOW",
			"epss":     0.01, // 1% exploitation probability
		},
	}
	actions, err = evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadLowEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for vulnerability with low EPSS: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" || a.Type == "warn" {
			t.Fatalf("did not expect deny/warn for vulnerability with low EPSS: %+v", actions)
		}
	}

	// Vulnerability without EPSS should pass
	payloadNoEPSS := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-0000",
			"severity": "MEDIUM",
		},
	}
	actions, err = evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadNoEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for vulnerability without EPSS: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" || a.Type == "warn" {
			t.Fatalf("did not expect deny/warn for vulnerability without EPSS: %+v", actions)
		}
	}
}

func TestPolicyIntegration_CompositeRiskScore(t *testing.T) {
	// Test composite risk scoring using multiple factors (KEV, EPSS, severity)
	polContent := `
policies:
  - name: composite-risk
    entrypoints: [scan_vulnerability]
    rules:
      # Highest priority: Known Exploited + Critical
      - action: deny
        when: |
          has(vulnerability.inKEV) &&
          vulnerability.inKEV == true &&
          vulnerability.severity == "CRITICAL"
        reason: "Critical + actively exploited"
      # High priority: High EPSS + Critical/High severity
      - action: deny
        when: |
          has(vulnerability.epss) &&
          vulnerability.epss >= 0.5 &&
          vulnerability.severity in ["CRITICAL", "HIGH"]
        reason: "High/Critical with very high exploitation probability"
`
	pol := filepath.Join(t.TempDir(), "composite-risk.yaml")
	if err := os.WriteFile(pol, []byte(polContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	// Critical + KEV should be denied
	payloadCriticalKEV := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-1234",
			"severity": "CRITICAL",
			"inKEV":    true,
			"epss":     0.3,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadCriticalKEV, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for Critical + KEV vulnerability")
	}

	// High + very high EPSS should be denied
	payloadHighEPSS := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-5678",
			"severity": "HIGH",
			"inKEV":    false,
			"epss":     0.6,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadHighEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for High severity + very high EPSS")
	}

	// Medium severity + high EPSS should pass (not in rules)
	payloadMediumHighEPSS := map[string]any{
		"vulnerability": map[string]any{
			"id":       "CVE-2024-9999",
			"severity": "MEDIUM",
			"inKEV":    false,
			"epss":     0.6,
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadMediumHighEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for Medium + high EPSS: %v", err)
	}
	for _, a := range actions {
		if a.Type == "deny" {
			t.Fatalf("did not expect deny for Medium severity + high EPSS: %+v", actions)
		}
	}
}
