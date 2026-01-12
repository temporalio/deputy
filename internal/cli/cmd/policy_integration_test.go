package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/picatz/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/policy"
)

// End-to-end style check: load the composed example bundle and execute the sbom entrypoint payload path.
func TestPolicyIntegration_ComposedBundleSbomComponent(t *testing.T) {
	bundlePath := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "license-allowlist-composed.yaml"))
	// Proto-first: pkg is the canonical variable for package info
	payload := map[string]any{
		"pkg": map[string]any{
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
	// Proto-first: pkg is the canonical variable for package info
	payload := map[string]any{
		"pkg": map[string]any{
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
// The composed bundle guards on env.command, so scan should be allowed.
func TestPolicyIntegration_ComposedBundleScanReport_NoDeny(t *testing.T) {
	bundlePath := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "license-allowlist-composed.yaml"))
	// Proto-first: pkg must be present
	payload := map[string]any{
		"pkg": map[string]any{
			"licenses": []any{}, // empty licenses, but scan command is not in_scope
		},
	}
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
	// Policy expects pkg.name to be synthesized from request.package
	denyPayload := map[string]any{
		"request": map[string]any{
			"ecosystem": "pypi",
			"package":   "randompkg",
		},
		"pkg": map[string]any{
			"name": "randompkg",
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
		"pkg": map[string]any{
			"name": "acme_toolkit",
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
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				},
				References: []string{"https://exploit-db.com/awesome-poc"},
			},
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial error for exploit-available vulnerability")
	}
}

func TestPolicyIntegration_DeprecatedModuleBlock(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "deprecated-module-block.yaml"))
	
	payload := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Summary: "Module is deprecated and unmaintained",
			},
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
		"pkg": &dependencyv1.Package{
			Licenses: []string{}, // Empty licenses
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", policy.EntrypointGoArtifactRequest, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for missing license metadata")
	}
}

func TestPolicyIntegration_NoFixEscalator(t *testing.T) {
	pol := filepath.Clean(filepath.Join("..", "..", "..", "policy", "examples", "no-fix-escalator.yaml"))
	
	payload := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Package: &dependencyv1.Package{
				Direct: true,
			},
			Advisory: &vulnerabilityv1.Advisory{
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
				},
				FixedVersions: []string{}, // No fix available
			},
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
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				},
			},
			Package: &dependencyv1.Package{
				ManifestRefs: []*dependencyv1.ManifestRef{
					{Groups: []string{"prod"}},
				},
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
		"request": &policyv1.ProxyRequest{
			Package: "aws-helper",
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
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-1234",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				},
			},
			Package: &dependencyv1.Package{
				Name:   "indirect-dep",
				Direct: false, // transitive dependency
			},
		},
		"env": &policyv1.Environment{Command: "scan", Entrypoint: "scan_vulnerability"},
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

	// Policy expects pkg.name to be synthesized from request.package
	payload := map[string]any{
		"request": &policyv1.ProxyRequest{
			Package:   "lodas",
			Ecosystem: "npm",
		},
		"pkg": &dependencyv1.Package{
			Name: "lodas",
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payload, "proxy", policy.EntrypointNpmArtifactRequest, &bytes.Buffer{}); err == nil {
		t.Fatalf("expected denial for typosquat package")
	}

	allowPayload := map[string]any{
		"request": &policyv1.ProxyRequest{
			Package:   "teamlib",
			Ecosystem: "npm",
		},
		"pkg": &dependencyv1.Package{
			Name: "teamlib",
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
          has(vulnerability.advisory) &&
          has(vulnerability.advisory.cwes) &&
          vulnerability.advisory.cwes.exists(c, c in ["CWE-89", "CWE-79", "CWE-78"])
        reason: "Injection vulnerability (SQL/XSS/Command)"
`
	pol := filepath.Join(t.TempDir(), "cwe-blocker.yaml")
	if err := os.WriteFile(pol, []byte(polContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	
	payloadWithCWE := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-1234",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
				},
				Cwes: []string{"CWE-89", "CWE-20"}, // SQL injection
			},
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadWithCWE, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for vulnerability with injection CWE")
	}

	
	payloadSafeCWE := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-5678",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				},
				Cwes: []string{"CWE-20", "CWE-400"}, // Input validation, resource consumption
			},
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

	
	payloadNoCWE := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-9999",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW,
				},
			},
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
          has(vulnerability.in_kev) &&
          vulnerability.in_kev == true
        reason: "CVE is in CISA's Known Exploited Vulnerabilities catalog"
`
	pol := filepath.Join(t.TempDir(), "kev-blocker.yaml")
	if err := os.WriteFile(pol, []byte(polContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	
	inKEV := true
	payloadInKEV := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-1234",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
				},
			},
			InKev: &inKEV,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadInKEV, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for vulnerability in KEV")
	}

	
	notInKEV := false
	payloadNotInKEV := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-5678",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				},
			},
			InKev: &notInKEV,
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

	
	payloadNoKEV := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-9999",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW,
				},
			},
			// InKev is nil (not set)
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

	
	highEPSS := 0.15 // 15% exploitation probability
	payloadHighEPSS := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-1234",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
				},
			},
			Epss: &highEPSS,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadHighEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for vulnerability with high EPSS")
	}

	
	mediumEPSS := 0.07 // 7% exploitation probability
	payloadMediumEPSS := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-5678",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				},
			},
			Epss: &mediumEPSS,
		},
	}
	actions, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadMediumEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("unexpected error for vulnerability with medium EPSS: %v", err)
	}
	if !slices.ContainsFunc(actions, func(a policy.Action) bool { return a.Type == "warn" }) {
		t.Fatalf("expected warn for vulnerability with medium EPSS, got %+v", actions)
	}

	
	lowEPSS := 0.01 // 1% exploitation probability
	payloadLowEPSS := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-9999",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW,
				},
			},
			Epss: &lowEPSS,
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

	
	payloadNoEPSS := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-0000",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				},
			},
			// Epss is nil (not set)
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
          has(vulnerability.in_kev) &&
          vulnerability.in_kev == true &&
          vulnerability.advisory.severity.level == severity.critical
        reason: "Critical + actively exploited"
      # High priority: High EPSS + Critical/High severity
      - action: deny
        when: |
          has(vulnerability.epss) &&
          vulnerability.epss >= 0.5 &&
          vulnerability.advisory.severity.level in [severity.critical, severity.high]
        reason: "High/Critical with very high exploitation probability"
`
	pol := filepath.Join(t.TempDir(), "composite-risk.yaml")
	if err := os.WriteFile(pol, []byte(polContent), 0644); err != nil {
		t.Fatalf("failed to write policy file: %v", err)
	}

	
	inKEV := true
	epss03 := 0.3
	payloadCriticalKEV := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-1234",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
				},
			},
			InKev: &inKEV,
			Epss:  &epss03,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadCriticalKEV, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for Critical + KEV vulnerability")
	}

	
	notInKEV := false
	epss06 := 0.6
	payloadHighEPSS := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-5678",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
				},
			},
			InKev: &notInKEV,
			Epss:  &epss06,
		},
	}
	if _, err := evaluatePoliciesForCommand(context.Background(), []string{pol}, payloadHighEPSS, "scan", policy.EntrypointScanVulnerability, &bytes.Buffer{}); err == nil {
		t.Fatal("expected denial for High severity + very high EPSS")
	}

	
	payloadMediumHighEPSS := map[string]any{
		"vulnerability": &vulnerabilityv1.Finding{
			Advisory: &vulnerabilityv1.Advisory{
				Id: "CVE-2024-9999",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				},
			},
			InKev: &notInKEV,
			Epss:  &epss06,
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
