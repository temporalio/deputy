package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Regression tests for #412: a policy deny used to abort `deputy scan`
// before any output was written, so the GitHub Action saw no SARIF, counted
// zero findings, and summarized a failed run as "No vulnerabilities found".

const reportDenyPolicyYAML = `
policies:
  - name: ci-block-fixable-high
    entrypoints: [scan_report]
    rules:
      - action: deny
        when: vulnerabilities.exists(v, v.advisory.severity.level == severity.high && size(v.advisory.fixed_versions) > 0)
        reason: High severity vulnerability has an available fix
        remediation: Upgrade to a fixed version
`

const vulnDenyPolicyYAML = `
policies:
  - name: block-high-vuln
    entrypoints: [scan_vulnerability]
    rules:
      - action: deny
        when: vulnerability.advisory.severity.level == severity.high
        reason: High severity vulnerability
`

func writePolicyFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	return path
}

// goJoseScanResult mirrors the #412 repro: go-jose/v4 v4.1.4 affected by
// GHSA-mgcc-cww5-fp2q (fixed in v4.1.6), plus an unrelated unfixed low
// finding that no deny rule should attribute.
func goJoseScanResult() scanning.Result {
	return scanning.Result{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "GHSA-mgcc-cww5-fp2q",
				Dependency: dependency.ID{Name: "github.com/go-jose/go-jose/v4", Ecosystem: "go"},
				Version:    "v4.1.4",
				Affected:   true,
			},
			{
				AdvisoryID: "GHSA-low-unfixed",
				Dependency: dependency.ID{Name: "github.com/acme/other", Ecosystem: "go"},
				Version:    "v1.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GHSA-mgcc-cww5-fp2q": {
				Id:            "GHSA-mgcc-cww5-fp2q",
				Severity:      vulnerability.NewSeverity("HIGH", "GHSA"),
				FixedVersions: []string{"v4.1.6"},
			},
			"GHSA-low-unfixed": {
				Id:       "GHSA-low-unfixed",
				Severity: vulnerability.NewSeverity("LOW", "GHSA"),
			},
		},
	}
}

func TestRunScanPoliciesReportDenyDoesNotError(t *testing.T) {
	policyPath := writePolicyFile(t, reportDenyPolicyYAML)

	actions, denied, err := runScanPolicies(t.Context(), []string{policyPath}, goJoseScanResult(), nil)
	if err != nil {
		t.Fatalf("runScanPolicies returned error on deny: %v", err)
	}

	denies := 0
	for _, act := range actions {
		if act.GetType() == policyv1.ActionType_ACTION_TYPE_DENY {
			denies++
		}
	}
	if denies != 1 {
		t.Fatalf("deny actions = %d, want 1: %v", denies, actions)
	}
	if len(denied) != 1 {
		t.Fatalf("denied findings = %v, want exactly the go-jose finding", denied)
	}
	got := denied[0]
	if got.Package != "github.com/go-jose/go-jose/v4" || got.Version != "v4.1.4" ||
		got.Advisory != "GHSA-mgcc-cww5-fp2q" || got.FixedIn != "v4.1.6" {
		t.Fatalf("denied finding = %+v, want go-jose/v4 v4.1.4 GHSA-mgcc-cww5-fp2q fixed in v4.1.6", got)
	}

	denyErr := scanPolicyDenyError(actions, denied)
	if denyErr == nil {
		t.Fatal("scanPolicyDenyError = nil, want blocking error")
	}
	for _, want := range []string{
		"denied command",
		"github.com/go-jose/go-jose/v4@v4.1.4",
		"GHSA-mgcc-cww5-fp2q",
		"fixed in v4.1.6",
	} {
		if !strings.Contains(denyErr.Error(), want) {
			t.Errorf("deny error %q does not contain %q", denyErr.Error(), want)
		}
	}
}

func TestRunScanPoliciesPerVulnerabilityDeny(t *testing.T) {
	policyPath := writePolicyFile(t, vulnDenyPolicyYAML)

	actions, denied, err := runScanPolicies(t.Context(), []string{policyPath}, goJoseScanResult(), nil)
	if err != nil {
		t.Fatalf("runScanPolicies returned error on deny: %v", err)
	}
	if len(denied) != 1 || denied[0].Advisory != "GHSA-mgcc-cww5-fp2q" {
		t.Fatalf("denied findings = %v, want exactly the go-jose finding", denied)
	}
	if denyErr := scanPolicyDenyError(actions, denied); denyErr == nil {
		t.Fatal("scanPolicyDenyError = nil, want blocking error")
	} else if !strings.Contains(denyErr.Error(), "GHSA-mgcc-cww5-fp2q") {
		t.Errorf("deny error %q does not name the denied finding", denyErr.Error())
	}
}

func TestRunScanPoliciesNoDeny(t *testing.T) {
	// No policies: no actions, no denied findings, no error.
	actions, denied, err := runScanPolicies(t.Context(), nil, goJoseScanResult(), nil)
	if err != nil {
		t.Fatalf("runScanPolicies error: %v", err)
	}
	if len(actions) != 0 || len(denied) != 0 {
		t.Fatalf("actions = %v, denied = %v, want both empty", actions, denied)
	}
	if err := scanPolicyDenyError(actions, denied); err != nil {
		t.Fatalf("scanPolicyDenyError = %v, want nil", err)
	}
}

func TestScanPolicyDenyError(t *testing.T) {
	actions, _, err := runScanPolicies(t.Context(), []string{writePolicyFile(t, reportDenyPolicyYAML)}, goJoseScanResult(), nil)
	if err != nil {
		t.Fatalf("runScanPolicies error: %v", err)
	}

	// Unattributed denies fall back to the policy message alone.
	if err := scanPolicyDenyError(actions, nil); err == nil {
		t.Fatal("scanPolicyDenyError without attribution = nil, want blocking error")
	} else if strings.Contains(err.Error(), "denied findings:") {
		t.Errorf("unattributed deny error %q lists findings it does not have", err.Error())
	}

	// Long denied lists are capped at five, with a count for the rest.
	many := make([]DeniedFinding, 0, 7)
	for i := 0; i < 7; i++ {
		many = append(many, DeniedFinding{
			Package:  "github.com/acme/pkg",
			Version:  "v1.0.0",
			Advisory: "GHSA-0000-0000-000" + string(rune('0'+i)),
			FixedIn:  "v1.0.1",
		})
	}
	capped := scanPolicyDenyError(actions, many)
	if capped == nil {
		t.Fatal("scanPolicyDenyError = nil, want blocking error")
	}
	if !strings.Contains(capped.Error(), "(and 2 more denied findings)") {
		t.Errorf("capped deny error %q does not report the overflow count", capped.Error())
	}
}

func TestRunScanRepositoryPolicyDenyStillWritesSARIF(t *testing.T) {
	// End-to-end shape of #412: a policy deny must still write the SARIF
	// file, and only then fail with an error naming the denied finding.
	// On base, runScanPolicies errored before any output was written, so
	// the SARIF file did not exist and the error named no finding.
	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	mockClients := newMockTriageClients(t, triageMockData{
		Findings: []vulnerability.Finding{{
			AdvisoryID: "GHSA-mgcc-cww5-fp2q",
			Dependency: dependency.ID{Name: "github.com/go-jose/go-jose/v4", Ecosystem: "go"},
			Version:    "v4.1.4",
			Affected:   true,
		}},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GHSA-mgcc-cww5-fp2q": {
				Id:            "GHSA-mgcc-cww5-fp2q",
				Severity:      vulnerability.NewSeverity("HIGH", "GHSA"),
				FixedVersions: []string{"v4.1.6"},
			},
		},
	})

	policyPath := writePolicyFile(t, reportDenyPolicyYAML)
	outPath := filepath.Join(tmpDir, "results.sarif")

	cmd := newScanTestCommand(t)
	cmd.Flags().StringArray("policy", nil, "")
	mustSetFlag(t, cmd, "policy", policyPath)
	mustSetFlag(t, cmd, "format", "sarif")
	mustSetFlag(t, cmd, "output", outPath)

	err := runScanRepository(mockClients, cmd, tmpDir)
	if err == nil {
		t.Fatal("runScanRepository = nil, want policy deny error")
	}
	for _, want := range []string{
		"github.com/go-jose/go-jose/v4@v4.1.4",
		"GHSA-mgcc-cww5-fp2q",
		"fixed in v4.1.6",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("scan error %q does not contain %q", err.Error(), want)
		}
	}

	sarif, readErr := os.ReadFile(outPath)
	if readErr != nil {
		t.Fatalf("SARIF output was not written on policy deny: %v", readErr)
	}
	for _, want := range []string{"GHSA-mgcc-cww5-fp2q", "go-jose"} {
		if !strings.Contains(string(sarif), want) {
			t.Errorf("SARIF output does not contain %q", want)
		}
	}
}
