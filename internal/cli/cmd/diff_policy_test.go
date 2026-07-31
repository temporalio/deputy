package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/policy"
)

// writeDiffTestBundle writes a policy bundle mirroring the shipped
// pr-review.yaml license check plus a targeted deny, and returns its path.
func writeDiffTestBundle(t *testing.T) string {
	t.Helper()
	bundle := `policies:
  - name: license-check
    description: Warn when license info is missing
    entrypoints: [diff_dependency_change]
    rules:
      - action: warn
        when: pkg.licenses.size() == 0
        reason: No license information detected
        remediation: Verify the dependency's license manually
  - name: block-bad-package
    description: Deny a specific package
    entrypoints: [diff_dependency_change]
    rules:
      - action: deny
        when: pkg.name == 'example.com/forbidden'
        reason: Package is on the block list
`
	path := filepath.Join(t.TempDir(), "bundle.yaml")
	if err := os.WriteFile(path, []byte(bundle), 0o600); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	return path
}

// TestRunDiffPolicies_AttributesSubjects reproduces the repeated
// subjectless-warning failure mode from the PR dependency diff: the same rule
// firing per package must come back as structured results that each carry the
// evaluated package, so renderers can group and deduplicate instead of
// printing one anonymous stderr line per package.
func TestRunDiffPolicies_AttributesSubjects(t *testing.T) {
	bundlePath := writeDiffTestBundle(t)
	diffReport := DiffPolicyReport{
		Repo:      "example.com/repo",
		BaseRef:   "main",
		TargetRef: "feature",
		Changes: []compare.Change{
			{Name: "golang.org/x/text", Ecosystem: "go", BaseVersion: "0.37.0", TargetVersion: "0.39.0", ChangeType: compare.Upgraded, IsDirect: true},
			{Name: "golang.org/x/crypto", Ecosystem: "go", BaseVersion: "0.52.0", TargetVersion: "0.53.0", ChangeType: compare.Upgraded, IsDirect: true},
		},
	}

	results, err := runDiffPolicies(t.Context(), []string{bundlePath}, diffReport)
	if err != nil {
		t.Fatalf("runDiffPolicies: %v", err)
	}

	var warns []*policyv1.Action
	for _, r := range results {
		if r.GetType() == policyv1.ActionType_ACTION_TYPE_WARN {
			warns = append(warns, r)
		}
	}
	if len(warns) != len(diffReport.Changes) {
		t.Fatalf("expected %d warn results, got %d (%v)", len(diffReport.Changes), len(warns), results)
	}
	for i, w := range warns {
		if w.GetRuleName() != "license-check" {
			t.Errorf("warn[%d] RuleName = %q, want license-check", i, w.GetRuleName())
		}
		if w.GetPolicyName() != bundlePath {
			t.Errorf("warn[%d] PolicyName = %q, want %q", i, w.GetPolicyName(), bundlePath)
		}
		if w.GetEntrypoint() != policy.EntrypointDiffDependencyChange.String() {
			t.Errorf("warn[%d] Entrypoint = %q, want %q", i, w.GetEntrypoint(), policy.EntrypointDiffDependencyChange)
		}
		subject := w.GetSubject()
		if subject == nil || subject.GetPackage() == "" || subject.GetVersion() == "" {
			t.Errorf("warn[%d] missing subject attribution: %v", i, subject)
		}
	}

	// No deny fired, so the results must not gate the command.
	if err := policyDenyError(results); err != nil {
		t.Fatalf("policyDenyError = %v, want nil", err)
	}
}

// TestRunDiffPolicies_DenyGatesAfterCollection verifies denies are collected
// rather than aborting evaluation, and that policyDenyError reports them with
// the policy source, rule, and reason a user needs to act.
func TestRunDiffPolicies_DenyGatesAfterCollection(t *testing.T) {
	bundlePath := writeDiffTestBundle(t)
	diffReport := DiffPolicyReport{
		Repo:      "example.com/repo",
		BaseRef:   "main",
		TargetRef: "feature",
		Changes: []compare.Change{
			{Name: "example.com/forbidden", Ecosystem: "go", TargetVersion: "1.0.0", ChangeType: compare.Added},
			{Name: "example.com/fine", Ecosystem: "go", TargetVersion: "1.0.0", ChangeType: compare.Added},
		},
	}

	results, err := runDiffPolicies(t.Context(), []string{bundlePath}, diffReport)
	if err != nil {
		t.Fatalf("runDiffPolicies: %v", err)
	}

	// Both changes evaluated: the deny on the first must not skip the second.
	var sawFine bool
	for _, r := range results {
		if r.GetSubject().GetPackage() == "example.com/fine" {
			sawFine = true
		}
	}
	if !sawFine {
		t.Fatalf("expected evaluation to continue past the deny; results: %v", results)
	}

	denyErr := policyDenyError(results)
	if denyErr == nil {
		t.Fatal("policyDenyError = nil, want blocking error")
	}
	for _, want := range []string{"block-bad-package", "Package is on the block list"} {
		if !strings.Contains(denyErr.Error(), want) {
			t.Errorf("deny error %q missing %q", denyErr, want)
		}
	}
}

// TestRunDiffPolicies_LicenseDataReachesPolicies verifies the license hoist:
// changes enriched with license data must satisfy pkg.licenses rules, so a
// package whose license the report displays no longer produces a
// false-positive "no license information" warning.
func TestRunDiffPolicies_LicenseDataReachesPolicies(t *testing.T) {
	bundlePath := writeDiffTestBundle(t)
	diffReport := DiffPolicyReport{
		Repo:      "example.com/repo",
		BaseRef:   "main",
		TargetRef: "feature",
		Changes: []compare.Change{
			{Name: "golang.org/x/crypto", Ecosystem: "go", BaseVersion: "0.52.0", TargetVersion: "0.53.0", ChangeType: compare.Upgraded, Licenses: []string{"BSD-3-Clause"}},
			{Name: "example.com/unlicensed", Ecosystem: "go", TargetVersion: "1.0.0", ChangeType: compare.Added},
		},
	}

	results, err := runDiffPolicies(t.Context(), []string{bundlePath}, diffReport)
	if err != nil {
		t.Fatalf("runDiffPolicies: %v", err)
	}

	var warns []*policyv1.Action
	for _, r := range results {
		if r.GetType() == policyv1.ActionType_ACTION_TYPE_WARN {
			warns = append(warns, r)
		}
	}
	if len(warns) != 1 {
		t.Fatalf("expected exactly one warn (the unlicensed package), got %d: %v", len(warns), warns)
	}
	if got := warns[0].GetSubject().GetPackage(); got != "example.com/unlicensed" {
		t.Errorf("warn subject = %q, want example.com/unlicensed", got)
	}
}
