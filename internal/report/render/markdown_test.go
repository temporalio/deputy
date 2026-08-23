package render

import (
	"fmt"
	"strings"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// diffMarkdownFixture builds a response exercising every section: mixed
// change kinds, licenses, a new and a pre-existing vulnerability, and a
// deduplicated policy warning group.
func diffMarkdownFixture() *diffv1.DiffVulnerabilitiesResponse {
	changes := []*diffv1.PackageChange{
		{
			Package:       &dependencyv1.Package{Name: "golang.org/x/crypto", Version: "0.53.0", Ecosystem: "go", Licenses: []string{"BSD-3-Clause"}},
			ChangeKind:    diffv1.ChangeKind_CHANGE_KIND_UPGRADED,
			BaseVersion:   "0.52.0",
			TargetVersion: "0.53.0",
			IsDirect:      true,
		},
		{
			Package:       &dependencyv1.Package{Name: "example.com/evil|pipe", Version: "1.0.0", Ecosystem: "go"},
			ChangeKind:    diffv1.ChangeKind_CHANGE_KIND_ADDED,
			TargetVersion: "1.0.0",
		},
		{
			Package:     &dependencyv1.Package{Name: "example.com/gone", Ecosystem: "go"},
			ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_REMOVED,
			BaseVersion: "2.0.0",
		},
	}
	return &diffv1.DiffVulnerabilitiesResponse{
		BaseTarget:   &targetv1.Target{DisplayPath: "main"},
		TargetTarget: &targetv1.Target{DisplayPath: "feature"},
		Changes:      changes,
		ChangeStats: &diffv1.DiffStats{
			AddedCount:    1,
			RemovedCount:  1,
			UpgradedCount: 1,
			TotalChanges:  3,
		},
		AddedVulnerabilities: []*vulnerabilityv1.Finding{{
			AdvisoryId: "GHSA-aaaa-bbbb-cccc",
			Package:    &dependencyv1.Package{Name: "example.com/evil|pipe", Version: "1.0.0"},
			Advisory: &vulnerabilityv1.Advisory{
				Id:            "GHSA-aaaa-bbbb-cccc",
				Severity:      &vulnerabilityv1.Severity{Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH},
				FixedVersions: []string{"1.0.1"},
			},
		}},
		UnchangedVulnerabilities: []*vulnerabilityv1.Finding{{
			AdvisoryId: "CVE-2026-0001",
			Package:    &dependencyv1.Package{Name: "example.com/old", Version: "3.0.0"},
		}},
		Stats: &diffv1.VulnerabilityDiffStats{AddedCount: 1, UnchangedCount: 1},
		PolicyActions: []*policyv1.Action{
			{
				Type:       policyv1.ActionType_ACTION_TYPE_WARN,
				PolicyName: "policy/ci/pr-review.yaml",
				RuleName:   "pr-license-check",
				Reason:     "No license information detected",
				Subject:    &policyv1.Subject{Package: "example.com/evil|pipe", Version: "1.0.0"},
			},
			{
				Type:       policyv1.ActionType_ACTION_TYPE_WARN,
				PolicyName: "policy/ci/pr-review.yaml",
				RuleName:   "pr-license-check",
				Reason:     "No license information detected",
				Subject:    &policyv1.Subject{Package: "example.com/gone", Version: "2.0.0"},
			},
		},
		PolicyFilesEvaluated: 1,
	}
}

func TestDiffMarkdown(t *testing.T) {
	out := DiffMarkdown(diffMarkdownFixture())

	for _, want := range []string{
		"## Deputy Dependency Diff",
		"`main` → `feature`",
		"**3 dependency changes** (1 added, 1 removed, 1 upgraded)",
		"❗ 1 new vulnerability",
		"⚠️ 2 policy warnings",
		"### Dependency changes",
		"| ↑ | `golang.org/x/crypto` | `0.52.0` → `0.53.0` | BSD-3-Clause | direct |",
		"| − | `example.com/gone` | `2.0.0` |  | indirect |",
		"### ❗ Newly introduced vulnerabilities (1)",
		"[GHSA-aaaa-bbbb-cccc](https://osv.dev/vulnerability/GHSA-aaaa-bbbb-cccc)",
		"HIGH",
		"1.0.1",
		"<details><summary>1 pre-existing vulnerability not introduced by this change</summary>",
		"### Policy evaluation",
		"⚠️ WARN **pr-license-check** (`policy/ci/pr-review.yaml`): No license information detected — 2 packages",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown missing %q\n---\n%s", want, out)
		}
	}

	// Pipe characters in package names must never survive unescaped inside a
	// table row, or they would add phantom columns.
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "evil") && strings.HasPrefix(line, "|") {
			if strings.Contains(line, "evil|pipe") {
				t.Errorf("unescaped pipe in table row: %q", line)
			}
		}
	}
}

func TestDiffMarkdown_EmptyDiff(t *testing.T) {
	out := DiffMarkdown(&diffv1.DiffVulnerabilitiesResponse{
		BaseTarget:   &targetv1.Target{DisplayPath: "main"},
		TargetTarget: &targetv1.Target{DisplayPath: "main"},
		ChangeStats:  &diffv1.DiffStats{},
	})
	if !strings.Contains(out, "No dependency changes detected") {
		t.Fatalf("expected empty-diff message, got:\n%s", out)
	}
	if strings.Contains(out, "### Dependency changes") || strings.Contains(out, "Policy evaluation") {
		t.Fatalf("expected no sections for an empty diff, got:\n%s", out)
	}
}

func TestDiffMarkdown_PoliciesAllPassed(t *testing.T) {
	out := DiffMarkdown(&diffv1.DiffVulnerabilitiesResponse{
		ChangeStats:          &diffv1.DiffStats{TotalChanges: 1, UpgradedCount: 1},
		PolicyFilesEvaluated: 2,
	})
	if !strings.Contains(out, "✅ policies passed") {
		t.Errorf("status line missing policies passed:\n%s", out)
	}
	if !strings.Contains(out, "2 policy files evaluated, all rules passed") {
		t.Errorf("policy section missing all-passed line:\n%s", out)
	}
}

func TestDiffMarkdown_CollapsesLargeChangeSets(t *testing.T) {
	resp := &diffv1.DiffVulnerabilitiesResponse{
		ChangeStats: &diffv1.DiffStats{TotalChanges: 30, AddedCount: 30},
	}
	for i := range 30 {
		resp.Changes = append(resp.Changes, &diffv1.PackageChange{
			Package:       &dependencyv1.Package{Name: fmt.Sprintf("example.com/pkg%02d", i), Version: "1.0.0"},
			ChangeKind:    diffv1.ChangeKind_CHANGE_KIND_ADDED,
			TargetVersion: "1.0.0",
		})
	}
	out := DiffMarkdown(resp)
	if !strings.Contains(out, "<details><summary>… and 10 more changes</summary>") {
		t.Fatalf("expected collapsed tail for 30 changes:\n%s", out)
	}
	if !strings.Contains(out, "example.com/pkg29") {
		t.Fatalf("collapsed tail must still contain the last change:\n%s", out)
	}
}

func TestDiffMarkdown_SeparatesRemediationFromDetails(t *testing.T) {
	resp := &diffv1.DiffVulnerabilitiesResponse{
		ChangeStats: &diffv1.DiffStats{TotalChanges: 1, AddedCount: 1},
		PolicyActions: []*policyv1.Action{{
			Type:        policyv1.ActionType_ACTION_TYPE_WARN,
			PolicyName:  "policy.yaml",
			RuleName:    "stable-release",
			Reason:      "prerelease dependency",
			Remediation: "Use a stable release",
			Subject:     &policyv1.Subject{Package: "example.com/pkg"},
		}},
		PolicyFilesEvaluated: 1,
	}
	out := DiffMarkdown(resp)

	if !strings.Contains(out, "  </details>\n\n  _Remediation: Use a stable release_\n") {
		t.Fatalf("remediation must start after the details HTML block:\n%s", out)
	}

	resp.PolicyActions[0].Remediation = ""
	out = DiffMarkdown(resp)
	if strings.Contains(out, "  </details>\n\n") {
		t.Fatalf("details without remediation must keep its existing spacing:\n%s", out)
	}
}

func TestDiffMarkdown_CollapsesLargeFindingSets(t *testing.T) {
	resp := &diffv1.DiffVulnerabilitiesResponse{
		ChangeStats: &diffv1.DiffStats{},
		Stats:       &diffv1.VulnerabilityDiffStats{AddedCount: 30},
	}
	for i := range 30 {
		resp.AddedVulnerabilities = append(resp.AddedVulnerabilities, &vulnerabilityv1.Finding{
			AdvisoryId: fmt.Sprintf("CVE-2026-%04d", i),
			Package:    &dependencyv1.Package{Name: fmt.Sprintf("example.com/pkg%02d", i), Version: "1.0.0"},
		})
	}

	out := DiffMarkdown(resp)
	if !strings.Contains(out, "<details><summary>… and 10 more findings</summary>") {
		t.Fatalf("expected collapsed finding tail:\n%s", out)
	}
	if !strings.Contains(out, "CVE-2026-0029") {
		t.Fatalf("collapsed tail must still contain the last finding:\n%s", out)
	}
	if strings.Contains(out, "see `--format json` for the full set") {
		t.Fatalf("finding overflow must not be lossy:\n%s", out)
	}

	resp.UnchangedVulnerabilities = resp.AddedVulnerabilities
	resp.AddedVulnerabilities = nil
	resp.Stats = &diffv1.VulnerabilityDiffStats{UnchangedCount: 30}
	out = DiffMarkdown(resp)
	if !strings.Contains(out, "CVE-2026-0029") {
		t.Fatalf("nested collapsed tail must still contain the last finding:\n%s", out)
	}
	if opened, closed := strings.Count(out, "<details>"), strings.Count(out, "</details>"); opened != closed {
		t.Fatalf("nested details blocks are unbalanced: %d open, %d closed\n%s", opened, closed, out)
	}
}
