package render

import (
	"bytes"
	"strings"
	"testing"

	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	"github.com/temporalio/deputy/internal/report"
)

func TestPolicyFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []report.PolicyFinding
		want     []string
		wantNone bool
	}{
		{
			name:     "Empty",
			findings: nil,
			wantNone: true,
		},
		{
			name: "NonEmpty",
			findings: []report.PolicyFinding{{
				Action:      "deny",
				Source:      "policy.yaml",
				Reason:      "blocked",
				Remediation: "upgrade",
			}},
			want: []string{"Policy Findings:", "DENY", "blocked", "Remediation:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			PolicyFindings(&buf, tt.findings)
			out := buf.String()
			if tt.wantNone && out != "" {
				t.Fatalf("expected no output, got %q", out)
			}
			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Fatalf("expected output to contain %q, got %q", w, out)
				}
			}
		})
	}
}

func TestPolicyEvaluationSummary(t *testing.T) {
	tests := []struct {
		name        string
		policyCount int
		findings    []report.PolicyFinding
		want        []string // strings that must appear
		wantNot     []string // strings that must NOT appear
		wantNone    bool     // expect no output at all
	}{
		{
			name:        "no policies",
			policyCount: 0,
			findings:    nil,
			wantNone:    true,
		},
		{
			name:        "all passed - single policy",
			policyCount: 1,
			findings:    nil,
			want:        []string{"Policy Evaluation:", "1 policy file evaluated", "all passed", "✓"},
		},
		{
			name:        "all passed - multiple policies",
			policyCount: 3,
			findings:    nil,
			want:        []string{"Policy Evaluation:", "3 policy files evaluated", "all passed", "✓"},
		},
		{
			name:        "warnings only",
			policyCount: 2,
			findings: []report.PolicyFinding{
				{Action: "warn", Source: "policy.yaml", Reason: "deprecated package"},
			},
			want:    []string{"Policy Evaluation:", "2 policy files evaluated", "1 warned", "!"},
			wantNot: []string{"denied", "all passed"},
		},
		{
			name:        "denials only",
			policyCount: 1,
			findings: []report.PolicyFinding{
				{Action: "deny", Source: "security.yaml", Reason: "critical vulnerability"},
			},
			want:    []string{"Policy Evaluation:", "1 policy file evaluated", "1 denied", "!"},
			wantNot: []string{"warned", "all passed"},
		},
		{
			name:        "mixed denials and warnings",
			policyCount: 2,
			findings: []report.PolicyFinding{
				{Action: "deny", Source: "security.yaml", Reason: "critical vulnerability"},
				{Action: "warn", Source: "license.yaml", Reason: "unknown license"},
				{Action: "warn", Source: "license.yaml", Reason: "GPL license"},
			},
			want:    []string{"Policy Evaluation:", "2 policy files evaluated", "1 denied", "2 warned"},
			wantNot: []string{"all passed"},
		},
		{
			name:        "allow actions are not counted as findings",
			policyCount: 1,
			findings: []report.PolicyFinding{
				{Action: "allow", Source: "policy.yaml", Reason: "explicitly allowed"},
			},
			want: []string{"Policy Evaluation:", "all passed", "✓"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			PolicyEvaluationSummary(&buf, tt.policyCount, tt.findings)
			out := buf.String()

			if tt.wantNone {
				if out != "" {
					t.Errorf("expected no output, got %q", out)
				}
				return
			}

			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("expected output to contain %q, got:\n%s", w, out)
				}
			}

			for _, nw := range tt.wantNot {
				if strings.Contains(out, nw) {
					t.Errorf("expected output NOT to contain %q, got:\n%s", nw, out)
				}
			}
		})
	}
}

func TestCountPolicyActions(t *testing.T) {
	tests := []struct {
		name       string
		findings   []report.PolicyFinding
		wantDenies int
		wantWarns  int
	}{
		{
			name:       "empty",
			findings:   nil,
			wantDenies: 0,
			wantWarns:  0,
		},
		{
			name: "only denies",
			findings: []report.PolicyFinding{
				{Action: "deny"},
				{Action: "DENY"},
				{Action: "Deny"},
			},
			wantDenies: 3,
			wantWarns:  0,
		},
		{
			name: "only warns",
			findings: []report.PolicyFinding{
				{Action: "warn"},
				{Action: "WARN"},
			},
			wantDenies: 0,
			wantWarns:  2,
		},
		{
			name: "mixed",
			findings: []report.PolicyFinding{
				{Action: "deny"},
				{Action: "warn"},
				{Action: "allow"},
				{Action: "deny"},
			},
			wantDenies: 2,
			wantWarns:  1,
		},
		{
			name: "allow and empty are ignored",
			findings: []report.PolicyFinding{
				{Action: "allow"},
				{Action: ""},
				{Action: "other"},
			},
			wantDenies: 0,
			wantWarns:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			denies, warns := countPolicyActions(tt.findings)
			if denies != tt.wantDenies {
				t.Errorf("denies: got %d, want %d", denies, tt.wantDenies)
			}
			if warns != tt.wantWarns {
				t.Errorf("warns: got %d, want %d", warns, tt.wantWarns)
			}
		})
	}
}

func TestPolicyFindingRendering(t *testing.T) {
	tests := []struct {
		name    string
		finding report.PolicyFinding
		want    []string
	}{
		{
			name: "deny with full details",
			finding: report.PolicyFinding{
				Action:      "deny",
				Source:      "security-policy.yaml",
				Reason:      "Critical vulnerability CVE-2024-1234",
				Remediation: "Upgrade to version 2.0.0 or later",
			},
			want: []string{"DENY", "security-policy.yaml", "Critical vulnerability", "Remediation:", "2.0.0"},
		},
		{
			name: "warn with message fallback",
			finding: report.PolicyFinding{
				Action:  "warn",
				Source:  "license.yaml",
				Message: "Unknown license detected",
			},
			want: []string{"WARN", "license.yaml", "Unknown license"},
		},
		{
			name: "empty action defaults to FINDING",
			finding: report.PolicyFinding{
				Action: "",
				Source: "policy.yaml",
				Reason: "Some reason",
			},
			want: []string{"FINDING", "policy.yaml", "Some reason"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			renderPolicyFinding(&buf, tt.finding)
			out := buf.String()

			for _, w := range tt.want {
				if !strings.Contains(out, w) {
					t.Errorf("expected output to contain %q, got:\n%s", w, out)
				}
			}
		})
	}
}

func TestPolicyActionsSection(t *testing.T) {
	warnFor := func(pkg, version string) *policyv1.Action {
		return &policyv1.Action{
			Type:        policyv1.ActionType_ACTION_TYPE_WARN,
			PolicyName:  "policy/ci/pr-review.yaml",
			RuleName:    "pr-license-check",
			Reason:      "No license information detected",
			Remediation: "Verify the dependency's license manually",
			Entrypoint:  "diff_dependency_change",
			Subject:     &policyv1.Subject{Package: pkg, Version: version, Ecosystem: "go"},
		}
	}

	t.Run("NoPoliciesRendersNothing", func(t *testing.T) {
		var buf bytes.Buffer
		PolicyActionsSection(&buf, 0, nil)
		if buf.Len() != 0 {
			t.Fatalf("expected no output, got %q", buf.String())
		}
	})

	t.Run("AllPassed", func(t *testing.T) {
		var buf bytes.Buffer
		PolicyActionsSection(&buf, 1, nil)
		out := buf.String()
		for _, w := range []string{"Policy Evaluation:", "1 policy file evaluated", "all passed"} {
			if !strings.Contains(out, w) {
				t.Fatalf("expected output to contain %q, got %q", w, out)
			}
		}
	})

	t.Run("DeduplicatesRepeatedRuleWithSubjects", func(t *testing.T) {
		var actions []*policyv1.Action
		pkgs := []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"}
		for _, p := range pkgs {
			actions = append(actions, warnFor("example.com/"+p, "1.0.0"))
		}
		var buf bytes.Buffer
		PolicyActionsSection(&buf, 1, actions)
		out := buf.String()

		if got := strings.Count(out, "pr-license-check"); got != 1 {
			t.Fatalf("expected one deduplicated group, rule appears %d times in %q", got, out)
		}
		for _, w := range []string{"12 warned", "(12 packages)", "No license information detected", "… and 7 more", "Remediation:", "example.com/a @ 1.0.0"} {
			if !strings.Contains(out, w) {
				t.Fatalf("expected output to contain %q, got %q", w, out)
			}
		}
		if strings.Contains(out, "example.com/f @") {
			t.Fatalf("expected subject list capped at 5, got %q", out)
		}
	})

	t.Run("DeniesRenderBeforeWarns", func(t *testing.T) {
		deny := &policyv1.Action{
			Type:       policyv1.ActionType_ACTION_TYPE_DENY,
			PolicyName: "policy/ci/pr-review.yaml",
			RuleName:   "pr-block-vulnerable-deps",
			Reason:     "New dependency introduces critical severity vulnerabilities",
		}
		actions := []*policyv1.Action{warnFor("example.com/a", "1.0.0"), deny}
		var buf bytes.Buffer
		PolicyActionsSection(&buf, 1, actions)
		out := buf.String()
		denyIdx := strings.Index(out, "[DENY]")
		warnIdx := strings.Index(out, "[WARN]")
		if denyIdx < 0 || warnIdx < 0 || denyIdx > warnIdx {
			t.Fatalf("expected [DENY] before [WARN], got %q", out)
		}
		if !strings.Contains(out, "1 denied") || !strings.Contains(out, "1 warned") {
			t.Fatalf("expected status counts in %q", out)
		}
	})

	t.Run("AdvisorySubjectsUseFindingsNoun", func(t *testing.T) {
		vulnWarn := func(advisory, pkg string) *policyv1.Action {
			return &policyv1.Action{
				Type:       policyv1.ActionType_ACTION_TYPE_WARN,
				PolicyName: "p.yaml",
				RuleName:   "kev-check",
				Reason:     "Known exploited vulnerability",
				Subject:    &policyv1.Subject{Advisory: advisory, Package: pkg, Version: "1.0.0"},
			}
		}
		var buf bytes.Buffer
		PolicyActionsSection(&buf, 1, []*policyv1.Action{
			vulnWarn("GHSA-aaaa-bbbb-cccc", "left-pad"),
			vulnWarn("GHSA-dddd-eeee-ffff", "right-pad"),
		})
		out := buf.String()
		for _, w := range []string{"(2 findings)", "GHSA-aaaa-bbbb-cccc (left-pad @ 1.0.0)"} {
			if !strings.Contains(out, w) {
				t.Fatalf("expected output to contain %q, got %q", w, out)
			}
		}
	})

	t.Run("AllowActionsCountAsPassed", func(t *testing.T) {
		allow := &policyv1.Action{Type: policyv1.ActionType_ACTION_TYPE_ALLOW, PolicyName: "p.yaml", RuleName: "ok"}
		var buf bytes.Buffer
		PolicyActionsSection(&buf, 1, []*policyv1.Action{allow})
		out := buf.String()
		if !strings.Contains(out, "all passed") {
			t.Fatalf("expected all passed for allow-only actions, got %q", out)
		}
		if strings.Contains(out, "[WARN]") || strings.Contains(out, "[DENY]") {
			t.Fatalf("allow actions must not render as findings: %q", out)
		}
	})
}

// TestPolicyActionsSection_RendersMessageBesideReason pins that a rule
// supplying both fields keeps its extra context in text output. Reason is the
// headline and message adds detail; showing only the reason would drop
// information that the JSON contract still carries.
func TestPolicyActionsSection_RendersMessageBesideReason(t *testing.T) {
	act := &policyv1.Action{
		Type:       policyv1.ActionType_ACTION_TYPE_WARN,
		PolicyName: "p.yaml",
		RuleName:   "r",
		Reason:     "License not on the allowlist",
		Message:    "Found GPL-3.0 via a transitive dependency",
	}

	var buf bytes.Buffer
	PolicyActionsSection(&buf, 1, []*policyv1.Action{act})
	out := buf.String()

	for _, want := range []string{"License not on the allowlist", "Found GPL-3.0 via a transitive dependency"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n---\n%s", want, out)
		}
	}

	// A message identical to the reason must not print twice.
	dup := &policyv1.Action{
		Type: policyv1.ActionType_ACTION_TYPE_WARN, PolicyName: "p.yaml", RuleName: "r",
		Reason: "same text", Message: "same text",
	}
	buf.Reset()
	PolicyActionsSection(&buf, 1, []*policyv1.Action{dup})
	if got := strings.Count(buf.String(), "same text"); got != 1 {
		t.Errorf("duplicate message rendered %d times, want 1\n---\n%s", got, buf.String())
	}
}
