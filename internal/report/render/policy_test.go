package render

import (
	"bytes"
	"strings"
	"testing"

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
		want        []string   // strings that must appear
		wantNot     []string   // strings that must NOT appear
		wantNone    bool       // expect no output at all
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
		name        string
		findings    []report.PolicyFinding
		wantDenies  int
		wantWarns   int
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
