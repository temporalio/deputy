package cmd

import (
	"bytes"
	"strings"
	"testing"
)

func TestDisplayVulnerabilities_NoVulns(t *testing.T) {
	var buf bytes.Buffer
	DisplayVulnerabilities(&buf, nil)
	out := buf.String()
	if !strings.Contains(out, "No vulnerabilities found") {
		t.Fatalf("expected output to mention no vulns, got %q", out)
	}
}

func TestDisplayPolicyFindings(t *testing.T) {
	tests := []struct {
		name     string
		findings []PolicyFinding
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
			findings: []PolicyFinding{{
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
			DisplayPolicyFindings(&buf, tt.findings)
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
