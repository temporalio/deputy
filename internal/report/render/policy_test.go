package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/report"
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
