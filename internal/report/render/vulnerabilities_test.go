package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/scanning"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestDisplayVulnerabilities_NoVulns(t *testing.T) {
	var buf bytes.Buffer
	DisplayVulnerabilities(&buf, scanning.Result{})
	out := buf.String()
	if !strings.Contains(out, "No vulnerabilities found") {
		t.Fatalf("expected output to mention no vulns, got %q", out)
	}
}

func TestUnfixableGuidance(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		cons     []vulnerability.Consolidated
		wantShow bool
		contains []string
	}{
		{
			name:     "no vulnerabilities",
			cons:     nil,
			wantShow: false,
		},
		{
			name: "all have fixes",
			cons: []vulnerability.Consolidated{
				{
					PrimaryID:     "CVE-2024-1234",
					Package:       "example/pkg",
					Version:       "1.0.0",
					FixedVersions: []string{"1.0.1"},
				},
			},
			wantShow: false,
		},
		{
			name: "unfixable direct dependency",
			cons: []vulnerability.Consolidated{
				{
					PrimaryID: "CVE-2024-9999",
					Package:   "example/unfixed",
					Version:   "2.0.0",
					Severity:  "HIGH",
					IsDirect:  true,
					Summary:   "Remote code execution vulnerability",
				},
			},
			wantShow: true,
			contains: []string{
				"example/unfixed@2.0.0",
				"CVE-2024-9999",
				"No fix available",
				"Recommendations",
			},
		},
		{
			name: "unfixable transitive dependency",
			cons: []vulnerability.Consolidated{
				{
					PrimaryID: "GHSA-xxxx-yyyy",
					Package:   "indirect/dep",
					Version:   "0.1.0",
					Severity:  "MEDIUM",
					IsDirect:  false,
				},
			},
			wantShow: true,
			contains: []string{
				"indirect/dep@0.1.0",
				"GHSA-xxxx-yyyy",
				"Transitive dependency",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			UnfixableGuidance(&buf, tt.cons)
			out := buf.String()

			if tt.wantShow {
				if out == "" {
					t.Error("expected guidance output, got empty string")
				}
				for _, want := range tt.contains {
					if !strings.Contains(out, want) {
						t.Errorf("expected output to contain %q, got:\n%s", want, out)
					}
				}
			} else {
				if out != "" {
					t.Errorf("expected no output, got:\n%s", out)
				}
			}
		})
	}
}
