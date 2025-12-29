package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/remediation"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/report/render"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestOutputDocs_Golden(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		golden string
		render func() (string, error)
	}{
		{
			name:   "ScanHeader",
			golden: "scan_header.golden",
			render: func() (string, error) {
				doc := render.ScanResultsHeaderDoc("github.com/acme/repo", "main", "deadbeef", "https://github.com/acme/repo")
				var buf bytes.Buffer
				if err := doc.Render(&buf, output.PlainStyles()); err != nil {
					return "", err
				}
				return buf.String(), nil
			},
		},
		{
			name:   "DiffHeader",
			golden: "diff_header.golden",
			render: func() (string, error) {
				doc := render.DiffHeaderDoc("main", "WORKING")
				var buf bytes.Buffer
				if err := doc.Render(&buf, output.PlainStyles()); err != nil {
					return "", err
				}
				return buf.String(), nil
			},
		},
		{
			name:   "TriageSummary",
			golden: "triage_summary.golden",
			render: func() (string, error) {
				triageReport := report.TriageReport{
					Target: report.Target{
						Repo:   "github.com/acme/repo",
						Ref:    "main",
						Commit: "deadbeef",
					},
					Stats: vulnerability.Stats{
						UniqueVulns:     2,
						CriticalSev:     1,
						HighSeverity:    1,
						MedSeverity:     0,
						LowSeverity:     1,
						FixAvailable:    2,
						DirectDeps:      1,
						IndirectDeps:    4,
						DuplicatesFound: 0,
					},
					TopPackages: []report.TriagePackageSummary{
						{Package: "a", Version: "1", Severity: "HIGH", SeverityType: "GHSA"},
						{Package: "b", Version: "2", Severity: "MED", SeverityType: "GHSA"},
					},
					PackagesWithVulns: 5,
				}
				doc := render.TriageSummaryDoc(render.TargetSummary{
					Repo:   triageReport.Target.Repo,
					Ref:    triageReport.Target.Ref,
					Commit: triageReport.Target.Commit,
				}, triageReport.Stats, triageReport.PackagesWithVulns)
				doc.AddBlank()
				doc.AddLine(output.Span{Text: render.TopImpactedTitle(triageReport.PackagesWithVulns, len(triageReport.TopPackages))})
				doc.AddLine(output.Span{Text: "  Severity shown per package = highest vuln severity in that package.", Style: output.StyleMeta})

				var buf bytes.Buffer
				if err := doc.Render(&buf, output.PlainStyles()); err != nil {
					return "", err
				}
				return buf.String(), nil
			},
		},
		{
			name:   "FixSummary",
			golden: "fix_summary.golden",
			render: func() (string, error) {
				plan := remediationPlan{
					Target: report.Target{
						Repo:   "github.com/acme/repo",
						Ref:    "main",
						Commit: "deadbeef",
					},
					StdlibUpgrade: "v1.23.0",
					Commands:      []remediation.Command{{Command: "go get example.com/a@v1.2.3"}},
					Stats: remediationPlanSummary{
						TotalCommands:    3,
						RunnableCommands: 2,
					},
				}
				doc, _ := render.FixSummaryDoc(render.TargetSummary{
					Repo:   plan.Target.Repo,
					Ref:    plan.Target.Ref,
					Commit: plan.Target.Commit,
				}, plan.StdlibUpgrade, plan.Stats.TotalCommands, plan.Stats.RunnableCommands, len(plan.Commands))

				var buf bytes.Buffer
				if err := doc.Render(&buf, output.PlainStyles()); err != nil {
					return "", err
				}
				return buf.String(), nil
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.render()
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			goldenPath := filepath.Join("testdata", tt.golden)
			wantBytes, err := os.ReadFile(goldenPath)
			if err != nil {
				t.Fatalf("read golden %s: %v", goldenPath, err)
			}
			want := strings.TrimSuffix(string(wantBytes), "\n")
			got = strings.TrimSuffix(got, "\n")
			if got != want {
				t.Fatalf("golden mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
		})
	}
}
