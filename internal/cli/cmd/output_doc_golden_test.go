package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/output"
	"github.com/temporalio/deputy/internal/report/render"
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
				stats := &vulnerabilityv1.Stats{
					Unique:       2,
					Critical:     1,
					High:         1,
					Medium:       0,
					Low:          1,
					FixAvailable: 2,
					DirectDeps:   1,
					IndirectDeps: 4,
					Duplicates:   0,
				}
				const packagesWithVulns, topPackages = 5, 2
				doc := render.TriageSummaryDoc(render.TargetSummary{
					Repo:   "github.com/acme/repo",
					Ref:    "main",
					Commit: "deadbeef",
				}, stats, packagesWithVulns)
				doc.AddBlank()
				doc.AddLine(output.Span{Text: render.TopImpactedTitle(packagesWithVulns, topPackages)})
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
				// Use simple values directly - golden test is for render output, not proto structure
				repo := "github.com/acme/repo"
				commit := "deadbeef"
				stdlibUpgrade := "v1.23.0"
				totalCommands := 3
				runnableCommands := 2
				commandCount := 1

				doc, _ := render.FixSummaryDoc(render.TargetSummary{
					Repo:   repo,
					Ref:    "main",
					Commit: commit,
				}, stdlibUpgrade, totalCommands, runnableCommands, commandCount)

				var buf bytes.Buffer
				if err := doc.Render(&buf, output.PlainStyles()); err != nil {
					return "", err
				}
				return buf.String(), nil
			},
		},
	}

	for _, tt := range tests {
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
