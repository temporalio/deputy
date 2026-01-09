package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/scanning"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/spf13/cobra"
)

func newTestRoot(out, errW *bytes.Buffer) *cobra.Command {
	root := &cobra.Command{
		Use:           "deputy",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	root.SetOut(out)
	root.SetErr(errW)
	RegisterCommands(root, Dependencies{})
	return root
}

func writeScanReportFile(t *testing.T, report ScanResult) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "scan-report-*.json")
	if err != nil {
		t.Fatalf("create temp report: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(report); err != nil {
		t.Fatalf("encode report: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close report: %v", err)
	}
	return f.Name()
}

func TestCLIOutput_TriageFromReport_WritesToCommandOut(t *testing.T) {
	v := report.Vulnerability{
		ID:           "OSV-TEST-1",
		Package:      "github.com/acme/mod",
		Version:      "v1.0.0",
		Ecosystem:    "Go",
		Severity:     "9.8",
		SeverityType: "CVSS_V3",
		FixedVersions: []string{
			"v1.0.1",
		},
		IsDirect: true,
	}
	findings, advisories := report.SplitVulnerabilities([]report.Vulnerability{v})
	result := scanning.Result{
		Target: inventory.Target{
			DisplayPath: "github.com/acme/repo",
			Ref:         "HEAD",
			CommitHash:  "deadbeef",
		},
		Findings:   findings,
		Advisories: advisories,
	}
	cons := vulnerability.Consolidate(result.Findings, result.Advisories)
	result.Stats = vulnerability.StatsFromConsolidated(cons, len(result.Findings))
	scanReport := buildScanReport(result)
	path := writeScanReportFile(t, scanReport)

	var out, errBuf bytes.Buffer
	root := newTestRoot(&out, &errBuf)
	root.SetArgs([]string{"triage", "--report", path, "--format", "text"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
	got := out.String()
	for _, want := range []string{"Triage Summary:", "Target:", "Commit:"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected stdout to contain %q, got %q", want, got)
		}
	}
}

func TestCLIOutput_FixFromReport_WritesToCommandOut(t *testing.T) {
	v := report.Vulnerability{
		ID:           "OSV-TEST-1",
		Package:      "github.com/acme/mod",
		Version:      "v1.0.0",
		Ecosystem:    "Go",
		Severity:     "9.8",
		SeverityType: "CVSS_V3",
		FixedVersions: []string{
			"v1.0.1",
		},
		IsDirect: true,
	}
	findings, advisories := report.SplitVulnerabilities([]report.Vulnerability{v})
	result := scanning.Result{
		Target: inventory.Target{
			DisplayPath: "github.com/acme/repo",
			Ref:         "HEAD",
			CommitHash:  "deadbeef",
		},
		Findings:   findings,
		Advisories: advisories,
	}
	cons := vulnerability.Consolidate(result.Findings, result.Advisories)
	result.Stats = vulnerability.StatsFromConsolidated(cons, len(result.Findings))
	scanReport := buildScanReport(result)
	path := writeScanReportFile(t, scanReport)

	var out, errBuf bytes.Buffer
	root := newTestRoot(&out, &errBuf)
	root.SetArgs([]string{"fix", "--report", path, "--format", "text"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("execute: %v", err)
	}

	if errBuf.Len() != 0 {
		t.Fatalf("unexpected stderr: %q", errBuf.String())
	}
	got := out.String()
	if !strings.Contains(got, "Remediation Plan:") {
		t.Fatalf("expected stdout to contain remediation header, got %q", got)
	}
}
