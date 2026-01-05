package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/dependency"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/spf13/cobra"
)

func TestTriageCommandTextOutput(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	scanner := newMockTriageScanner(t, triageMockData{
		Findings: []vulnerability.Finding{{
			AdvisoryID: "GHSA-1234-5678-9012",
			Dependency: dependency.ID{Name: "github.com/acme/lib", Ecosystem: "Go"},
			Version:    "v1.0.0",
			Affected:   true,
		}},
		Advisories: map[string]vulnerability.Advisory{
			"GHSA-1234-5678-9012": {
				ID:       "GHSA-1234-5678-9012",
				Severity: vulnerability.NewSeverity("HIGH", "GHSA"),
			},
		},
	})

	cmd := newTriageTestCommand(t)
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(scanner, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	output := stdout.String()
	// Text output shows package summary, not individual vuln IDs
	if !strings.Contains(output, "github.com/acme/lib") {
		t.Errorf("expected output to contain package name, got: %s", output)
	}
	if !strings.Contains(output, "HIGH") {
		t.Errorf("expected output to contain severity, got: %s", output)
	}
	if !strings.Contains(output, "Critical/High: 1") {
		t.Errorf("expected output to show 1 critical/high vuln, got: %s", output)
	}
}

func TestTriageCommandJSONOutput(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	scanner := newMockTriageScanner(t, triageMockData{
		Findings: []vulnerability.Finding{{
			AdvisoryID: "CVE-2024-1234",
			Version:    "v1.0.0",
			Affected:   true,
		}},
		Advisories: map[string]vulnerability.Advisory{
			"CVE-2024-1234": {
				ID:       "CVE-2024-1234",
				Severity: vulnerability.NewSeverity("CRITICAL", "GHSA"),
			},
		},
	})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(scanner, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if triageReport.Stats.TotalVulns != 1 {
		t.Errorf("expected 1 total vulnerability, got %d", triageReport.Stats.TotalVulns)
	}
	if triageReport.Stats.CriticalSev != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", triageReport.Stats.CriticalSev)
	}
}

func TestTriageCommandIgnoreUnfixed(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	scanner := newMockTriageScanner(t, triageMockData{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "GHSA-unfixed",
				Version:    "v1.0.0",
				Affected:   true,
			},
			{
				AdvisoryID: "GHSA-fixed",
				Version:    "v1.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]vulnerability.Advisory{
			"GHSA-unfixed": {
				ID:            "GHSA-unfixed",
				Severity:      vulnerability.NewSeverity("HIGH", "GHSA"),
				FixedVersions: nil, // No fix available
			},
			"GHSA-fixed": {
				ID:            "GHSA-fixed",
				Severity:      vulnerability.NewSeverity("MEDIUM", "GHSA"),
				FixedVersions: []string{"v1.1.0"},
			},
		},
	})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "ignore-unfixed", "true")
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(scanner, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	// Only the fixed vulnerability should remain
	if triageReport.Stats.TotalVulns != 1 {
		t.Errorf("expected 1 vulnerability after filtering unfixed, got %d", triageReport.Stats.TotalVulns)
	}
}

func TestTriageCommandFromReport(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a mock scan report JSON file
	scanReport := ScanResult{
		Vulnerabilities: []report.Vulnerability{
			{
				ID:           "CVE-2024-5678",
				Package:      "lodash",
				Version:      "4.17.20",
				Severity:     "HIGH",
				SeverityType: "GHSA",
				Affected:     true,
			},
		},
		Stats: vulnerability.Stats{
			TotalVulns:   1,
			UniqueVulns:  1,
			HighSeverity: 1,
		},
	}
	reportPath := filepath.Join(tmpDir, "report.json")
	reportData, err := json.Marshal(scanReport)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}
	if err := os.WriteFile(reportPath, reportData, 0644); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	// Create scanner (won't be used when reading from report)
	scanner := newMockTriageScanner(t, triageMockData{})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "report", reportPath)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(scanner, cmd, nil); err != nil {
		t.Fatalf("runTriage from report: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if triageReport.Stats.TotalVulns != 1 {
		t.Errorf("expected 1 vulnerability from report, got %d", triageReport.Stats.TotalVulns)
	}
}

func TestTriageCommandNoVulnerabilities(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	scanner := newMockTriageScanner(t, triageMockData{}) // No vulnerabilities

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(scanner, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if triageReport.Stats.TotalVulns != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", triageReport.Stats.TotalVulns)
	}
}

func TestTriageCommandInvalidFormat(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	scanner := newMockTriageScanner(t, triageMockData{})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "xml")

	err := runTriage(scanner, cmd, []string{tmpDir})
	if err == nil {
		t.Fatal("expected error for invalid format")
	}
	if !strings.Contains(err.Error(), "unsupported") {
		t.Errorf("expected unsupported format error, got: %v", err)
	}
}

// newTriageTestCommand creates a cobra command with triage flags for testing.
func newTriageTestCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{
		Use: "triage",
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	cmd.SetContext(context.Background())
	cmd.SetIn(strings.NewReader(""))
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	// Add all triage flags
	cmd.Flags().String("report", "", "")
	cmd.Flags().String("ref", "", "")
	cmd.Flags().StringSlice("ecosystems", nil, "")
	cmd.Flags().Bool("ignore-unfixed", false, "")
	cmd.Flags().String("published-before", "", "")
	cmd.Flags().String("published-after", "", "")
	cmd.Flags().String("as-of", "", "")
	cmd.Flags().StringP("format", "f", "text", "")
	cmd.Flags().String("agent", "", "")
	cmd.Flags().String("agent-model", "", "")
	cmd.Flags().String("agent-sandbox", "read-only", "")
	cmd.Flags().Bool("agent-full-auto", false, "")
	cmd.Flags().String("agent-thread", "", "")
	cmd.Flags().Bool("agent-include-plan-tool", true, "")
	cmd.Flags().Bool("agent-skip-git-check", true, "")
	cmd.Flags().StringArray("policy", nil, "")
	cmd.Flags().Bool("show-db-info", false, "")

	return cmd
}

// triageMockData holds mock findings and advisories for test scanners.
type triageMockData struct {
	Findings   []vulnerability.Finding
	Advisories map[string]vulnerability.Advisory
}

// newMockTriageScanner creates a scanner that returns mock vulnerability data.
func newMockTriageScanner(t *testing.T, mock triageMockData) *Scanner {
	t.Helper()
	return &Scanner{
		service: scan.NewServiceWithConfig(&scan.ServiceConfig{
			CollectInventory: func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error) {
				return []*extractor.Package{
					{
						Name:      "github.com/acme/lib",
						Version:   "v1.0.0",
						PURLType:  purl.TypeGolang,
						Locations: []string{"go.mod"},
					},
				}, nil
			},
			QueryVulnerabilities: func(ctx context.Context, client osv.Client, inputs []osv.PkgInput) ([]vulnerability.Finding, map[string]vulnerability.Advisory, error) {
				return mock.Findings, mock.Advisories, nil
			},
		}),
	}
}
