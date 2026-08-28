package cmd

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/spf13/cobra"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	triagev1 "github.com/temporalio/deputy/gen/deputy/triage/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/inventory"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/services"
	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestTriageCommandTextOutput(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	mockClients := newMockTriageClients(t, triageMockData{
		Findings: []vulnerability.Finding{{
			AdvisoryID: "GHSA-1234-5678-9012",
			Dependency: dependency.ID{Name: "github.com/acme/lib", Ecosystem: "Go"},
			Version:    "v1.0.0",
			Affected:   true,
		}},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GHSA-1234-5678-9012": {
				Id:       "GHSA-1234-5678-9012",
				Severity: vulnerability.NewSeverity("HIGH", "GHSA"),
			},
		},
	})

	cmd := newTriageTestCommand(t)
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClients, cmd, []string{tmpDir}); err != nil {
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

	mockClients := newMockTriageClients(t, triageMockData{
		Findings: []vulnerability.Finding{{
			AdvisoryID: "GHSA-1234-5678-9012",
			Dependency: dependency.ID{Name: "github.com/acme/lib", Ecosystem: "Go"},
			Version:    "v1.0.0",
			Affected:   true,
		}},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GHSA-1234-5678-9012": {
				Id:       "GHSA-1234-5678-9012",
				Severity: vulnerability.NewSeverity("HIGH", "GHSA"),
			},
		},
	})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClients, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport triagev1.TriageResponse
	if err := protojson.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if triageReport.Stats.Total != 1 {
		t.Errorf("expected 1 vulnerability, got %d", triageReport.Stats.Total)
	}
	if triageReport.Stats.High != 1 {
		t.Errorf("expected 1 high severity vuln, got %d", triageReport.Stats.High)
	}
}

func TestTriageCommandIgnoreUnfixed(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	mockClients := newMockTriageClients(t, triageMockData{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "GHSA-unfixed",
				Dependency: dependency.ID{Name: "github.com/acme/lib", Ecosystem: "Go"},
				Version:    "v1.0.0",
				Affected:   true,
			},
			{
				AdvisoryID: "GHSA-fixed",
				Version:    "v1.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GHSA-unfixed": {
				Id:            "GHSA-unfixed",
				Severity:      vulnerability.NewSeverity("HIGH", "GHSA"),
				FixedVersions: nil, // No fix available
			},
			"GHSA-fixed": {
				Id:            "GHSA-fixed",
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

	if err := runTriage(mockClients, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport triagev1.TriageResponse
	if err := protojson.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	// Only the fixed vulnerability should remain
	if triageReport.Stats.Total != 1 {
		t.Errorf("expected 1 vulnerability after filtering unfixed, got %d", triageReport.Stats.Total)
	}
}

func TestTriageCommandFromReport(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	// Create a mock scan report in proto JSON format
	scanResp := &scanv1.ScanResponse{
		Target: &targetv1.Target{
			DisplayPath: "github.com/test/repo",
			CommitHash:  "abc123",
		},
		Findings: []*vulnerabilityv1.Finding{
			{
				AdvisoryId: "CVE-2024-5678",
				Package: &dependencyv1.Package{
					Name:      "lodash",
					Version:   "4.17.20",
					Ecosystem: "npm",
					Direct:    true,
				},
				Advisory: &vulnerabilityv1.Advisory{
					Id:      "CVE-2024-5678",
					Summary: "Test vulnerability",
					Severity: &vulnerabilityv1.Severity{
						Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
						Type:  vulnerabilityv1.SeverityType_SEVERITY_TYPE_GHSA,
					},
				},
				Affected: true,
			},
		},
		Stats: &vulnerabilityv1.Stats{
			Total:  1,
			Unique: 1,
			High:   1,
		},
	}

	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}
	reportData, err := opts.Marshal(scanResp)
	if err != nil {
		t.Fatalf("failed to marshal report: %v", err)
	}
	reportPath := filepath.Join(tmpDir, "report.json")
	if err := os.WriteFile(reportPath, reportData, 0644); err != nil {
		t.Fatalf("failed to write report: %v", err)
	}

	// Create mock clients (won't be used when reading from report)
	mockClients := newMockTriageClients(t, triageMockData{})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "report", reportPath)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClients, cmd, nil); err != nil {
		t.Fatalf("runTriage from report: %v", err)
	}

	var triageReport triagev1.TriageResponse
	if err := protojson.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if triageReport.Stats.Total != 1 {
		t.Errorf("expected 1 vulnerability from report, got %d", triageReport.Stats.Total)
	}
}

func TestTriageCommandNoVulnerabilities(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	mockClients := newMockTriageClients(t, triageMockData{})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClients, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport triagev1.TriageResponse
	if err := protojson.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if triageReport.Stats.Total != 0 {
		t.Errorf("expected 0 vulnerabilities, got %d", triageReport.Stats.Total)
	}
}

func TestTriageCommandInvalidFormat(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	mockClients := newMockTriageClients(t, triageMockData{})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "xml")

	err := runTriage(mockClients, cmd, []string{tmpDir})
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
	cmd.SetContext(t.Context())
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

// triageMockData holds mock findings and advisories for test clients.
type triageMockData struct {
	Findings   []vulnerability.Finding
	Advisories map[string]*vulnerabilityv1.Advisory
	// Warnings are the scan's non-fatal warnings, such as an advisory whose
	// record could not be expanded.
	Warnings []string
}

// mockTriageScanHandler is a mock ScanServiceHandler for testing.
type mockTriageScanHandler struct {
	scanv1connect.UnimplementedScanServiceHandler
	data triageMockData
}

func (m *mockTriageScanHandler) Scan(ctx context.Context, req *connect.Request[scanv1.ScanRequest]) (*connect.Response[scanv1.ScanResponse], error) {
	// Compute stats from findings and advisories
	cons := vulnerability.Consolidate(m.data.Findings, m.data.Advisories)
	stats := vulnerability.StatsFromConsolidated(cons, len(m.data.Findings))

	// Build a scanning.Result with the mock data
	result := &scanning.Result{
		Target: inventory.Target{
			Kind:        targets.KindDir,
			LocalPath:   req.Msg.Target,
			DisplayPath: req.Msg.Target,
		},
		Findings:   m.data.Findings,
		Advisories: m.data.Advisories,
		Stats:      stats,
		Warnings:   m.data.Warnings,
	}

	// Convert to proto
	response := internalproto.ScanningResultToProto(result)
	return connect.NewResponse(response), nil
}

// newMockTriageClients creates mock clients that return mock vulnerability data.
func newMockTriageClients(t *testing.T, mock triageMockData) *services.Clients {
	t.Helper()

	// Create mock handler
	handler := &mockTriageScanHandler{data: mock}

	// Build HTTP mux with the mock handler
	mux := http.NewServeMux()
	path, h := scanv1connect.NewScanServiceHandler(handler)
	mux.Handle(path, h)

	// Create in-process transport
	transport := services.NewInProcessTransport(mux)
	httpClient := transport.HTTPClient()

	return &services.Clients{
		Vulns: scanv1connect.NewScanServiceClient(httpClient, ""),
	}
}

// TestTriageCommandCarriesScanWarnings pins the guarantee triage inherits from
// the scan it summarizes. An advisory whose record could not be expanded is
// absent from the findings, so the summary looks like the whole picture; the
// warning is the only thing saying otherwise, and it has to reach both the JSON
// output and a text reader's terminal. The zero-finding cases matter most: those
// are the runs that read as clean.
func TestTriageCommandCarriesScanWarnings(t *testing.T) {
	t.Parallel()

	const unresolved = "osv: advisory GO-2026-6255 reported for github.com/moby/buildkit@v0.30.0 is absent from osv's findings: withdrawn"

	vulnerable := []vulnerability.Finding{{
		AdvisoryID: "GHSA-1234-5678-9012",
		Dependency: dependency.ID{Name: "github.com/acme/lib", Ecosystem: "Go"},
		Version:    "v1.0.0",
		Affected:   true,
	}}
	advisories := map[string]*vulnerabilityv1.Advisory{
		"GHSA-1234-5678-9012": {
			Id:       "GHSA-1234-5678-9012",
			Severity: vulnerability.NewSeverity("HIGH", "GHSA"),
		},
	}

	tests := []struct {
		name string
		// fromReport routes through --report instead of a live scan.
		fromReport bool
		findings   []vulnerability.Finding
		advisories map[string]*vulnerabilityv1.Advisory
		warnings   []string
		want       []string
	}{
		{
			// The run that used to read as clean: nothing found, and no sign
			// that a record went missing on the way.
			name:     "live scan with no findings still reports the warning",
			warnings: []string{unresolved},
			want:     []string{unresolved},
		},
		{
			name:       "live scan with findings reports the warning",
			findings:   vulnerable,
			advisories: advisories,
			warnings:   []string{unresolved},
			want:       []string{unresolved},
		},
		{
			name:       "clean live scan reports no warning",
			findings:   vulnerable,
			advisories: advisories,
		},
		{
			name:       "report with no findings still reports the warning",
			fromReport: true,
			warnings:   []string{unresolved},
			want:       []string{unresolved},
		},
		{
			name:       "report with findings reports the warning",
			fromReport: true,
			findings:   vulnerable,
			advisories: advisories,
			warnings:   []string{unresolved},
			want:       []string{unresolved},
		},
		{
			name:       "clean report reports no warning",
			fromReport: true,
			findings:   vulnerable,
			advisories: advisories,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tmpDir := t.TempDir()
			mock := triageMockData{Findings: tt.findings, Advisories: tt.advisories, Warnings: tt.warnings}
			cmd := newTriageTestCommand(t)
			mustSetFlag(t, cmd, "format", "json")
			var stdout, stderr bytes.Buffer
			cmd.SetOut(&stdout)
			cmd.SetErr(&stderr)

			var args []string
			if tt.fromReport {
				mustSetFlag(t, cmd, "report", writeTriageReport(t, tmpDir, mock))
			} else {
				writeGoModule(t, tmpDir)
				initGitRepo(t, tmpDir)
				args = []string{tmpDir}
			}

			if err := runTriage(newMockTriageClients(t, mock), cmd, args); err != nil {
				t.Fatalf("runTriage: %v", err)
			}

			var got triagev1.TriageResponse
			if err := protojson.Unmarshal(stdout.Bytes(), &got); err != nil {
				t.Fatalf("parse JSON output: %v (output = %s)", err, stdout.String())
			}
			if !slices.Equal(got.GetWarnings(), tt.want) {
				t.Fatalf("triage response warnings = %q, want %q", got.GetWarnings(), tt.want)
			}
			// The text reader never sees the JSON, so the same fact has to
			// reach stderr on every path that produces it.
			for _, warning := range tt.want {
				if !strings.Contains(stderr.String(), warning) {
					t.Errorf("stderr = %q, want it to mention %q", stderr.String(), warning)
				}
			}
		})
	}
}

// writeTriageReport marshals mock scan data the way "deputy scan --format json"
// does and returns the path, so a --report test consumes the real wire format
// rather than a hand-built stand-in.
func writeTriageReport(t *testing.T, dir string, mock triageMockData) string {
	t.Helper()
	cons := vulnerability.Consolidate(mock.Findings, mock.Advisories)
	scanResp := internalproto.ScanningResultToProto(&scanning.Result{
		Target: inventory.Target{
			Kind:        targets.KindDir,
			LocalPath:   dir,
			DisplayPath: "github.com/test/repo",
		},
		Findings:   mock.Findings,
		Advisories: mock.Advisories,
		Stats:      vulnerability.StatsFromConsolidated(cons, len(mock.Findings)),
		Warnings:   mock.Warnings,
	})
	data, err := internalproto.CLIJSONMarshalOptions().Marshal(scanResp)
	if err != nil {
		t.Fatalf("marshal scan report: %v", err)
	}
	path := filepath.Join(dir, "report.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write scan report: %v", err)
	}
	return path
}
