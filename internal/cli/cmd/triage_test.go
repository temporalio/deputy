package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"connectrpc.com/connect"

	diffv1 "github.com/picatz/deputy/gen/deputy/diff/v1"
	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/client"
	"github.com/picatz/deputy/internal/dependency"
	internalproto "github.com/picatz/deputy/internal/proto"
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

	mockClient := newMockTriageClient(t, triageMockData{
		Findings: []vulnerability.Finding{{
			AdvisoryID: "GHSA-1234-5678-9012",
			Dependency: dependency.ID{Name: "github.com/acme/lib", Ecosystem: "Go"},
			Version:    "v1.0.0",
			Affected:   true,
		}},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"GHSA-1234-5678-9012": {
				Id:       "GHSA-1234-5678-9012",
				Severity: vulnerability.NewSeverity("HIGH", "GHSA"),
			},
		},
	})

	cmd := newTriageTestCommand(t)
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClient, cmd, []string{tmpDir}); err != nil {
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

	mockClient := newMockTriageClient(t, triageMockData{
		Findings: []vulnerability.Finding{{
			AdvisoryID: "CVE-2024-1234",
			Version:    "v1.0.0",
			Affected:   true,
		}},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1234": {
				Id:       "CVE-2024-1234",
				Severity: vulnerability.NewSeverity("CRITICAL", "GHSA"),
			},
		},
	})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClient, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if triageReport.Stats.Total != 1 {
		t.Errorf("expected 1 total vulnerability, got %d", triageReport.Stats.Total)
	}
	if triageReport.Stats.Critical != 1 {
		t.Errorf("expected 1 critical vulnerability, got %d", triageReport.Stats.Critical)
	}
}

func TestTriageCommandIgnoreUnfixed(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeGoModule(t, tmpDir)
	initGitRepo(t, tmpDir)

	mockClient := newMockTriageClient(t, triageMockData{
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
		Advisories: map[string]vulnerabilityv1.Advisory{
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

	if err := runTriage(mockClient, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
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
		Stats: vulnerabilityv1.Stats{
			Total:  1,
			Unique: 1,
			High:   1,
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

	// Create mock client (won't be used when reading from report)
	mockClient := newMockTriageClient(t, triageMockData{})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "report", reportPath)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClient, cmd, nil); err != nil {
		t.Fatalf("runTriage from report: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
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

	mockClient := newMockTriageClient(t, triageMockData{}) // No vulnerabilities

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "json")
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)

	if err := runTriage(mockClient, cmd, []string{tmpDir}); err != nil {
		t.Fatalf("runTriage: %v", err)
	}

	var triageReport report.TriageReport
	if err := json.Unmarshal(stdout.Bytes(), &triageReport); err != nil {
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

	mockClient := newMockTriageClient(t, triageMockData{})

	cmd := newTriageTestCommand(t)
	mustSetFlag(t, cmd, "format", "xml")

	err := runTriage(mockClient, cmd, []string{tmpDir})
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

// triageMockData holds mock findings and advisories for test clients.
type triageMockData struct {
	Findings   []vulnerability.Finding
	Advisories map[string]vulnerabilityv1.Advisory
}

// mockTriageClient is a mock client.Client for testing triage command.
type mockTriageClient struct {
	data triageMockData
}

// Ensure mockTriageClient implements client.Client at compile time.
var _ client.Client = (*mockTriageClient)(nil)

// newMockTriageClient creates a mock client that returns mock vulnerability data.
func newMockTriageClient(t *testing.T, mock triageMockData) *mockTriageClient {
	t.Helper()
	return &mockTriageClient{data: mock}
}

func (m *mockTriageClient) Scan(ctx context.Context, req *connect.Request[scanv1.ScanRequest]) (*connect.Response[scanv1.ScanResponse], error) {
	// Compute stats from findings and advisories
	cons := vulnerability.Consolidate(m.data.Findings, m.data.Advisories)
	stats := vulnerability.StatsFromConsolidated(cons, len(m.data.Findings))

	// Build a scan.Result with the mock data
	result := &scan.Result{
		Target: scan.Target{
			LocalPath:   req.Msg.Target,
			DisplayPath: req.Msg.Target,
		},
		Findings:   m.data.Findings,
		Advisories: m.data.Advisories,
		Stats:      stats,
	}

	// Convert to proto
	response := internalproto.ScanResultToProto(result)
	return connect.NewResponse(response), nil
}

func (m *mockTriageClient) StreamScan(ctx context.Context, req *connect.Request[scanv1.StreamScanRequest]) (client.Stream[scanv1.ScanProgress], error) {
	return nil, nil
}

func (m *mockTriageClient) ListPackages(ctx context.Context, req *connect.Request[listv1.ListPackagesRequest]) (*connect.Response[listv1.ListPackagesResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) ListEcosystems(ctx context.Context, req *connect.Request[listv1.ListEcosystemsRequest]) (*connect.Response[listv1.ListEcosystemsResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) GenerateSBOM(ctx context.Context, req *connect.Request[sbomv1.GenerateRequest]) (*connect.Response[sbomv1.GenerateResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) DiffSBOM(ctx context.Context, req *connect.Request[sbomv1.DiffRequest]) (*connect.Response[sbomv1.DiffResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) GeneratePlan(ctx context.Context, req *connect.Request[remediationv1.GeneratePlanRequest]) (*connect.Response[remediationv1.GeneratePlanResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) ExecutePlan(ctx context.Context, req *connect.Request[remediationv1.ExecutePlanRequest]) (client.Stream[remediationv1.ExecutionEvent], error) {
	return nil, nil
}

func (m *mockTriageClient) ExecuteWithAgent(ctx context.Context, req *connect.Request[remediationv1.ExecuteWithAgentRequest]) (client.Stream[remediationv1.AgentEvent], error) {
	return nil, nil
}

func (m *mockTriageClient) ResumeAgent(ctx context.Context, req *connect.Request[remediationv1.ResumeAgentRequest]) (client.Stream[remediationv1.AgentEvent], error) {
	return nil, nil
}

func (m *mockTriageClient) ListAgents(ctx context.Context, req *connect.Request[remediationv1.ListAgentsRequest]) (*connect.Response[remediationv1.ListAgentsResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) ApproveStep(ctx context.Context, req *connect.Request[remediationv1.ApproveStepRequest]) (*connect.Response[remediationv1.ApproveStepResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) ScanSecrets(ctx context.Context, req *connect.Request[secretsv1.ScanRequest]) (*connect.Response[secretsv1.ScanResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) StreamScanSecrets(ctx context.Context, req *connect.Request[secretsv1.StreamScanRequest]) (client.Stream[secretsv1.ScanProgress], error) {
	return nil, nil
}

func (m *mockTriageClient) ScanSecretsHistory(ctx context.Context, req *connect.Request[secretsv1.ScanHistoryRequest]) (*connect.Response[secretsv1.ScanHistoryResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) ScanSecretsDiff(ctx context.Context, req *connect.Request[secretsv1.ScanDiffRequest]) (*connect.Response[secretsv1.ScanDiffResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) VerifySecrets(ctx context.Context, req *connect.Request[secretsv1.VerifyRequest]) (*connect.Response[secretsv1.VerifyResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) ListDetectors(ctx context.Context, req *connect.Request[secretsv1.ListDetectorsRequest]) (*connect.Response[secretsv1.ListDetectorsResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) DiffPackages(ctx context.Context, req *connect.Request[diffv1.DiffPackagesRequest]) (*connect.Response[diffv1.DiffPackagesResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) DiffVulnerabilities(ctx context.Context, req *connect.Request[diffv1.DiffVulnerabilitiesRequest]) (*connect.Response[diffv1.DiffVulnerabilitiesResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) DiffContainerImages(ctx context.Context, req *connect.Request[diffv1.DiffContainerImagesRequest]) (*connect.Response[diffv1.DiffContainerImagesResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) BuildGraph(ctx context.Context, req *connect.Request[graphv1.BuildGraphRequest]) (*connect.Response[graphv1.BuildGraphResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) WhyDependency(ctx context.Context, req *connect.Request[graphv1.WhyDependencyRequest]) (*connect.Response[graphv1.WhyDependencyResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) QueryGraph(ctx context.Context, req *connect.Request[graphv1.QueryGraphRequest]) (*connect.Response[graphv1.QueryGraphResponse], error) {
	return nil, nil
}

func (m *mockTriageClient) Mode() client.Mode {
	return client.ModeInProcess
}

func (m *mockTriageClient) Close() error {
	return nil
}
