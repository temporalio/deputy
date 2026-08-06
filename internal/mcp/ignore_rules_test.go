package mcp

import (
	"os"
	"path/filepath"
	"testing"

	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
)

// writeIgnoreFile drops a .deputyignore.yaml suppressing the fixture package
// into dir, so tools scanning dir must exclude its findings.
func writeIgnoreFile(t *testing.T, dir string) {
	t.Helper()
	rules := "ignore:\n  - package: github.com/example/widget\n    ecosystem: go\n    reason: test suppression\n"
	if err := os.WriteFile(filepath.Join(dir, ".deputyignore.yaml"), []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestMCPToolsHonorIgnoreRules pins the suppression contract across the MCP
// assessment tools: a finding ignored by the target's .deputyignore.yaml must
// disappear from results and be reported via ignoredCount, matching the CLI's
// "ignored by rules" behavior.
func TestMCPToolsHonorIgnoreRules(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir)
	ctx := t.Context()

	t.Run("scan_directory", func(t *testing.T) {
		mockScan := &mockScanHandler{scanResponse: migrationOnlyScanResponse()}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

		result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{Path: dir}, &mcpv1.ScanDirectoryResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := result.GetIgnoredCount(); got != 1 {
			t.Fatalf("ignoredCount = %d, want 1", got)
		}
		if len(result.Vulnerabilities) != 0 {
			t.Fatalf("vulnerabilities = %d, want 0 after suppression", len(result.Vulnerabilities))
		}
		if !result.GetClean() {
			t.Fatal("expected clean result once the only finding is suppressed")
		}
	})

	t.Run("triage_vulnerabilities", func(t *testing.T) {
		mockScan := &mockScanHandler{scanResponse: migrationOnlyScanResponse()}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

		result, err := callProtoTool(t, ctx, s.triageVulnerabilities, &mcpv1.TriageRequest{Path: dir}, &mcpv1.TriageResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := result.GetIgnoredCount(); got != 1 {
			t.Fatalf("ignoredCount = %d, want 1", got)
		}
		if result.TotalVulnerabilities != 0 || len(result.Vulnerabilities) != 0 {
			t.Fatalf("triage still reports suppressed findings: total %d, listed %d", result.TotalVulnerabilities, len(result.Vulnerabilities))
		}
	})

	t.Run("get_remediation", func(t *testing.T) {
		mockScan := &mockScanHandler{scanResponse: migrationOnlyScanResponse()}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

		result, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{Path: dir}, &mcpv1.GetRemediationResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := result.GetIgnoredCount(); got != 1 {
			t.Fatalf("ignoredCount = %d, want 1", got)
		}
		if result.VulnerabilitiesFound != 0 || len(result.Steps) != 0 {
			t.Fatalf("plan still covers suppressed findings: found %d, steps %d", result.VulnerabilitiesFound, len(result.Steps))
		}
	})

	t.Run("analyze_dependency_graph", func(t *testing.T) {
		mockScan := &mockScanHandler{scanResponse: migrationOnlyScanResponse()}
		mockGraph := &mockGraphHandler{buildResponse: &graphv1.BuildGraphResponse{
			Nodes: []*graphv1.Node{
				{
					Purl:      "pkg:golang/github.com/example/widget@v1.4.0",
					Name:      "github.com/example/widget",
					Version:   "v1.4.0",
					Ecosystem: "go",
					Direct:    true,
				},
			},
			Stats: &graphv1.GraphStats{TotalNodes: 1, DirectNodes: 1},
		}}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan, graphHandler: mockGraph})))

		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{Path: dir}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := result.GetStats().GetVulnerableNodes(); got != 0 {
			t.Fatalf("vulnerableNodes = %d, want 0: graph annotation must honor suppressions like every other assessment tool", got)
		}
		if got := result.GetVulnerablePathCount(); got != 0 {
			t.Fatalf("vulnerablePathCount = %d, want 0 after suppression", got)
		}
	})

	t.Run("without rules nothing is suppressed", func(t *testing.T) {
		plain := t.TempDir()
		mockScan := &mockScanHandler{scanResponse: migrationOnlyScanResponse()}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

		result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{Path: plain}, &mcpv1.ScanDirectoryResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := result.GetIgnoredCount(); got != 0 {
			t.Fatalf("ignoredCount = %d, want 0", got)
		}
		if len(result.Vulnerabilities) != 1 {
			t.Fatalf("vulnerabilities = %d, want 1", len(result.Vulnerabilities))
		}
	})
}

// TestContainerToolsHonorIgnorePath pins the ignorePath contract for the
// container tools, which have no target directory to discover rules from: a
// directory source discovers its .deputyignore.yaml, a file source loads
// directly, and a path that does not resolve is an argument error rather than
// a silently unfiltered result.
func TestContainerToolsHonorIgnorePath(t *testing.T) {
	dir := t.TempDir()
	writeIgnoreFile(t, dir)
	ctx := t.Context()

	scanContainer := func(t *testing.T, ignorePath string) (*mcpv1.ScanContainerResult, error) {
		t.Helper()
		mockScan := &mockScanHandler{scanResponse: migrationOnlyScanResponse()}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
		return callProtoTool(t, ctx, s.scanContainer, &mcpv1.ScanContainerRequest{
			Image:      "example/app:v1",
			IgnorePath: ignorePath,
		}, &mcpv1.ScanContainerResult{})
	}

	tests := []struct {
		name       string
		ignorePath string
	}{
		{name: "directory source discovers rules", ignorePath: dir},
		{name: "file source loads directly", ignorePath: filepath.Join(dir, ".deputyignore.yaml")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := scanContainer(t, tt.ignorePath)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got := result.GetIgnoredCount(); got != 1 {
				t.Fatalf("ignoredCount = %d, want 1", got)
			}
			if len(result.Vulnerabilities) != 0 {
				t.Fatalf("vulnerabilities = %d, want 0 after suppression", len(result.Vulnerabilities))
			}
		})
	}

	t.Run("unresolvable ignorePath is an argument error", func(t *testing.T) {
		if _, err := scanContainer(t, filepath.Join(dir, "no-such-rules.yaml")); err == nil {
			t.Fatal("expected error for unresolvable ignorePath, got filtered-or-not result")
		}
	})

	t.Run("diff_refs container mode honors ignorePath", func(t *testing.T) {
		mockScan := &mockScanHandler{scanResponses: []*scanv1.ScanResponse{
			migrationOnlyScanResponse(),
			migrationOnlyScanResponse(),
		}}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
		result, err := s.diffContainerImages(ctx, &mcpv1.DiffRefsRequest{
			BaseRef:    "example/app:v1",
			TargetRef:  "example/app:v2",
			IgnorePath: dir,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := result.GetIgnoredCount(); got != 1 {
			t.Fatalf("ignoredCount = %d, want 1", got)
		}
		if len(result.Vulnerabilities) != 0 {
			t.Fatalf("vulnerabilities = %d, want 0 after suppression", len(result.Vulnerabilities))
		}
	})

	// Entering through the tool rather than diffContainerImages: diffRefsTool
	// rebuilds the request into a fresh literal before routing, so a field it
	// forgets to copy is silently dropped and every direct-call test still
	// passes.
	t.Run("diff_refs tool entrypoint preserves ignorePath through normalization", func(t *testing.T) {
		mockScan := &mockScanHandler{scanResponses: []*scanv1.ScanResponse{
			migrationOnlyScanResponse(),
			migrationOnlyScanResponse(),
		}}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
		result, err := callProtoTool(t, ctx, s.diffRefs, &mcpv1.DiffRefsRequest{
			BaseRef:    "example/app:v1",
			TargetRef:  "example/app:v2",
			IgnorePath: dir,
		}, &mcpv1.DiffRefsResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got := result.GetIgnoredCount(); got != 1 {
			t.Fatalf("ignoredCount = %d, want 1 (ignorePath dropped during normalization?)", got)
		}
		if len(result.Vulnerabilities) != 0 {
			t.Fatalf("vulnerabilities = %d, want 0 after suppression", len(result.Vulnerabilities))
		}
	})
}
