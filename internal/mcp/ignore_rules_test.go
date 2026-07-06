package mcp

import (
	"os"
	"path/filepath"
	"testing"

	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
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
