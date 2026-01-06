package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/vulnerability"
	"osv.dev/bindings/go/osvdev"
)

// mockOSVClient is a mock implementation of osv.Client for testing.
type mockOSVClient struct {
	vulns map[string]*osvschema.Vulnerability
}

func (m *mockOSVClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	if vuln, ok := m.vulns[id]; ok {
		return vuln, nil
	}
	return nil, nil
}

func (m *mockOSVClient) QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	return &osvdev.BatchedResponse{}, nil
}

// mockScanner is a mock implementation of scan.Scanner for testing.
type mockScanner struct {
	result *scan.Result
	err    error
}

func (m *mockScanner) ScanRepository(ctx context.Context, repoArg, ref string, refProvided bool, opts scan.Options) (*scan.Execution, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &scan.Execution{Result: *m.result}, nil
}

func (m *mockScanner) ScanDirectory(ctx context.Context, path string, opts scan.Options) (*scan.Execution, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &scan.Execution{Result: *m.result}, nil
}

func (m *mockScanner) ScanSBOM(ctx context.Context, pkgs []*extractor.Package, direct map[string]bool, opts scan.Options) (*scan.Execution, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &scan.Execution{Result: *m.result}, nil
}

func (m *mockScanner) ScanContainerImage(ctx context.Context, target string, targetOpts map[string]string, opts scan.Options) (*scan.Execution, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &scan.Execution{Result: *m.result}, nil
}

func (m *mockScanner) ScanDockerfile(ctx context.Context, target string, opts scan.Options) (*scan.Execution, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &scan.Execution{Result: *m.result}, nil
}

func (m *mockScanner) ScanPURL(ctx context.Context, purlStr string, opts scan.Options) (*scan.Execution, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &scan.Execution{Result: *m.result}, nil
}

func TestNewServer(t *testing.T) {
	s := NewServer()
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.server == nil {
		t.Error("server field is nil")
	}
	if s.osv == nil {
		t.Error("osv field is nil")
	}
	if s.scanner == nil {
		t.Error("scanner field is nil")
	}
}

func TestNewServer_WithOptions(t *testing.T) {
	mockOSV := &mockOSVClient{}
	mockScan := &mockScanner{}

	s := NewServer(
		WithOSVClient(mockOSV),
		WithScanner(mockScan),
	)

	// Check that options were applied (can't compare interfaces directly,
	// but we can verify by testing behavior)
	if s.osv == nil {
		t.Error("WithOSVClient option not applied")
	}
	if s.scanner == nil {
		t.Error("WithScanner option not applied")
	}
}

func TestExplainVulnerability(t *testing.T) {
	mockOSV := &mockOSVClient{
		vulns: map[string]*osvschema.Vulnerability{
			"CVE-2021-44228": {
				ID:      "CVE-2021-44228",
				Summary: "Log4Shell vulnerability",
				Details: "Remote code execution in Log4j",
				Aliases: []string{"GHSA-jfh8-c2jp-5v3q"},
				Severity: []osvschema.Severity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
				},
				References: []osvschema.Reference{
					{URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
				},
			},
		},
	}

	s := NewServer(WithOSVClient(mockOSV))
	ctx := context.Background()

	t.Run("valid vulnerability", func(t *testing.T) {
		_, result, err := s.explainVulnerability(ctx, nil, ExplainVulnInput{ID: "CVE-2021-44228"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.ID != "CVE-2021-44228" {
			t.Errorf("expected ID CVE-2021-44228, got %s", result.ID)
		}
		if result.Summary != "Log4Shell vulnerability" {
			t.Errorf("expected summary 'Log4Shell vulnerability', got %s", result.Summary)
		}
		if len(result.Aliases) != 1 || result.Aliases[0] != "GHSA-jfh8-c2jp-5v3q" {
			t.Errorf("unexpected aliases: %v", result.Aliases)
		}
	})

	t.Run("empty ID", func(t *testing.T) {
		_, _, err := s.explainVulnerability(ctx, nil, ExplainVulnInput{ID: ""})
		if err == nil {
			t.Error("expected error for empty ID")
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, _, err := s.explainVulnerability(ctx, nil, ExplainVulnInput{ID: "CVE-9999-9999"})
		if err == nil {
			t.Error("expected error for non-existent vulnerability")
		}
	})
}

func TestExplainVulnerabilities(t *testing.T) {
	mockOSV := &mockOSVClient{
		vulns: map[string]*osvschema.Vulnerability{
			"CVE-2021-44228": {
				ID:      "CVE-2021-44228",
				Summary: "Log4Shell",
			},
			"CVE-2022-22965": {
				ID:      "CVE-2022-22965",
				Summary: "Spring4Shell",
			},
		},
	}

	s := NewServer(WithOSVClient(mockOSV))
	ctx := context.Background()

	t.Run("multiple vulnerabilities", func(t *testing.T) {
		_, result, err := s.explainVulnerabilities(ctx, nil, ExplainVulnsInput{
			IDs: []string{"CVE-2021-44228", "CVE-2022-22965"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Vulnerabilities) != 2 {
			t.Errorf("expected 2 vulnerabilities, got %d", len(result.Vulnerabilities))
		}
	})

	t.Run("partial success", func(t *testing.T) {
		_, result, err := s.explainVulnerabilities(ctx, nil, ExplainVulnsInput{
			IDs: []string{"CVE-2021-44228", "CVE-NONEXISTENT"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Vulnerabilities) != 1 {
			t.Errorf("expected 1 vulnerability, got %d", len(result.Vulnerabilities))
		}
		if len(result.Errors) != 1 {
			t.Errorf("expected 1 error, got %d", len(result.Errors))
		}
	})

	t.Run("empty IDs", func(t *testing.T) {
		_, _, err := s.explainVulnerabilities(ctx, nil, ExplainVulnsInput{IDs: nil})
		if err == nil {
			t.Error("expected error for empty IDs")
		}
	})
}

func TestScanPackage(t *testing.T) {
	s := NewServer()
	ctx := context.Background()

	t.Run("missing name", func(t *testing.T) {
		_, _, err := s.scanPackage(ctx, nil, ScanPackageInput{
			Version:   "1.0.0",
			Ecosystem: "npm",
		})
		if err == nil {
			t.Error("expected error for missing name")
		}
	})

	t.Run("missing version", func(t *testing.T) {
		_, _, err := s.scanPackage(ctx, nil, ScanPackageInput{
			Name:      "lodash",
			Ecosystem: "npm",
		})
		if err == nil {
			t.Error("expected error for missing version")
		}
	})

	t.Run("missing ecosystem", func(t *testing.T) {
		_, _, err := s.scanPackage(ctx, nil, ScanPackageInput{
			Name:    "lodash",
			Version: "4.17.15",
		})
		if err == nil {
			t.Error("expected error for missing ecosystem")
		}
	})
}

func TestScanDirectory(t *testing.T) {
	mockScan := &mockScanner{
		result: &scan.Result{
			PackagesScanned: 10,
			Findings:        []vulnerability.Finding{},
			Advisories:      map[string]vulnerability.Advisory{},
			Stats: vulnerability.Stats{
				UniqueVulns: 0,
			},
			Inventory: scan.Inventory{
				Packages: []*extractor.Package{},
			},
		},
	}

	s := NewServer(WithScanner(mockScan))
	ctx := context.Background()

	t.Run("missing path", func(t *testing.T) {
		_, _, err := s.scanDirectory(ctx, nil, ScanDirectoryInput{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("valid scan", func(t *testing.T) {
		_, result, err := s.scanDirectory(ctx, nil, ScanDirectoryInput{Path: "/test/path"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.PackagesScanned != 10 {
			t.Errorf("expected 10 packages scanned, got %d", result.PackagesScanned)
		}
		if !result.Clean {
			t.Error("expected clean result")
		}
	})

	t.Run("with vulnerabilities", func(t *testing.T) {
		mockScan.result = &scan.Result{
			PackagesScanned: 5,
			Findings: []vulnerability.Finding{
				{AdvisoryID: "CVE-2021-44228"},
			},
			Advisories: map[string]vulnerability.Advisory{
				"CVE-2021-44228": {
					ID:       "CVE-2021-44228",
					Summary:  "Test vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
			},
			Stats: vulnerability.Stats{
				UniqueVulns: 1,
				CriticalSev: 1,
			},
			Inventory: scan.Inventory{
				Packages: []*extractor.Package{},
			},
		}

		_, result, err := s.scanDirectory(ctx, nil, ScanDirectoryInput{Path: "/test/path"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Clean {
			t.Error("expected non-clean result")
		}
		if len(result.Vulnerabilities) != 1 {
			t.Errorf("expected 1 vulnerability, got %d", len(result.Vulnerabilities))
		}
		if result.VulnerabilitiesBy["critical"] != 1 {
			t.Errorf("expected 1 critical, got %d", result.VulnerabilitiesBy["critical"])
		}
	})
}

func TestListDependencies(t *testing.T) {
	mockScan := &mockScanner{
		result: &scan.Result{
			Inventory: scan.Inventory{
				Packages: []*extractor.Package{
					{Name: "pkg1", Version: "1.0.0"},
					{Name: "pkg2", Version: "2.0.0"},
				},
				Direct: map[string]bool{},
			},
		},
	}

	s := NewServer(WithScanner(mockScan))
	ctx := context.Background()

	t.Run("missing path", func(t *testing.T) {
		_, _, err := s.listDependencies(ctx, nil, ListDependenciesInput{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("list all", func(t *testing.T) {
		_, result, err := s.listDependencies(ctx, nil, ListDependenciesInput{Path: "/test/path"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Total != 2 {
			t.Errorf("expected 2 dependencies, got %d", result.Total)
		}
	})
}

func TestGenerateSBOM(t *testing.T) {
	s := NewServer()
	ctx := context.Background()

	t.Run("missing path", func(t *testing.T) {
		_, _, err := s.generateSBOM(ctx, nil, GenerateSBOMInput{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		_, _, err := s.generateSBOM(ctx, nil, GenerateSBOMInput{
			Path:   "/test/path",
			Format: "invalid-format",
		})
		if err == nil {
			t.Error("expected error for invalid format")
		}
	})
}

func TestGetRemediation(t *testing.T) {
	mockScan := &mockScanner{
		result: &scan.Result{
			Findings:   []vulnerability.Finding{},
			Advisories: map[string]vulnerability.Advisory{},
			Stats: vulnerability.Stats{
				UniqueVulns: 0,
			},
			Inventory: scan.Inventory{
				Packages: []*extractor.Package{},
			},
		},
	}

	s := NewServer(WithScanner(mockScan))
	ctx := context.Background()

	t.Run("missing path", func(t *testing.T) {
		_, _, err := s.getRemediation(ctx, nil, GetRemediationInput{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("no vulnerabilities", func(t *testing.T) {
		_, result, err := s.getRemediation(ctx, nil, GetRemediationInput{Path: "/test/path"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.VulnerabilitiesFound != 0 {
			t.Errorf("expected 0 vulnerabilities, got %d", result.VulnerabilitiesFound)
		}
	})
}

func TestAnalyzeDependencyGraph(t *testing.T) {
	mockScan := &mockScanner{
		result: &scan.Result{
			Findings:   []vulnerability.Finding{},
			Advisories: map[string]vulnerability.Advisory{},
			Stats: vulnerability.Stats{
				UniqueVulns: 0,
			},
			Inventory: scan.Inventory{
				Packages: []*extractor.Package{
					{Name: "pkg1", Version: "1.0.0"},
					{Name: "pkg2", Version: "2.0.0"},
				},
				Direct: map[string]bool{},
			},
		},
	}

	s := NewServer(WithScanner(mockScan))
	ctx := context.Background()

	t.Run("missing path", func(t *testing.T) {
		_, _, err := s.analyzeDependencyGraph(ctx, nil, AnalyzeGraphInput{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("basic graph analysis", func(t *testing.T) {
		_, result, err := s.analyzeDependencyGraph(ctx, nil, AnalyzeGraphInput{Path: "/test/path"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// Graph analysis returns the stats from building a graph from the inventory.
		// With packages that have no PURL, the graph will have 0 nodes.
		// This is expected behavior - the test verifies the tool runs without error.
		if result.Path != "/test/path" {
			t.Errorf("expected path /test/path, got %s", result.Path)
		}
	})
}

func TestExtractSeverity(t *testing.T) {
	tests := []struct {
		name     string
		vuln     *osvschema.Vulnerability
		expected string
	}{
		{
			name:     "nil vulnerability",
			vuln:     nil,
			expected: "UNKNOWN", // Default severity level is UNKNOWN
		},
		{
			name: "CVSS severity",
			vuln: &osvschema.Vulnerability{
				Severity: []osvschema.Severity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
				},
			},
			expected: "CRITICAL",
		},
		{
			name: "database specific severity",
			vuln: &osvschema.Vulnerability{
				DatabaseSpecific: map[string]interface{}{
					"severity": "HIGH",
				},
			},
			expected: "HIGH",
		},
		{
			name: "no severity",
			vuln: &osvschema.Vulnerability{
				ID: "TEST-123",
			},
			expected: "UNKNOWN", // Default severity level is UNKNOWN
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sev := extractSeverity(tt.vuln)
			if sev.Level.String() != tt.expected {
				t.Errorf("expected severity %q, got %q", tt.expected, sev.Level.String())
			}
		})
	}
}

func TestPathToStrings(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		result := pathToStrings(nil)
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %v", result)
		}
	})
}

// TestIntegration_ScanDirectory tests the scan_directory tool against a real directory.
// This test is skipped in short mode.
func TestIntegration_ScanDirectory(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Create a temporary directory with a go.mod file
	tmpDir := t.TempDir()
	goModContent := `module test

go 1.21

require golang.org/x/text v0.3.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("failed to create go.mod: %v", err)
	}

	s := NewServer()
	ctx := context.Background()

	_, result, err := s.scanDirectory(ctx, nil, ScanDirectoryInput{Path: tmpDir})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	// We should have at least scanned the directory
	if result.Path != tmpDir {
		t.Errorf("expected path %s, got %s", tmpDir, result.Path)
	}
}

// TestIntegration_ListDependencies tests the list_dependencies tool against a real directory.
func TestIntegration_ListDependencies(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	tmpDir := t.TempDir()
	goModContent := `module test

go 1.21

require golang.org/x/text v0.3.0
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("failed to create go.mod: %v", err)
	}

	s := NewServer()
	ctx := context.Background()

	_, result, err := s.listDependencies(ctx, nil, ListDependenciesInput{Path: tmpDir})
	if err != nil {
		t.Fatalf("list dependencies failed: %v", err)
	}

	if result.Path != tmpDir {
		t.Errorf("expected path %s, got %s", tmpDir, result.Path)
	}
}

// TestHTTPHandler tests the HTTP handler endpoints.
func TestHTTPHandler(t *testing.T) {
	s := NewServer()
	handler := s.HTTPHandler()

	t.Run("health endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		var resp map[string]string
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["status"] != "healthy" {
			t.Errorf("expected status 'healthy', got %q", resp["status"])
		}
		if resp["service"] != "deputy-mcp" {
			t.Errorf("expected service 'deputy-mcp', got %q", resp["service"])
		}
	})

	t.Run("info endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("expected status 200, got %d", w.Code)
		}

		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		if resp["name"] != "deputy" {
			t.Errorf("expected name 'deputy', got %q", resp["name"])
		}
		if resp["protocol"] != "mcp" {
			t.Errorf("expected protocol 'mcp', got %q", resp["protocol"])
		}
		if resp["transport"] != "sse" {
			t.Errorf("expected transport 'sse', got %q", resp["transport"])
		}

		tools, ok := resp["tools"].([]any)
		if !ok {
			t.Fatal("expected tools to be a slice")
		}
		if len(tools) != 13 {
			t.Errorf("expected 13 tools, got %d", len(tools))
		}
	})

	t.Run("health endpoint content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type 'application/json', got %q", contentType)
		}
	})

	t.Run("info endpoint content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)

		contentType := w.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type 'application/json', got %q", contentType)
		}
	})
}

// TestDefaultHTTPConfig tests the default HTTP configuration values.
func TestDefaultHTTPConfig(t *testing.T) {
	cfg := DefaultHTTPConfig()

	if cfg.ReadTimeout != 30*1e9 { // 30 seconds in nanoseconds
		t.Errorf("expected ReadTimeout 30s, got %v", cfg.ReadTimeout)
	}
	if cfg.WriteTimeout != 0 {
		t.Errorf("expected WriteTimeout 0 (disabled for SSE), got %v", cfg.WriteTimeout)
	}
	if cfg.IdleTimeout != 120*1e9 { // 120 seconds
		t.Errorf("expected IdleTimeout 120s, got %v", cfg.IdleTimeout)
	}
	if cfg.ReadHeaderTimeout != 10*1e9 { // 10 seconds
		t.Errorf("expected ReadHeaderTimeout 10s, got %v", cfg.ReadHeaderTimeout)
	}
	if cfg.MaxHeaderBytes != 1<<20 { // 1MB
		t.Errorf("expected MaxHeaderBytes 1MB, got %v", cfg.MaxHeaderBytes)
	}
	if cfg.ShutdownTimeout != 30*1e9 { // 30 seconds
		t.Errorf("expected ShutdownTimeout 30s, got %v", cfg.ShutdownTimeout)
	}
}

// TestDefaultToolTimeouts tests the default tool timeout values.
func TestDefaultToolTimeouts(t *testing.T) {
	timeouts := DefaultToolTimeouts()

	if timeouts.Default != 30*1e9 { // 30 seconds
		t.Errorf("expected Default timeout 30s, got %v", timeouts.Default)
	}
	if timeouts.Scan != 5*60*1e9 { // 5 minutes
		t.Errorf("expected Scan timeout 5m, got %v", timeouts.Scan)
	}
	if timeouts.Graph != 2*60*1e9 { // 2 minutes
		t.Errorf("expected Graph timeout 2m, got %v", timeouts.Graph)
	}
	if timeouts.SBOM != 3*60*1e9 { // 3 minutes
		t.Errorf("expected SBOM timeout 3m, got %v", timeouts.SBOM)
	}
}

// TestWithToolTimeouts tests the WithToolTimeouts option.
func TestWithToolTimeouts(t *testing.T) {
	customTimeouts := ToolTimeouts{
		Default: 10 * 1e9,
		Scan:    60 * 1e9,
		Graph:   30 * 1e9,
		SBOM:    45 * 1e9,
	}

	s := NewServer(WithToolTimeouts(customTimeouts))

	if s.toolTimeouts.Default != customTimeouts.Default {
		t.Errorf("expected Default timeout %v, got %v", customTimeouts.Default, s.toolTimeouts.Default)
	}
	if s.toolTimeouts.Scan != customTimeouts.Scan {
		t.Errorf("expected Scan timeout %v, got %v", customTimeouts.Scan, s.toolTimeouts.Scan)
	}
	if s.toolTimeouts.Graph != customTimeouts.Graph {
		t.Errorf("expected Graph timeout %v, got %v", customTimeouts.Graph, s.toolTimeouts.Graph)
	}
	if s.toolTimeouts.SBOM != customTimeouts.SBOM {
		t.Errorf("expected SBOM timeout %v, got %v", customTimeouts.SBOM, s.toolTimeouts.SBOM)
	}
}

// TestToolNamesRegistration tests that all tools are registered and tracked.
func TestToolNamesRegistration(t *testing.T) {
	s := NewServer()

	expectedTools := []string{
		"explain_vulnerability",
		"explain_vulnerabilities",
		"scan_package",
		"scan_directory",
		"list_dependencies",
		"generate_sbom",
		"get_remediation",
		"analyze_dependency_graph",
		"graph_why",
		"graph_needs",
		"triage_vulnerabilities",
		"scan_container",
		"diff_refs",
	}

	if len(s.toolNames) != len(expectedTools) {
		t.Errorf("expected %d tools, got %d", len(expectedTools), len(s.toolNames))
	}

	// Check that all expected tools are present
	toolSet := make(map[string]bool)
	for _, name := range s.toolNames {
		toolSet[name] = true
	}

	for _, expected := range expectedTools {
		if !toolSet[expected] {
			t.Errorf("expected tool %q not found in registered tools", expected)
		}
	}
}
