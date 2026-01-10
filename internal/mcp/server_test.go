package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"connectrpc.com/connect"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/gen/deputy/list/v1/listv1connect"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	"github.com/picatz/deputy/gen/deputy/scan/v1/scanv1connect"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/gen/deputy/vulnerability/v1/vulnerabilityv1connect"
	"github.com/picatz/deputy/internal/services"
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

// mockScanHandler is a mock scan service handler for testing.
type mockScanHandler struct {
	scanv1connect.UnimplementedScanServiceHandler
	scanResponse *scanv1.ScanResponse
	err          error
}

func (m *mockScanHandler) Scan(ctx context.Context, req *connect.Request[scanv1.ScanRequest]) (*connect.Response[scanv1.ScanResponse], error) {
	if m.err != nil {
		return nil, m.err
	}
	return connect.NewResponse(m.scanResponse), nil
}

// mockListHandler is a mock list service handler for testing.
type mockListHandler struct {
	listv1connect.UnimplementedListServiceHandler
	listResponse *listv1.ListPackagesResponse
	err          error
}

func (m *mockListHandler) ListPackages(ctx context.Context, req *connect.Request[listv1.ListPackagesRequest]) (*connect.Response[listv1.ListPackagesResponse], error) {
	if m.err != nil {
		return nil, m.err
	}
	return connect.NewResponse(m.listResponse), nil
}

// mockVulnerabilityHandler is a mock vulnerability service handler for testing.
type mockVulnerabilityHandler struct {
	osvClient *mockOSVClient
}

func (m *mockVulnerabilityHandler) GetAdvisory(ctx context.Context, req *connect.Request[vulnerabilityv1.GetAdvisoryRequest]) (*connect.Response[vulnerabilityv1.GetAdvisoryResponse], error) {
	id := req.Msg.GetId()
	if id == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, nil)
	}

	vuln, _ := m.osvClient.GetVulnByID(ctx, id)
	if vuln == nil {
		return connect.NewResponse(&vulnerabilityv1.GetAdvisoryResponse{Found: false}), nil
	}

	// Convert to proto Advisory
	advisory := &vulnerabilityv1.Advisory{
		Id:      vuln.ID,
		Aliases: vuln.Aliases,
		Summary: vuln.Summary,
		Details: vuln.Details,
	}

	// Extract references
	for _, ref := range vuln.References {
		advisory.References = append(advisory.References, ref.URL)
	}

	// Extract severity
	for _, sev := range vuln.Severity {
		if sev.Score != "" {
			advisory.Severity = vulnerability.NewSeverity(sev.Score, string(sev.Type))
			break
		}
	}

	return connect.NewResponse(&vulnerabilityv1.GetAdvisoryResponse{
		Advisory: advisory,
		Found:    true,
	}), nil
}

func (m *mockVulnerabilityHandler) GetAdvisories(ctx context.Context, req *connect.Request[vulnerabilityv1.GetAdvisoriesRequest]) (*connect.Response[vulnerabilityv1.GetAdvisoriesResponse], error) {
	resp := &vulnerabilityv1.GetAdvisoriesResponse{
		Advisories: make(map[string]*vulnerabilityv1.Advisory),
	}
	for _, id := range req.Msg.GetIds() {
		vuln, _ := m.osvClient.GetVulnByID(ctx, id)
		if vuln != nil {
			resp.Advisories[id] = &vulnerabilityv1.Advisory{
				Id:      vuln.ID,
				Aliases: vuln.Aliases,
				Summary: vuln.Summary,
				Details: vuln.Details,
			}
		} else {
			resp.NotFound = append(resp.NotFound, id)
		}
	}
	return connect.NewResponse(resp), nil
}

// mockClientsConfig configures mock clients for testing.
type mockClientsConfig struct {
	scanHandler          *mockScanHandler
	listHandler          *mockListHandler
	vulnerabilityHandler *mockVulnerabilityHandler
}

// newMockClients creates mock clients with the given handlers for testing.
func newMockClients(cfg mockClientsConfig) *services.Clients {
	mux := http.NewServeMux()

	if cfg.scanHandler != nil {
		path, handler := scanv1connect.NewScanServiceHandler(cfg.scanHandler)
		mux.Handle(path, handler)
	}
	if cfg.listHandler != nil {
		path, handler := listv1connect.NewListServiceHandler(cfg.listHandler)
		mux.Handle(path, handler)
	}
	if cfg.vulnerabilityHandler != nil {
		path, handler := vulnerabilityv1connect.NewVulnerabilityServiceHandler(cfg.vulnerabilityHandler)
		mux.Handle(path, handler)
	}

	transport := services.NewInProcessTransport(mux)
	httpClient := transport.HTTPClient()

	return &services.Clients{
		Vulns:     scanv1connect.NewScanServiceClient(httpClient, ""),
		Inventory: listv1connect.NewListServiceClient(httpClient, ""),
		Advisory:  vulnerabilityv1connect.NewVulnerabilityServiceClient(httpClient, ""),
	}
}

func TestNewServer(t *testing.T) {
	s := NewServer()
	if s == nil {
		t.Fatal("NewServer returned nil")
	}
	if s.server == nil {
		t.Error("server field is nil")
	}
	if s.clients == nil {
		t.Error("clients field is nil")
	}
}

func TestNewServer_WithOptions(t *testing.T) {
	mockClients := newMockClients(mockClientsConfig{
		scanHandler: &mockScanHandler{},
		listHandler: &mockListHandler{},
	})

	s := NewServer(WithClients(mockClients))

	if s.clients == nil {
		t.Error("WithClients option not applied")
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

	mockClients := newMockClients(mockClientsConfig{
		vulnerabilityHandler: &mockVulnerabilityHandler{osvClient: mockOSV},
	})
	s := NewServer(WithClients(mockClients))
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

	mockClients := newMockClients(mockClientsConfig{
		vulnerabilityHandler: &mockVulnerabilityHandler{osvClient: mockOSV},
	})
	s := NewServer(WithClients(mockClients))
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
	mockScan := &mockScanHandler{
		scanResponse: &scanv1.ScanResponse{
			PackagesScanned: 10,
			Findings:        []*vulnerabilityv1.Finding{},
			Advisories:      map[string]*vulnerabilityv1.Advisory{},
			Stats: &vulnerabilityv1.Stats{
				Unique: 0,
			},
			Packages: []*dependencyv1.Package{},
		},
	}

	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
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
		mockScan.scanResponse = &scanv1.ScanResponse{
			PackagesScanned: 5,
			Findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "CVE-2021-44228"},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2021-44228": {
					Id:       "CVE-2021-44228",
					Summary:  "Test vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
			},
			Stats: &vulnerabilityv1.Stats{
				Unique:   1,
				Critical: 1,
			},
			Packages: []*dependencyv1.Package{},
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
		if result.VulnerabilitiesBySeverity["critical"] != 1 {
			t.Errorf("expected 1 critical, got %d", result.VulnerabilitiesBySeverity["critical"])
		}
	})
}

func TestListDependencies(t *testing.T) {
	mockList := &mockListHandler{
		listResponse: &listv1.ListPackagesResponse{
			Packages: []*dependencyv1.Package{
				{Name: "pkg1", Version: "1.0.0", Ecosystem: "go"},
				{Name: "pkg2", Version: "2.0.0", Ecosystem: "go"},
			},
			Stats: &listv1.ListStats{
				TotalPackages: 2,
			},
		},
	}

	s := NewServer(WithClients(newMockClients(mockClientsConfig{listHandler: mockList})))
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
	mockScan := &mockScanHandler{
		scanResponse: &scanv1.ScanResponse{
			Findings:   []*vulnerabilityv1.Finding{},
			Advisories: map[string]*vulnerabilityv1.Advisory{},
			Stats: &vulnerabilityv1.Stats{
				Unique: 0,
			},
			Packages: []*dependencyv1.Package{},
		},
	}

	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
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
	mockScan := &mockScanHandler{
		scanResponse: &scanv1.ScanResponse{
			Findings:   []*vulnerabilityv1.Finding{},
			Advisories: map[string]*vulnerabilityv1.Advisory{},
			Stats: &vulnerabilityv1.Stats{
				Unique: 0,
			},
			Packages: []*dependencyv1.Package{
				{Name: "pkg1", Version: "1.0.0", Ecosystem: "go"},
				{Name: "pkg2", Version: "2.0.0", Ecosystem: "go"},
			},
		},
	}

	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
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
