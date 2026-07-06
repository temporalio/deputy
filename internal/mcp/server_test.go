package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	"github.com/temporalio/deputy/gen/deputy/graph/v1/graphv1connect"
	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	"github.com/temporalio/deputy/gen/deputy/list/v1/listv1connect"
	mcpv1 "github.com/temporalio/deputy/gen/deputy/mcp/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	"github.com/temporalio/deputy/gen/deputy/scan/v1/scanv1connect"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/gen/deputy/vulnerability/v1/vulnerabilityv1connect"
	"github.com/temporalio/deputy/internal/cli/flags"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/policy"
	deputyserver "github.com/temporalio/deputy/internal/server"
	"github.com/temporalio/deputy/internal/services"
	"github.com/temporalio/deputy/internal/vulnerability"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"osv.dev/bindings/go/osvdev"
)

// callProtoTool invokes a proto-contract tool handler with a protojson-encoded
// request and decodes the protojson result, mirroring the SDK's raw-message
// flow.
func callProtoTool[Res proto.Message](t *testing.T, ctx context.Context,
	handler func(context.Context, *mcpsdk.CallToolRequest, json.RawMessage) (*mcpsdk.CallToolResult, json.RawMessage, error),
	req proto.Message, res Res) (Res, error) {
	t.Helper()
	raw, err := protojson.Marshal(req)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	_, out, err := handler(ctx, nil, raw)
	if err != nil {
		return res, err
	}
	if err := protojson.Unmarshal(out, res); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	return res, nil
}

// mockOSVClient is a mock implementation of osv.Client for testing.
type mockOSVClient struct {
	vulns map[string]*osvschema.Vulnerability
	errs  map[string]error
}

func (m *mockOSVClient) GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	if err := m.errs[id]; err != nil {
		return nil, err
	}
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
	scanResponse  *scanv1.ScanResponse
	scanResponses []*scanv1.ScanResponse
	requests      []*scanv1.ScanRequest
	err           error
}

func (m *mockScanHandler) Scan(ctx context.Context, req *connect.Request[scanv1.ScanRequest]) (*connect.Response[scanv1.ScanResponse], error) {
	if m.err != nil {
		return nil, m.err
	}
	m.requests = append(m.requests, req.Msg)
	if len(m.scanResponses) > 0 {
		resp := m.scanResponses[0]
		m.scanResponses = m.scanResponses[1:]
		return connect.NewResponse(resp), nil
	}
	return connect.NewResponse(m.scanResponse), nil
}

// mockListHandler is a mock list service handler for testing.
type mockListHandler struct {
	listv1connect.UnimplementedListServiceHandler
	listResponse *listv1.ListPackagesResponse
	requests     []*listv1.ListPackagesRequest
	err          error
}

func (m *mockListHandler) ListPackages(ctx context.Context, req *connect.Request[listv1.ListPackagesRequest]) (*connect.Response[listv1.ListPackagesResponse], error) {
	if m.err != nil {
		return nil, m.err
	}
	m.requests = append(m.requests, req.Msg)
	return connect.NewResponse(m.listResponse), nil
}

// mockGraphHandler is a mock graph service handler for testing.
type mockGraphHandler struct {
	graphv1connect.UnimplementedGraphServiceHandler
	buildResponse *graphv1.BuildGraphResponse
	requests      []*graphv1.BuildGraphRequest
	err           error
}

func (m *mockGraphHandler) BuildGraph(ctx context.Context, req *connect.Request[graphv1.BuildGraphRequest]) (*connect.Response[graphv1.BuildGraphResponse], error) {
	if m.err != nil {
		return nil, m.err
	}
	m.requests = append(m.requests, req.Msg)
	return connect.NewResponse(m.buildResponse), nil
}

// mockVulnerabilityHandler is a mock vulnerability service handler for testing.
type mockVulnerabilityHandler struct {
	osvClient              *mockOSVClient
	getAdvisoryRequests    []string
	getAdvisoriesRequests  [][]string
	getAdvisoriesResponses []*vulnerabilityv1.GetAdvisoriesResponse
}

func (m *mockVulnerabilityHandler) GetAdvisory(ctx context.Context, req *connect.Request[vulnerabilityv1.GetAdvisoryRequest]) (*connect.Response[vulnerabilityv1.GetAdvisoryResponse], error) {
	m.getAdvisoryRequests = append(m.getAdvisoryRequests, req.Msg.GetId())
	handler := deputyserver.NewVulnerabilityHandler(deputyserver.WithVulnerabilityOSVClient(m.osvClient))
	return handler.GetAdvisory(ctx, req)
}

func (m *mockVulnerabilityHandler) GetAdvisories(ctx context.Context, req *connect.Request[vulnerabilityv1.GetAdvisoriesRequest]) (*connect.Response[vulnerabilityv1.GetAdvisoriesResponse], error) {
	m.getAdvisoriesRequests = append(m.getAdvisoriesRequests, slices.Clone(req.Msg.GetIds()))
	if len(m.getAdvisoriesResponses) > 0 {
		resp := m.getAdvisoriesResponses[0]
		m.getAdvisoriesResponses = m.getAdvisoriesResponses[1:]
		return connect.NewResponse(resp), nil
	}
	handler := deputyserver.NewVulnerabilityHandler(deputyserver.WithVulnerabilityOSVClient(m.osvClient))
	return handler.GetAdvisories(ctx, req)
}

// mockClientsConfig configures mock clients for testing.
type mockClientsConfig struct {
	scanHandler          *mockScanHandler
	listHandler          *mockListHandler
	graphHandler         *mockGraphHandler
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
	if cfg.graphHandler != nil {
		path, handler := graphv1connect.NewGraphServiceHandler(cfg.graphHandler)
		mux.Handle(path, handler)
	}
	if cfg.vulnerabilityHandler != nil {
		path, handler := vulnerabilityv1connect.NewVulnerabilityServiceHandler(cfg.vulnerabilityHandler)
		mux.Handle(path, handler)
	}

	transport := services.NewInProcessTransport(mux)
	httpClient := transport.HTTPClient()

	return &services.Clients{
		Vulns:    scanv1connect.NewScanServiceClient(httpClient, ""),
		Packages: listv1connect.NewListServiceClient(httpClient, ""),
		Graph:    graphv1connect.NewGraphServiceClient(httpClient, ""),
		Advisory: vulnerabilityv1connect.NewVulnerabilityServiceClient(httpClient, ""),
	}
}

const (
	testRootPURL  = "pkg:golang/github.com/example/root@v1.0.0"
	testChildPURL = "pkg:golang/github.com/example/child@v2.0.0"
)

func testBuildGraphResponse() *graphv1.BuildGraphResponse {
	return &graphv1.BuildGraphResponse{
		Nodes: []*graphv1.Node{
			{
				Purl:      testRootPURL,
				Name:      "github.com/example/root",
				Version:   "v1.0.0",
				Ecosystem: "Go",
				Direct:    true,
				Depth:     0,
			},
			{
				Purl:      testChildPURL,
				Name:      "github.com/example/child",
				Version:   "v2.0.0",
				Ecosystem: "Go",
				Direct:    false,
				Depth:     1,
			},
		},
		Edges: []*graphv1.Edge{
			{From: testRootPURL, To: testChildPURL},
		},
		Roots: []string{testRootPURL},
	}
}

func testEscapedVersionGraphResponse() *graphv1.BuildGraphResponse {
	const (
		rootPURL   = "pkg:golang/example.com/root@v1.0.0"
		dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
	)
	return &graphv1.BuildGraphResponse{
		Nodes: []*graphv1.Node{
			{
				Purl:      rootPURL,
				Name:      "example.com/root",
				Version:   "v1.0.0",
				Ecosystem: "Go",
				Direct:    true,
				Depth:     0,
			},
			{
				Purl:      dockerPURL,
				Name:      "github.com/docker/docker",
				Version:   "28.5.2+incompatible",
				Ecosystem: "go",
				Direct:    false,
				Depth:     1,
			},
		},
		Edges: []*graphv1.Edge{
			{From: rootPURL, To: dockerPURL},
		},
		Roots: []string{rootPURL},
		Stats: &graphv1.GraphStats{TotalNodes: 2, DirectNodes: 1, TransitiveNodes: 1},
	}
}

func testWideTargetGraphResponse(pathCount int) *graphv1.BuildGraphResponse {
	const targetPURL = "pkg:npm/shared-target@1.0.0"
	resp := &graphv1.BuildGraphResponse{
		Nodes: []*graphv1.Node{
			{
				Purl:               targetPURL,
				Name:               "shared-target",
				Version:            "1.0.0",
				Ecosystem:          "npm",
				Depth:              1,
				VulnerabilityCount: &graphv1.VulnerabilityCount{Total: 1, High: 1},
			},
		},
		Stats: &graphv1.GraphStats{TotalNodes: int32(pathCount + 1), VulnerableNodes: 1},
	}
	for i := range pathCount {
		rootPURL := fmt.Sprintf("pkg:npm/root-%02d@1.0.0", i)
		resp.Nodes = append(resp.Nodes, &graphv1.Node{
			Purl:      rootPURL,
			Name:      fmt.Sprintf("root-%02d", i),
			Version:   "1.0.0",
			Ecosystem: "npm",
			Direct:    true,
			Depth:     0,
		})
		resp.Edges = append(resp.Edges, &graphv1.Edge{From: rootPURL, To: targetPURL})
		resp.Roots = append(resp.Roots, rootPURL)
	}
	return resp
}

func emptyScanResponse() *scanv1.ScanResponse {
	return &scanv1.ScanResponse{
		Findings:   []*vulnerabilityv1.Finding{},
		Advisories: map[string]*vulnerabilityv1.Advisory{},
		Stats:      &vulnerabilityv1.Stats{},
		Packages:   []*dependencyv1.Package{},
	}
}

func TestVulnExplanationSeverityIsCanonical(t *testing.T) {
	tests := []struct {
		name string
		in   vulnerability.Consolidated
		want string
	}{
		{
			name: "label",
			in:   vulnerability.Consolidated{PrimaryID: "CVE-2024-0001", Severity: "HIGH"},
			want: "HIGH",
		},
		{
			name: "cvss vector",
			in: vulnerability.Consolidated{
				PrimaryID:    "CVE-2024-0002",
				Severity:     "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
				SeverityType: "CVSS_V3",
			},
			want: "CRITICAL",
		},
		{
			name: "empty",
			in:   vulnerability.Consolidated{PrimaryID: "CVE-2024-0003"},
			want: "UNKNOWN",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := vulnExplanationProto(tt.in, vulnExplanationOptions{referenceLimit: compactVulnReferenceLimit})
			if got.Severity != tt.want {
				t.Errorf("severity = %q, want %q", got.Severity, tt.want)
			}
		})
	}

	rawAdvisory := advisoryExplanationProto(&vulnerabilityv1.Advisory{
		Id:       "CVE-2024-0004",
		Severity: &vulnerabilityv1.Severity{Raw: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", RawType: "CVSS_V3"},
	}, allVulnReferences)
	if rawAdvisory.Severity != "CRITICAL" {
		t.Errorf("raw advisory severity = %q, want CRITICAL", rawAdvisory.Severity)
	}

	nilAdvisory := advisoryExplanationProto(nil, allVulnReferences)
	if nilAdvisory.Severity != "UNKNOWN" {
		t.Errorf("nil advisory severity = %q, want UNKNOWN", nilAdvisory.Severity)
	}
}

func migrationOnlyScanResponse() *scanv1.ScanResponse {
	pkg := &dependencyv1.Package{
		Name:      "github.com/example/widget",
		Version:   "v1.4.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/widget@v1.4.0",
		Direct:    true,
		ManifestRefs: []*dependencyv1.ManifestRef{
			{Path: "go.mod", Manager: "go"},
		},
	}
	return &scanv1.ScanResponse{
		PackagesScanned: 1,
		Findings: []*vulnerabilityv1.Finding{
			{AdvisoryId: "GO-2026-0001", Package: pkg, Affected: true},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GO-2026-0001": {
				Id:       "GO-2026-0001",
				Summary:  "Migration-only vulnerability",
				Severity: vulnerability.NewSeverity("HIGH", ""),
				PackageFixes: []*vulnerabilityv1.PackageFix{
					{
						Module:        "github.com/example/widget/v2",
						Ecosystem:     "Go",
						FixedVersions: []string{"v2.0.1"},
					},
				},
				ResolvedFix: &vulnerabilityv1.FixVerdict{
					Status:       vulnerabilityv1.FixVerdict_STATUS_MIGRATION,
					Version:      "v2.0.1",
					TargetModule: "github.com/example/widget/v2",
					Claimed:      "v2.0.1",
				},
			},
		},
		Stats:    &vulnerabilityv1.Stats{Unique: 1, High: 1, FixViaMigration: 1},
		Packages: []*dependencyv1.Package{pkg},
	}
}

func groupedMigrationScanResponse() *scanv1.ScanResponse {
	resp := migrationOnlyScanResponse()
	pkg := resp.Packages[0]
	resp.Findings = append(resp.Findings, &vulnerabilityv1.Finding{
		AdvisoryId: "GO-2026-0003",
		Package:    pkg,
		Affected:   true,
	})
	resp.Advisories["GO-2026-0003"] = &vulnerabilityv1.Advisory{
		Id:       "GO-2026-0003",
		Summary:  "Second migration-only vulnerability on the same package",
		Severity: vulnerability.NewSeverity("HIGH", ""),
		PackageFixes: []*vulnerabilityv1.PackageFix{
			{
				Module:        "github.com/example/widget/v2",
				Ecosystem:     "Go",
				FixedVersions: []string{"v2.0.1"},
			},
		},
		ResolvedFix: &vulnerabilityv1.FixVerdict{
			Status:       vulnerabilityv1.FixVerdict_STATUS_MIGRATION,
			Version:      "v2.0.1",
			TargetModule: "github.com/example/widget/v2",
			Claimed:      "v2.0.1",
		},
	}
	resp.Stats = &vulnerabilityv1.Stats{Unique: 2, High: 2, FixViaMigration: 2}
	return resp
}

func indirectMigrationOnlyScanResponse() *scanv1.ScanResponse {
	resp := migrationOnlyScanResponse()
	pkg := resp.Packages[0]
	pkg.Direct = false
	resp.Findings[0].Package = pkg
	return resp
}

func multiIndirectMigrationScanResponse() *scanv1.ScanResponse {
	resp := indirectMigrationOnlyScanResponse()
	pkg := &dependencyv1.Package{
		Name:      "github.com/containerd/containerd",
		Version:   "v1.7.33",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/containerd/containerd@1.7.33",
		Direct:    false,
		ManifestRefs: []*dependencyv1.ManifestRef{
			{Path: "go.mod", Manager: "go"},
		},
	}
	resp.PackagesScanned = 2
	resp.Findings = append(resp.Findings, &vulnerabilityv1.Finding{
		AdvisoryId: "GO-2026-0002",
		Package:    pkg,
		Affected:   true,
	})
	resp.Advisories["GO-2026-0002"] = &vulnerabilityv1.Advisory{
		Id:       "GO-2026-0002",
		Summary:  "Second migration-only vulnerability",
		Severity: vulnerability.NewSeverity("HIGH", ""),
		PackageFixes: []*vulnerabilityv1.PackageFix{
			{
				Module:        "github.com/containerd/containerd/v2",
				Ecosystem:     "Go",
				FixedVersions: []string{"v2.1.9"},
			},
		},
		ResolvedFix: &vulnerabilityv1.FixVerdict{
			Status:       vulnerabilityv1.FixVerdict_STATUS_MIGRATION,
			Version:      "v2.1.9",
			TargetModule: "github.com/containerd/containerd/v2",
			Claimed:      "v2.1.9",
		},
	}
	resp.Stats = &vulnerabilityv1.Stats{Unique: 2, High: 2, FixViaMigration: 2}
	resp.Packages = append(resp.Packages, pkg)
	return resp
}

func directUnfixableTransitiveFixableScanResponse() *scanv1.ScanResponse {
	directPkg := &dependencyv1.Package{
		Name:      "github.com/example/direct",
		Version:   "v1.0.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/direct@v1.0.0",
		Direct:    true,
	}
	transitivePkg := &dependencyv1.Package{
		Name:      "github.com/example/transitive",
		Version:   "v1.0.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/transitive@v1.0.0",
		Direct:    false,
	}
	return &scanv1.ScanResponse{
		PackagesScanned: 2,
		Findings: []*vulnerabilityv1.Finding{
			{AdvisoryId: "GO-2026-1001", Package: directPkg, Affected: true},
			{AdvisoryId: "GO-2026-1002", Package: transitivePkg, Affected: true},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GO-2026-1001": {
				Id:       "GO-2026-1001",
				Summary:  "Direct vulnerability without a fix",
				Severity: vulnerability.NewSeverity("HIGH", ""),
			},
			"GO-2026-1002": {
				Id:            "GO-2026-1002",
				Summary:       "Transitive vulnerability with a fix",
				Severity:      vulnerability.NewSeverity("HIGH", ""),
				FixedVersions: []string{"v1.0.1"},
			},
		},
		Stats:    &vulnerabilityv1.Stats{Unique: 2, High: 2, FixAvailable: 1},
		Packages: []*dependencyv1.Package{directPkg, transitivePkg},
	}
}

func unknownSeverityScanResponse() *scanv1.ScanResponse {
	firstPkg := &dependencyv1.Package{
		Name:      "github.com/example/unknown-one",
		Version:   "v1.0.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/unknown-one@v1.0.0",
		Direct:    false,
	}
	secondPkg := &dependencyv1.Package{
		Name:      "github.com/example/unknown-two",
		Version:   "v1.0.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/unknown-two@v1.0.0",
		Direct:    false,
	}
	return &scanv1.ScanResponse{
		PackagesScanned: 2,
		Findings: []*vulnerabilityv1.Finding{
			{AdvisoryId: "GO-2026-2001", Package: firstPkg, Affected: true},
			{AdvisoryId: "GO-2026-2002", Package: secondPkg, Affected: true},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"GO-2026-2001": {
				Id:            "GO-2026-2001",
				Summary:       "Unknown severity vulnerability with a fix",
				FixedVersions: []string{"v1.0.1"},
			},
			"GO-2026-2002": {
				Id:      "GO-2026-2002",
				Summary: "Unknown severity vulnerability without a fix",
			},
		},
		Stats:    &vulnerabilityv1.Stats{Unique: 2, FixAvailable: 1},
		Packages: []*dependencyv1.Package{firstPkg, secondPkg},
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

func TestServerInstructionsReferenceRealTools(t *testing.T) {
	if strings.TrimSpace(serverInstructions) == "" {
		t.Fatal("serverInstructions is empty")
	}
	registered := make(map[string]bool)
	for _, name := range NewServer().toolNames {
		registered[name] = true
	}
	// Tools named in the instructions must exist, so guidance can't reference a
	// renamed or removed tool.
	for _, name := range []string{
		"scan_directory", "triage_vulnerabilities", "graph_why", "graph_needs",
		"get_remediation", "diff_refs", "scan_container", "scan_package",
		"list_policy_entrypoints",
	} {
		if !strings.Contains(serverInstructions, name) {
			t.Errorf("serverInstructions does not mention %q", name)
		}
		if !registered[name] {
			t.Errorf("serverInstructions references %q which is not a registered tool", name)
		}
	}
	// Key output conventions agents rely on must stay documented.
	for _, phrase := range []string{"unknown", "Truncated", "clean: true", "found: false", "PURL"} {
		if !strings.Contains(serverInstructions, phrase) {
			t.Errorf("serverInstructions should describe %q", phrase)
		}
	}
}

func TestDiffChangeTypeVocabularyMatchesCompare(t *testing.T) {
	// MCP diff output must speak the same change-type vocabulary as the canonical
	// compare package. changeTypeRank returns 5 for anything it does not know, so
	// every compare.ChangeType string must rank below that.
	for _, ct := range []compare.ChangeType{
		compare.Added, compare.Removed, compare.Updated, compare.Upgraded, compare.Downgraded,
	} {
		if rank := changeTypeRank(ct.String()); rank >= 5 {
			t.Errorf("compare change type %q is unknown to MCP changeTypeRank (vocabulary drift)", ct.String())
		}
	}
}

func TestMCPCoverageAndKindConversion(t *testing.T) {
	if got := mcpFindingKind(vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE); got != "malware" {
		t.Errorf("mcpFindingKind(MALWARE) = %q, want malware", got)
	}
	if got := mcpFindingKind(vulnerabilityv1.FindingKind_FINDING_KIND_UNSPECIFIED); got != "" {
		t.Errorf("mcpFindingKind(UNSPECIFIED) = %q, want empty", got)
	}
	if coverageProto(nil) != nil {
		t.Error("coverageProto(nil) should be nil")
	}
	cov := coverageProto(&vulnerabilityv1.ScanCoverage{
		Covered:   []*vulnerabilityv1.CoverageEntry{{Ecosystem: "go", Artifact: vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE, Sources: []string{"osv"}, PackageCount: 5}},
		Uncovered: []*vulnerabilityv1.CoverageEntry{{Ecosystem: "docker", Artifact: vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF, PackageCount: 2}},
	})
	if cov == nil || len(cov.GetCovered()) != 1 || len(cov.GetUncovered()) != 1 {
		t.Fatalf("coverage = %+v, want 1 covered + 1 uncovered", cov)
	}
	if cov.GetCovered()[0].GetArtifact() != "package" || cov.GetCovered()[0].GetEcosystem() != "go" {
		t.Errorf("covered[0] = %+v, want go/package", cov.GetCovered()[0])
	}
	if cov.GetUncovered()[0].GetArtifact() != "container_image_ref" {
		t.Errorf("uncovered[0].Artifact = %q, want container_image_ref", cov.GetUncovered()[0].GetArtifact())
	}
}

func TestMCPEcosystemAliasesAreConsistent(t *testing.T) {
	// Every github-actions spelling must canonicalize identically and map to
	// the same purl type, including "gha" which a previous duplicate table missed.
	for _, alias := range []string{"github-actions", "github", "gha", "GitHub Actions", "github_actions", "githubactions"} {
		if got := mcpOutputEcosystem(alias); got != "github-actions" {
			t.Errorf("mcpOutputEcosystem(%q) = %q, want github-actions", alias, got)
		}
		if got, want := mcpPURLType(alias), mcpPURLType("github-actions"); got != want {
			t.Errorf("mcpPURLType(%q) = %q, want %q (github-actions)", alias, got, want)
		}
	}
	// The OSV display form for cargo now resolves via the canonical ecosystem table.
	if got := mcpOutputEcosystem("cargo (crates.io)"); got != "cargo" {
		t.Errorf("mcpOutputEcosystem(\"cargo (crates.io)\") = %q, want cargo", got)
	}
}

func TestListPolicyEntrypointsTool(t *testing.T) {
	s := NewServer()
	ctx := t.Context()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	tool := findMCPTool(t, tools.Tools, "list_policy_entrypoints")
	schema := toolInputSchema(t, tool)
	if _, ok := schema["required"]; ok {
		t.Fatalf("list_policy_entrypoints schema has required fields %v, want none", schema["required"])
	}
	properties := schemaObject(t, schema, "properties")
	category := schemaObject(t, properties, "category")
	enum := schemaArray(t, category, "enum")
	for _, want := range []string{"scan", "server", "sandbox", "container", "service", "exec"} {
		if !slices.ContainsFunc(enum, func(v any) bool { return v == want }) {
			t.Fatalf("category enum = %v, want %q", enum, want)
		}
	}

	result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      "list_policy_entrypoints",
		Arguments: map[string]any{"unexpected": true},
	})
	if err != nil {
		t.Fatalf("CallTool invalid arguments failed: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("invalid list_policy_entrypoints arguments unexpectedly passed validation: %#v", result)
	}

	result, err = clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name:      "list_policy_entrypoints",
		Arguments: map[string]any{"category": "scan"},
	})
	if err != nil {
		t.Fatalf("CallTool list_policy_entrypoints failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("list_policy_entrypoints returned error result: %#v", result)
	}
	structured := structuredContentObject(t, result)
	if got, want := structured["category"], "scan"; got != want {
		t.Fatalf("category = %v, want %q", got, want)
	}
	if got, want := structured["entrypointCount"], float64(len(policy.EntrypointsScan)); got != want {
		t.Fatalf("entrypointCount = %v, want %v", got, want)
	}
	entrypoints := structuredArray(t, structured, "entrypoints")
	entrypointByName := map[string]map[string]any{}
	for _, raw := range entrypoints {
		entrypoint, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("entrypoint has type %T, want object", raw)
		}
		name, ok := entrypoint["name"].(string)
		if !ok {
			t.Fatalf("entrypoint name has type %T, want string", entrypoint["name"])
		}
		entrypointByName[name] = entrypoint
	}

	scanVulnerability := entrypointByName[string(policy.EntrypointScanVulnerability)]
	if scanVulnerability == nil {
		t.Fatalf("missing %s entrypoint in %v", policy.EntrypointScanVulnerability, entrypointByName)
	}
	if scanVulnerability["description"] != policy.GetBindingProfile(policy.EntrypointScanVulnerability).Description {
		t.Fatalf("scan_vulnerability description = %v", scanVulnerability["description"])
	}
	variables := structuredArray(t, scanVulnerability, "variables")
	requiredByName := map[string]bool{}
	for _, raw := range variables {
		variable, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("variable has type %T, want object", raw)
		}
		name, ok := variable["name"].(string)
		if !ok {
			t.Fatalf("variable name has type %T, want string", variable["name"])
		}
		// The protojson wire omits false booleans, so an absent required key
		// means the variable is optional.
		required, _ := variable["required"].(bool)
		requiredByName[name] = required
	}
	if !requiredByName["vulnerability"] {
		t.Fatalf("vulnerability required = false, want true")
	}
	if requiredByName["target"] {
		t.Fatalf("target required = true, want false")
	}

	direct, err := callProtoTool(t, ctx, s.listPolicyEntrypoints,
		&mcpv1.ListPolicyEntrypointsRequest{Category: "service"}, &mcpv1.ListPolicyEntrypointsResult{})
	if err != nil {
		t.Fatalf("listPolicyEntrypoints service alias failed: %v", err)
	}
	if got, want := direct.Category, "server"; got != want {
		t.Fatalf("service alias category = %q, want %q", got, want)
	}
	if got, want := int(direct.EntrypointCount), len(policy.EntrypointsService); got != want {
		t.Fatalf("service alias entrypointCount = %d, want %d", got, want)
	}

	direct, err = callProtoTool(t, ctx, s.listPolicyEntrypoints,
		&mcpv1.ListPolicyEntrypointsRequest{Category: "exec"}, &mcpv1.ListPolicyEntrypointsResult{})
	if err != nil {
		t.Fatalf("listPolicyEntrypoints exec alias failed: %v", err)
	}
	if got, want := direct.Category, "sandbox"; got != want {
		t.Fatalf("exec alias category = %q, want %q", got, want)
	}
	if got, want := int(direct.EntrypointCount), len(policy.EntrypointsSandbox); got != want {
		t.Fatalf("exec alias entrypointCount = %d, want %d", got, want)
	}
}

func TestMCPToolInputSchemasAvoidTopLevelComposition(t *testing.T) {
	s := NewServer(WithClients(newMockClients(mockClientsConfig{})))
	ctx := t.Context()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	for _, tool := range tools.Tools {
		schema := toolInputSchema(t, tool)
		for _, keyword := range []string{"oneOf", "allOf", "anyOf"} {
			if _, ok := schema[keyword]; ok {
				t.Fatalf("tool %q input schema has top-level %s: %#v", tool.Name, keyword, schema[keyword])
			}
		}
	}
}

func TestExplainVulnerabilityToolSchemas(t *testing.T) {
	s := NewServer()
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	single := findMCPTool(t, tools.Tools, "explain_vulnerability")
	singleSchema := toolInputSchema(t, single)
	if got, want := schemaRequired(t, singleSchema), []string{"id"}; !slices.Equal(got, want) {
		t.Fatalf("explain_vulnerability required fields = %v, want %v", got, want)
	}
	singleProperties := schemaObject(t, singleSchema, "properties")
	idProperty, ok := singleProperties["id"].(map[string]any)
	if !ok {
		t.Fatalf("explain_vulnerability id schema has type %T, want map[string]any", singleProperties["id"])
	}
	if got := idProperty["minLength"]; got != float64(1) {
		t.Fatalf("explain_vulnerability id minLength = %v, want 1", got)
	}
	singleReferenceLimit := schemaObject(t, singleProperties, "referenceLimit")
	if got := singleReferenceLimit["type"]; got != "integer" {
		t.Fatalf("explain_vulnerability referenceLimit type = %v, want integer", got)
	}
	// The output schema is derived from the deputy.mcp.v1 descriptor; protojson
	// omits zero values on the wire, so no field is "required". Guard that the
	// collection fields stay in the advertised contract instead.
	singleOutputSchema := toolOutputSchema(t, single)
	requireSchemaProperties(t, singleOutputSchema, "aliases", "fixedVersions", "packageFixes", "references")

	batch := findMCPTool(t, tools.Tools, "explain_vulnerabilities")
	batchSchema := toolInputSchema(t, batch)
	if got, want := schemaRequired(t, batchSchema), []string{"ids"}; !slices.Equal(got, want) {
		t.Fatalf("explain_vulnerabilities required fields = %v, want %v", got, want)
	}
	batchProperties := schemaObject(t, batchSchema, "properties")
	idsProperty, ok := batchProperties["ids"].(map[string]any)
	if !ok {
		t.Fatalf("explain_vulnerabilities ids schema has type %T, want map[string]any", batchProperties["ids"])
	}
	if got := idsProperty["minItems"]; got != float64(1) {
		t.Fatalf("explain_vulnerabilities ids minItems = %v, want 1", got)
	}
	batchReferenceLimit := schemaObject(t, batchProperties, "referenceLimit")
	if got := batchReferenceLimit["type"]; got != "integer" {
		t.Fatalf("explain_vulnerabilities referenceLimit type = %v, want integer", got)
	}
	items, ok := idsProperty["items"].(map[string]any)
	if !ok {
		t.Fatalf("explain_vulnerabilities ids items schema has type %T, want map[string]any", idsProperty["items"])
	}
	if got := items["minLength"]; got != float64(1) {
		t.Fatalf("explain_vulnerabilities ids item minLength = %v, want 1", got)
	}
	batchOutputSchema := toolOutputSchema(t, batch)
	requireSchemaProperties(t, batchOutputSchema, "errors", "vulnerabilities")

	invalidCalls := []struct {
		name      string
		arguments map[string]any
	}{
		{name: "empty single ID", arguments: map[string]any{"id": ""}},
		{name: "snake case single ID", arguments: map[string]any{"vulnerability_id": "CVE-2021-44228"}},
		{name: "empty batch IDs", arguments: map[string]any{"ids": []any{}}},
		{name: "blank batch ID", arguments: map[string]any{"ids": []any{"CVE-2021-44228", ""}}},
	}
	for _, tt := range invalidCalls {
		toolName := "explain_vulnerability"
		if strings.Contains(tt.name, "batch") {
			toolName = "explain_vulnerabilities"
		}
		result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
			Name:      toolName,
			Arguments: tt.arguments,
		})
		if err != nil {
			t.Fatalf("CallTool with %s failed: %v", tt.name, err)
		}
		if result == nil || !result.IsError {
			t.Fatalf("%s arguments unexpectedly passed validation: %#v", tt.name, result)
		}
	}
}

// TestExplainVulnerabilitiesOmitsEmptyCollections pins the proto-contract
// wire shape: the protojson dialect omits empty collections (errors, aliases,
// fixedVersions, packageFixes, references), so absence means empty, while
// severity is always set and therefore always present.
func TestExplainVulnerabilitiesOmitsEmptyCollections(t *testing.T) {
	mockOSV := &mockOSVClient{
		vulns: map[string]*osvschema.Vulnerability{
			"CVE-2021-44228": {
				ID:      "CVE-2021-44228",
				Summary: "Log4Shell",
				References: []osvschema.Reference{
					{URL: "https://example.com/one"},
					{URL: "https://example.com/two"},
					{URL: "https://example.com/three"},
				},
			},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{
		vulnerabilityHandler: &mockVulnerabilityHandler{osvClient: mockOSV},
	})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "explain_vulnerabilities",
		Arguments: map[string]any{
			"ids":            []string{"CVE-2021-44228"},
			"referenceLimit": 0,
		},
	})
	if err != nil {
		t.Fatalf("CallTool explain_vulnerabilities failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("explain_vulnerabilities returned error result: %#v", result)
	}
	structured := structuredContentObject(t, result)
	requireStructuredEmptyCollection(t, structured, "errors")
	vulnerabilities := structuredArray(t, structured, "vulnerabilities")
	if len(vulnerabilities) != 1 {
		t.Fatalf("structured vulnerabilities has length %d, want 1", len(vulnerabilities))
	}
	vulnerability, ok := vulnerabilities[0].(map[string]any)
	if !ok {
		t.Fatalf("structured vulnerability has type %T, want object", vulnerabilities[0])
	}
	requireStructuredEmptyCollection(t, vulnerability, "aliases")
	requireStructuredEmptyCollection(t, vulnerability, "fixedVersions")
	requireStructuredEmptyCollection(t, vulnerability, "packageFixes")
	requireStructuredEmptyCollection(t, vulnerability, "references")
	severity, ok := vulnerability["severity"].(string)
	if !ok || severity == "" {
		t.Fatalf("structured severity = %v, want always-present non-empty string", vulnerability["severity"])
	}
}

func TestScanPackageToolSchema(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: emptyScanResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	tool := findMCPTool(t, tools.Tools, "scan_package")
	if !strings.Contains(tool.Description, "PURL") {
		t.Errorf("scan_package description = %q, want PURL guidance", tool.Description)
	}

	schema := toolInputSchema(t, tool)
	if got := schema["type"]; got != "object" {
		t.Fatalf("scan_package schema type = %v, want object", got)
	}
	if _, ok := schema["required"]; ok {
		t.Fatalf("scan_package schema has top-level required %v, want runtime validation alternatives", schema["required"])
	}
	for _, keyword := range []string{"oneOf", "allOf", "anyOf"} {
		if _, ok := schema[keyword]; ok {
			t.Fatalf("scan_package schema has top-level %s: %#v", keyword, schema[keyword])
		}
	}

	properties := schemaObject(t, schema, "properties")
	if _, ok := properties["purl"]; !ok {
		t.Fatal("scan_package schema is missing purl property")
	}
	if _, ok := properties["name"]; !ok {
		t.Fatal("scan_package schema is missing name property")
	}
	ecosystemProperty, ok := properties["ecosystem"].(map[string]any)
	if !ok {
		t.Fatalf("scan_package ecosystem schema has type %T, want map[string]any", properties["ecosystem"])
	}
	ecosystemDescription, ok := ecosystemProperty["description"].(string)
	if !ok {
		t.Fatalf("scan_package ecosystem description has type %T, want string", ecosystemProperty["description"])
	}
	for _, badExample := range []string{"Go", "PyPI", "Maven", "Cargo", "GitHub Actions"} {
		if strings.Contains(ecosystemDescription, badExample) {
			t.Fatalf("scan_package ecosystem description = %q, want canonical lowercase examples", ecosystemDescription)
		}
	}
	for _, wantExample := range []string{"go", "pypi", "maven", "cargo", "github-actions"} {
		if !strings.Contains(ecosystemDescription, wantExample) {
			t.Fatalf("scan_package ecosystem description = %q, want %q mentioned", ecosystemDescription, wantExample)
		}
	}

	invalidCalls := []struct {
		name      string
		arguments map[string]any
	}{
		{name: "empty", arguments: map[string]any{}},
		{name: "name only", arguments: map[string]any{"name": "lodash"}},
	}
	for _, tt := range invalidCalls {
		result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
			Name:      "scan_package",
			Arguments: tt.arguments,
		})
		if err != nil {
			t.Fatalf("CallTool with %s failed: %v", tt.name, err)
		}
		if result == nil || !result.IsError {
			t.Fatalf("%s scan_package arguments unexpectedly passed validation: %#v", tt.name, result)
		}
		if len(mockScan.requests) != 0 {
			t.Fatalf("%s scan_package arguments reached scan service, got %d requests", tt.name, len(mockScan.requests))
		}
	}

	validCalls := []struct {
		name       string
		arguments  map[string]any
		wantTarget string
	}{
		{
			name: "purl",
			arguments: map[string]any{
				"purl": "pkg:npm/lodash@4.17.21",
			},
			wantTarget: "pkg:npm/lodash@4.17.21",
		},
		{
			name: "split fields",
			arguments: map[string]any{
				"name":      "golang.org/x/net",
				"version":   "0.17.0",
				"ecosystem": "go",
			},
			wantTarget: "pkg:golang/golang.org/x/net@v0.17.0",
		},
		{
			name: "name as purl",
			arguments: map[string]any{
				"name": "pkg:npm/lodash@4.17.21",
			},
			wantTarget: "pkg:npm/lodash@4.17.21",
		},
	}
	for i, tt := range validCalls {
		result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
			Name:      "scan_package",
			Arguments: tt.arguments,
		})
		if err != nil {
			t.Fatalf("CallTool with %s failed: %v", tt.name, err)
		}
		if result == nil || result.IsError {
			t.Fatalf("%s scan_package arguments failed validation: %#v", tt.name, result)
		}
		if got, want := len(mockScan.requests), i+1; got != want {
			t.Fatalf("%s scan_package arguments produced %d scan requests, want %d", tt.name, got, want)
		}
		if got := mockScan.requests[i].Target; got != tt.wantTarget {
			t.Fatalf("%s scan target = %q, want %q", tt.name, got, tt.wantTarget)
		}
	}
}

func TestScanContainerToolSchema(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: emptyScanResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	tool := findMCPTool(t, tools.Tools, "scan_container")
	if !strings.Contains(tool.Description, "remote registries") {
		t.Errorf("scan_container description = %q, want registry guidance", tool.Description)
	}

	schema := toolInputSchema(t, tool)
	if got := schema["type"]; got != "object" {
		t.Fatalf("scan_container schema type = %v, want object", got)
	}
	if got, want := schemaRequired(t, schema), []string{"image"}; !slices.Equal(got, want) {
		t.Fatalf("scan_container required fields = %v, want %v", got, want)
	}

	properties := schemaObject(t, schema, "properties")
	for _, field := range []string{"image", "platform"} {
		if _, ok := properties[field]; !ok {
			t.Fatalf("scan_container schema is missing %s property", field)
		}
	}
	imageProperty, ok := properties["image"].(map[string]any)
	if !ok {
		t.Fatalf("scan_container image schema has type %T, want map[string]any", properties["image"])
	}
	if got := imageProperty["minLength"]; got != float64(1) {
		t.Fatalf("scan_container image minLength = %v, want 1", got)
	}
	if got := imageProperty["pattern"]; got != "\\S" {
		t.Fatalf("scan_container image pattern = %v, want non-whitespace guard", got)
	}

	invalidCalls := []struct {
		name      string
		arguments map[string]any
	}{
		{name: "missing image", arguments: map[string]any{}},
		{name: "empty image", arguments: map[string]any{"image": ""}},
		{name: "unknown field", arguments: map[string]any{"image": "debian:bookworm", "includeSecrets": true}},
	}
	for _, tt := range invalidCalls {
		result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
			Name:      "scan_container",
			Arguments: tt.arguments,
		})
		if err != nil {
			t.Fatalf("CallTool with %s failed: %v", tt.name, err)
		}
		if result == nil || !result.IsError {
			t.Fatalf("%s scan_container arguments unexpectedly passed validation: %#v", tt.name, result)
		}
		if len(mockScan.requests) != 0 {
			t.Fatalf("%s scan_container arguments reached scan service, got %d requests", tt.name, len(mockScan.requests))
		}
	}

	result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "scan_container",
		Arguments: map[string]any{
			"image":    "debian:bookworm",
			"platform": "linux/amd64",
		},
	})
	if err != nil {
		t.Fatalf("CallTool with valid scan_container arguments failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("valid scan_container arguments failed validation: %#v", result)
	}
	if got, want := len(mockScan.requests), 1; got != want {
		t.Fatalf("valid scan_container arguments produced %d scan requests, want %d", got, want)
	}
	if got := mockScan.requests[0].Target; got != "debian:bookworm" {
		t.Fatalf("scan target = %q, want debian:bookworm", got)
	}
	if got := mockScan.requests[0].Options.GetPlatform(); got != "linux/amd64" {
		t.Fatalf("scan platform = %q, want linux/amd64", got)
	}
}

func TestDiffRefsToolSchema(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			emptyScanResponse(),
			emptyScanResponse(),
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	tool := findMCPTool(t, tools.Tools, "diff_refs")
	if !strings.Contains(tool.Description, "container images") {
		t.Errorf("diff_refs description = %q, want container image guidance", tool.Description)
	}

	schema := toolInputSchema(t, tool)
	if got := schema["type"]; got != "object" {
		t.Fatalf("diff_refs schema type = %v, want object", got)
	}
	if got, want := schemaRequired(t, schema), []string{"baseRef", "targetRef"}; !slices.Equal(got, want) {
		t.Fatalf("diff_refs required fields = %v, want %v", got, want)
	}

	properties := schemaObject(t, schema, "properties")
	for _, field := range []string{"path", "baseRef", "targetRef", "platform", "ecosystems", "excludePaths"} {
		if _, ok := properties[field]; !ok {
			t.Fatalf("diff_refs schema is missing %s property", field)
		}
	}

	outputSchema := toolOutputSchema(t, tool)
	if got := outputSchema["type"]; got != "object" {
		t.Fatalf("diff_refs output schema type = %v, want object", got)
	}
	// The output schema is derived from the deputy.mcp.v1 descriptor; protojson
	// omits zero values on the wire, so no field is "required". Guard that the
	// advertised contract keeps the diff counts and collections instead.
	requireSchemaProperties(t, outputSchema,
		"path", "baseRef", "targetRef", "changes", "isContainerDiff",
		"addedCount", "removedCount", "updatedCount",
	)

	result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "diff_refs",
		Arguments: map[string]any{
			"baseRef":   "localhost:5000/app:v1",
			"targetRef": "localhost:5000/app:v2",
			"platform":  "linux/arm64",
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("pathless container diff failed validation: %#v", result)
	}
	if got, want := len(mockScan.requests), 2; got != want {
		t.Fatalf("container diff scan requests = %d, want %d", got, want)
	}
	if got, want := mockScan.requests[0].Target, "localhost:5000/app:v1"; got != want {
		t.Fatalf("base scan target = %q, want %q", got, want)
	}
	if got, want := mockScan.requests[1].Target, "localhost:5000/app:v2"; got != want {
		t.Fatalf("target scan target = %q, want %q", got, want)
	}
	for i, req := range mockScan.requests {
		if got, want := req.Options.GetPlatform(), "linux/arm64"; got != want {
			t.Fatalf("scan request %d platform = %q, want %q", i, got, want)
		}
	}
	structured := structuredContentObject(t, result)
	if _, ok := structured["path"]; ok {
		t.Fatalf("container diff structured content unexpectedly included path: %#v", structured["path"])
	}
	if got, want := structured["baseRef"], "localhost:5000/app:v1"; got != want {
		t.Fatalf("structured baseRef = %v, want %q", got, want)
	}
	if got, want := structured["targetRef"], "localhost:5000/app:v2"; got != want {
		t.Fatalf("structured targetRef = %v, want %q", got, want)
	}
	if got, want := structured["platform"], "linux/arm64"; got != want {
		t.Fatalf("structured platform = %v, want %q", got, want)
	}

	result, err = clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "diff_refs",
		Arguments: map[string]any{
			"targetRef": "localhost:5000/app:v2",
		},
	})
	if err != nil {
		t.Fatalf("CallTool with missing baseRef failed: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("missing baseRef unexpectedly passed validation: %#v", result)
	}
	if got, want := len(mockScan.requests), 2; got != want {
		t.Fatalf("invalid diff_refs arguments reached scan service: got %d requests, want %d", got, want)
	}
}

func TestLocalPathToolSchemasExposeAgentControls(t *testing.T) {
	s := NewServer()
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	tests := []struct {
		name       string
		properties []string
		required   []string
		booleans   []string
	}{
		{
			name:       "scan_directory",
			properties: []string{"path", "ref", "ecosystems", "excludePaths"},
			required:   []string{"path"},
		},
		{
			name:       "list_dependencies",
			properties: []string{"path", "directOnly", "ref", "ecosystems", "excludePaths"},
			required:   []string{"path"},
			booleans:   []string{"directOnly"},
		},
		{
			name:       "generate_sbom",
			properties: []string{"path", "ref", "format", "enrichLicenses", "ecosystems", "excludePaths"},
			required:   []string{"path"},
			booleans:   []string{"enrichLicenses"},
		},
		{
			name:       "get_remediation",
			properties: []string{"path", "ref", "ecosystems", "excludePaths"},
			required:   []string{"path"},
		},
		{
			name:       "analyze_dependency_graph",
			properties: []string{"path", "targetPurl", "ref", "ecosystems", "excludePaths", "resolveTransitives", "extended"},
			required:   []string{"path"},
			booleans:   []string{"resolveTransitives", "extended"},
		},
		{
			name:       "graph_why",
			properties: []string{"path", "package", "ref", "showAll", "ecosystems", "excludePaths", "resolveTransitives", "extended"},
			required:   []string{"package", "path"},
			booleans:   []string{"showAll", "resolveTransitives", "extended"},
		},
		{
			name:       "graph_needs",
			properties: []string{"path", "package", "ref", "ecosystems", "excludePaths", "resolveTransitives", "extended"},
			required:   []string{"package", "path"},
			booleans:   []string{"resolveTransitives", "extended"},
		},
		{
			name:       "triage_vulnerabilities",
			properties: []string{"path", "ref", "ecosystems", "excludePaths"},
			required:   []string{"path"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tool := findMCPTool(t, tools.Tools, tt.name)
			schema := toolInputSchema(t, tool)
			if got, want := schemaRequired(t, schema), tt.required; !slices.Equal(got, want) {
				t.Fatalf("%s required fields = %v, want %v", tt.name, got, want)
			}
			properties := schemaObject(t, schema, "properties")
			for _, property := range tt.properties {
				if _, ok := properties[property]; !ok {
					t.Fatalf("%s schema is missing %s property", tt.name, property)
				}
			}
			pathProperty := schemaObject(t, properties, "path")
			if got := pathProperty["minLength"]; got != float64(1) {
				t.Fatalf("%s path minLength = %v, want 1", tt.name, got)
			}
			if got := pathProperty["pattern"]; got != "\\S" {
				t.Fatalf("%s path pattern = %v, want non-whitespace guard", tt.name, got)
			}
			for _, property := range tt.booleans {
				boolProperty := schemaObject(t, properties, property)
				if got := boolProperty["type"]; got != "boolean" {
					t.Fatalf("%s %s type = %v, want boolean", tt.name, property, got)
				}
			}
			for _, property := range []string{"ecosystems", "excludePaths"} {
				if !slices.Contains(tt.properties, property) {
					continue
				}
				prop, ok := properties[property].(map[string]any)
				if !ok {
					t.Fatalf("%s %s schema has type %T, want map[string]any", tt.name, property, properties[property])
				}
				items, ok := prop["items"].(map[string]any)
				if !ok {
					t.Fatalf("%s %s items schema has type %T, want map[string]any", tt.name, property, prop["items"])
				}
				if got := items["minLength"]; got != float64(1) {
					t.Fatalf("%s %s item minLength = %v, want 1", tt.name, property, got)
				}
				if got := items["pattern"]; got != "\\S" {
					t.Fatalf("%s %s item pattern = %v, want non-whitespace guard", tt.name, property, got)
				}
			}
			if slices.Contains(tt.properties, "resolveTransitives") {
				resolveTransitives, ok := properties["resolveTransitives"].(map[string]any)
				if !ok {
					t.Fatalf("%s resolveTransitives schema has type %T, want map[string]any", tt.name, properties["resolveTransitives"])
				}
				description, ok := resolveTransitives["description"].(string)
				if !ok {
					t.Fatalf("%s resolveTransitives description has type %T, want string", tt.name, resolveTransitives["description"])
				}
				if !strings.Contains(description, "deps.dev") {
					t.Fatalf("%s resolveTransitives description = %q, want deps.dev mentioned", tt.name, description)
				}
			}
			if slices.Contains(tt.properties, "extended") {
				extended, ok := properties["extended"].(map[string]any)
				if !ok {
					t.Fatalf("%s extended schema has type %T, want map[string]any", tt.name, properties["extended"])
				}
				description, ok := extended["description"].(string)
				if !ok {
					t.Fatalf("%s extended description has type %T, want string", tt.name, extended["description"])
				}
				if !strings.Contains(description, "import status") {
					t.Fatalf("%s extended description = %q, want import status mentioned", tt.name, description)
				}
			}
			if tt.name == "analyze_dependency_graph" {
				// The targetPurl guard is enforced client-side by strict MCP
				// clients, so the advertised pattern must stay in the schema.
				targetPurl := schemaObject(t, properties, "targetPurl")
				if got := targetPurl["pattern"]; got != "^[Pp][Kk][Gg]:\\S+" {
					t.Fatalf("%s targetPurl pattern = %v, want PURL prefix guard", tt.name, got)
				}
			}
			if tt.name == "get_remediation" {
				// The output schema is derived from the deputy.mcp.v1
				// descriptor; protojson omits zero values on the wire, so no
				// field is "required". Guard that the command/remediation
				// counts stay in the advertised contract instead.
				outputSchema := toolOutputSchema(t, tool)
				requireSchemaProperties(t, outputSchema,
					"commandCount",
					"executableCommandCount",
					"manualCommandCount",
					"commands",
					"remediableCount",
					"vulnerabilitiesFound",
				)
			}
			if tt.name == "triage_vulnerabilities" {
				// The triage output schema is derived from the
				// deputy.mcp.v1 TriageResult descriptor; protojson omits
				// zero values, so no field is "required" on the wire.
				// Guard that the fixability/directness counts stay in the
				// advertised contract instead.
				outputSchema := toolOutputSchema(t, tool)
				outputProperties := schemaObject(t, outputSchema, "properties")
				for _, property := range []string{
					"directFixableCount",
					"transitiveFixableCount",
					"fixableCount",
					"directVulnerabilities",
					"transitiveVulnerabilities",
					"unknownCount",
				} {
					if _, ok := outputProperties[property]; !ok {
						t.Fatalf("%s output schema is missing %s property", tt.name, property)
					}
				}
			}
			if tt.name == "graph_why" {
				showAll, ok := properties["showAll"].(map[string]any)
				if !ok {
					t.Fatalf("%s showAll schema has type %T, want map[string]any", tt.name, properties["showAll"])
				}
				description, ok := showAll["description"].(string)
				if !ok {
					t.Fatalf("%s showAll description has type %T, want string", tt.name, showAll["description"])
				}
				for _, want := range []string{"default 10", "100", "pathsTruncated"} {
					if !strings.Contains(description, want) {
						t.Fatalf("%s showAll description = %q, want %q mentioned", tt.name, description, want)
					}
				}
				if strings.Contains(description, "all dependency paths") {
					t.Fatalf("%s showAll description = %q, must not imply a complete path set", tt.name, description)
				}
			}
		})
	}
}

func TestListDependenciesOutputSchemaIncludesManifestRefs(t *testing.T) {
	s := NewServer()
	ctx := t.Context()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	outputSchema := toolOutputSchema(t, findMCPTool(t, tools.Tools, "list_dependencies"))
	outputProperties := schemaObject(t, outputSchema, "properties")
	dependenciesSchema := schemaObject(t, outputProperties, "dependencies")
	dependencyItem := schemaResolvedRef(t, outputSchema, schemaObject(t, dependenciesSchema, "items"))
	dependencyProperties := schemaObject(t, dependencyItem, "properties")
	for _, property := range []string{"name", "version", "ecosystem", "purl", "direct", "locations", "manifestRefs"} {
		if _, ok := dependencyProperties[property]; !ok {
			t.Fatalf("dependency schema is missing %s property", property)
		}
	}

	manifestRefsSchema := schemaObject(t, dependencyProperties, "manifestRefs")
	description, ok := manifestRefsSchema["description"].(string)
	if !ok {
		t.Fatalf("manifestRefs description has type %T, want string", manifestRefsSchema["description"])
	}
	for _, want := range []string{"manager", "groups", "component key"} {
		if !strings.Contains(strings.ToLower(description), want) {
			t.Fatalf("manifestRefs description = %q, want %q mentioned", description, want)
		}
	}

	manifestRefItem := schemaResolvedRef(t, outputSchema, schemaObject(t, manifestRefsSchema, "items"))
	manifestRefProperties := schemaObject(t, manifestRefItem, "properties")
	for _, property := range []string{"path", "manager", "groups", "componentKey"} {
		if _, ok := manifestRefProperties[property]; !ok {
			t.Fatalf("manifestRef schema is missing %s property", property)
		}
	}
	groupsSchema := schemaObject(t, manifestRefProperties, "groups")
	groupsItems := schemaObject(t, groupsSchema, "items")
	if got := groupsItems["type"]; got != "string" {
		t.Fatalf("manifestRef groups item type = %v, want string", got)
	}
}

func TestGraphToolsReturnStableEmptyCollections(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: emptyScanResponse()}
	mockGraph := &mockGraphHandler{buildResponse: testBuildGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{
		scanHandler:  mockScan,
		graphHandler: mockGraph,
	})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}
	// The output schemas are derived from the deputy.mcp.v1 descriptors;
	// protojson omits zero values on the wire, so nothing is "required".
	// Guard that the collections stay in the advertised contract instead.
	analyzeSchema := toolOutputSchema(t, findMCPTool(t, tools.Tools, "analyze_dependency_graph"))
	requireSchemaProperties(t, analyzeSchema, "vulnerablePaths", "pathsToTarget")
	graphWhySchema := toolOutputSchema(t, findMCPTool(t, tools.Tools, "graph_why"))
	requireSchemaProperties(t, graphWhySchema, "paths")

	result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "analyze_dependency_graph",
		Arguments: map[string]any{
			"path":       "/test/path",
			"targetPurl": "pkg:golang/github.com/example/missing@v1.0.0",
		},
	})
	if err != nil {
		t.Fatalf("CallTool analyze_dependency_graph failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("analyze_dependency_graph returned error result: %#v", result)
	}
	structured := structuredContentObject(t, result)
	requireStructuredEmptyCollection(t, structured, "vulnerablePaths")
	requireStructuredEmptyCollection(t, structured, "pathsToTarget")
	target, ok := structured["target"].(map[string]any)
	if !ok {
		t.Fatalf("target structured content has type %T, want object", structured["target"])
	}
	requireStructuredEmptyCollection(t, target, "matchedPurls")

	result, err = clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "graph_why",
		Arguments: map[string]any{
			"path":    "/test/path",
			"package": "github.com/example/missing",
		},
	})
	if err != nil {
		t.Fatalf("CallTool graph_why failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("graph_why returned error result: %#v", result)
	}
	structured = structuredContentObject(t, result)
	requireStructuredEmptyCollection(t, structured, "paths")
}

func TestGraphWhyCallToolReturnsMatchedNodeForPathlessPackage(t *testing.T) {
	const dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
	mockGraph := &mockGraphHandler{buildResponse: &graphv1.BuildGraphResponse{
		Nodes: []*graphv1.Node{
			{
				Purl:         dockerPURL,
				Name:         "github.com/docker/docker",
				Version:      "28.5.2+incompatible",
				Ecosystem:    "Go",
				Direct:       false,
				Depth:        graph.DepthDisconnected,
				ImportStatus: graphv1.ImportStatus_IMPORT_STATUS_REQUIRED,
			},
		},
		Stats: &graphv1.GraphStats{TotalNodes: 1, DisconnectedNodes: 1},
	}}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "graph_why",
		Arguments: map[string]any{
			"path":               "/test/path",
			"package":            dockerPURL,
			"resolveTransitives": true,
			"extended":           true,
		},
	})
	if err != nil {
		t.Fatalf("CallTool graph_why failed: %v", err)
	}
	if result == nil || result.IsError {
		t.Fatalf("graph_why returned error result: %#v", result)
	}

	structured := structuredContentObject(t, result)
	requireStructuredEmptyCollection(t, structured, "paths")
	matchedNode, ok := structured["matchedNode"].(map[string]any)
	if !ok {
		t.Fatalf("matchedNode structured content has type %T, want object", structured["matchedNode"])
	}
	if got := matchedNode["purl"]; got != dockerPURL {
		t.Fatalf("matchedNode.purl = %v, want %q", got, dockerPURL)
	}
	if got := matchedNode["importStatus"]; got != "required" {
		t.Fatalf("matchedNode.importStatus = %v, want required", got)
	}
	if got := matchedNode["disconnected"]; got != true {
		t.Fatalf("matchedNode.disconnected = %v, want true", got)
	}
	message, ok := structured["message"].(string)
	if !ok || !strings.Contains(message, "required dependency") {
		t.Fatalf("message = %v, want required dependency context", structured["message"])
	}
	if len(mockGraph.requests) != 1 {
		t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
	}
	opts := mockGraph.requests[0].GetOptions()
	if !opts.GetUseProxy() || !opts.GetUseGit() || !opts.GetExtended() {
		t.Fatalf("graph options = %+v, want proxy, git, and extended enabled", opts)
	}
}

func TestToolAnnotationsExposeReadOnlySafetyHints(t *testing.T) {
	s := NewServer()
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	closedWorldTools := map[string]bool{
		"get_server_info":         true,
		"list_dependencies":       true,
		"list_policy_entrypoints": true,
	}
	for _, tool := range tools.Tools {
		annotations := tool.Annotations
		if annotations == nil {
			t.Fatalf("tool %q missing annotations", tool.Name)
		}
		if !annotations.ReadOnlyHint {
			t.Fatalf("tool %q ReadOnlyHint = false, want true", tool.Name)
		}
		if annotations.DestructiveHint == nil {
			t.Fatalf("tool %q missing DestructiveHint", tool.Name)
		}
		if *annotations.DestructiveHint {
			t.Fatalf("tool %q DestructiveHint = true, want false", tool.Name)
		}
		if annotations.OpenWorldHint == nil {
			t.Fatalf("tool %q missing OpenWorldHint", tool.Name)
		}
		wantOpenWorld := !closedWorldTools[tool.Name]
		if *annotations.OpenWorldHint != wantOpenWorld {
			t.Fatalf("tool %q OpenWorldHint = %v, want %v", tool.Name, *annotations.OpenWorldHint, wantOpenWorld)
		}
	}
}

func TestLocalPathToolSchemasRejectInvalidRequiredStrings(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: emptyScanResponse()}
	mockList := &mockListHandler{listResponse: &listv1.ListPackagesResponse{Stats: &listv1.ListStats{}}}
	mockGraph := &mockGraphHandler{buildResponse: &graphv1.BuildGraphResponse{Stats: &graphv1.GraphStats{}}}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{
		scanHandler:  mockScan,
		listHandler:  mockList,
		graphHandler: mockGraph,
	})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tests := []struct {
		name      string
		tool      string
		arguments map[string]any
	}{
		{name: "scan directory empty path", tool: "scan_directory", arguments: map[string]any{"path": ""}},
		{name: "scan directory whitespace path", tool: "scan_directory", arguments: map[string]any{"path": " \t"}},
		{name: "list dependencies empty path", tool: "list_dependencies", arguments: map[string]any{"path": ""}},
		{name: "get remediation empty path", tool: "get_remediation", arguments: map[string]any{"path": ""}},
		{name: "triage empty path", tool: "triage_vulnerabilities", arguments: map[string]any{"path": ""}},
		{name: "analyze graph empty path", tool: "analyze_dependency_graph", arguments: map[string]any{"path": ""}},
		{name: "analyze graph invalid target purl", tool: "analyze_dependency_graph", arguments: map[string]any{"path": ".", "targetPurl": "not-a-purl"}},
		{name: "graph why empty package", tool: "graph_why", arguments: map[string]any{"path": ".", "package": ""}},
		{name: "graph why whitespace package", tool: "graph_why", arguments: map[string]any{"path": ".", "package": " \t"}},
		{name: "graph needs empty package", tool: "graph_needs", arguments: map[string]any{"path": ".", "package": ""}},
	}

	for _, tt := range tests {
		result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
			Name:      tt.tool,
			Arguments: tt.arguments,
		})
		if err != nil {
			t.Fatalf("CallTool with %s failed: %v", tt.name, err)
		}
		if result == nil || !result.IsError {
			t.Fatalf("%s unexpectedly passed validation: %#v", tt.name, result)
		}
	}
	if len(mockScan.requests) != 0 {
		t.Fatalf("invalid local-source arguments reached scan service, got %d requests", len(mockScan.requests))
	}
	if len(mockList.requests) != 0 {
		t.Fatalf("invalid local-source arguments reached list service, got %d requests", len(mockList.requests))
	}
	if len(mockGraph.requests) != 0 {
		t.Fatalf("invalid local-source arguments reached graph service, got %d requests", len(mockGraph.requests))
	}
}

func TestStringArrayToolSchemasRejectBlankItems(t *testing.T) {
	mockList := &mockListHandler{
		listResponse: &listv1.ListPackagesResponse{Stats: &listv1.ListStats{}},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{listHandler: mockList})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tests := []struct {
		name      string
		arguments map[string]any
	}{
		{name: "blank ecosystem", arguments: map[string]any{"path": ".", "ecosystems": []any{"go", " "}}},
		{name: "blank exclude path", arguments: map[string]any{"path": ".", "excludePaths": []any{".bin/**", ""}}},
	}

	for _, tt := range tests {
		result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
			Name:      "list_dependencies",
			Arguments: tt.arguments,
		})
		if err != nil {
			t.Fatalf("CallTool with %s failed: %v", tt.name, err)
		}
		if result == nil || !result.IsError {
			t.Fatalf("%s unexpectedly passed validation: %#v", tt.name, result)
		}
	}
	if len(mockList.requests) != 0 {
		t.Fatalf("invalid string-array arguments reached list service, got %d requests", len(mockList.requests))
	}
}

func TestGeneratedToolSchemasRejectUnknownArguments(t *testing.T) {
	mockList := &mockListHandler{
		listResponse: &listv1.ListPackagesResponse{Stats: &listv1.ListStats{}},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{listHandler: mockList})))
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	result, err := clientSession.CallTool(ctx, &mcpsdk.CallToolParams{
		Name: "list_dependencies",
		Arguments: map[string]any{
			"path":          ".",
			"direct_only":   true,
			"exclude_paths": []any{".bin/**"},
		},
	})
	if err != nil {
		t.Fatalf("CallTool failed: %v", err)
	}
	if result == nil || !result.IsError {
		t.Fatalf("stale snake_case arguments unexpectedly passed validation: %#v", result)
	}
	if len(mockList.requests) != 0 {
		t.Fatalf("invalid list_dependencies arguments reached list service, got %d requests", len(mockList.requests))
	}
}

func TestGenerateSBOMToolContractRequiresLocalPath(t *testing.T) {
	s := NewServer()
	ctx := context.Background()
	clientSession := connectMCPClientSession(t, ctx, s)

	tools, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools failed: %v", err)
	}

	tool := findMCPTool(t, tools.Tools, "generate_sbom")
	if !strings.Contains(tool.Description, "local directory or repository checkout") {
		t.Fatalf("generate_sbom description = %q, want local checkout wording", tool.Description)
	}

	schema := toolInputSchema(t, tool)
	if got, want := schemaRequired(t, schema), []string{"path"}; !slices.Equal(got, want) {
		t.Fatalf("generate_sbom required fields = %v, want %v", got, want)
	}
	properties := schemaObject(t, schema, "properties")
	pathProperty, ok := properties["path"].(map[string]any)
	if !ok {
		t.Fatalf("generate_sbom path schema has type %T, want map[string]any", properties["path"])
	}
	description, ok := pathProperty["description"].(string)
	if !ok {
		t.Fatalf("generate_sbom path description has type %T, want string", pathProperty["description"])
	}
	if !strings.Contains(strings.ToLower(description), "local directory") {
		t.Fatalf("generate_sbom path description = %q, want local directory wording", description)
	}

	formatProperty, ok := properties["format"].(map[string]any)
	if !ok {
		t.Fatalf("generate_sbom format schema has type %T, want map[string]any", properties["format"])
	}
	rawFormats, ok := formatProperty["enum"].([]any)
	if !ok {
		t.Fatalf("generate_sbom format enum has type %T, want []any", formatProperty["enum"])
	}
	formats := make([]string, 0, len(rawFormats))
	for _, rawFormat := range rawFormats {
		format, ok := rawFormat.(string)
		if !ok {
			t.Fatalf("generate_sbom format enum entry has type %T, want string", rawFormat)
		}
		formats = append(formats, format)
	}
	slices.Sort(formats)
	// Canonical forms plus the short aliases, so strict MCP clients accept both.
	wantFormats := []string{"cyclonedx", "cyclonedx-json", "protobom", "protobom-json", "spdx", "spdx-json"}
	if !slices.Equal(formats, wantFormats) {
		t.Fatalf("generate_sbom format enum = %v, want %v", formats, wantFormats)
	}
	// The descriptor-derived schema no longer advertises a JSON Schema
	// "default"; the default lives in the proto comment so agents still see it.
	formatDescription, ok := formatProperty["description"].(string)
	if !ok {
		t.Fatalf("generate_sbom format description has type %T, want string", formatProperty["description"])
	}
	if !strings.Contains(formatDescription, "cyclonedx-json") {
		t.Fatalf("generate_sbom format description = %q, want default cyclonedx-json mentioned", formatDescription)
	}
}

func connectMCPClientSession(t *testing.T, ctx context.Context, s *Server) *mcpsdk.ClientSession {
	t.Helper()

	serverTransport, clientTransport := mcpsdk.NewInMemoryTransports()
	serverSession, err := s.server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatalf("server Connect failed: %v", err)
	}
	t.Cleanup(func() { serverSession.Close() })

	client := mcpsdk.NewClient(&mcpsdk.Implementation{Name: "deputy-test", Version: "v0.0.0"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client Connect failed: %v", err)
	}
	t.Cleanup(func() { clientSession.Close() })

	return clientSession
}

func findMCPTool(t *testing.T, tools []*mcpsdk.Tool, name string) *mcpsdk.Tool {
	t.Helper()

	for _, tool := range tools {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %q not found", name)
	return nil
}

func toolInputSchema(t *testing.T, tool *mcpsdk.Tool) map[string]any {
	t.Helper()

	schema, ok := tool.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("tool %q input schema has type %T, want map[string]any", tool.Name, tool.InputSchema)
	}
	return schema
}

func toolOutputSchema(t *testing.T, tool *mcpsdk.Tool) map[string]any {
	t.Helper()

	schema, ok := tool.OutputSchema.(map[string]any)
	if !ok {
		t.Fatalf("tool %q output schema has type %T, want map[string]any", tool.Name, tool.OutputSchema)
	}
	return schema
}

func structuredContentObject(t *testing.T, result *mcpsdk.CallToolResult) map[string]any {
	t.Helper()

	if result == nil {
		t.Fatal("CallToolResult is nil")
	}
	if result.StructuredContent == nil {
		t.Fatal("structured content is nil")
	}
	if object, ok := result.StructuredContent.(map[string]any); ok {
		return object
	}

	data, err := json.Marshal(result.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content of type %T: %v", result.StructuredContent, err)
	}
	var object map[string]any
	if err := json.Unmarshal(data, &object); err != nil {
		t.Fatalf("unmarshal structured content object from type %T: %v", result.StructuredContent, err)
	}
	return object
}

func requireStructuredEmptyArray(t *testing.T, object map[string]any, field string) {
	t.Helper()

	array := structuredArray(t, object, field)
	if len(array) != 0 {
		t.Fatalf("structured content %q has length %d, want 0", field, len(array))
	}
}

// requireStructuredEmptyCollection asserts a proto-contract collection field
// carries no elements. The MCP protojson dialect omits empty repeated fields,
// so on the wire absence and an explicit empty array both mean empty.
func requireStructuredEmptyCollection(t *testing.T, object map[string]any, field string) {
	t.Helper()

	value, ok := object[field]
	if !ok {
		return
	}
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("structured content %q has type %T, want array", field, value)
	}
	if len(array) != 0 {
		t.Fatalf("structured content %q has length %d, want 0", field, len(array))
	}
}

// requireSchemaProperties asserts the schema advertises each property.
// Descriptor-derived result schemas carry no required list (protojson omits
// zero values on the wire), so property presence is the advertised contract.
func requireSchemaProperties(t *testing.T, schema map[string]any, fields ...string) {
	t.Helper()

	properties := schemaObject(t, schema, "properties")
	for _, field := range fields {
		if _, ok := properties[field]; !ok {
			t.Fatalf("schema is missing %q property", field)
		}
	}
}

func structuredArray(t *testing.T, object map[string]any, field string) []any {
	t.Helper()

	value, ok := object[field]
	if !ok {
		t.Fatalf("structured content missing %q", field)
	}
	array, ok := value.([]any)
	if !ok {
		t.Fatalf("structured content %q has type %T, want array", field, value)
	}
	return array
}

func schemaObject(t *testing.T, schema map[string]any, field string) map[string]any {
	t.Helper()

	value, ok := schema[field].(map[string]any)
	if !ok {
		t.Fatalf("schema field %q has type %T, want map[string]any", field, schema[field])
	}
	return value
}

func schemaResolvedRef(t *testing.T, root, schema map[string]any) map[string]any {
	t.Helper()

	ref, ok := schema["$ref"].(string)
	if !ok || ref == "" {
		return schema
	}
	name, ok := strings.CutPrefix(ref, "#/$defs/")
	if !ok || name == "" {
		t.Fatalf("schema $ref = %q, want #/$defs/<name>", ref)
	}
	defs := schemaObject(t, root, "$defs")
	return schemaObject(t, defs, name)
}

func schemaArray(t *testing.T, schema map[string]any, field string) []any {
	t.Helper()

	value, ok := schema[field].([]any)
	if !ok {
		t.Fatalf("schema field %q has type %T, want []any", field, schema[field])
	}
	return value
}

func schemaRequired(t *testing.T, schema map[string]any) []string {
	t.Helper()

	rawRequired := schemaArray(t, schema, "required")
	got := make([]string, 0, len(rawRequired))
	for _, field := range rawRequired {
		fieldName, ok := field.(string)
		if !ok {
			t.Fatalf("required field has type %T, want string", field)
		}
		got = append(got, fieldName)
	}
	slices.Sort(got)
	return got
}

func requireSchemaRequiredContains(t *testing.T, schema map[string]any, fields ...string) {
	t.Helper()

	required := schemaRequired(t, schema)
	for _, field := range fields {
		if !slices.Contains(required, field) {
			t.Fatalf("schema required fields = %v, want %q", required, field)
		}
	}
}

func TestExplainVulnerability(t *testing.T) {
	mockOSV := &mockOSVClient{
		vulns: map[string]*osvschema.Vulnerability{
			"CVE-2021-44228": {
				ID:        "CVE-2021-44228",
				Modified:  time.Date(2026, 5, 13, 15, 33, 43, 0, time.UTC),
				Published: time.Date(2021, 12, 10, 10, 15, 30, 0, time.UTC),
				Summary:   "Log4Shell vulnerability",
				Details:   "Remote code execution in Log4j",
				Aliases:   []string{"GHSA-jfh8-c2jp-5v3q"},
				Severity: []osvschema.Severity{
					{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},
				},
				References: []osvschema.Reference{
					{URL: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
					{URL: "https://example.com/advisory"},
					{URL: "https://example.com/patch"},
				},
				Affected: []osvschema.Affected{
					{
						Package: osvschema.Package{Name: "org.apache.logging.log4j:log4j-core", Ecosystem: "Maven"},
						Ranges: []osvschema.Range{{
							Type:   osvschema.RangeEcosystem,
							Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.17.0"}},
						}},
					},
					{
						Package: osvschema.Package{Name: "apache/logging-log4j2", Ecosystem: "Git"},
						Ranges: []osvschema.Range{{
							Type:   osvschema.RangeGit,
							Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "38513a7d57343881f7bf58f37e67d6a87e0a47c5"}},
						}},
					},
					{
						Package: osvschema.Package{Name: "apache/logging-log4j2", Ecosystem: "Git"},
						Ranges: []osvschema.Range{{
							Type:   osvschema.RangeEcosystem,
							Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "f2e7063ee409ff40a60b14370c58dceee1a2efd4"}},
						}},
					},
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
		result, err := callProtoTool(t, ctx, s.explainVulnerability,
			&mcpv1.ExplainVulnerabilityRequest{Id: "CVE-2021-44228"}, &mcpv1.VulnExplanation{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Id != "CVE-2021-44228" {
			t.Errorf("expected ID CVE-2021-44228, got %s", result.Id)
		}
		if result.Summary != "Log4Shell vulnerability" {
			t.Errorf("expected summary 'Log4Shell vulnerability', got %s", result.Summary)
		}
		if result.Details != "Remote code execution in Log4j" {
			t.Errorf("expected full details, got %q", result.Details)
		}
		if len(result.Aliases) != 1 || result.Aliases[0] != "GHSA-jfh8-c2jp-5v3q" {
			t.Errorf("unexpected aliases: %v", result.Aliases)
		}
		wantRefs := []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			"https://example.com/advisory",
			"https://example.com/patch",
		}
		if !slices.Equal(result.References, wantRefs) {
			t.Errorf("expected full references, got %v", result.References)
		}
		if result.ReferenceCount != 0 || result.ReferencesTruncated {
			t.Errorf("expected explanation references to be untruncated, got count=%d truncated=%v", result.ReferenceCount, result.ReferencesTruncated)
		}
		if result.Severity != "CRITICAL" {
			t.Errorf("expected severity CRITICAL, got %q", result.Severity)
		}
		if result.Published != "2021-12-10T10:15:30Z" {
			t.Errorf("published = %q, want RFC3339 timestamp", result.Published)
		}
		if result.Modified != "2026-05-13T15:33:43Z" {
			t.Errorf("modified = %q, want RFC3339 timestamp", result.Modified)
		}
		if !slices.Equal(result.FixedVersions, []string{"2.17.0"}) {
			t.Errorf("expected package fixed versions only, got %v", result.FixedVersions)
		}
		if len(result.PackageFixes) != 1 {
			t.Fatalf("expected 1 package fix, got %d", len(result.PackageFixes))
		}
		if got := result.PackageFixes[0].Module; got != "org.apache.logging.log4j:log4j-core" {
			t.Errorf("expected package fix module log4j-core, got %q", got)
		}
		if got := result.PackageFixes[0].Ecosystem; got != "maven" {
			t.Errorf("expected canonical package fix ecosystem maven, got %q", got)
		}
		if !slices.Equal(result.PackageFixes[0].FixedVersions, []string{"2.17.0"}) {
			t.Errorf("expected package fix versions [2.17.0], got %v", result.PackageFixes[0].FixedVersions)
		}
	})

	t.Run("limits references", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.explainVulnerability,
			&mcpv1.ExplainVulnerabilityRequest{Id: "CVE-2021-44228", ReferenceLimit: proto.Int32(2)}, &mcpv1.VulnExplanation{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		wantRefs := []string{
			"https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			"https://example.com/advisory",
		}
		if !slices.Equal(result.References, wantRefs) {
			t.Errorf("references = %v, want %v", result.References, wantRefs)
		}
		if result.ReferenceCount != 3 {
			t.Errorf("referenceCount = %d, want 3", result.ReferenceCount)
		}
		if !result.ReferencesTruncated {
			t.Error("referencesTruncated = false, want true")
		}
	})

	t.Run("zero references", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.explainVulnerability,
			&mcpv1.ExplainVulnerabilityRequest{Id: "CVE-2021-44228", ReferenceLimit: proto.Int32(0)}, &mcpv1.VulnExplanation{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.References) != 0 {
			t.Errorf("references = %v, want none", result.References)
		}
		if result.ReferenceCount != 3 {
			t.Errorf("referenceCount = %d, want 3", result.ReferenceCount)
		}
		if !result.ReferencesTruncated {
			t.Error("referencesTruncated = false, want true")
		}
	})

	t.Run("trims ID", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.explainVulnerability,
			&mcpv1.ExplainVulnerabilityRequest{Id: " CVE-2021-44228\t"}, &mcpv1.VulnExplanation{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Id != "CVE-2021-44228" {
			t.Errorf("expected ID CVE-2021-44228, got %s", result.Id)
		}
	})

	t.Run("empty ID", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.explainVulnerability,
			&mcpv1.ExplainVulnerabilityRequest{Id: ""}, &mcpv1.VulnExplanation{})
		if err == nil {
			t.Error("expected error for empty ID")
		}
	})

	t.Run("not found", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.explainVulnerability,
			&mcpv1.ExplainVulnerabilityRequest{Id: "CVE-9999-9999"}, &mcpv1.VulnExplanation{})
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
				References: []osvschema.Reference{
					{URL: "https://example.com/one"},
					{URL: "https://example.com/two"},
					{URL: "https://example.com/three"},
				},
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
		result, err := callProtoTool(t, ctx, s.explainVulnerabilities, &mcpv1.ExplainVulnerabilitiesRequest{
			Ids:            []string{"CVE-2021-44228", "CVE-2022-22965"},
			ReferenceLimit: proto.Int32(1),
		}, &mcpv1.ExplainVulnerabilitiesResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Vulnerabilities) != 2 {
			t.Errorf("expected 2 vulnerabilities, got %d", len(result.Vulnerabilities))
		}
		if got := result.Vulnerabilities[0].References; !slices.Equal(got, []string{"https://example.com/one"}) {
			t.Errorf("batch references = %v, want first reference only", got)
		}
		if result.Vulnerabilities[0].ReferenceCount != 3 {
			t.Errorf("batch referenceCount = %d, want 3", result.Vulnerabilities[0].ReferenceCount)
		}
		if !result.Vulnerabilities[0].ReferencesTruncated {
			t.Error("batch referencesTruncated = false, want true")
		}
	})

	t.Run("trims IDs", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.explainVulnerabilities, &mcpv1.ExplainVulnerabilitiesRequest{
			Ids: []string{" CVE-2021-44228 ", "\tCVE-2022-22965"},
		}, &mcpv1.ExplainVulnerabilitiesResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Errors) != 0 {
			t.Fatalf("expected no errors, got %v", result.Errors)
		}
		if len(result.Vulnerabilities) != 2 {
			t.Errorf("expected 2 vulnerabilities, got %d", len(result.Vulnerabilities))
		}
	})

	t.Run("partial success", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.explainVulnerabilities, &mcpv1.ExplainVulnerabilitiesRequest{
			Ids: []string{"CVE-2021-44228", "CVE-NONEXISTENT"},
		}, &mcpv1.ExplainVulnerabilitiesResult{})
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

	t.Run("not found does not leak raw OSV client error", func(t *testing.T) {
		mockOSV := &mockOSVClient{
			vulns: map[string]*osvschema.Vulnerability{
				"CVE-2021-44228": {
					ID:      "CVE-2021-44228",
					Summary: "Log4Shell",
				},
			},
			errs: map[string]error{
				"CVE-NONEXISTENT": errors.New(`client error: status="404 Not Found" body={"code":5,"message":"Bug not found."}`),
			},
		}
		s := NewServer(WithClients(newMockClients(mockClientsConfig{
			vulnerabilityHandler: &mockVulnerabilityHandler{osvClient: mockOSV},
		})))

		result, err := callProtoTool(t, t.Context(), s.explainVulnerabilities, &mcpv1.ExplainVulnerabilitiesRequest{
			Ids: []string{"CVE-2021-44228", "CVE-NONEXISTENT"},
		}, &mcpv1.ExplainVulnerabilitiesResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Vulnerabilities) != 1 {
			t.Fatalf("vulnerabilities = %d, want 1", len(result.Vulnerabilities))
		}
		want := "CVE-NONEXISTENT: vulnerability CVE-NONEXISTENT not found"
		if !slices.Equal(result.Errors, []string{want}) {
			t.Fatalf("errors = %v, want %q", result.Errors, want)
		}
	})

	t.Run("empty IDs", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.explainVulnerabilities,
			&mcpv1.ExplainVulnerabilitiesRequest{Ids: nil}, &mcpv1.ExplainVulnerabilitiesResult{})
		if err == nil {
			t.Error("expected error for empty IDs")
		}
	})

	t.Run("blank ID", func(t *testing.T) {
		// Blank items violate the ids items pattern (\S); protovalidate rejects
		// the request and its message names the offending index.
		_, err := callProtoTool(t, ctx, s.explainVulnerabilities, &mcpv1.ExplainVulnerabilitiesRequest{
			Ids: []string{"CVE-2021-44228", " \t"},
		}, &mcpv1.ExplainVulnerabilitiesResult{})
		if err == nil {
			t.Fatal("expected error for blank ID")
		}
		if !strings.Contains(err.Error(), "ids[1]") {
			t.Fatalf("error = %q, want indexed blank ID guidance", err)
		}
	})
}

func TestExplainVulnerabilitiesUsesBatchAdvisoryLookup(t *testing.T) {
	mockVuln := &mockVulnerabilityHandler{
		getAdvisoriesResponses: []*vulnerabilityv1.GetAdvisoriesResponse{
			{
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2024-0001": {
						Id:      "CVE-2024-0001",
						Summary: "first",
					},
					"GO-2024-0002": {
						Id:      "GO-2024-0002",
						Aliases: []string{"CVE-2024-0002"},
						Summary: "second",
					},
				},
			},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{vulnerabilityHandler: mockVuln})))

	result, err := callProtoTool(t, t.Context(), s.explainVulnerabilities, &mcpv1.ExplainVulnerabilitiesRequest{
		Ids: []string{"CVE-2024-0001", "cve-2024-0001", "CVE-2024-0002"},
	}, &mcpv1.ExplainVulnerabilitiesResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mockVuln.getAdvisoryRequests) != 0 {
		t.Fatalf("single advisory requests = %v, want none", mockVuln.getAdvisoryRequests)
	}
	if got, want := len(mockVuln.getAdvisoriesRequests), 1; got != want {
		t.Fatalf("batch advisory requests = %d, want %d", got, want)
	}
	if got, want := mockVuln.getAdvisoriesRequests[0], []string{"CVE-2024-0001", "CVE-2024-0002"}; !slices.Equal(got, want) {
		t.Fatalf("batch IDs = %v, want %v", got, want)
	}
	if len(result.Errors) != 0 {
		t.Fatalf("errors = %v, want none", result.Errors)
	}
	gotIDs := make([]string, 0, len(result.Vulnerabilities))
	for _, vuln := range result.Vulnerabilities {
		gotIDs = append(gotIDs, vuln.Id)
	}
	wantIDs := []string{"CVE-2024-0001", "CVE-2024-0001", "GO-2024-0002"}
	if !slices.Equal(gotIDs, wantIDs) {
		t.Fatalf("result IDs = %v, want %v", gotIDs, wantIDs)
	}
}

func TestScanPackage(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: emptyScanResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
	ctx := context.Background()

	t.Run("missing name", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.scanPackage, &mcpv1.ScanPackageRequest{
			Version:   "1.0.0",
			Ecosystem: "npm",
		}, &mcpv1.ScanPackageResult{})
		if err == nil {
			t.Error("expected error for missing name")
		}
	})

	t.Run("missing version", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.scanPackage, &mcpv1.ScanPackageRequest{
			Name:      "lodash",
			Ecosystem: "npm",
		}, &mcpv1.ScanPackageResult{})
		if err == nil {
			t.Error("expected error for missing version")
		}
	})

	t.Run("missing ecosystem", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.scanPackage, &mcpv1.ScanPackageRequest{
			Name:    "lodash",
			Version: "4.17.15",
		}, &mcpv1.ScanPackageResult{})
		if err == nil {
			t.Error("expected error for missing ecosystem")
		}
	})

	t.Run("canonical package purls", func(t *testing.T) {
		tests := []struct {
			name          string
			in            *mcpv1.ScanPackageRequest
			wantPURL      string
			wantVersion   string
			wantEcosystem string
		}{
			{
				name: "go alias normalizes version",
				in: &mcpv1.ScanPackageRequest{
					Name:      " golang.org/x/net ",
					Version:   " 0.17.0 ",
					Ecosystem: " Golang ",
				},
				wantPURL:      "pkg:golang/golang.org/x/net@v0.17.0",
				wantVersion:   "v0.17.0",
				wantEcosystem: "go",
			},
			{
				name: "ruby alias uses gem purl type",
				in: &mcpv1.ScanPackageRequest{
					Name:      "rails",
					Version:   "7.0.4",
					Ecosystem: "ruby",
				},
				wantPURL:      "pkg:gem/rails@7.0.4",
				wantVersion:   "7.0.4",
				wantEcosystem: "rubygems",
			},
			{
				name: "maven coordinates split group and artifact",
				in: &mcpv1.ScanPackageRequest{
					Name:      "org.apache.logging.log4j:log4j-core",
					Version:   "2.14.0",
					Ecosystem: "java",
				},
				wantPURL:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
				wantVersion:   "2.14.0",
				wantEcosystem: "maven",
			},
			{
				name: "npm scoped package uses encoded scope namespace",
				in: &mcpv1.ScanPackageRequest{
					Name:      "@temporalio/worker",
					Version:   "1.10.0",
					Ecosystem: "npm",
				},
				wantPURL:      "pkg:npm/%40temporalio/worker@1.10.0",
				wantVersion:   "1.10.0",
				wantEcosystem: "npm",
			},
			{
				name: "github actions package keeps owner namespace",
				in: &mcpv1.ScanPackageRequest{
					Name:      "actions/checkout",
					Version:   "v4",
					Ecosystem: "github-actions",
				},
				wantPURL:      "pkg:githubactions/actions/checkout@v4",
				wantVersion:   "v4",
				wantEcosystem: "github-actions",
			},
			{
				name: "github actions spaced alias uses githubactions purl type",
				in: &mcpv1.ScanPackageRequest{
					Name:      "actions/checkout",
					Version:   "v4",
					Ecosystem: "GitHub Actions",
				},
				wantPURL:      "pkg:githubactions/actions/checkout@v4",
				wantVersion:   "v4",
				wantEcosystem: "github-actions",
			},
			{
				name: "purl input normalizes go version",
				in: &mcpv1.ScanPackageRequest{
					Purl: "pkg:golang/golang.org/x/net@0.17.0",
				},
				wantPURL:      "pkg:golang/golang.org/x/net@v0.17.0",
				wantVersion:   "v0.17.0",
				wantEcosystem: "go",
			},
			{
				name: "name accepts purl input",
				in: &mcpv1.ScanPackageRequest{
					Name: "pkg:npm/lodash@4.17.21",
				},
				wantPURL:      "pkg:npm/lodash@4.17.21",
				wantVersion:   "4.17.21",
				wantEcosystem: "npm",
			},
			{
				name: "purl input accepts separate version",
				in: &mcpv1.ScanPackageRequest{
					Purl:    "pkg:npm/lodash",
					Version: "4.17.21",
				},
				wantPURL:      "pkg:npm/lodash@4.17.21",
				wantVersion:   "4.17.21",
				wantEcosystem: "npm",
			},
			{
				name: "maven purl uses coordinate display name",
				in: &mcpv1.ScanPackageRequest{
					Purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
				},
				wantPURL:      "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
				wantVersion:   "2.14.0",
				wantEcosystem: "maven",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				mockScan.requests = nil
				mockScan.scanResponse = emptyScanResponse()

				result, err := callProtoTool(t, ctx, s.scanPackage, tt.in, &mcpv1.ScanPackageResult{})
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(mockScan.requests) != 1 {
					t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
				}
				if got := mockScan.requests[0].Target; got != tt.wantPURL {
					t.Errorf("scan target = %q, want %q", got, tt.wantPURL)
				}
				if result.Purl != tt.wantPURL {
					t.Errorf("result PURL = %q, want %q", result.Purl, tt.wantPURL)
				}
				if result.Version != tt.wantVersion {
					t.Errorf("result version = %q, want %q", result.Version, tt.wantVersion)
				}
				if result.Ecosystem != tt.wantEcosystem {
					t.Errorf("result ecosystem = %q, want %q", result.Ecosystem, tt.wantEcosystem)
				}
				if result.Package == "" {
					t.Error("result package is empty")
				}
				if !result.Clean {
					t.Error("expected clean result")
				}
			})
		}
	})

	t.Run("purl missing version", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.scanPackage,
			&mcpv1.ScanPackageRequest{Purl: "pkg:npm/lodash"}, &mcpv1.ScanPackageResult{})
		if err == nil {
			t.Error("expected error for purl without version")
		}
	})

	t.Run("purl conflicting version", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.scanPackage, &mcpv1.ScanPackageRequest{
			Purl:    "pkg:npm/lodash@4.17.21",
			Version: "4.17.20",
		}, &mcpv1.ScanPackageResult{})
		if err == nil {
			t.Error("expected error for conflicting purl version")
		}
	})

	t.Run("purl conflicting ecosystem", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.scanPackage, &mcpv1.ScanPackageRequest{
			Purl:      "pkg:npm/lodash@4.17.21",
			Ecosystem: "pypi",
		}, &mcpv1.ScanPackageResult{})
		if err == nil {
			t.Error("expected error for conflicting purl ecosystem")
		}
	})

	t.Run("deduplicates advisory aliases", func(t *testing.T) {
		vulnerablePkg := &dependencyv1.Package{
			Name:      "golang.org/x/net",
			Version:   "v0.17.0",
			Ecosystem: "go",
			Purl:      "pkg:golang/golang.org/x/net@v0.17.0",
			Direct:    true,
		}
		mockScan.requests = nil
		mockScan.scanResponse = &scanv1.ScanResponse{
			PackagesScanned: 1,
			Findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "GO-2024-0001", Package: vulnerablePkg, Affected: true},
				{AdvisoryId: "GHSA-abcd-efgh-ijkl", Package: vulnerablePkg, Affected: true},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{
				"GO-2024-0001": {
					Id:       "GO-2024-0001",
					Aliases:  []string{"GHSA-abcd-efgh-ijkl", "CVE-2024-1234"},
					Summary:  "Test vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
				"GHSA-abcd-efgh-ijkl": {
					Id:       "GHSA-abcd-efgh-ijkl",
					Aliases:  []string{"GO-2024-0001", "CVE-2024-1234"},
					Summary:  "Same test vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
			},
			Stats: &vulnerabilityv1.Stats{Unique: 2, Critical: 2},
		}

		result, err := callProtoTool(t, ctx, s.scanPackage, &mcpv1.ScanPackageRequest{
			Name:      "golang.org/x/net",
			Version:   "v0.17.0",
			Ecosystem: "go",
		}, &mcpv1.ScanPackageResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Clean {
			t.Error("expected non-clean result")
		}
		if len(result.Vulnerabilities) != 1 {
			t.Fatalf("expected 1 consolidated vulnerability, got %d", len(result.Vulnerabilities))
		}
		if got := result.Vulnerabilities[0].Id; got != "CVE-2024-1234" {
			t.Errorf("expected CVE primary ID, got %q", got)
		}
	})

	t.Run("compacts verbose advisories", func(t *testing.T) {
		vulnerablePkg := &dependencyv1.Package{
			Name:      "golang.org/x/crypto",
			Version:   "v0.17.0",
			Ecosystem: "go",
			Purl:      "pkg:golang/golang.org/x/crypto@v0.17.0",
			Direct:    true,
		}
		refs := []string{
			"https://example.com/advisory",
			"https://example.com/nvd",
			"https://example.com/patch",
			"https://example.com/issue",
			"https://example.com/announce",
			"https://example.com/downstream",
		}
		mockScan.requests = nil
		mockScan.scanResponse = &scanv1.ScanResponse{
			PackagesScanned: 1,
			Findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "CVE-2024-9999", Package: vulnerablePkg, Affected: true},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2024-9999": {
					Id:            "CVE-2024-9999",
					Aliases:       []string{"GO-2024-9999"},
					Summary:       "Verbose test vulnerability",
					Details:       strings.Repeat("long advisory detail ", 64),
					References:    refs,
					FixedVersions: []string{"v0.18.0"},
					Severity:      vulnerability.NewSeverity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CVSS_V3"),
				},
			},
			Stats: &vulnerabilityv1.Stats{Unique: 1, Critical: 1},
		}

		result, err := callProtoTool(t, ctx, s.scanPackage, &mcpv1.ScanPackageRequest{
			Name:      "golang.org/x/crypto",
			Version:   "v0.17.0",
			Ecosystem: "go",
		}, &mcpv1.ScanPackageResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Vulnerabilities) != 1 {
			t.Fatalf("expected 1 vulnerability, got %d", len(result.Vulnerabilities))
		}
		vuln := result.Vulnerabilities[0]
		if vuln.Severity != "CRITICAL" {
			t.Errorf("scan_package severity = %q, want CRITICAL", vuln.Severity)
		}
		if vuln.Details != "" {
			t.Errorf("scan_package details = %q, want compact output without details", vuln.Details)
		}
		if !slices.Equal(vuln.References, refs[:compactVulnReferenceLimit]) {
			t.Errorf("scan_package references = %v, want %v", vuln.References, refs[:compactVulnReferenceLimit])
		}
		if int(vuln.ReferenceCount) != len(refs) {
			t.Errorf("scan_package referenceCount = %d, want %d", vuln.ReferenceCount, len(refs))
		}
		if !vuln.ReferencesTruncated {
			t.Error("scan_package referencesTruncated = false, want true")
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
		_, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{}, &mcpv1.ScanDirectoryResult{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("valid scan", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{Path: "/test/path"}, &mcpv1.ScanDirectoryResult{})
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

	t.Run("trims path before scan", func(t *testing.T) {
		mockScan.requests = nil
		result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{Path: " /test/path "}, &mcpv1.ScanDirectoryResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Path != "/test/path" {
			t.Fatalf("result path = %q, want /test/path", result.Path)
		}
		if len(mockScan.requests) != 1 {
			t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
		}
		if got := mockScan.requests[0].Target; got != "/test/path" {
			t.Fatalf("scan target = %q, want /test/path", got)
		}
	})

	t.Run("forwards exclude paths trimmed", func(t *testing.T) {
		mockScan.requests = nil
		_, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{
			Path:         "/test/path",
			ExcludePaths: []string{" .bin/** ", "**/testdata"},
		}, &mcpv1.ScanDirectoryResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockScan.requests) != 1 {
			t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
		}
		got := mockScan.requests[0].Options.GetExcludePaths()
		want := []string{".bin/**", "**/testdata"}
		if !slicesEqual(got, want) {
			t.Fatalf("exclude paths = %v, want %v", got, want)
		}
	})

	t.Run("rejects blank exclude path items", func(t *testing.T) {
		// The advertised schema gives excludePaths items minLength 1, so a
		// blank item is a contract violation: the SDK rejects it at the server
		// boundary and protovalidate rejects it on direct handler invocations.
		mockScan.requests = nil
		_, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{
			Path:         "/test/path",
			ExcludePaths: []string{".bin/**", ""},
		}, &mcpv1.ScanDirectoryResult{})
		if err == nil {
			t.Fatal("expected validation error for blank exclude path item")
		}
		if len(mockScan.requests) != 0 {
			t.Fatalf("expected no scan requests, got %d", len(mockScan.requests))
		}
	})

	t.Run("forwards ref", func(t *testing.T) {
		mockScan.scanResponse = emptyScanResponse()
		mockScan.scanResponse.Target = &targetv1.Target{
			Ref:          "refs/tags/v1.2.3",
			EffectiveRef: "refs/tags/v1.2.3",
			CommitHash:   "abc123",
		}
		mockScan.requests = nil
		result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{
			Path: "/test/path",
			Ref:  " refs/tags/v1.2.3 ",
		}, &mcpv1.ScanDirectoryResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockScan.requests) != 1 {
			t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
		}
		if got := mockScan.requests[0].Options.GetRef(); got != "refs/tags/v1.2.3" {
			t.Fatalf("scan ref = %q, want refs/tags/v1.2.3", got)
		}
		if result.Ref != "refs/tags/v1.2.3" || result.EffectiveRef != "refs/tags/v1.2.3" || result.Commit != "abc123" {
			t.Fatalf("result target metadata = ref %q effective %q commit %q, want refs/tags/v1.2.3 refs/tags/v1.2.3 abc123", result.Ref, result.EffectiveRef, result.Commit)
		}
	})

	t.Run("with vulnerabilities", func(t *testing.T) {
		mockScan.scanResponse = &scanv1.ScanResponse{
			PackagesScanned: 5,
			Findings: []*vulnerabilityv1.Finding{
				{
					AdvisoryId: "CVE-2021-44228",
					Package: &dependencyv1.Package{
						Name:      "github.com/example/vulnerable",
						Version:   "v1.0.0",
						Ecosystem: "go",
						Purl:      "pkg:golang/github.com/example/vulnerable@v1.0.0",
						Direct:    true,
					},
					Affected: true,
				},
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

		result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{Path: "/test/path"}, &mcpv1.ScanDirectoryResult{})
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

	t.Run("deduplicates advisory aliases", func(t *testing.T) {
		vulnerablePkg := &dependencyv1.Package{
			Name:      "github.com/example/vulnerable",
			Version:   "v1.0.0",
			Ecosystem: "go",
			Purl:      "pkg:golang/github.com/example/vulnerable@v1.0.0",
			Direct:    true,
		}
		mockScan.scanResponse = &scanv1.ScanResponse{
			PackagesScanned: 5,
			Findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "GO-2024-0001", Package: vulnerablePkg, Affected: true},
				{AdvisoryId: "GHSA-abcd-efgh-ijkl", Package: vulnerablePkg, Affected: true},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{
				"GO-2024-0001": {
					Id:       "GO-2024-0001",
					Aliases:  []string{"GHSA-abcd-efgh-ijkl", "CVE-2024-1234"},
					Summary:  "Test vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
				"GHSA-abcd-efgh-ijkl": {
					Id:       "GHSA-abcd-efgh-ijkl",
					Aliases:  []string{"GO-2024-0001", "CVE-2024-1234"},
					Summary:  "Same test vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
			},
			Stats:    &vulnerabilityv1.Stats{Unique: 2, Critical: 2},
			Packages: []*dependencyv1.Package{},
		}

		result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{Path: "/test/path"}, &mcpv1.ScanDirectoryResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Vulnerabilities) != 1 {
			t.Fatalf("expected 1 consolidated vulnerability, got %d", len(result.Vulnerabilities))
		}
		if got := result.Vulnerabilities[0].Id; got != "CVE-2024-1234" {
			t.Errorf("expected CVE primary ID, got %q", got)
		}
		if result.VulnerabilitiesBySeverity["critical"] != 1 {
			t.Errorf("expected 1 consolidated critical, got %d", result.VulnerabilitiesBySeverity["critical"])
		}
	})
}

func TestScanContainerDeduplicatesAdvisoryAliases(t *testing.T) {
	vulnerablePkg := &dependencyv1.Package{
		Name:      "openssl",
		Version:   "3.0.0",
		Ecosystem: "deb",
		Purl:      "pkg:deb/debian/openssl@3.0.0",
	}
	mockScan := &mockScanHandler{
		scanResponse: &scanv1.ScanResponse{
			PackagesScanned: 12,
			Findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "CVE-2024-1234", Package: vulnerablePkg, Affected: true},
				{AdvisoryId: "GHSA-abcd-efgh-ijkl", Package: vulnerablePkg, Affected: true},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{
				"CVE-2024-1234": {
					Id:       "CVE-2024-1234",
					Aliases:  []string{"GHSA-abcd-efgh-ijkl"},
					Summary:  "Container package vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
				"GHSA-abcd-efgh-ijkl": {
					Id:       "GHSA-abcd-efgh-ijkl",
					Aliases:  []string{"CVE-2024-1234"},
					Summary:  "Same container package vulnerability",
					Severity: vulnerability.NewSeverity("CRITICAL", ""),
				},
			},
			Stats:    &vulnerabilityv1.Stats{Unique: 2, Critical: 2},
			Packages: []*dependencyv1.Package{vulnerablePkg},
		},
	}

	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
	result, err := callProtoTool(t, context.Background(), s.scanContainer, &mcpv1.ScanContainerRequest{Image: "debian:bookworm"}, &mcpv1.ScanContainerResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.Clean {
		t.Fatal("expected non-clean container scan")
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 consolidated vulnerability, got %d", len(result.Vulnerabilities))
	}
	if got := result.Vulnerabilities[0].Id; got != "CVE-2024-1234" {
		t.Errorf("expected CVE primary ID, got %q", got)
	}
	if result.VulnerabilitiesBySeverity["critical"] != 1 {
		t.Errorf("expected 1 consolidated critical, got %d", result.VulnerabilitiesBySeverity["critical"])
	}
}

func TestScanContainerNormalizesImageAndPlatform(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: emptyScanResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := callProtoTool(t, context.Background(), s.scanContainer, &mcpv1.ScanContainerRequest{
		Image:    " debian:bookworm ",
		Platform: " linux/amd64\t",
	}, &mcpv1.ScanContainerResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Image != "debian:bookworm" {
		t.Fatalf("result image = %q, want debian:bookworm", result.Image)
	}
	if result.Platform != "linux/amd64" {
		t.Fatalf("result platform = %q, want linux/amd64", result.Platform)
	}
	if len(mockScan.requests) != 1 {
		t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
	}
	if got := mockScan.requests[0].Target; got != "debian:bookworm" {
		t.Fatalf("scan target = %q, want debian:bookworm", got)
	}
	if got := mockScan.requests[0].Options.GetPlatform(); got != "linux/amd64" {
		t.Fatalf("scan platform = %q, want linux/amd64", got)
	}
}

func TestListDependencies(t *testing.T) {
	mockList := &mockListHandler{
		listResponse: &listv1.ListPackagesResponse{
			Packages: []*dependencyv1.Package{
				{
					Name:      "pkg1",
					Version:   "1.0.0",
					Ecosystem: "Go",
					Locations: []string{"mise.toml"},
					ManifestRefs: []*dependencyv1.ManifestRef{
						{
							Path:         "mise.toml",
							Manager:      "mise",
							Groups:       []string{"tools", "prod"},
							ComponentKey: "npm:pkg1",
						},
					},
				},
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
		_, err := callProtoTool(t, ctx, s.listDependencies, &mcpv1.ListDependenciesRequest{}, &mcpv1.ListDependenciesResult{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("list all", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.listDependencies, &mcpv1.ListDependenciesRequest{Path: "/test/path"}, &mcpv1.ListDependenciesResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Total != 2 {
			t.Errorf("expected 2 dependencies, got %d", result.Total)
		}
		if result.TotalDiscovered != 2 {
			t.Errorf("expected 2 discovered dependencies, got %d", result.TotalDiscovered)
		}
		if got := result.Dependencies[0].Ecosystem; got != "go" {
			t.Errorf("expected canonical ecosystem go, got %q", got)
		}
		manifestRefs := result.Dependencies[0].ManifestRefs
		if len(manifestRefs) != 1 {
			t.Fatalf("manifestRefs len = %d, want 1: %+v", len(manifestRefs), manifestRefs)
		}
		ref := manifestRefs[0]
		if ref.Path != "mise.toml" || ref.Manager != "mise" || ref.ComponentKey != "npm:pkg1" {
			t.Fatalf("manifest ref = %+v, want mise.toml/mise/npm:pkg1", ref)
		}
		if !slices.Equal(ref.Groups, []string{"tools", "prod"}) {
			t.Fatalf("manifest ref groups = %v, want [tools prod]", ref.Groups)
		}
	})

	t.Run("direct only reports returned and discovered counts separately", func(t *testing.T) {
		mockFilteredList := &mockListHandler{
			listResponse: &listv1.ListPackagesResponse{
				Packages: []*dependencyv1.Package{
					{Name: "direct", Version: "1.0.0", Ecosystem: "go", Direct: true},
				},
				Stats: &listv1.ListStats{
					TotalPackages:      3,
					DirectPackages:     1,
					TransitivePackages: 2,
				},
			},
		}
		filteredServer := NewServer(WithClients(newMockClients(mockClientsConfig{listHandler: mockFilteredList})))

		result, err := callProtoTool(t, ctx, filteredServer.listDependencies, &mcpv1.ListDependenciesRequest{
			Path:       "/test/path",
			DirectOnly: true,
		}, &mcpv1.ListDependenciesResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.Dependencies) != 1 {
			t.Fatalf("expected 1 returned dependency, got %d", len(result.Dependencies))
		}
		if result.Total != 1 || result.Direct != 1 || result.Transitive != 0 {
			t.Fatalf("returned counts = total %d, direct %d, transitive %d; want 1, 1, 0", result.Total, result.Direct, result.Transitive)
		}
		if result.TotalDiscovered != 3 || result.DirectDiscovered != 1 || result.TransitiveDiscovered != 2 {
			t.Fatalf("discovered counts = total %d, direct %d, transitive %d; want 3, 1, 2", result.TotalDiscovered, result.DirectDiscovered, result.TransitiveDiscovered)
		}
	})

	t.Run("forwards exclude paths", func(t *testing.T) {
		mockList.requests = nil
		_, err := callProtoTool(t, ctx, s.listDependencies, &mcpv1.ListDependenciesRequest{
			Path:         "/test/path",
			ExcludePaths: []string{".bin/**"},
		}, &mcpv1.ListDependenciesResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockList.requests) != 1 {
			t.Fatalf("expected 1 list request, got %d", len(mockList.requests))
		}
		if got, want := mockList.requests[0].Options.GetExcludePaths(), []string{".bin/**"}; !slicesEqual(got, want) {
			t.Fatalf("exclude paths = %v, want %v", got, want)
		}
	})

	t.Run("forwards ref", func(t *testing.T) {
		mockList.listResponse.Target = &targetv1.Target{
			Ref:          "feature/deps",
			EffectiveRef: "refs/heads/feature/deps",
			CommitHash:   "def456",
		}
		mockList.requests = nil
		result, err := callProtoTool(t, ctx, s.listDependencies, &mcpv1.ListDependenciesRequest{
			Path: "/test/path",
			Ref:  " feature/deps ",
		}, &mcpv1.ListDependenciesResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockList.requests) != 1 {
			t.Fatalf("expected 1 list request, got %d", len(mockList.requests))
		}
		if got := mockList.requests[0].Options.GetRef(); got != "feature/deps" {
			t.Fatalf("list ref = %q, want feature/deps", got)
		}
		if result.Ref != "feature/deps" || result.EffectiveRef != "refs/heads/feature/deps" || result.Commit != "def456" {
			t.Fatalf("result target metadata = ref %q effective %q commit %q, want feature/deps refs/heads/feature/deps def456", result.Ref, result.EffectiveRef, result.Commit)
		}
	})
}

func TestGenerateSBOM(t *testing.T) {
	s := NewServer()
	ctx := context.Background()

	t.Run("missing path", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.generateSBOM, &mcpv1.GenerateSBOMRequest{}, &mcpv1.GenerateSBOMResult{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("invalid format", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.generateSBOM, &mcpv1.GenerateSBOMRequest{
			Path:   "/test/path",
			Format: "invalid-format",
		}, &mcpv1.GenerateSBOMResult{})
		if err == nil {
			t.Error("expected error for invalid format")
		}
	})
}

// TestGenerateSBOMFormatMatchesCLI pins the MCP generate_sbom format handling to
// the same shared normalizer the CLI uses, so the two surfaces accept the same
// spellings (short aliases and mixed case), not just the canonical *-json forms.
func TestGenerateSBOMFormatMatchesCLI(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{name: "default", want: "cyclonedx-json"},
		{name: "trim cyclonedx", in: " cyclonedx-json ", want: "cyclonedx-json"},
		{name: "short cyclonedx alias", in: "cyclonedx", want: "cyclonedx-json"},
		{name: "trim spdx", in: "\tspdx-json\n", want: "spdx-json"},
		{name: "short spdx alias", in: "spdx", want: "spdx-json"},
		{name: "short protobom alias", in: "protobom", want: "protobom-json"},
		{name: "mixed case", in: " CycloneDX-JSON ", want: "cyclonedx-json"},
		{name: "invalid", in: "nonsense", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := flags.NormalizeSBOMOutputFormat(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("NormalizeSBOMOutputFormat(%q) = nil error, want error", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeSBOMOutputFormat(%q) unexpected error: %v", tt.in, err)
			}
			if got != tt.want {
				t.Fatalf("NormalizeSBOMOutputFormat(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestGenerateSBOMFormatEnumIsServerAccepted guards the invariant that broke in
// practice: MCP clients enforce the input-schema enum before the call reaches
// Deputy, so every advertised enum value must be one the server accepts, and the
// short aliases must be advertised (not just accepted server-side). The enum is
// derived from the deputy.mcp.v1 GenerateSBOMRequest descriptor, the same way
// the registered tool schema is.
func TestGenerateSBOMFormatEnumIsServerAccepted(t *testing.T) {
	inputSchema, _ := mustToolSchemas(
		(&mcpv1.GenerateSBOMRequest{}).ProtoReflect().Descriptor(),
		(&mcpv1.GenerateSBOMResult{}).ProtoReflect().Descriptor(),
	)
	formatProperty, ok := inputSchema.Properties["format"]
	if !ok || formatProperty == nil {
		t.Fatal("generate_sbom input schema is missing the format property")
	}
	enum := formatProperty.Enum
	if len(enum) == 0 {
		t.Fatal("sbom format enum is empty")
	}
	advertised := make(map[string]bool, len(enum))
	for _, v := range enum {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("enum value %v is not a string", v)
		}
		advertised[s] = true
		if _, err := flags.NormalizeSBOMOutputFormat(s); err != nil {
			t.Errorf("enum advertises %q but the server rejects it: %v", s, err)
		}
	}
	for _, alias := range []string{"cyclonedx", "spdx", "protobom"} {
		if !advertised[alias] {
			t.Errorf("sbom format enum should advertise short alias %q so strict MCP clients accept it", alias)
		}
	}
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
		_, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{}, &mcpv1.GetRemediationResult{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("no vulnerabilities", func(t *testing.T) {
		result, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{Path: "/test/path"}, &mcpv1.GetRemediationResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.VulnerabilitiesFound != 0 {
			t.Errorf("expected 0 vulnerabilities, got %d", result.VulnerabilitiesFound)
		}
		if result.CommandCount != 0 {
			t.Errorf("expected 0 remediation commands, got %d", result.CommandCount)
		}
		if result.ExecutableCommandCount != 0 {
			t.Errorf("expected 0 executable commands, got %d", result.ExecutableCommandCount)
		}
		if result.ManualCommandCount != 0 {
			t.Errorf("expected 0 manual commands, got %d", result.ManualCommandCount)
		}
	})

	t.Run("forwards ref", func(t *testing.T) {
		mockScan.scanResponse = emptyScanResponse()
		mockScan.scanResponse.Target = &targetv1.Target{
			Ref:          "origin/main",
			EffectiveRef: "refs/remotes/origin/main",
			CommitHash:   "789abc",
		}
		mockScan.requests = nil
		result, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{
			Path: "/test/path",
			Ref:  " origin/main ",
		}, &mcpv1.GetRemediationResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockScan.requests) != 1 {
			t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
		}
		if got := mockScan.requests[0].Options.GetRef(); got != "origin/main" {
			t.Fatalf("scan ref = %q, want origin/main", got)
		}
		if result.Ref != "origin/main" || result.EffectiveRef != "refs/remotes/origin/main" || result.Commit != "789abc" {
			t.Fatalf("result target metadata = ref %q effective %q commit %q, want origin/main refs/remotes/origin/main 789abc", result.Ref, result.EffectiveRef, result.Commit)
		}
	})

	t.Run("migration-only fix counts as remediable", func(t *testing.T) {
		mockScan.scanResponse = migrationOnlyScanResponse()

		result, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{Path: "/test/path"}, &mcpv1.GetRemediationResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.RemediableCount != 1 {
			t.Errorf("expected 1 remediable vulnerability, got %d", result.RemediableCount)
		}
		if result.MigrationCount != 1 {
			t.Errorf("expected 1 migration fix, got %d", result.MigrationCount)
		}
		if result.UnfixableCount != 0 {
			t.Errorf("expected 0 unfixable vulnerabilities, got %d", result.UnfixableCount)
		}
		if result.CommandCount != 1 {
			t.Errorf("expected 1 remediation command, got %d", result.CommandCount)
		}
		if result.ExecutableCommandCount != 0 {
			t.Errorf("expected 0 executable commands, got %d", result.ExecutableCommandCount)
		}
		if result.ManualCommandCount != 1 {
			t.Errorf("expected 1 manual command, got %d", result.ManualCommandCount)
		}

		var foundMigrationCommand bool
		for _, cmd := range result.Commands {
			if cmd.Command == "go get github.com/example/widget/v2@v2.0.1" {
				foundMigrationCommand = true
				if cmd.Executable {
					t.Error("expected migration command to be non-executable")
				}
			}
		}
		if !foundMigrationCommand {
			t.Fatalf("expected migration command, got %+v", result.Commands)
		}
	})

	t.Run("counts commands separately from grouped vulnerabilities", func(t *testing.T) {
		mockScan.scanResponse = groupedMigrationScanResponse()

		result, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{Path: "/test/path"}, &mcpv1.GetRemediationResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.VulnerabilitiesFound != 2 {
			t.Errorf("expected 2 vulnerabilities, got %d", result.VulnerabilitiesFound)
		}
		if result.RemediableCount != 2 {
			t.Errorf("expected 2 remediable vulnerabilities, got %d", result.RemediableCount)
		}
		if result.MigrationCount != 2 {
			t.Errorf("expected 2 migration fixes, got %d", result.MigrationCount)
		}
		if result.CommandCount != 1 {
			t.Errorf("expected 1 grouped remediation command, got %d", result.CommandCount)
		}
		if result.ExecutableCommandCount != 0 {
			t.Errorf("expected 0 executable commands, got %d", result.ExecutableCommandCount)
		}
		if result.ManualCommandCount != 1 {
			t.Errorf("expected 1 manual command, got %d", result.ManualCommandCount)
		}
		if len(result.Commands) != int(result.CommandCount) {
			t.Errorf("commands length = %d, want commandCount %d", len(result.Commands), result.CommandCount)
		}
	})

	t.Run("indirect migration hint uses MCP graph tool", func(t *testing.T) {
		mockScan.scanResponse = indirectMigrationOnlyScanResponse()

		result, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{Path: "/test/path"}, &mcpv1.GetRemediationResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.MigrationCount != 1 {
			t.Errorf("expected 1 migration fix, got %d", result.MigrationCount)
		}

		var foundIndirectMigration bool
		for _, cmd := range result.Commands {
			if cmd.Package != "github.com/example/widget" {
				continue
			}
			foundIndirectMigration = true
			if cmd.Purl != "pkg:golang/github.com/example/widget@v1.4.0" {
				t.Errorf("purl = %q, want pkg:golang/github.com/example/widget@v1.4.0", cmd.Purl)
			}
			if !cmd.Migration {
				t.Error("expected migration command")
			}
			if cmd.TargetModule != "github.com/example/widget/v2" {
				t.Errorf("target module = %q, want github.com/example/widget/v2", cmd.TargetModule)
			}
			if cmd.TargetVersion != "v2.0.1" {
				t.Errorf("target version = %q, want v2.0.1", cmd.TargetVersion)
			}
			if cmd.Executable {
				t.Error("expected indirect migration command to be non-executable")
			}
			if !strings.Contains(cmd.Hint, "graph_why") {
				t.Errorf("hint = %q, want graph_why guidance", cmd.Hint)
			}
			if !strings.Contains(cmd.Hint, "resolveTransitives true") {
				t.Errorf("hint = %q, want resolveTransitives guidance", cmd.Hint)
			}
			if !strings.Contains(cmd.Hint, cmd.Purl) {
				t.Errorf("hint = %q, want vulnerable package PURL", cmd.Hint)
			}
			if strings.Contains(cmd.Hint, "--with-graph") {
				t.Errorf("hint leaked CLI flag: %q", cmd.Hint)
			}
		}
		if !foundIndirectMigration {
			t.Fatalf("expected indirect migration command, got %+v", result.Commands)
		}
	})

	t.Run("distinct indirect migrations stay distinct", func(t *testing.T) {
		mockScan.scanResponse = multiIndirectMigrationScanResponse()

		result, err := callProtoTool(t, ctx, s.getRemediation, &mcpv1.GetRemediationRequest{Path: "/test/path"}, &mcpv1.GetRemediationResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.MigrationCount != 2 {
			t.Errorf("expected 2 migration fixes, got %d", result.MigrationCount)
		}
		if result.CommandCount != 2 {
			t.Errorf("expected 2 remediation commands, got %d", result.CommandCount)
		}
		if result.ManualCommandCount != 2 {
			t.Errorf("expected 2 manual commands, got %d", result.ManualCommandCount)
		}

		indirectMigrations := map[string]*mcpv1.RemediationCommand{}
		for _, cmd := range result.Commands {
			if cmd.Command == "Upgrade the dependency that pulls this in (indirect — no in-place fix)" {
				indirectMigrations[cmd.Package] = cmd
			}
		}
		wantPURLs := map[string]string{
			"github.com/example/widget":        "pkg:golang/github.com/example/widget@v1.4.0",
			"github.com/containerd/containerd": "pkg:golang/github.com/containerd/containerd@1.7.33",
		}
		if len(indirectMigrations) != len(wantPURLs) {
			t.Fatalf("indirect migration command count = %d, want %d: %+v", len(indirectMigrations), len(wantPURLs), result.Commands)
		}
		for pkgName, wantPURL := range wantPURLs {
			cmd, ok := indirectMigrations[pkgName]
			if !ok {
				t.Fatalf("missing indirect migration command for %s: %+v", pkgName, result.Commands)
			}
			if cmd.Purl != wantPURL {
				t.Errorf("%s purl = %q, want %q", pkgName, cmd.Purl, wantPURL)
			}
			if !strings.Contains(cmd.Hint, cmd.Purl) {
				t.Errorf("%s hint = %q, want vulnerable package PURL", pkgName, cmd.Hint)
			}
			if !strings.Contains(cmd.Hint, "graph_why") {
				t.Errorf("%s hint = %q, want graph_why guidance", pkgName, cmd.Hint)
			}
			if !strings.Contains(cmd.Hint, "resolveTransitives true") {
				t.Errorf("%s hint = %q, want resolveTransitives guidance", pkgName, cmd.Hint)
			}
			if cmd.Executable {
				t.Errorf("%s indirect migration command should not be executable", pkgName)
			}
		}
	})
}

func TestTriageVulnerabilitiesMigrationFix(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: migrationOnlyScanResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))
	ctx := context.Background()

	result, err := callProtoTool(t, ctx, s.triageVulnerabilities, &mcpv1.TriageRequest{Path: "/test/path"}, &mcpv1.TriageResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.FixableCount != 1 {
		t.Errorf("expected 1 fixable vulnerability, got %d", result.FixableCount)
	}
	if result.MigrationCount != 1 {
		t.Errorf("expected 1 migration fix, got %d", result.MigrationCount)
	}
	if result.UnfixableCount != 0 {
		t.Errorf("expected 0 unfixable vulnerabilities, got %d", result.UnfixableCount)
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(result.Vulnerabilities))
	}
	vuln := result.Vulnerabilities[0]
	if !vuln.HasFix {
		t.Error("expected migration-only vulnerability to have a fix")
	}
	if vuln.ResolvedFix == nil {
		t.Fatal("expected resolved fix")
	}
	if vuln.ResolvedFix.Status != "migration" {
		t.Errorf("resolved fix status = %q, want migration", vuln.ResolvedFix.Status)
	}
	if vuln.ResolvedFix.TargetModule != "github.com/example/widget/v2" {
		t.Errorf("resolved fix target = %q, want github.com/example/widget/v2", vuln.ResolvedFix.TargetModule)
	}
	if vuln.Purl != "pkg:golang/github.com/example/widget@v1.4.0" {
		t.Errorf("purl = %q, want pkg:golang/github.com/example/widget@v1.4.0", vuln.Purl)
	}
	if len(vuln.PackageFixes) != 1 {
		t.Fatalf("expected 1 package fix, got %d", len(vuln.PackageFixes))
	}
	if vuln.PackageFixes[0].Module != "github.com/example/widget/v2" {
		t.Errorf("package fix module = %q, want github.com/example/widget/v2", vuln.PackageFixes[0].Module)
	}
	if vuln.PackageFixes[0].Ecosystem != "go" {
		t.Errorf("package fix ecosystem = %q, want go", vuln.PackageFixes[0].Ecosystem)
	}
}

func TestTriageVulnerabilitiesForwardsRef(t *testing.T) {
	resp := emptyScanResponse()
	resp.Target = &targetv1.Target{
		Ref:          "refs/heads/security",
		EffectiveRef: "refs/heads/security",
		CommitHash:   "abc789",
	}
	mockScan := &mockScanHandler{scanResponse: resp}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := callProtoTool(t, t.Context(), s.triageVulnerabilities, &mcpv1.TriageRequest{
		Path: "/test/path",
		Ref:  " refs/heads/security ",
	}, &mcpv1.TriageResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mockScan.requests) != 1 {
		t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
	}
	if got := mockScan.requests[0].Options.GetRef(); got != "refs/heads/security" {
		t.Fatalf("scan ref = %q, want refs/heads/security", got)
	}
	if result.Ref != "refs/heads/security" || result.EffectiveRef != "refs/heads/security" || result.Commit != "abc789" {
		t.Fatalf("result target metadata = ref %q effective %q commit %q, want refs/heads/security refs/heads/security abc789", result.Ref, result.EffectiveRef, result.Commit)
	}
}

func TestTriageVulnerabilitiesDoesNotRecommendDirectUpdateForTransitiveFix(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: directUnfixableTransitiveFixableScanResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := callProtoTool(t, t.Context(), s.triageVulnerabilities, &mcpv1.TriageRequest{Path: "/test/path"}, &mcpv1.TriageResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DirectVulnerabilities != 1 {
		t.Errorf("direct vulnerabilities = %d, want 1", result.DirectVulnerabilities)
	}
	if result.TransitiveVulnerabilities != 1 {
		t.Errorf("transitive vulnerabilities = %d, want 1", result.TransitiveVulnerabilities)
	}
	if result.FixableCount != 1 {
		t.Errorf("fixable count = %d, want 1", result.FixableCount)
	}
	if result.DirectFixableCount != 0 {
		t.Errorf("direct fixable count = %d, want 0", result.DirectFixableCount)
	}
	if result.TransitiveFixableCount != 1 {
		t.Errorf("transitive fixable count = %d, want 1", result.TransitiveFixableCount)
	}
	if result.UnfixableCount != 1 {
		t.Errorf("unfixable count = %d, want 1", result.UnfixableCount)
	}
	for _, recommendation := range result.Recommendations {
		if strings.Contains(recommendation, "Update or migrate direct dependencies") {
			t.Fatalf("unexpected direct dependency recommendation: %q", recommendation)
		}
	}
}

func TestTriageVulnerabilitiesCountsUnknownSeverity(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: unknownSeverityScanResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := callProtoTool(t, t.Context(), s.triageVulnerabilities, &mcpv1.TriageRequest{Path: "/test/path"}, &mcpv1.TriageResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.TotalVulnerabilities != 2 {
		t.Errorf("total vulnerabilities = %d, want 2", result.TotalVulnerabilities)
	}
	if result.UnknownCount != 2 {
		t.Errorf("unknown count = %d, want 2", result.UnknownCount)
	}
	if got := result.CriticalCount + result.HighCount + result.MediumCount + result.LowCount + result.UnknownCount; got != result.TotalVulnerabilities {
		t.Errorf("severity count sum = %d, want total %d", got, result.TotalVulnerabilities)
	}
	if result.FixableCount != 1 {
		t.Errorf("fixable count = %d, want 1", result.FixableCount)
	}
	if result.TransitiveFixableCount != 1 {
		t.Errorf("transitive fixable count = %d, want 1", result.TransitiveFixableCount)
	}
	var foundFixableUnknown bool
	for _, vuln := range result.Vulnerabilities {
		if vuln.Id == "GO-2026-2001" {
			foundFixableUnknown = true
			if vuln.PriorityReason != "Unknown severity with fix available in transitive dependency" {
				t.Errorf("priority reason = %q, want unknown severity fix guidance", vuln.PriorityReason)
			}
		}
	}
	if !foundFixableUnknown {
		t.Fatalf("missing fixable unknown severity vulnerability: %+v", result.Vulnerabilities)
	}
}

func TestCalculatePriorityReasonsKeepFixContext(t *testing.T) {
	tests := []struct {
		name       string
		severity   string
		hasFix     bool
		isDirect   bool
		wantLevel  string
		wantReason string
	}{
		{
			name:       "high transitive fixable",
			severity:   "HIGH",
			hasFix:     true,
			wantLevel:  "high",
			wantReason: "High severity with fix available in transitive dependency",
		},
		{
			name:       "medium transitive fixable",
			severity:   "MEDIUM",
			hasFix:     true,
			wantLevel:  "low",
			wantReason: "Medium severity with fix available in transitive dependency",
		},
		{
			name:       "low direct fixable",
			severity:   "LOW",
			hasFix:     true,
			isDirect:   true,
			wantLevel:  "low",
			wantReason: "Low severity, fixable, in direct dependency",
		},
		{
			name:       "unknown transitive fixable",
			severity:   "UNKNOWN",
			hasFix:     true,
			wantLevel:  "low",
			wantReason: "Unknown severity with fix available in transitive dependency",
		},
		{
			name:       "unknown no fix",
			severity:   "UNKNOWN",
			wantLevel:  "low",
			wantReason: "Unknown severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotLevel, gotReason := vulnerability.TriagePriority(tt.severity, tt.hasFix, tt.isDirect)
			if gotLevel != tt.wantLevel {
				t.Errorf("priority level = %q, want %q", gotLevel, tt.wantLevel)
			}
			if gotReason != tt.wantReason {
				t.Errorf("priority reason = %q, want %q", gotReason, tt.wantReason)
			}
		})
	}
}

func TestAnalyzeDependencyGraph(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponse: emptyScanResponse(),
	}
	mockGraph := &mockGraphHandler{
		buildResponse: testBuildGraphResponse(),
	}

	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan, graphHandler: mockGraph})))
	ctx := context.Background()

	t.Run("missing path", func(t *testing.T) {
		_, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{}, &mcpv1.AnalyzeGraphResult{})
		if err == nil {
			t.Error("expected error for missing path")
		}
	})

	t.Run("basic graph analysis", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:         "/test/path",
			TargetPurl:   testChildPURL,
			ExcludePaths: []string{".bin/**"},
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Path != "/test/path" {
			t.Errorf("expected path /test/path, got %s", result.Path)
		}
		if result.Stats.TotalNodes != 2 {
			t.Errorf("expected 2 graph nodes, got %d", result.Stats.TotalNodes)
		}
		if result.Stats.DirectNodes != 1 {
			t.Errorf("expected 1 direct node, got %d", result.Stats.DirectNodes)
		}
		if result.Stats.TransitiveNodes != 1 {
			t.Errorf("expected 1 transitive node, got %d", result.Stats.TransitiveNodes)
		}
		if result.Stats.Ecosystems["go"] != 2 {
			t.Errorf("expected 2 go nodes, got %d", result.Stats.Ecosystems["go"])
		}
		if len(result.PathsToTarget) != 1 {
			t.Fatalf("expected 1 path to target, got %d", len(result.PathsToTarget))
		}
		if result.Target == nil {
			t.Fatal("expected target summary")
		}
		if !result.Target.Found {
			t.Fatal("expected target summary to report found")
		}
		if got, want := int(result.Target.PathCount), 1; got != want {
			t.Fatalf("target path count = %d, want %d", got, want)
		}
		if got, want := result.Target.MatchedPurls, []string{testChildPURL}; !slicesEqual(got, want) {
			t.Fatalf("target matched PURLs = %v, want %v", got, want)
		}
		if !strings.Contains(result.Target.Message, "1 dependency path") {
			t.Fatalf("target message = %q, want path count guidance", result.Target.Message)
		}
		wantPath := []string{"github.com/example/root@v1.0.0", "github.com/example/child@v2.0.0"}
		if got := result.PathsToTarget[0].Nodes; !slicesEqual(got, wantPath) {
			t.Errorf("unexpected path to target: got %v want %v", got, wantPath)
		}
		if len(result.PathsToTarget[0].NodeDetails) != 2 {
			t.Fatalf("expected 2 structured path nodes, got %d", len(result.PathsToTarget[0].NodeDetails))
		}
		child := result.PathsToTarget[0].NodeDetails[1]
		if child.Purl != testChildPURL {
			t.Errorf("structured child PURL = %q, want %q", child.Purl, testChildPURL)
		}
		if child.Ecosystem != "go" {
			t.Errorf("structured child ecosystem = %q, want go", child.Ecosystem)
		}
		if child.Depth != 1 {
			t.Errorf("structured child depth = %d, want 1", child.Depth)
		}
		if len(mockGraph.requests) != 1 {
			t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
		}
		if got, want := mockGraph.requests[0].Options.GetExcludePaths(), []string{".bin/**"}; !slicesEqual(got, want) {
			t.Fatalf("graph exclude paths = %v, want %v", got, want)
		}
		if mockGraph.requests[0].Options.GetUseProxy() || mockGraph.requests[0].Options.GetUseGit() {
			t.Fatal("graph request should not use network-backed transitive resolution by default")
		}
		if len(mockScan.requests) != 1 {
			t.Fatalf("expected 1 scan annotation request, got %d", len(mockScan.requests))
		}
		if got, want := mockScan.requests[0].Options.GetExcludePaths(), []string{".bin/**"}; !slicesEqual(got, want) {
			t.Fatalf("scan exclude paths = %v, want %v", got, want)
		}
	})

	t.Run("resolve transitives opts into proxy and git resolution", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		_, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:               "/test/path",
			ResolveTransitives: true,
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockGraph.requests) != 1 {
			t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
		}
		if !mockGraph.requests[0].Options.GetUseProxy() || !mockGraph.requests[0].Options.GetUseGit() {
			t.Fatal("resolveTransitives should enable proxy and git graph resolution")
		}
	})

	t.Run("extended opts into import status graph metadata", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		_, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:     "/test/path",
			Extended: true,
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockGraph.requests) != 1 {
			t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
		}
		if !mockGraph.requests[0].Options.GetExtended() {
			t.Fatal("extended should enable GraphOptions.extended")
		}
	})

	t.Run("ref is forwarded to graph and scan annotation", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		mockGraph.buildResponse = testBuildGraphResponse()
		_, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path: "/test/path",
			Ref:  " v1.2.3 ",
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(mockGraph.requests) != 1 {
			t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
		}
		if got, want := mockGraph.requests[0].Options.GetRef(), "v1.2.3"; got != want {
			t.Fatalf("graph ref = %q, want %q", got, want)
		}
		if len(mockScan.requests) != 1 {
			t.Fatalf("expected 1 scan annotation request, got %d", len(mockScan.requests))
		}
		if got, want := mockScan.requests[0].Options.GetRef(), "v1.2.3"; got != want {
			t.Fatalf("scan annotation ref = %q, want %q", got, want)
		}
	})

	t.Run("trims path before graph and scan annotation", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path: " /test/path ",
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Path != "/test/path" {
			t.Fatalf("result path = %q, want /test/path", result.Path)
		}
		if len(mockGraph.requests) != 1 {
			t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
		}
		if got := mockGraph.requests[0].Target; got != "/test/path" {
			t.Fatalf("graph target = %q, want /test/path", got)
		}
		if len(mockScan.requests) != 1 {
			t.Fatalf("expected 1 scan annotation request, got %d", len(mockScan.requests))
		}
		if got := mockScan.requests[0].Target; got != "/test/path" {
			t.Fatalf("scan annotation target = %q, want /test/path", got)
		}
	})

	t.Run("target purl can omit version", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:       "/test/path",
			TargetPurl: "pkg:golang/github.com/example/child",
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.PathsToTarget) != 1 {
			t.Fatalf("expected 1 path to target, got %d", len(result.PathsToTarget))
		}
	})

	t.Run("target purl accepts semver equivalent version", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:       "/test/path",
			TargetPurl: "pkg:golang/github.com/example/child@2.0.0",
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.PathsToTarget) != 1 {
			t.Fatalf("expected 1 path to target, got %d", len(result.PathsToTarget))
		}
	})

	t.Run("target purl accepts scan-emitted escaped version equivalents", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		mockGraph.buildResponse = testEscapedVersionGraphResponse()
		const dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:       "/test/path",
			TargetPurl: "pkg:golang/github.com/docker/docker@v28.5.2+incompatible",
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result.Target == nil {
			t.Fatal("expected target summary")
		}
		if !result.Target.Found {
			t.Fatal("expected target summary to report found")
		}
		if got, want := result.Target.MatchedPurls, []string{dockerPURL}; !slices.Equal(got, want) {
			t.Fatalf("target matched PURLs = %v, want %v", got, want)
		}
		if got, want := int(result.Target.PathCount), 1; got != want {
			t.Fatalf("target path count = %d, want %d", got, want)
		}
		if len(result.PathsToTarget) != 1 {
			t.Fatalf("expected 1 path to target, got %d", len(result.PathsToTarget))
		}
		nodes := result.PathsToTarget[0].NodeDetails
		if len(nodes) != 2 {
			t.Fatalf("target path node details = %d, want 2", len(nodes))
		}
		if got := nodes[1].Purl; got != dockerPURL {
			t.Fatalf("target path leaf PURL = %q, want %q", got, dockerPURL)
		}
	})

	t.Run("path limits report counts and truncation", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		mockGraph.buildResponse = testWideTargetGraphResponse(55)
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:       "/test/path",
			TargetPurl: "pkg:npm/shared-target",
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got, want := int(result.VulnerablePathCount), 55; got != want {
			t.Fatalf("vulnerable path count = %d, want %d", got, want)
		}
		if got, want := len(result.VulnerablePaths), maxMCPVulnerablePaths; got != want {
			t.Fatalf("returned vulnerable paths = %d, want %d", got, want)
		}
		if !result.VulnerablePathsTruncated {
			t.Fatal("expected vulnerable paths to report truncation")
		}
		if result.Target == nil {
			t.Fatal("expected target summary")
		}
		if got, want := int(result.Target.PathCount), 55; got != want {
			t.Fatalf("target path count = %d, want %d", got, want)
		}
		if got, want := len(result.PathsToTarget), maxMCPPathsToTarget; got != want {
			t.Fatalf("returned target paths = %d, want %d", got, want)
		}
		if !result.PathsToTargetTruncated {
			t.Fatal("expected pathsToTarget to report truncation")
		}
	})

	t.Run("target purl not found is explicit", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		mockGraph.buildResponse = testBuildGraphResponse()
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:       "/test/path",
			TargetPurl: "pkg:golang/github.com/example/missing@v1.0.0",
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.PathsToTarget) != 0 {
			t.Fatalf("paths to missing target = %d, want 0", len(result.PathsToTarget))
		}
		if result.Target == nil {
			t.Fatal("expected target summary")
		}
		if result.Target.Found {
			t.Fatal("expected target summary to report not found")
		}
		if got := result.Target.PathCount; got != 0 {
			t.Fatalf("target path count = %d, want 0", got)
		}
		if !strings.Contains(result.Target.Message, "not found") {
			t.Fatalf("target message = %q, want not found guidance", result.Target.Message)
		}
	})

	t.Run("target purl present without path is explicit", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		const disconnectedPURL = "pkg:golang/github.com/example/disconnected@v1.0.0"
		mockGraph.buildResponse = &graphv1.BuildGraphResponse{
			Nodes: []*graphv1.Node{
				{
					Purl:      disconnectedPURL,
					Name:      "github.com/example/disconnected",
					Version:   "v1.0.0",
					Ecosystem: "Go",
					Direct:    false,
					Depth:     graph.DepthDisconnected,
				},
			},
		}
		result, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:       "/test/path",
			TargetPurl: disconnectedPURL,
		}, &mcpv1.AnalyzeGraphResult{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(result.PathsToTarget) != 0 {
			t.Fatalf("paths to disconnected target = %d, want 0", len(result.PathsToTarget))
		}
		if result.Target == nil {
			t.Fatal("expected target summary")
		}
		if !result.Target.Found {
			t.Fatal("expected target summary to report found")
		}
		if got := result.Target.PathCount; got != 0 {
			t.Fatalf("target path count = %d, want 0", got)
		}
		if got, want := result.Target.MatchedPurls, []string{disconnectedPURL}; !slicesEqual(got, want) {
			t.Fatalf("target matched PURLs = %v, want %v", got, want)
		}
		if len(result.Target.MatchedNodes) != 1 {
			t.Fatalf("target matched nodes = %d, want 1", len(result.Target.MatchedNodes))
		}
		if !result.Target.MatchedNodes[0].Disconnected {
			t.Fatal("target matched node should report disconnected")
		}
		if !strings.Contains(result.Target.Message, "no dependency path") {
			t.Fatalf("target message = %q, want no-path guidance", result.Target.Message)
		}
	})

	t.Run("rejects invalid target purl", func(t *testing.T) {
		mockScan.requests = nil
		mockGraph.requests = nil
		_, err := callProtoTool(t, ctx, s.analyzeDependencyGraph, &mcpv1.AnalyzeGraphRequest{
			Path:       "/test/path",
			TargetPurl: "not-a-purl",
		}, &mcpv1.AnalyzeGraphResult{})
		if err == nil {
			t.Fatal("expected error")
		}
		if len(mockGraph.requests) != 0 {
			t.Fatalf("expected target validation before graph request, got %d requests", len(mockGraph.requests))
		}
	})
}

func TestGraphWhyUsesGraphService(t *testing.T) {
	mockGraph := &mockGraphHandler{buildResponse: testBuildGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))
	ctx := context.Background()

	result, err := callProtoTool(t, ctx, s.graphWhy, &mcpv1.GraphWhyRequest{
		Path:         "/test/path",
		Package:      "github.com/example/child",
		Ref:          " refs/tags/v1.2.3 ",
		ExcludePaths: []string{".bin/**"},
	}, &mcpv1.GraphWhyResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if result.Direct {
		t.Fatal("expected child package to be transitive")
	}
	if result.PathCount != 1 {
		t.Fatalf("expected 1 dependency path, got %d", result.PathCount)
	}

	wantPath := []string{"github.com/example/root@v1.0.0", "github.com/example/child@v2.0.0"}
	if got := result.Paths[0].Nodes; !slicesEqual(got, wantPath) {
		t.Errorf("unexpected dependency path: got %v want %v", got, wantPath)
	}
	if len(result.Paths[0].NodeDetails) != 2 {
		t.Fatalf("expected 2 structured path nodes, got %d", len(result.Paths[0].NodeDetails))
	}
	if got := result.Paths[0].NodeDetails[1].Purl; got != testChildPURL {
		t.Errorf("structured path target PURL = %q, want %q", got, testChildPURL)
	}
	if result.Paths[0].NodeDetails[1].Direct {
		t.Error("structured path target should be transitive")
	}
	if len(mockGraph.requests) != 1 {
		t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
	}
	if got, want := mockGraph.requests[0].Options.GetExcludePaths(), []string{".bin/**"}; !slicesEqual(got, want) {
		t.Fatalf("exclude paths = %v, want %v", got, want)
	}
	if got, want := mockGraph.requests[0].Options.GetRef(), "refs/tags/v1.2.3"; got != want {
		t.Fatalf("graph why ref = %q, want %q", got, want)
	}
	if mockGraph.requests[0].Options.GetUseProxy() || mockGraph.requests[0].Options.GetUseGit() {
		t.Fatal("graph why should not use network-backed transitive resolution by default")
	}
}

func TestGraphWhyReportsPathTruncation(t *testing.T) {
	tests := []struct {
		name          string
		showAll       bool
		wantReturned  int
		wantTruncated bool
	}{
		{
			name:          "default cap",
			wantReturned:  maxMCPGraphWhyPaths,
			wantTruncated: true,
		},
		{
			name:         "show all within cap",
			showAll:      true,
			wantReturned: 15,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGraph := &mockGraphHandler{buildResponse: testWideTargetGraphResponse(15)}
			s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

			result, err := callProtoTool(t, t.Context(), s.graphWhy, &mcpv1.GraphWhyRequest{
				Path:    "/test/path",
				Package: "shared-target",
				ShowAll: tt.showAll,
			}, &mcpv1.GraphWhyResult{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := int(result.PathCount), 15; got != want {
				t.Fatalf("PathCount = %d, want %d", got, want)
			}
			if got := len(result.Paths); got != tt.wantReturned {
				t.Fatalf("returned paths = %d, want %d", got, tt.wantReturned)
			}
			if got := result.PathsTruncated; got != tt.wantTruncated {
				t.Fatalf("PathsTruncated = %t, want %t", got, tt.wantTruncated)
			}
		})
	}
}

func TestGraphWhyReturnsDirectPath(t *testing.T) {
	mockGraph := &mockGraphHandler{buildResponse: testBuildGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	result, err := callProtoTool(t, context.Background(), s.graphWhy, &mcpv1.GraphWhyRequest{
		Path:    "/test/path",
		Package: "github.com/example/root",
	}, &mcpv1.GraphWhyResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if !result.Direct {
		t.Fatal("expected root package to be direct")
	}
	if result.PathCount != 1 {
		t.Fatalf("expected 1 direct dependency path, got %d", result.PathCount)
	}
	if len(result.Paths) != 1 {
		t.Fatalf("expected 1 returned path, got %d", len(result.Paths))
	}
	if result.Paths[0].Depth != 0 {
		t.Fatalf("expected zero-hop direct path, got depth %d", result.Paths[0].Depth)
	}
	wantPath := []string{"github.com/example/root@v1.0.0"}
	if got := result.Paths[0].Nodes; !slicesEqual(got, wantPath) {
		t.Errorf("unexpected direct dependency path: got %v want %v", got, wantPath)
	}
	if len(result.Paths[0].NodeDetails) != 1 {
		t.Fatalf("expected 1 structured path node, got %d", len(result.Paths[0].NodeDetails))
	}
	root := result.Paths[0].NodeDetails[0]
	if root.Purl != testRootPURL {
		t.Errorf("structured path PURL = %q, want %q", root.Purl, testRootPURL)
	}
	if !root.Direct {
		t.Error("structured path root should be direct")
	}
	if root.Depth != 0 {
		t.Errorf("structured path root depth = %d, want 0", root.Depth)
	}
	if root.Ecosystem != "go" {
		t.Errorf("structured path root ecosystem = %q, want go", root.Ecosystem)
	}
}

func TestGraphWhyFindsDirectDependencyWithRealGraphService(t *testing.T) {
	tmpDir := t.TempDir()
	goMod := `module example.com/app

go 1.21

require github.com/pkg/errors v0.9.1
`
	if err := os.WriteFile(filepath.Join(tmpDir, "go.mod"), []byte(goMod), 0644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	mux := http.NewServeMux()
	path, handler := graphv1connect.NewGraphServiceHandler(deputyserver.NewGraphHandler(deputyserver.WithGraphLocalMode()))
	mux.Handle(path, handler)
	transport := services.NewInProcessTransport(mux)
	clients := &services.Clients{
		Graph: graphv1connect.NewGraphServiceClient(transport.HTTPClient(), ""),
	}
	s := NewServer(WithClients(clients))

	result, err := callProtoTool(t, context.Background(), s.graphWhy, &mcpv1.GraphWhyRequest{
		Path:       tmpDir,
		Package:    "github.com/pkg/errors",
		Ecosystems: []string{"go"},
	}, &mcpv1.GraphWhyResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected direct dependency to be found")
	}
	if !result.Direct {
		t.Fatal("expected dependency to be direct")
	}
	if got, want := result.Purl, "pkg:golang/github.com/pkg/errors@0.9.1"; got != want {
		t.Fatalf("PURL = %q, want %q", got, want)
	}
	if got, want := int(result.PathCount), 1; got != want {
		t.Fatalf("PathCount = %d, want %d", got, want)
	}
	if got, want := len(result.Paths), 1; got != want {
		t.Fatalf("returned paths = %d, want %d", got, want)
	}
	if got, want := int(result.Paths[0].Depth), 0; got != want {
		t.Fatalf("path depth = %d, want %d", got, want)
	}
}

func TestGraphWhyAcceptsPURLQuery(t *testing.T) {
	mockGraph := &mockGraphHandler{buildResponse: testBuildGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	result, err := callProtoTool(t, context.Background(), s.graphWhy, &mcpv1.GraphWhyRequest{
		Path:    "/test/path",
		Package: " " + testChildPURL + " ",
	}, &mcpv1.GraphWhyResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if result.Purl != testChildPURL {
		t.Fatalf("PURL = %q, want %q", result.Purl, testChildPURL)
	}
	if result.PathCount != 1 {
		t.Fatalf("expected 1 dependency path, got %d", result.PathCount)
	}
}

func TestGraphWhyAcceptsScanEmittedPURLWithEscapedVersion(t *testing.T) {
	const dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
	mockGraph := &mockGraphHandler{buildResponse: &graphv1.BuildGraphResponse{
		Nodes: []*graphv1.Node{
			{
				Purl:      dockerPURL,
				Name:      "github.com/docker/docker",
				Version:   "28.5.2+incompatible",
				Ecosystem: "go",
				Direct:    true,
			},
		},
		Roots: []string{dockerPURL},
		Stats: &graphv1.GraphStats{TotalNodes: 1, DirectNodes: 1},
	}}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	result, err := callProtoTool(t, context.Background(), s.graphWhy, &mcpv1.GraphWhyRequest{
		Path:    "/test/path",
		Package: dockerPURL,
	}, &mcpv1.GraphWhyResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if result.Purl != dockerPURL {
		t.Fatalf("PURL = %q, want %q", result.Purl, dockerPURL)
	}
	if result.PathCount != 1 {
		t.Fatalf("PathCount = %d, want 1", result.PathCount)
	}
}

func TestGraphWhyExplainsDisconnectedMatchedNode(t *testing.T) {
	const dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
	mockGraph := &mockGraphHandler{buildResponse: &graphv1.BuildGraphResponse{
		Nodes: []*graphv1.Node{
			{
				Purl:         dockerPURL,
				Name:         "github.com/docker/docker",
				Version:      "28.5.2+incompatible",
				Ecosystem:    "Go",
				Direct:       false,
				Depth:        graph.DepthDisconnected,
				ImportStatus: graphv1.ImportStatus_IMPORT_STATUS_REQUIRED,
			},
		},
		Stats: &graphv1.GraphStats{TotalNodes: 1, DisconnectedNodes: 1},
	}}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	result, err := callProtoTool(t, context.Background(), s.graphWhy, &mcpv1.GraphWhyRequest{
		Path:               "/test/path",
		Package:            dockerPURL,
		ResolveTransitives: true,
		Extended:           true,
	}, &mcpv1.GraphWhyResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if result.PathCount != 0 {
		t.Fatalf("PathCount = %d, want 0", result.PathCount)
	}
	if result.MatchedNode == nil {
		t.Fatal("expected matched node details")
	}
	if !result.MatchedNode.Disconnected {
		t.Fatal("matched node should report disconnected")
	}
	if result.MatchedNode.ImportStatus != "required" {
		t.Fatalf("matched node import status = %q, want required", result.MatchedNode.ImportStatus)
	}
	if !strings.Contains(result.Message, "required dependency") {
		t.Fatalf("message = %q, want required dependency context", result.Message)
	}
	if len(mockGraph.requests) != 1 {
		t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
	}
	if !mockGraph.requests[0].Options.GetUseProxy() || !mockGraph.requests[0].Options.GetUseGit() || !mockGraph.requests[0].Options.GetExtended() {
		t.Fatalf("graph options = %+v, want proxy, git, and extended enabled", mockGraph.requests[0].Options)
	}
}

func TestGraphNeedsUsesGraphService(t *testing.T) {
	mockGraph := &mockGraphHandler{buildResponse: testBuildGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))
	ctx := context.Background()

	result, err := callProtoTool(t, ctx, s.graphNeeds, &mcpv1.GraphNeedsRequest{
		Path:         "/test/path",
		Package:      "github.com/example/child",
		Ref:          " refs/tags/v1.2.3 ",
		ExcludePaths: []string{".bin/**"},
	}, &mcpv1.GraphNeedsResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if result.DirectCount != 1 {
		t.Fatalf("expected 1 direct dependent, got %d", result.DirectCount)
	}
	if len(result.Dependents) != 1 {
		t.Fatalf("expected 1 dependent, got %d", len(result.Dependents))
	}
	if got := result.Dependents[0].Name; got != "github.com/example/root" {
		t.Errorf("unexpected dependent name: got %q", got)
	}
	if len(mockGraph.requests) != 1 {
		t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
	}
	if got, want := mockGraph.requests[0].Options.GetExcludePaths(), []string{".bin/**"}; !slicesEqual(got, want) {
		t.Fatalf("exclude paths = %v, want %v", got, want)
	}
	if got, want := mockGraph.requests[0].Options.GetRef(), "refs/tags/v1.2.3"; got != want {
		t.Fatalf("graph needs ref = %q, want %q", got, want)
	}
	if mockGraph.requests[0].Options.GetUseProxy() || mockGraph.requests[0].Options.GetUseGit() {
		t.Fatal("graph needs should not use network-backed transitive resolution by default")
	}
}

func TestGraphNeedsSortsDependentsDeterministically(t *testing.T) {
	const (
		targetPURL     = "pkg:npm/shared@1.0.0"
		directAPURL    = "pkg:npm/a-direct@1.0.0"
		directZPURL    = "pkg:npm/z-direct@1.0.0"
		transitivePURL = "pkg:npm/transitive@1.0.0"
	)
	mockGraph := &mockGraphHandler{buildResponse: &graphv1.BuildGraphResponse{
		Nodes: []*graphv1.Node{
			{Purl: targetPURL, Name: "shared", Version: "1.0.0", Ecosystem: "npm", Direct: false, Depth: 2},
			{Purl: directZPURL, Name: "z-direct", Version: "1.0.0", Ecosystem: "npm", Direct: true, Depth: 0},
			{Purl: directAPURL, Name: "a-direct", Version: "1.0.0", Ecosystem: "npm", Direct: true, Depth: 0},
			{Purl: transitivePURL, Name: "transitive", Version: "1.0.0", Ecosystem: "npm", Direct: false, Depth: 1},
		},
		Edges: []*graphv1.Edge{
			{From: transitivePURL, To: targetPURL},
			{From: directZPURL, To: targetPURL},
			{From: directAPURL, To: targetPURL},
		},
		Roots: []string{directZPURL, directAPURL},
		Stats: &graphv1.GraphStats{TotalNodes: 4, DirectNodes: 2, TransitiveNodes: 2},
	}}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	result, err := callProtoTool(t, context.Background(), s.graphNeeds, &mcpv1.GraphNeedsRequest{
		Path:    "/test/path",
		Package: targetPURL,
	}, &mcpv1.GraphNeedsResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := make([]string, 0, len(result.Dependents))
	for _, dep := range result.Dependents {
		got = append(got, dep.Name)
	}
	want := []string{"a-direct", "z-direct", "transitive"}
	if !slices.Equal(got, want) {
		t.Fatalf("dependents = %v, want %v", got, want)
	}
	if result.DirectCount != 2 || result.TransitiveCount != 1 {
		t.Fatalf("counts = direct %d transitive %d, want 2 and 1", result.DirectCount, result.TransitiveCount)
	}
}

func TestGraphNeedsPassesExtendedGraphOption(t *testing.T) {
	mockGraph := &mockGraphHandler{buildResponse: testBuildGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	_, err := callProtoTool(t, context.Background(), s.graphNeeds, &mcpv1.GraphNeedsRequest{
		Path:     "/test/path",
		Package:  "github.com/example/child",
		Extended: true,
	}, &mcpv1.GraphNeedsResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mockGraph.requests) != 1 {
		t.Fatalf("expected 1 graph request, got %d", len(mockGraph.requests))
	}
	if !mockGraph.requests[0].Options.GetExtended() {
		t.Fatal("extended should enable GraphOptions.extended")
	}
}

func TestGraphNeedsExplainsEmptyDependents(t *testing.T) {
	tests := []struct {
		name        string
		node        *graphv1.Node
		roots       []string
		wantDirect  bool
		wantMessage string
	}{
		{
			name: "direct dependency",
			node: &graphv1.Node{
				Purl:      "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible",
				Name:      "github.com/docker/docker",
				Version:   "28.5.2+incompatible",
				Ecosystem: "go",
				Direct:    true,
				Depth:     0,
			},
			roots:       []string{"pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"},
			wantDirect:  true,
			wantMessage: "direct/root dependency",
		},
		{
			name: "disconnected package",
			node: &graphv1.Node{
				Purl:      "pkg:githubactions/actions/checkout@v4",
				Name:      "actions/checkout",
				Version:   "v4",
				Ecosystem: "githubactions",
				Depth:     graph.DepthDisconnected,
			},
			wantMessage: "disconnected from dependency roots",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockGraph := &mockGraphHandler{buildResponse: &graphv1.BuildGraphResponse{
				Nodes: []*graphv1.Node{tt.node},
				Roots: tt.roots,
				Stats: &graphv1.GraphStats{TotalNodes: 1},
			}}
			s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

			result, err := callProtoTool(t, context.Background(), s.graphNeeds, &mcpv1.GraphNeedsRequest{
				Path:    "/test/path",
				Package: tt.node.Purl,
			}, &mcpv1.GraphNeedsResult{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !result.Found {
				t.Fatal("expected package to be found")
			}
			if result.Direct != tt.wantDirect {
				t.Fatalf("Direct = %v, want %v", result.Direct, tt.wantDirect)
			}
			// The protojson wire omits empty collections, so an empty
			// dependents list round-trips as nil: absent means zero.
			if len(result.Dependents) != 0 {
				t.Fatalf("expected no dependents, got %d", len(result.Dependents))
			}
			if !strings.Contains(result.Message, tt.wantMessage) {
				t.Fatalf("Message = %q, want substring %q", result.Message, tt.wantMessage)
			}
		})
	}
}

func TestGraphNeedsAcceptsVersionedPackageQuery(t *testing.T) {
	mockGraph := &mockGraphHandler{buildResponse: testBuildGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	result, err := callProtoTool(t, context.Background(), s.graphNeeds, &mcpv1.GraphNeedsRequest{
		Path:    "/test/path",
		Package: "child@v2.0.0",
	}, &mcpv1.GraphNeedsResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if result.Purl != testChildPURL {
		t.Fatalf("PURL = %q, want %q", result.Purl, testChildPURL)
	}
	if result.DirectCount != 1 {
		t.Fatalf("expected 1 direct dependent, got %d", result.DirectCount)
	}

	result, err = callProtoTool(t, context.Background(), s.graphNeeds, &mcpv1.GraphNeedsRequest{
		Path:    "/test/path",
		Package: "child@v9.0.0",
	}, &mcpv1.GraphNeedsResult{})
	if err != nil {
		t.Fatalf("unexpected error for version mismatch: %v", err)
	}
	if result.Found {
		t.Fatal("expected version mismatch not to match")
	}
	// The protojson wire omits empty collections: absent means zero.
	if len(result.Dependents) != 0 {
		t.Fatalf("expected no dependents for version mismatch, got %d", len(result.Dependents))
	}
	if !strings.Contains(result.Message, `Package "child@v9.0.0" not found`) {
		t.Fatalf("Message = %q, want not-found guidance", result.Message)
	}
}

func TestGraphNeedsAcceptsScanEmittedPURLWithEscapedVersionEquivalent(t *testing.T) {
	const (
		rootPURL   = "pkg:golang/example.com/root@v1.0.0"
		dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
	)
	mockGraph := &mockGraphHandler{buildResponse: testEscapedVersionGraphResponse()}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{graphHandler: mockGraph})))

	result, err := callProtoTool(t, t.Context(), s.graphNeeds, &mcpv1.GraphNeedsRequest{
		Path:    "/test/path",
		Package: "pkg:golang/github.com/docker/docker@v28.5.2+incompatible",
	}, &mcpv1.GraphNeedsResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Found {
		t.Fatal("expected package to be found")
	}
	if result.Purl != dockerPURL {
		t.Fatalf("PURL = %q, want %q", result.Purl, dockerPURL)
	}
	if result.Direct {
		t.Fatal("Direct = true, want false")
	}
	if result.DirectCount != 1 {
		t.Fatalf("expected 1 direct dependent, got %d", result.DirectCount)
	}
	if len(result.Dependents) != 1 {
		t.Fatalf("expected 1 dependent, got %d", len(result.Dependents))
	}
	if got := result.Dependents[0].Purl; got != rootPURL {
		t.Fatalf("dependent PURL = %q, want %q", got, rootPURL)
	}
}

func TestValidateLocalPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{
			name: "current directory",
			path: ".",
		},
		{
			name: "relative project path",
			path: "./project",
		},
		{
			name: "absolute project path",
			path: "/Users/example/project",
		},
		{
			name: "benign dot sequence in name",
			path: "/tmp/deps..cache/project",
		},
		{
			name:    "empty",
			path:    "",
			wantErr: true,
		},
		{
			name:    "blank",
			path:    " \t ",
			wantErr: true,
		},
		{
			name:    "null byte",
			path:    "project\x00name",
			wantErr: true,
		},
		{
			name:    "parent traversal prefix",
			path:    "../secret",
			wantErr: true,
		},
		{
			name:    "parent traversal middle",
			path:    "project/../secret",
			wantErr: true,
		},
		{
			name:    "remote URL",
			path:    "https://github.com/temporalio/deputy",
			wantErr: true,
		},
		{
			name:    "filesystem root",
			path:    "/",
			wantErr: true,
		},
		{
			name:    "sensitive system path exact",
			path:    "/etc",
			wantErr: true,
		},
		{
			name:    "sensitive system path child",
			path:    "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "sensitive usr tree",
			path:    "/usr/local/bin",
			wantErr: true,
		},
		{
			name:    "sensitive linux boot tree",
			path:    "/boot",
			wantErr: true,
		},
		{
			name:    "sensitive macos system tree",
			path:    "/System/Library",
			wantErr: true,
		},
		{
			name:    "sensitive macos applications tree",
			path:    "/Applications",
			wantErr: true,
		},
		{
			name:    "sensitive var database tree",
			path:    "/private/var/db",
			wantErr: true,
		},
		{
			name:    "sensitive macos private etc",
			path:    "/private/etc/hosts",
			wantErr: true,
		},
		{
			name:    "sensitive macos root home",
			path:    "/var/root/.ssh/config",
			wantErr: true,
		},
		{
			name:    "windows drive root",
			path:    `C:\`,
			wantErr: true,
		},
		{
			name:    "windows drive root with slash",
			path:    "C:/",
			wantErr: true,
		},
		{
			name:    "windows drive relative path",
			path:    "C:project",
			wantErr: true,
		},
		{
			name:    "windows system directory",
			path:    `C:\Windows\System32`,
			wantErr: true,
		},
		{
			name:    "windows program files directory",
			path:    "C:/Program Files/Deputy",
			wantErr: true,
		},
		{
			name:    "windows unc network path",
			path:    `\\server\share\project`,
			wantErr: true,
		},
		{
			name: "windows user project directory",
			path: `C:\Users\example\src\project`,
		},
		{
			name:    "windows user ssh directory",
			path:    `C:\Users\example\.ssh\config`,
			wantErr: true,
		},
		{
			name:    "relative ssh directory",
			path:    ".ssh/config",
			wantErr: true,
		},
		{
			name:    "nested aws directory",
			path:    "project/.aws/config",
			wantErr: true,
		},
		{
			name:    "absolute kube directory",
			path:    "/Users/example/.kube/config",
			wantErr: true,
		},
		{
			name:    "local share directory",
			path:    "project/.local/share/keyrings",
			wantErr: true,
		},
		{
			name:    "secrets component",
			path:    "project/secrets/token",
			wantErr: true,
		},
		{
			name: "configish is not config",
			path: "/tmp/project/.configish",
		},
		{
			name: "secretsauce is not secrets",
			path: "/tmp/project/secretsauce",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateLocalPath(tt.path)
			if tt.wantErr && err == nil {
				t.Fatal("expected error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNormalizeMCPEcosystems(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{name: "empty", want: nil},
		{name: "all", in: []string{"all"}, want: nil},
		{name: "aliases", in: []string{"golang", "Python", "go"}, want: []string{"go", "pypi"}},
		{name: "custom", in: []string{"github-actions"}, want: []string{"github-actions"}},
		{name: "github actions aliases", in: []string{"GitHub Actions", "github_actions", "gha"}, want: []string{"github-actions"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeMCPEcosystems(tt.in); !slicesEqual(got, tt.want) {
				t.Errorf("normalizeMCPEcosystems(%v) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

func TestMCPOutputEcosystem(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{in: "Go", want: "go"},
		{in: "GitHub Actions", want: "github-actions"},
		{in: "github_actions", want: "github-actions"},
		{in: "Cargo (crates.io)", want: "cargo"},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := mcpOutputEcosystem(tt.in); got != tt.want {
				t.Fatalf("mcpOutputEcosystem(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestNormalizeMCPExcludePaths(t *testing.T) {
	got := normalizeMCPExcludePaths(
		[]string{" .bin/** ", "", "\t", "**/testdata"},
		[]string{"**/testdata", "node_modules"},
	)
	want := []string{".bin/**", "**/testdata"}
	want = append(want, "node_modules")
	if !slicesEqual(got, want) {
		t.Fatalf("normalizeMCPExcludePaths = %v, want %v", got, want)
	}
	if got := normalizeMCPExcludePaths([]string{"", " "}); got != nil {
		t.Fatalf("blank exclude paths = %v, want nil", got)
	}
}

func TestDefaultExcludePathsApplyToMCPScans(t *testing.T) {
	mockScan := &mockScanHandler{scanResponse: emptyScanResponse()}
	s := NewServer(
		WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})),
		WithDefaultExcludePaths([]string{" .bin/** ", "", "**/testdata"}),
	)

	_, err := callProtoTool(t, context.Background(), s.scanDirectory, &mcpv1.ScanDirectoryRequest{
		Path:         "/test/path",
		ExcludePaths: []string{"**/testdata", "node_modules"},
	}, &mcpv1.ScanDirectoryResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(mockScan.requests) != 1 {
		t.Fatalf("expected 1 scan request, got %d", len(mockScan.requests))
	}
	got := mockScan.requests[0].Options.GetExcludePaths()
	want := []string{".bin/**", "**/testdata", "node_modules"}
	if !slicesEqual(got, want) {
		t.Fatalf("exclude paths = %v, want %v", got, want)
	}
}

func TestDiffGitRefsPreservesDirectness(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{
				Packages: []*dependencyv1.Package{
					{Name: "removed", Version: "1.0.0", Ecosystem: "go", Direct: true},
					{Name: "updated", Version: "1.0.0", Ecosystem: "go", Direct: false},
				},
				Stats: &vulnerabilityv1.Stats{},
			},
			{
				Packages: []*dependencyv1.Package{
					{Name: "updated", Version: "1.1.0", Ecosystem: "go", Direct: true},
					{Name: "added", Version: "1.0.0", Ecosystem: "go", Direct: true},
				},
				Stats: &vulnerabilityv1.Stats{},
			},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := s.diffGitRefs(context.Background(), &mcpv1.DiffRefsRequest{
		Path:         "/test/path",
		BaseRef:      "base",
		TargetRef:    "target",
		ExcludePaths: []string{".bin/**"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wantDirect := map[string]bool{
		"added":   true,
		"updated": true,
		"removed": true,
	}
	if len(result.Changes) != len(wantDirect) {
		t.Fatalf("expected %d changes, got %d: %v", len(wantDirect), len(result.Changes), result.Changes)
	}
	for _, change := range result.Changes {
		want, ok := wantDirect[change.Name]
		if !ok {
			t.Fatalf("unexpected change %q", change.Name)
		}
		if change.IsDirect != want {
			t.Errorf("%s isDirect = %v, want %v", change.Name, change.IsDirect, want)
		}
	}
	if len(mockScan.requests) != 2 {
		t.Fatalf("expected 2 scan requests, got %d", len(mockScan.requests))
	}
	for i, req := range mockScan.requests {
		if got, want := req.Options.GetExcludePaths(), []string{".bin/**"}; !slicesEqual(got, want) {
			t.Fatalf("scan request %d exclude paths = %v, want %v", i, got, want)
		}
	}
}

func TestDiffGitRefsNormalizesPath(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			emptyScanResponse(),
			emptyScanResponse(),
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := s.diffGitRefs(context.Background(), &mcpv1.DiffRefsRequest{
		Path:      " /test/path ",
		BaseRef:   " base ",
		TargetRef: "\ttarget ",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Path != "/test/path" {
		t.Fatalf("result path = %q, want /test/path", result.Path)
	}
	if result.BaseRef != "base" {
		t.Fatalf("result base ref = %q, want base", result.BaseRef)
	}
	if result.TargetRef != "target" {
		t.Fatalf("result target ref = %q, want target", result.TargetRef)
	}
	if len(mockScan.requests) != 2 {
		t.Fatalf("expected 2 scan requests, got %d", len(mockScan.requests))
	}
	for i, req := range mockScan.requests {
		if req.Target != "/test/path" {
			t.Fatalf("scan request %d target = %q, want /test/path", i, req.Target)
		}
	}
	if got := mockScan.requests[0].Options.GetRef(); got != "base" {
		t.Fatalf("base scan ref = %q, want base", got)
	}
	if got := mockScan.requests[1].Options.GetRef(); got != "target" {
		t.Fatalf("target scan ref = %q, want target", got)
	}
}

func TestDiffGitRefsUsesPURLIdentity(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{
				Packages: []*dependencyv1.Package{
					{Name: "core", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/%40scope-b/core@1.0.0", Direct: true},
					{Name: "core", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/%40scope-a/core@1.0.0", Direct: true},
				},
				Stats: &vulnerabilityv1.Stats{},
			},
			{
				Packages: []*dependencyv1.Package{
					{Name: "core", Version: "2.0.0", Ecosystem: "npm", Purl: "pkg:npm/%40scope-b/core@2.0.0", Direct: true},
					{Name: "core", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/%40scope-a/core@1.0.0", Direct: true},
				},
				Stats: &vulnerabilityv1.Stats{},
			},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := s.diffGitRefs(context.Background(), &mcpv1.DiffRefsRequest{
		Path:      "/test/path",
		BaseRef:   "base",
		TargetRef: "target",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.Changes) != 1 {
		t.Fatalf("expected 1 PURL-distinguished change, got %d: %v", len(result.Changes), result.Changes)
	}

	change := result.Changes[0]
	if change.ChangeType != "upgraded" {
		t.Fatalf("expected upgraded change, got %q", change.ChangeType)
	}
	if change.Purl != "pkg:npm/%40scope-b/core@2.0.0" {
		t.Fatalf("unexpected changed PURL: got %q", change.Purl)
	}
}

func TestDiffGitRefsDeduplicatesTargetVulnerabilities(t *testing.T) {
	vulnerablePkg := &dependencyv1.Package{
		Name:      "github.com/example/vulnerable",
		Version:   "v1.0.0",
		Ecosystem: "go",
		Purl:      "pkg:golang/github.com/example/vulnerable@v1.0.0",
		Direct:    true,
	}
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{
				Packages: []*dependencyv1.Package{},
				Stats:    &vulnerabilityv1.Stats{},
			},
			{
				PackagesScanned: 1,
				Packages:        []*dependencyv1.Package{vulnerablePkg},
				Findings: []*vulnerabilityv1.Finding{
					{AdvisoryId: "CVE-2024-1234", Package: vulnerablePkg, Affected: true},
					{AdvisoryId: "GHSA-abcd-efgh-ijkl", Package: vulnerablePkg, Affected: true},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2024-1234": {
						Id:       "CVE-2024-1234",
						Aliases:  []string{"GHSA-abcd-efgh-ijkl"},
						Summary:  "Test vulnerability",
						Severity: vulnerability.NewSeverity("CRITICAL", ""),
					},
					"GHSA-abcd-efgh-ijkl": {
						Id:       "GHSA-abcd-efgh-ijkl",
						Aliases:  []string{"CVE-2024-1234"},
						Summary:  "Same test vulnerability",
						Severity: vulnerability.NewSeverity("CRITICAL", ""),
					},
				},
				Stats: &vulnerabilityv1.Stats{Unique: 2, Critical: 2},
			},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := s.diffGitRefs(context.Background(), &mcpv1.DiffRefsRequest{
		Path:      "/test/path",
		BaseRef:   "base",
		TargetRef: "target",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.VulnerabilitySummary["critical"] != 1 {
		t.Fatalf("expected 1 consolidated critical vulnerability, got %d", result.VulnerabilitySummary["critical"])
	}
	if len(result.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 consolidated vulnerability, got %d", len(result.Vulnerabilities))
	}
	if got := result.Vulnerabilities[0].Id; got != "CVE-2024-1234" {
		t.Fatalf("expected CVE primary ID, got %q", got)
	}
}

func TestDiffRefsRoutesLocalhostRegistryAsContainer(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{Stats: &vulnerabilityv1.Stats{}},
			{Stats: &vulnerabilityv1.Stats{}},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := callProtoTool(t, context.Background(), s.diffRefs, &mcpv1.DiffRefsRequest{
		BaseRef:   " localhost:5000/app:v1 ",
		TargetRef: "\tlocalhost:5000/app:v2",
	}, &mcpv1.DiffRefsResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.IsContainerDiff {
		t.Fatalf("expected container diff")
	}
	if got, want := result.BaseRef, "localhost:5000/app:v1"; got != want {
		t.Fatalf("base ref = %q, want %q", got, want)
	}
	if got, want := result.TargetRef, "localhost:5000/app:v2"; got != want {
		t.Fatalf("target ref = %q, want %q", got, want)
	}
	if got, want := len(mockScan.requests), 2; got != want {
		t.Fatalf("scan requests = %d, want %d", got, want)
	}
	if got, want := mockScan.requests[0].Target, "localhost:5000/app:v1"; got != want {
		t.Fatalf("base scan target = %q, want %q", got, want)
	}
	if got, want := mockScan.requests[1].Target, "localhost:5000/app:v2"; got != want {
		t.Fatalf("target scan target = %q, want %q", got, want)
	}
}

func TestDiffRefsValidationRequiresRefs(t *testing.T) {
	s := NewServer(WithClients(newMockClients(mockClientsConfig{})))

	// In production the SDK rejects these against the input schema using JSON
	// property names; protovalidate guards direct invocations and names the
	// proto fields.
	_, err := callProtoTool(t, context.Background(), s.diffRefs, &mcpv1.DiffRefsRequest{
		TargetRef: "main",
	}, &mcpv1.DiffRefsResult{})
	if err == nil {
		t.Fatal("expected missing baseRef error")
	}
	if !strings.Contains(err.Error(), "base_ref") {
		t.Fatalf("missing baseRef error = %q", err)
	}

	_, err = callProtoTool(t, context.Background(), s.diffRefs, &mcpv1.DiffRefsRequest{
		BaseRef: "main",
	}, &mcpv1.DiffRefsResult{})
	if err == nil {
		t.Fatal("expected missing targetRef error")
	}
	if !strings.Contains(err.Error(), "target_ref") {
		t.Fatalf("missing targetRef error = %q", err)
	}
}

func TestDiffRefsPathlessCommonGitRefsRequirePath(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{Stats: &vulnerabilityv1.Stats{}},
			{Stats: &vulnerabilityv1.Stats{}},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	_, err := callProtoTool(t, context.Background(), s.diffRefs, &mcpv1.DiffRefsRequest{
		BaseRef:   "main",
		TargetRef: "develop",
	}, &mcpv1.DiffRefsResult{})
	if err == nil {
		t.Fatal("expected missing path error")
	}
	if !strings.Contains(err.Error(), "path is required for Git ref comparison") {
		t.Fatalf("error = %q, want Git path guidance", err)
	}
	if len(mockScan.requests) != 0 {
		t.Fatalf("scan requests = %d, want 0", len(mockScan.requests))
	}
}

func TestDiffRefsRejectsMixedContainerAndGitRefs(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{Stats: &vulnerabilityv1.Stats{}},
			{Stats: &vulnerabilityv1.Stats{}},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	tests := []*mcpv1.DiffRefsRequest{
		{BaseRef: "docker://nginx:1.25", TargetRef: "main"},
		{BaseRef: "nginx:1.25", TargetRef: "main"},
		{Path: "/repo", BaseRef: "ghcr.io/owner/app:v1", TargetRef: "main"},
	}
	for _, tt := range tests {
		t.Run(tt.GetBaseRef()+" to "+tt.GetTargetRef(), func(t *testing.T) {
			_, err := callProtoTool(t, context.Background(), s.diffRefs, tt, &mcpv1.DiffRefsResult{})
			if err == nil {
				t.Fatal("expected mixed ref error")
			}
			if !strings.Contains(err.Error(), "must both be Git refs or both be container image refs") {
				t.Fatalf("error = %q, want mixed ref guidance", err)
			}
			if len(mockScan.requests) != 0 {
				t.Fatalf("scan requests = %d, want 0", len(mockScan.requests))
			}
		})
	}
}

func TestDiffContainerImagesReportsDeduplicatedVulnerabilityChanges(t *testing.T) {
	const (
		pkgName    = "github.com/example/vulnerable"
		basePURL   = "pkg:golang/github.com/example/vulnerable@v1.0.0"
		targetPURL = "pkg:golang/github.com/example/vulnerable@v1.0.1"
	)
	basePkg := &dependencyv1.Package{Name: pkgName, Version: "v1.0.0", Ecosystem: "go", Purl: basePURL}
	targetPkg := &dependencyv1.Package{Name: pkgName, Version: "v1.0.1", Ecosystem: "go", Purl: targetPURL}
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{
				PackagesScanned: 1,
				Packages:        []*dependencyv1.Package{basePkg},
				Findings: []*vulnerabilityv1.Finding{
					{AdvisoryId: "GO-2024-0001", Package: basePkg, Affected: true},
					{AdvisoryId: "GHSA-abcd-efgh-ijkl", Package: basePkg, Affected: true},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"GO-2024-0001": {
						Id:       "GO-2024-0001",
						Aliases:  []string{"GHSA-abcd-efgh-ijkl", "CVE-2024-1234"},
						Summary:  "Test vulnerability",
						Severity: vulnerability.NewSeverity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CVSS_V3"),
					},
					"GHSA-abcd-efgh-ijkl": {
						Id:       "GHSA-abcd-efgh-ijkl",
						Aliases:  []string{"GO-2024-0001", "CVE-2024-1234"},
						Summary:  "Same test vulnerability",
						Severity: vulnerability.NewSeverity("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "CVSS_V3"),
					},
				},
				Stats: &vulnerabilityv1.Stats{Unique: 2, Critical: 2},
			},
			{
				PackagesScanned: 1,
				Packages:        []*dependencyv1.Package{targetPkg},
				Advisories:      map[string]*vulnerabilityv1.Advisory{},
				Stats:           &vulnerabilityv1.Stats{},
			},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := s.diffContainerImages(context.Background(), &mcpv1.DiffRefsRequest{
		BaseRef:   "example/app:v1",
		TargetRef: "example/app:v2",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Path != "" {
		t.Fatalf("container diff path = %q, want empty because image diffs do not have a local path", result.Path)
	}
	if got, want := len(result.VulnerabilityChanges), 1; got != want {
		t.Fatalf("vulnerability changes = %d, want %d: %#v", got, want, result.VulnerabilityChanges)
	}
	change := result.VulnerabilityChanges[0]
	if got, want := change.GetId(), "CVE-2024-1234"; got != want {
		t.Fatalf("change ID = %q, want %q", got, want)
	}
	if got, want := change.ChangeType, "fixed"; got != want {
		t.Fatalf("change type = %q, want %q", got, want)
	}
	if got, want := change.Severity, "CRITICAL"; got != want {
		t.Fatalf("change severity = %q, want %q", got, want)
	}
	if got, want := change.BaseVersion, "v1.0.0"; got != want {
		t.Fatalf("base version = %q, want %q", got, want)
	}
	if got, want := change.TargetVersion, "v1.0.1"; got != want {
		t.Fatalf("target version = %q, want %q", got, want)
	}
	if result.ContainerSummary == nil {
		t.Fatal("expected container summary")
	}
	if got, want := int(result.ContainerSummary.GetVulnerabilitiesFixed()), 1; got != want {
		t.Fatalf("vulnerabilities fixed = %d, want %d", got, want)
	}
}

func TestDiffContainerImagesNormalizesAndForwardsPlatform(t *testing.T) {
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			emptyScanResponse(),
			emptyScanResponse(),
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := s.diffContainerImages(context.Background(), &mcpv1.DiffRefsRequest{
		BaseRef:   " example/app:v1 ",
		TargetRef: " example/app:v2 ",
		Platform:  " linux/amd64\t",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.BaseRef != "example/app:v1" {
		t.Fatalf("baseRef = %q, want example/app:v1", result.BaseRef)
	}
	if result.TargetRef != "example/app:v2" {
		t.Fatalf("targetRef = %q, want example/app:v2", result.TargetRef)
	}
	if result.Platform != "linux/amd64" {
		t.Fatalf("platform = %q, want linux/amd64", result.Platform)
	}
	if len(mockScan.requests) != 2 {
		t.Fatalf("scan requests = %d, want 2", len(mockScan.requests))
	}
	for i, req := range mockScan.requests {
		if got := req.Options.GetPlatform(); got != "linux/amd64" {
			t.Fatalf("scan request %d platform = %q, want linux/amd64", i, got)
		}
	}
}

func TestDiffRefsPrefersGitRefsInRepositoryContext(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	mockScan := &mockScanHandler{
		scanResponses: []*scanv1.ScanResponse{
			{Stats: &vulnerabilityv1.Stats{}},
			{Stats: &vulnerabilityv1.Stats{}},
		},
	}
	s := NewServer(WithClients(newMockClients(mockClientsConfig{scanHandler: mockScan})))

	result, err := callProtoTool(t, context.Background(), s.diffRefs, &mcpv1.DiffRefsRequest{
		Path:      repo,
		BaseRef:   "main",
		TargetRef: "develop",
	}, &mcpv1.DiffRefsResult{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IsContainerDiff {
		t.Fatalf("expected Git ref diff")
	}
	if got, want := len(mockScan.requests), 2; got != want {
		t.Fatalf("scan requests = %d, want %d", got, want)
	}
	if got, want := mockScan.requests[0].Target, repo; got != want {
		t.Fatalf("base scan target = %q, want %q", got, want)
	}
	if got, want := mockScan.requests[0].Options.GetRef(), "main"; got != want {
		t.Fatalf("base ref = %q, want %q", got, want)
	}
	if got, want := mockScan.requests[1].Options.GetRef(), "develop"; got != want {
		t.Fatalf("target ref = %q, want %q", got, want)
	}
}

func TestSortDependencyChangesStableAgentOrder(t *testing.T) {
	changes := []*mcpv1.DependencyChange{
		{Name: "zeta", Ecosystem: "npm", Purl: "pkg:npm/zeta@1.0.0", ChangeType: "added"},
		{Name: "bravo", Ecosystem: "go", Purl: "pkg:golang/example.com/bravo@v1.0.0", ChangeType: "removed", IsDirect: true},
		{Name: "alpha", Ecosystem: "go", Purl: "pkg:golang/example.com/alpha@v1.1.0", ChangeType: "upgraded"},
		{Name: "alpha", Ecosystem: "go", Purl: "pkg:golang/example.com/alpha@v1.0.0", ChangeType: "added", IsDirect: true},
		{Name: "charlie", Ecosystem: "go", Purl: "pkg:golang/example.com/charlie@v1.0.0", ChangeType: "downgraded", IsDirect: true},
	}

	sortDependencyChanges(changes)

	want := []string{
		"alpha:added:true",
		"bravo:removed:true",
		"charlie:downgraded:true",
		"zeta:added:false",
		"alpha:upgraded:false",
	}
	for i, want := range want {
		got := fmt.Sprintf("%s:%s:%t", changes[i].Name, changes[i].ChangeType, changes[i].IsDirect)
		if got != want {
			t.Fatalf("change %d = %s, want %s; full order: %+v", i, got, want, changes)
		}
	}
}

func TestIsContainerImageRef(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{ref: "nginx:1.25", want: true},
		{ref: "nginx", want: true},
		{ref: "docker://nginx:1.25", want: true},
		{ref: "oci://nginx:1.25", want: true},
		{ref: "ghcr.io/owner/app:v1", want: true},
		{ref: "localhost:5000/app:dev", want: true},
		{ref: "owner/repo:v1.0", want: true},
		{ref: "pkg:npm/lodash@1.0.0", want: false},
		{ref: "github.com/owner/repo", want: false},
		{ref: "origin/main", want: false},
		{ref: "main", want: false},
		{ref: "develop", want: false},
		{ref: "refs/heads/main", want: false},
		{ref: "docker://main", want: true},
		{ref: "HEAD", want: false},
		{ref: "./relative/path", want: false},
		{ref: "/absolute/path", want: false},
		{ref: "git@github.com:owner/repo.git", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			if got := isContainerImageRef(tt.ref); got != tt.want {
				t.Fatalf("isContainerImageRef(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestCompareVersionsUsesSemverOrdering(t *testing.T) {
	if got := compareVersions("1.9.0", "1.10.0"); got >= 0 {
		t.Fatalf("compareVersions(1.9.0, 1.10.0) = %d, want < 0", got)
	}
	if got := compareVersions("v2.0.0", "v1.10.0"); got <= 0 {
		t.Fatalf("compareVersions(v2.0.0, v1.10.0) = %d, want > 0", got)
	}
}

func TestMCPGraphStatsPreservesDisconnectedAndImportStatus(t *testing.T) {
	stats := mcpGraphStats(&graphv1.GraphStats{
		TotalNodes:        5,
		DirectNodes:       1,
		TransitiveNodes:   3,
		MaxDepth:          999,
		MaxConnectedDepth: 2,
		DisconnectedNodes: 1,
		VulnerableNodes:   2,
		Ecosystems: map[string]int32{
			"Go": 4,
		},
		ImportStatusCounts: &graphv1.ImportStatusCounts{
			Imported: 2,
			Required: 2,
			Declared: 1,
		},
	})

	if stats.MaxDepth != 999 {
		t.Fatalf("MaxDepth = %d, want 999", stats.MaxDepth)
	}
	if stats.MaxConnectedDepth != 2 {
		t.Fatalf("MaxConnectedDepth = %d, want 2", stats.MaxConnectedDepth)
	}
	if stats.DisconnectedNodes != 1 {
		t.Fatalf("DisconnectedNodes = %d, want 1", stats.DisconnectedNodes)
	}
	if stats.Ecosystems["go"] != 4 {
		t.Fatalf("ecosystem stats = %v, want go:4", stats.Ecosystems)
	}
	if stats.ImportStatusCounts == nil {
		t.Fatal("expected import status counts")
	}
	if stats.ImportStatusCounts.Imported != 2 || stats.ImportStatusCounts.Required != 2 || stats.ImportStatusCounts.Declared != 1 {
		t.Fatalf("unexpected import status counts: %+v", stats.ImportStatusCounts)
	}
}

func TestPathToStrings(t *testing.T) {
	t.Run("empty path", func(t *testing.T) {
		result := pathToStrings(nil)
		if len(result) != 0 {
			t.Errorf("expected empty slice, got %v", result)
		}
	})

	t.Run("omits trailing at for unknown version", func(t *testing.T) {
		result := pathToStrings(graph.Path{{Name: "project"}})
		if len(result) != 1 || result[0] != "project" {
			t.Fatalf("pathToStrings = %v, want [project]", result)
		}
	})
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
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

	result, err := callProtoTool(t, ctx, s.scanDirectory, &mcpv1.ScanDirectoryRequest{Path: tmpDir}, &mcpv1.ScanDirectoryResult{})
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

	result, err := callProtoTool(t, ctx, s.listDependencies, &mcpv1.ListDependenciesRequest{Path: tmpDir}, &mcpv1.ListDependenciesResult{})
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
		if resp["processId"] == nil {
			t.Fatal("expected processId in info response")
		}
		if resp["startedAt"] == "" {
			t.Fatal("expected startedAt in info response")
		}
		if resp["toolCount"] != float64(15) {
			t.Errorf("expected toolCount 15, got %v", resp["toolCount"])
		}

		tools, ok := resp["tools"].([]any)
		if !ok {
			t.Fatal("expected tools to be a slice")
		}
		if len(tools) != 15 {
			t.Errorf("expected 15 tools, got %d", len(tools))
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
		"get_server_info",
		"list_policy_entrypoints",
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

func TestGetServerInfo(t *testing.T) {
	s := NewServer(WithDefaultExcludePaths([]string{".bin/**"}))

	info, err := callProtoTool(t, t.Context(), s.getServerInfo, &mcpv1.GetServerInfoRequest{}, &mcpv1.GetServerInfoResult{})
	if err != nil {
		t.Fatalf("getServerInfo failed: %v", err)
	}
	if info.GetName() != "deputy" {
		t.Fatalf("Name = %q, want deputy", info.GetName())
	}
	if info.GetVersion() == "" {
		t.Fatal("expected Version")
	}
	if info.GetProtocol() != "mcp" {
		t.Fatalf("Protocol = %q, want mcp", info.GetProtocol())
	}
	if info.GetTransport() != "" {
		t.Fatalf("Transport = %q, want empty for transport-neutral tool response", info.GetTransport())
	}
	if int(info.GetProcessId()) != os.Getpid() {
		t.Fatalf("ProcessId = %d, want %d", info.GetProcessId(), os.Getpid())
	}
	if info.GetStartedAt() == "" {
		t.Fatal("expected StartedAt")
	}
	if int(info.GetToolCount()) != len(info.GetTools()) {
		t.Fatalf("ToolCount = %d, len(Tools) = %d", info.GetToolCount(), len(info.GetTools()))
	}
	if !slices.Contains(info.GetTools(), "get_server_info") {
		t.Fatalf("tools = %v, want get_server_info", info.GetTools())
	}
	if !slices.Equal(info.GetDefaultExcludePaths(), []string{".bin/**"}) {
		t.Fatalf("DefaultExcludePaths = %v, want .bin/**", info.GetDefaultExcludePaths())
	}
}
