package graph

import (
	"testing"
)

func TestParseGoModGraphOutput(t *testing.T) {
	// Sample output from `go mod graph`
	output := `example.com/myapp golang.org/x/text@v0.3.7
example.com/myapp github.com/pkg/errors@v0.9.1
golang.org/x/text@v0.3.7 golang.org/x/tools@v0.1.0
golang.org/x/text@v0.3.7 golang.org/x/tools@v0.0.9
github.com/pkg/errors@v0.9.1 golang.org/x/net@v0.0.0-20210405180319-a5a99cb37ef4
`
	graph, err := ParseGoModGraphOutput(output)
	if err != nil {
		t.Fatalf("ParseGoModGraphOutput failed: %v", err)
	}

	// Check main module detection
	if graph.MainModule != "example.com/myapp" {
		t.Errorf("expected main module 'example.com/myapp', got '%s'", graph.MainModule)
	}

	// Check edge count
	if len(graph.Edges) != 5 {
		t.Errorf("expected 5 edges, got %d", len(graph.Edges))
	}

	// Check that we captured the multiple versions of golang.org/x/tools
	toolsVersions := graph.Modules["golang.org/x/tools"]
	if len(toolsVersions) != 2 {
		t.Errorf("expected 2 versions of golang.org/x/tools, got %d: %v", len(toolsVersions), toolsVersions)
	}

	// Check first edge
	edge := graph.Edges[0]
	if edge.FromModule != "example.com/myapp" || edge.FromVersion != "" {
		t.Errorf("first edge from should be main module without version, got %s@%s", edge.FromModule, edge.FromVersion)
	}
	if edge.ToModule != "golang.org/x/text" || edge.ToVersion != "v0.3.7" {
		t.Errorf("first edge to should be golang.org/x/text@v0.3.7, got %s@%s", edge.ToModule, edge.ToVersion)
	}
}

func TestParseGoListMAll(t *testing.T) {
	output := `example.com/myapp
golang.org/x/text v0.3.7
github.com/pkg/errors v0.9.1
golang.org/x/tools v0.1.0
`
	modules := ParseGoListMAll(output)

	// Check main module (no version)
	if ver, ok := modules["example.com/myapp"]; !ok || ver != "" {
		t.Errorf("main module should have empty version, got: %q", ver)
	}

	// Check a versioned module
	if ver := modules["golang.org/x/text"]; ver != "v0.3.7" {
		t.Errorf("expected golang.org/x/text v0.3.7, got %s", ver)
	}

	// Check that tools is v0.1.0 (MVS selected version, not v0.0.9)
	if ver := modules["golang.org/x/tools"]; ver != "v0.1.0" {
		t.Errorf("expected golang.org/x/tools v0.1.0 (MVS selected), got %s", ver)
	}
}

func TestParseModuleVersion(t *testing.T) {
	tests := []struct {
		input   string
		wantMod string
		wantVer string
	}{
		{"example.com/myapp", "example.com/myapp", ""},
		{"golang.org/x/text@v0.3.7", "golang.org/x/text", "v0.3.7"},
		{"github.com/user/repo@v1.2.3-beta.1", "github.com/user/repo", "v1.2.3-beta.1"},
		{"example.com/pkg@v0.0.0-20210405180319-a5a99cb37ef4", "example.com/pkg", "v0.0.0-20210405180319-a5a99cb37ef4"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			gotMod, gotVer := parseModuleVersion(tt.input)
			if gotMod != tt.wantMod || gotVer != tt.wantVer {
				t.Errorf("parseModuleVersion(%q) = (%q, %q), want (%q, %q)",
					tt.input, gotMod, gotVer, tt.wantMod, tt.wantVer)
			}
		})
	}
}

func TestImportStatusConstants(t *testing.T) {
	// Verify the constants match proto values
	if ImportStatusUnspecified != 0 {
		t.Errorf("ImportStatusUnspecified should be 0, got %d", ImportStatusUnspecified)
	}
	if ImportStatusImported != 1 {
		t.Errorf("ImportStatusImported should be 1, got %d", ImportStatusImported)
	}
	if ImportStatusRequired != 2 {
		t.Errorf("ImportStatusRequired should be 2, got %d", ImportStatusRequired)
	}
	if ImportStatusDeclared != 3 {
		t.Errorf("ImportStatusDeclared should be 3, got %d", ImportStatusDeclared)
	}
}

func TestFilterByImportStatus(t *testing.T) {
	g := New()

	// Add nodes with different import statuses
	imported := &Node{Purl: "pkg:golang/imported@1.0", Name: "imported", ImportStatus: ImportStatusImported}
	required := &Node{Purl: "pkg:golang/required@1.0", Name: "required", ImportStatus: ImportStatusRequired}
	declared := &Node{Purl: "pkg:golang/declared@1.0", Name: "declared", ImportStatus: ImportStatusDeclared}

	g.AddNode(imported)
	g.AddNode(required)
	g.AddNode(declared)

	// Filter to only imported
	filtered := g.FilterByImportStatus(ImportStatusImported)
	count := 0
	for range filtered.Nodes() {
		count++
	}
	if count != 1 {
		t.Errorf("expected 1 imported node, got %d", count)
	}

	// Filter to imported + required
	filtered = g.FilterByImportStatus(ImportStatusImported, ImportStatusRequired)
	count = 0
	for range filtered.Nodes() {
		count++
	}
	if count != 2 {
		t.Errorf("expected 2 nodes (imported + required), got %d", count)
	}
}

func TestCountImportStatuses(t *testing.T) {
	g := New()

	// Add nodes with different import statuses
	g.AddNode(&Node{Purl: "pkg:golang/imp1@1.0", ImportStatus: ImportStatusImported})
	g.AddNode(&Node{Purl: "pkg:golang/imp2@1.0", ImportStatus: ImportStatusImported})
	g.AddNode(&Node{Purl: "pkg:golang/req1@1.0", ImportStatus: ImportStatusRequired})
	g.AddNode(&Node{Purl: "pkg:golang/decl1@1.0", ImportStatus: ImportStatusDeclared})
	g.AddNode(&Node{Purl: "pkg:golang/decl2@1.0", ImportStatus: ImportStatusDeclared})
	g.AddNode(&Node{Purl: "pkg:golang/decl3@1.0", ImportStatus: ImportStatusDeclared})

	counts := g.CountImportStatuses()

	if counts.Imported != 2 {
		t.Errorf("expected 2 imported, got %d", counts.Imported)
	}
	if counts.Required != 1 {
		t.Errorf("expected 1 required, got %d", counts.Required)
	}
	if counts.Declared != 3 {
		t.Errorf("expected 3 declared, got %d", counts.Declared)
	}
}

func TestParseGoSum(t *testing.T) {
	// Sample go.sum content
	goSum := `github.com/pkg/errors v0.9.1 h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=
github.com/pkg/errors v0.9.1/go.mod h1:bwawxfHBFNV+L2hUp1rHADufV3IMtnDRdf1r5NINEl0=
golang.org/x/text v0.3.7 h1:olpwvP2KacW1ZWvsR7uQhoyTYvKAupfQrRGBFM352Gk=
golang.org/x/text v0.3.7/go.mod h1:u+2+/6zg+i71rQMx5EYifcz6MCKuco9NR6JIITiCfzQ=
golang.org/x/tools v0.1.0 h1:D9Dp5/pEjUn6pRQWaOLI0vn35mAOlC4ESTHcSqPc2Lg=
golang.org/x/tools v0.1.0/go.mod h1:xkSsbof2nBLbhDlRMhhhyNLN/zl3eTqcnHD5viDpcZ0=
golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4 h1:4nGaVu0QrbjT/AK2PRLuQfQuh6DJve+pELhqTdAj3x0=
golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4/go.mod h1:p54w0d4576C0XHj96bSt6lcn1PtDYWL6XObtHCRCNQM=
`
	modules := ParseGoSum(goSum)

	// Check that we parsed the correct number of modules
	if len(modules) != 4 {
		t.Errorf("expected 4 modules, got %d", len(modules))
	}

	// Check specific versions
	if ver := modules["github.com/pkg/errors"]; ver != "v0.9.1" {
		t.Errorf("expected github.com/pkg/errors v0.9.1, got %s", ver)
	}

	if ver := modules["golang.org/x/text"]; ver != "v0.3.7" {
		t.Errorf("expected golang.org/x/text v0.3.7, got %s", ver)
	}

	if ver := modules["golang.org/x/tools"]; ver != "v0.1.0" {
		t.Errorf("expected golang.org/x/tools v0.1.0, got %s", ver)
	}

	// Check pseudo-version
	if ver := modules["golang.org/x/net"]; ver != "v0.0.0-20210405180319-a5a99cb37ef4" {
		t.Errorf("expected golang.org/x/net v0.0.0-20210405180319-a5a99cb37ef4, got %s", ver)
	}
}

func TestParseGoSum_EmptyContent(t *testing.T) {
	modules := ParseGoSum("")
	if len(modules) != 0 {
		t.Errorf("expected 0 modules for empty content, got %d", len(modules))
	}
}

func TestParseGoSum_MultipleVersions(t *testing.T) {
	// When go.sum has multiple versions for the same module, we keep the highest
	goSum := `example.com/foo v1.0.0 h1:hash1=
example.com/foo v1.0.0/go.mod h1:hash2=
example.com/foo v1.2.0 h1:hash3=
example.com/foo v1.2.0/go.mod h1:hash4=
example.com/foo v1.1.0 h1:hash5=
example.com/foo v1.1.0/go.mod h1:hash6=
`
	modules := ParseGoSum(goSum)

	// Should have only one entry for example.com/foo
	if len(modules) != 1 {
		t.Errorf("expected 1 module, got %d", len(modules))
	}

	// Should be the highest version
	if ver := modules["example.com/foo"]; ver != "v1.2.0" {
		t.Errorf("expected v1.2.0 (highest), got %s", ver)
	}
}

func TestMergeExtendedIntoGraph(t *testing.T) {
	// Create a base graph with some existing Go modules
	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:golang/github.com/existing/pkg@1.0.0",
		Name:      "github.com/existing/pkg",
		Version:   "1.0.0",
		Ecosystem: "Go",
		Direct:    true,
		Depth:     0,
	})
	g.AddNode(&Node{
		Purl:      "pkg:golang/github.com/existing/dep@2.0.0",
		Name:      "github.com/existing/dep",
		Version:   "2.0.0",
		Ecosystem: "Go",
		Direct:    false,
		Depth:     1,
	})

	// Create extended graph result with declared-only modules
	extended := &ExtendedGraphResult{
		FullGraph: &ModGraph{
			MainModule: "example.com/myapp",
			Edges: []ModGraphEdge{
				{FromModule: "example.com/myapp", FromVersion: "", ToModule: "github.com/phantom/pkg", ToVersion: "v1.0.0"},
				{FromModule: "github.com/phantom/pkg", FromVersion: "v1.0.0", ToModule: "github.com/phantom/dep", ToVersion: "v2.0.0"},
			},
			Modules: map[string][]string{
				"github.com/phantom/pkg": {"v1.0.0"},
				"github.com/phantom/dep": {"v2.0.0"},
			},
		},
		SelectedModules: map[string]string{
			"github.com/existing/pkg": "1.0.0",
			"github.com/existing/dep": "2.0.0",
		},
		DeclaredOnlyModules: map[string][]string{
			"github.com/phantom/pkg": {"v1.0.0"},
			"github.com/phantom/dep": {"v2.0.0"},
		},
	}

	MergeExtendedIntoGraph(g, extended)

	// Verify existing nodes got REQUIRED status
	existingNode := g.Node("pkg:golang/github.com/existing/pkg@1.0.0")
	if existingNode == nil {
		t.Fatal("existing node should still exist")
	}
	if existingNode.ImportStatus != ImportStatusRequired {
		t.Errorf("existing Go node should have REQUIRED status, got %v", existingNode.ImportStatus)
	}

	// Verify phantom nodes were added with DECLARED status
	phantomNode := g.Node("pkg:golang/github.com/phantom/pkg@1.0.0")
	if phantomNode == nil {
		t.Fatal("phantom node should be added")
	}
	if phantomNode.ImportStatus != ImportStatusDeclared {
		t.Errorf("phantom node should have DECLARED status, got %v", phantomNode.ImportStatus)
	}
	if phantomNode.Depth != DepthDisconnected {
		t.Errorf("phantom node should have DepthDisconnected, got %d", phantomNode.Depth)
	}

	// Verify edges were added between declared nodes
	edgeCount := 0
	for range g.Edges() {
		edgeCount++
	}
	if edgeCount == 0 {
		t.Error("expected some edges to be added for declared modules")
	}
}

func TestMergeExtendedIntoGraph_NilInputs(t *testing.T) {
	g := New()
	g.AddNode(&Node{Purl: "pkg:golang/test@1.0", Name: "test"})

	// Should not panic with nil extended
	MergeExtendedIntoGraph(g, nil)

	// Should not panic with nil FullGraph
	MergeExtendedIntoGraph(g, &ExtendedGraphResult{})

	// Graph should be unchanged
	if g.Size() != 1 {
		t.Errorf("graph should still have 1 node, got %d", g.Size())
	}
}

func TestMergeExtendedIntoGraph_EdgeDeduplication(t *testing.T) {
	g := New()

	// Add nodes that will be connected
	g.AddNode(&Node{
		Purl:         "pkg:golang/from@1.0.0",
		Name:         "from",
		Ecosystem:    "Go",
		ImportStatus: ImportStatusDeclared,
	})
	g.AddNode(&Node{
		Purl:         "pkg:golang/to@1.0.0",
		Name:         "to",
		Ecosystem:    "Go",
		ImportStatus: ImportStatusDeclared,
	})

	// Add an existing edge
	g.AddEdge(&Edge{From: "pkg:golang/from@1.0.0", To: "pkg:golang/to@1.0.0"})

	// Create extended result that would create the same edge
	extended := &ExtendedGraphResult{
		FullGraph: &ModGraph{
			Edges: []ModGraphEdge{
				{FromModule: "from", FromVersion: "v1.0.0", ToModule: "to", ToVersion: "v1.0.0"},
				{FromModule: "from", FromVersion: "v1.0.0", ToModule: "to", ToVersion: "v1.0.0"}, // Duplicate
			},
			Modules: map[string][]string{},
		},
		DeclaredOnlyModules: map[string][]string{},
	}

	initialEdgeCount := 0
	for range g.Edges() {
		initialEdgeCount++
	}

	MergeExtendedIntoGraph(g, extended)

	finalEdgeCount := 0
	for range g.Edges() {
		finalEdgeCount++
	}

	// Edge count should not increase due to deduplication
	if finalEdgeCount != initialEdgeCount {
		t.Errorf("edge count should stay at %d, got %d (duplicates were added)", initialEdgeCount, finalEdgeCount)
	}
}

func TestDeclaredOnlyNodes(t *testing.T) {
	g := New()

	// Add nodes with different statuses
	g.AddNode(&Node{Purl: "pkg:golang/imported@1.0", ImportStatus: ImportStatusImported})
	g.AddNode(&Node{Purl: "pkg:golang/required@1.0", ImportStatus: ImportStatusRequired})
	g.AddNode(&Node{Purl: "pkg:golang/declared1@1.0", ImportStatus: ImportStatusDeclared})
	g.AddNode(&Node{Purl: "pkg:golang/declared2@1.0", ImportStatus: ImportStatusDeclared})

	count := 0
	for range g.DeclaredOnlyNodes() {
		count++
	}

	if count != 2 {
		t.Errorf("expected 2 declared-only nodes, got %d", count)
	}
}

func TestRequiredOnlyNodes(t *testing.T) {
	g := New()

	// Add nodes with different statuses
	g.AddNode(&Node{Purl: "pkg:golang/imported@1.0", ImportStatus: ImportStatusImported})
	g.AddNode(&Node{Purl: "pkg:golang/required1@1.0", ImportStatus: ImportStatusRequired})
	g.AddNode(&Node{Purl: "pkg:golang/required2@1.0", ImportStatus: ImportStatusRequired})
	g.AddNode(&Node{Purl: "pkg:golang/required3@1.0", ImportStatus: ImportStatusRequired})
	g.AddNode(&Node{Purl: "pkg:golang/declared@1.0", ImportStatus: ImportStatusDeclared})

	count := 0
	for range g.RequiredOnlyNodes() {
		count++
	}

	if count != 3 {
		t.Errorf("expected 3 required-only nodes, got %d", count)
	}
}

func TestParseGoModGraphOutput_EmptyInput(t *testing.T) {
	graph, err := ParseGoModGraphOutput("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if graph.MainModule != "" {
		t.Errorf("expected empty main module, got %q", graph.MainModule)
	}
	if len(graph.Edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(graph.Edges))
	}
}

func TestParseGoModGraphOutput_MalformedLines(t *testing.T) {
	// Should skip malformed lines gracefully
	output := `example.com/myapp golang.org/x/text@v0.3.7
malformed line with too many parts extra
single-part-line
example.com/myapp github.com/pkg/errors@v0.9.1
`
	graph, err := ParseGoModGraphOutput(output)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should only have 2 valid edges
	if len(graph.Edges) != 2 {
		t.Errorf("expected 2 edges (skipping malformed), got %d", len(graph.Edges))
	}
}

func TestEdgeKey(t *testing.T) {
	// Test that edge keys are unique and don't collide
	key1 := edgeKey("pkg:golang/a@1.0", "pkg:golang/b@1.0")
	key2 := edgeKey("pkg:golang/a@1.0", "pkg:golang/c@1.0")
	key3 := edgeKey("pkg:golang/b@1.0", "pkg:golang/a@1.0") // Reverse direction

	if key1 == key2 {
		t.Error("different edges should have different keys")
	}
	if key1 == key3 {
		t.Error("reverse direction should have different key")
	}

	// Same edge should have same key
	key1dup := edgeKey("pkg:golang/a@1.0", "pkg:golang/b@1.0")
	if key1 != key1dup {
		t.Error("same edge should have same key")
	}
}

func TestFilterByImportStatus_Empty(t *testing.T) {
	g := New()
	g.AddNode(&Node{Purl: "pkg:golang/test@1.0", ImportStatus: ImportStatusImported})

	// Filter with no statuses should return empty graph
	filtered := g.FilterByImportStatus()
	if filtered.Size() != 0 {
		t.Errorf("filtering with no statuses should return empty graph, got %d nodes", filtered.Size())
	}
}

func TestFilterByImportStatus_PreservesEdges(t *testing.T) {
	g := New()
	g.AddNode(&Node{Purl: "pkg:golang/a@1.0", ImportStatus: ImportStatusRequired})
	g.AddNode(&Node{Purl: "pkg:golang/b@1.0", ImportStatus: ImportStatusRequired})
	g.AddNode(&Node{Purl: "pkg:golang/c@1.0", ImportStatus: ImportStatusDeclared})
	g.AddEdge(&Edge{From: "pkg:golang/a@1.0", To: "pkg:golang/b@1.0"})
	g.AddEdge(&Edge{From: "pkg:golang/b@1.0", To: "pkg:golang/c@1.0"})

	// Filter to only required - should keep edge between a and b
	filtered := g.FilterByImportStatus(ImportStatusRequired)

	edgeCount := 0
	for range filtered.Edges() {
		edgeCount++
	}

	if edgeCount != 1 {
		t.Errorf("expected 1 edge (between required nodes), got %d", edgeCount)
	}
}

func TestMergeExtendedIntoGraph_NonGoNodesUnaffected(t *testing.T) {
	g := New()

	// Add a non-Go node
	npmNode := &Node{
		Purl:         "pkg:npm/lodash@4.17.21",
		Name:         "lodash",
		Ecosystem:    "npm",
		ImportStatus: ImportStatusUnspecified,
	}
	g.AddNode(npmNode)

	extended := &ExtendedGraphResult{
		FullGraph: &ModGraph{
			Edges:   []ModGraphEdge{},
			Modules: map[string][]string{},
		},
		DeclaredOnlyModules: map[string][]string{},
	}

	MergeExtendedIntoGraph(g, extended)

	// npm node should be unaffected
	updatedNode := g.Node("pkg:npm/lodash@4.17.21")
	if updatedNode.ImportStatus != ImportStatusUnspecified {
		t.Errorf("non-Go node should remain unaffected, got status %v", updatedNode.ImportStatus)
	}
}
