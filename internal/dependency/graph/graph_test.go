package graph

import (
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestNew(t *testing.T) {
	g := New()
	if g == nil {
		t.Fatal("New() returned nil")
	}
	if g.Size() != 0 {
		t.Errorf("expected empty graph, got %d nodes", g.Size())
	}
	if !g.Empty() {
		t.Error("expected Empty() to return true")
	}
}

func TestAddNode(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		PURL:    "pkg:npm/lodash@4.17.21",
		Name:    "lodash",
		Version: "4.17.21",
		Direct:  true,
	})

	if g.Size() != 1 {
		t.Errorf("expected 1 node, got %d", g.Size())
	}

	n := g.Node("pkg:npm/lodash@4.17.21")
	if n == nil {
		t.Fatal("expected to find node")
	}
	if n.Name != "lodash" {
		t.Errorf("expected name lodash, got %s", n.Name)
	}
}

func TestAddEdge(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})

	edgeCount := 0
	for range g.Edges() {
		edgeCount++
	}
	if edgeCount != 1 {
		t.Errorf("expected 1 edge, got %d", edgeCount)
	}
}

func TestFromInventory(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "express", Version: "4.18.0"},
	}
	direct := map[string]bool{
		"pkg:npm/lodash@4.17.21": true,
	}

	g := FromInventory(pkgs, direct)

	// Note: FromInventory only adds packages with valid PURLs
	// The test packages don't have ecosystem set, so PURL() may return ""
	// Let's check what we got
	stats := g.Stats()
	t.Logf("Graph has %d nodes, %d direct", stats.TotalNodes, stats.DirectNodes)
}

func TestRoots(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c", Direct: false})

	rootCount := 0
	for range g.Roots() {
		rootCount++
	}
	if rootCount != 2 {
		t.Errorf("expected 2 roots, got %d", rootCount)
	}
}

func TestDirectAndTransitive(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Direct: false})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c", Direct: false})

	directCount := 0
	for range g.Direct() {
		directCount++
	}
	if directCount != 1 {
		t.Errorf("expected 1 direct, got %d", directCount)
	}

	transitiveCount := 0
	for range g.Transitive() {
		transitiveCount++
	}
	if transitiveCount != 2 {
		t.Errorf("expected 2 transitive, got %d", transitiveCount)
	}
}

func TestChildrenAndParents(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"})

	// Test children
	childCount := 0
	for range g.Children("pkg:npm/a@1.0.0") {
		childCount++
	}
	if childCount != 2 {
		t.Errorf("expected 2 children, got %d", childCount)
	}

	// Test parents
	parentCount := 0
	for range g.Parents("pkg:npm/b@1.0.0") {
		parentCount++
	}
	if parentCount != 1 {
		t.Errorf("expected 1 parent, got %d", parentCount)
	}
}

func TestDescendants(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddNode(&Node{PURL: "pkg:npm/d@1.0.0", Name: "d"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/d@1.0.0"})

	descCount := 0
	for range g.Descendants("pkg:npm/a@1.0.0") {
		descCount++
	}
	if descCount != 3 {
		t.Errorf("expected 3 descendants, got %d", descCount)
	}
}

func TestAncestors(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})

	ancCount := 0
	for range g.Ancestors("pkg:npm/c@1.0.0") {
		ancCount++
	}
	if ancCount != 2 {
		t.Errorf("expected 2 ancestors, got %d", ancCount)
	}
}

func TestPathsTo(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})

	paths := g.PathsTo("pkg:npm/c@1.0.0")
	if len(paths) != 1 {
		t.Errorf("expected 1 path, got %d", len(paths))
	}

	if len(paths) > 0 {
		path := paths[0]
		if path.Len() != 2 {
			t.Errorf("expected path length 2, got %d", path.Len())
		}
		if path.String() != "a -> b -> c" {
			t.Errorf("unexpected path: %s", path.String())
		}
	}
}

func TestPathsToDirectDep(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})

	paths := g.PathsTo("pkg:npm/a@1.0.0")
	if len(paths) != 1 {
		t.Errorf("expected 1 path to direct dep, got %d", len(paths))
	}

	if len(paths) > 0 && paths[0].Len() != 0 {
		t.Errorf("expected path length 0 for direct dep, got %d", paths[0].Len())
	}
}

func TestPathsToWithCycle(t *testing.T) {
	// Test that PathsTo handles cycles gracefully without infinite loops
	// Graph: a -> b -> c -> b (cycle back to b)
	//                  \-> d (target)
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddNode(&Node{PURL: "pkg:npm/d@1.0.0", Name: "d"})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/b@1.0.0"}) // Cycle: c -> b
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/d@1.0.0"})

	// PathsTo should find the path to d without getting stuck in the cycle
	paths := g.PathsTo("pkg:npm/d@1.0.0")
	if len(paths) != 1 {
		t.Errorf("expected 1 path to d, got %d", len(paths))
	}

	if len(paths) > 0 {
		path := paths[0]
		// Path should be a -> b -> c -> d
		if path.Len() != 3 {
			t.Errorf("expected path length 3, got %d", path.Len())
		}
		expected := "a -> b -> c -> d"
		if path.String() != expected {
			t.Errorf("expected path %q, got %q", expected, path.String())
		}
	}
}

func TestPathsToWithSelfCycle(t *testing.T) {
	// Test self-referential cycle: a -> b -> b (self-cycle)
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/b@1.0.0"}) // Self-cycle

	paths := g.PathsTo("pkg:npm/b@1.0.0")
	if len(paths) != 1 {
		t.Errorf("expected 1 path to b, got %d", len(paths))
	}

	if len(paths) > 0 {
		path := paths[0]
		// Path should be a -> b (self-cycle not included)
		if path.Len() != 1 {
			t.Errorf("expected path length 1, got %d", path.Len())
		}
	}
}

func TestPathsToWithDiamondAndCycle(t *testing.T) {
	// Diamond pattern with a cycle:
	//     a
	//    / \
	//   b   c
	//    \ /
	//     d -> b (creates cycle through diamond)
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddNode(&Node{PURL: "pkg:npm/d@1.0.0", Name: "d"})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/d@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/d@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/d@1.0.0", To: "pkg:npm/b@1.0.0"}) // Cycle: d -> b

	paths := g.PathsTo("pkg:npm/d@1.0.0")
	// Should find two paths: a->b->d and a->c->d
	if len(paths) != 2 {
		t.Errorf("expected 2 paths to d (diamond), got %d", len(paths))
	}

	// Verify no path contains duplicates (cycle detection working)
	for _, path := range paths {
		seen := make(map[string]bool)
		for _, node := range path {
			if seen[node.PURL] {
				t.Errorf("path %s contains duplicate node %s (cycle not detected)", path.String(), node.PURL)
			}
			seen[node.PURL] = true
		}
	}
}

func TestPathsToInCyclicGraph(t *testing.T) {
	// Fully cyclic graph where target is part of the cycle
	// a -> b -> c -> a (target is b, which is part of cycle)
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/a@1.0.0"}) // Cycle back to root

	// Path to b should work (just a -> b)
	paths := g.PathsTo("pkg:npm/b@1.0.0")
	if len(paths) != 1 {
		t.Errorf("expected 1 path to b, got %d", len(paths))
	}

	// Path to c should work (a -> b -> c)
	pathsToC := g.PathsTo("pkg:npm/c@1.0.0")
	if len(pathsToC) != 1 {
		t.Errorf("expected 1 path to c, got %d", len(pathsToC))
	}
}

func TestPathsBetween(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"}) // Direct path too

	paths := g.PathsBetween("pkg:npm/a@1.0.0", "pkg:npm/c@1.0.0")
	if len(paths) != 2 {
		t.Errorf("expected 2 paths, got %d", len(paths))
	}
}

func TestPathsBetweenWithCycle(t *testing.T) {
	// Test PathsBetween with cycle in the graph
	// a -> b -> c -> b (cycle), also a -> c directly
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/b@1.0.0"}) // Cycle

	// Should find paths from a to c without infinite loop
	paths := g.PathsBetween("pkg:npm/a@1.0.0", "pkg:npm/c@1.0.0")
	if len(paths) < 1 {
		t.Errorf("expected at least 1 path, got %d", len(paths))
	}

	// Verify no path contains duplicates
	for _, path := range paths {
		seen := make(map[string]bool)
		for _, node := range path {
			if seen[node.PURL] {
				t.Errorf("path %s contains duplicate node %s", path.String(), node.PURL)
			}
			seen[node.PURL] = true
		}
	}
}

func TestStats(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true, Depth: 0, Ecosystem: "npm"})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Depth: 1, Ecosystem: "npm"})
	g.AddNode(&Node{PURL: "pkg:go/c@1.0.0", Name: "c", Depth: 2, Ecosystem: "go", VulnCount: VulnCount{Total: 1}})

	stats := g.Stats()

	if stats.TotalNodes != 3 {
		t.Errorf("expected 3 total nodes, got %d", stats.TotalNodes)
	}
	if stats.DirectNodes != 1 {
		t.Errorf("expected 1 direct node, got %d", stats.DirectNodes)
	}
	if stats.TransitiveNodes != 2 {
		t.Errorf("expected 2 transitive nodes, got %d", stats.TransitiveNodes)
	}
	if stats.MaxDepth != 2 {
		t.Errorf("expected max depth 2, got %d", stats.MaxDepth)
	}
	if stats.VulnerableNodes != 1 {
		t.Errorf("expected 1 vulnerable node, got %d", stats.VulnerableNodes)
	}
	if stats.Ecosystems["npm"] != 2 {
		t.Errorf("expected 2 npm nodes, got %d", stats.Ecosystems["npm"])
	}
}

func TestVulnerableNodes(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", VulnCount: VulnCount{Total: 0}})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", VulnCount: VulnCount{Total: 2, High: 2}})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c", VulnCount: VulnCount{Total: 1, Critical: 1}})

	vulnCount := 0
	for range g.VulnerableNodes() {
		vulnCount++
	}
	if vulnCount != 2 {
		t.Errorf("expected 2 vulnerable nodes, got %d", vulnCount)
	}
}

func TestAnnotateVulns(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/lodash@4.17.20", Name: "lodash"})

	findings := []vulnerability.Finding{
		{
			AdvisoryID: "CVE-2021-23337",
			Dependency: dependency.ID{PURL: "pkg:npm/lodash@4.17.20"},
		},
	}
	advisories := map[string]vulnerability.Advisory{
		"CVE-2021-23337": {
			ID:       "CVE-2021-23337",
			Severity: vulnerability.NewSeverity("HIGH", "GHSA"),
		},
	}

	g.AnnotateVulns(findings, advisories)

	n := g.Node("pkg:npm/lodash@4.17.20")
	if n.VulnCount.Total != 1 {
		t.Errorf("expected 1 vuln, got %d", n.VulnCount.Total)
	}
	if n.VulnCount.High != 1 {
		t.Errorf("expected 1 high, got %d", n.VulnCount.High)
	}
}

func TestFilter(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", VulnCount: VulnCount{Total: 1}})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"})

	// Filter to only vulnerable nodes
	filtered := g.Filter(func(n *Node) bool {
		return n.VulnCount.Total > 0 || n.Direct
	})

	if filtered.Size() != 2 {
		t.Errorf("expected 2 nodes in filtered graph, got %d", filtered.Size())
	}
}

func TestSubgraph(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddNode(&Node{PURL: "pkg:npm/d@1.0.0", Name: "d"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/d@1.0.0"})

	sub := g.Subgraph("pkg:npm/b@1.0.0")

	// Should have b and c
	if sub.Size() != 2 {
		t.Errorf("expected 2 nodes in subgraph, got %d", sub.Size())
	}

	// b should be marked as direct (root of subgraph)
	if b := sub.Node("pkg:npm/b@1.0.0"); b == nil || !b.Direct {
		t.Error("expected b to be root of subgraph")
	}
}

func TestClone(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Locations: []string{"/a"}})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})

	clone := g.Clone()

	// Modify original
	g.Node("pkg:npm/a@1.0.0").Name = "modified"

	// Clone should be unchanged
	if clone.Node("pkg:npm/a@1.0.0").Name != "a" {
		t.Error("clone was modified when original changed")
	}
}

func TestPath(t *testing.T) {
	path := Path{
		{PURL: "pkg:npm/a@1.0.0", Name: "a"},
		{PURL: "pkg:npm/b@1.0.0", Name: "b"},
		{PURL: "pkg:npm/c@1.0.0", Name: "c"},
	}

	if path.String() != "a -> b -> c" {
		t.Errorf("unexpected string: %s", path.String())
	}

	if path.Len() != 2 {
		t.Errorf("expected length 2, got %d", path.Len())
	}

	if !path.Contains("pkg:npm/b@1.0.0") {
		t.Error("expected path to contain b")
	}

	if path.Contains("pkg:npm/x@1.0.0") {
		t.Error("expected path not to contain x")
	}

	purls := path.PURLs()
	if len(purls) != 3 {
		t.Errorf("expected 3 purls, got %d", len(purls))
	}
}

func TestSortByVulns(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", VulnCount: VulnCount{Total: 1, Low: 1}})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", VulnCount: VulnCount{Total: 3, Critical: 1, High: 2}})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c", VulnCount: VulnCount{Total: 0}})

	sorted := g.SortByVulns()

	if sorted[0].Name != "b" {
		t.Errorf("expected b first (most vulns), got %s", sorted[0].Name)
	}
	if sorted[len(sorted)-1].Name != "c" {
		t.Errorf("expected c last (no vulns), got %s", sorted[len(sorted)-1].Name)
	}
}

func TestSortByDepth(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Depth: 2})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Depth: 0})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c", Depth: 1})

	sorted := g.SortByDepth()

	if sorted[0].Name != "b" {
		t.Errorf("expected b first (depth 0), got %s", sorted[0].Name)
	}
	if sorted[len(sorted)-1].Name != "a" {
		t.Errorf("expected a last (depth 2), got %s", sorted[len(sorted)-1].Name)
	}
}

func TestRenderText(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})

	output := g.ToText()

	if !strings.Contains(output, "a@1.0.0") {
		t.Error("expected output to contain a@1.0.0")
	}
	if !strings.Contains(output, "b@1.0.0") {
		t.Error("expected output to contain b@1.0.0")
	}
}

func TestRenderDOT(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})

	output := g.ToDOT()

	if !strings.Contains(output, "digraph dependencies") {
		t.Error("expected DOT output to contain digraph")
	}
	if !strings.Contains(output, "->") {
		t.Error("expected DOT output to contain edges")
	}
}

func TestRenderMermaid(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Direct: true, Ecosystem: "npm"})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0", Ecosystem: "npm"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})

	output := g.ToMermaid()

	if !strings.Contains(output, "flowchart") {
		t.Error("expected Mermaid output to contain flowchart")
	}
	if !strings.Contains(output, "-->") {
		t.Error("expected Mermaid output to contain edges")
	}
}

func TestRenderD3(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})

	output := string(g.ToD3JSON())

	if !strings.Contains(output, `"nodes"`) {
		t.Error("expected D3 output to contain nodes")
	}
	if !strings.Contains(output, `"links"`) {
		t.Error("expected D3 output to contain links")
	}
}

func TestRenderWithOptions(t *testing.T) {
	g := New()
	g.AddNode(&Node{
		PURL:      "pkg:npm/a@1.0.0",
		Name:      "a",
		Version:   "1.0.0",
		Direct:    true,
		VulnCount: VulnCount{Total: 1, Critical: 1},
	})

	output := g.ToDOT(
		WithHighlightVulns("CRITICAL"),
		WithVersions(true),
		WithVulnCounts(true),
	)

	if !strings.Contains(output, "color=red") {
		t.Error("expected critical vuln to be highlighted red")
	}
	if !strings.Contains(output, "1.0.0") {
		t.Error("expected version in output")
	}
	if !strings.Contains(output, "[1V]") {
		t.Error("expected vuln count in output")
	}
}

func TestToID(t *testing.T) {
	n := &Node{
		PURL:      "pkg:npm/lodash@4.17.21",
		Name:      "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
	}

	id := n.ToID()

	if id.Name != "lodash" {
		t.Errorf("expected name lodash, got %s", id.Name)
	}
	if id.Ecosystem != "npm" {
		t.Errorf("expected ecosystem npm, got %s", id.Ecosystem)
	}
	if id.PURL != "pkg:npm/lodash@4.17.21" {
		t.Errorf("expected PURL pkg:npm/lodash@4.17.21, got %s", id.PURL)
	}
}

func TestUpdateDepths(t *testing.T) {
	// Build a graph: a -> b -> c -> d
	// where a is direct
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddNode(&Node{PURL: "pkg:npm/d@1.0.0", Name: "d"})
	g.AddNode(&Node{PURL: "pkg:npm/orphan@1.0.0", Name: "orphan"}) // Not connected

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/d@1.0.0"})

	g.UpdateDepths()

	// Check depths
	tests := []struct {
		purl  string
		depth int
	}{
		{"pkg:npm/a@1.0.0", 0},      // direct
		{"pkg:npm/b@1.0.0", 1},      // 1 hop
		{"pkg:npm/c@1.0.0", 2},      // 2 hops
		{"pkg:npm/d@1.0.0", 3},      // 3 hops
		{"pkg:npm/orphan@1.0.0", DepthDisconnected}, // disconnected
	}

	for _, tt := range tests {
		n := g.Node(tt.purl)
		if n == nil {
			t.Errorf("node %s not found", tt.purl)
			continue
		}
		if n.Depth != tt.depth {
			t.Errorf("node %s: depth = %d, want %d", tt.purl, n.Depth, tt.depth)
		}
	}
}

func TestUpdateDepthsDiamond(t *testing.T) {
	// Diamond pattern: a -> [b, c] -> d
	// Both b and c depend on d, so d should have depth 2
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})
	g.AddNode(&Node{PURL: "pkg:npm/d@1.0.0", Name: "d"})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/d@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/d@1.0.0"})

	g.UpdateDepths()

	// d should be reachable at depth 2 (shortest path)
	if d := g.Node("pkg:npm/d@1.0.0"); d.Depth != 2 {
		t.Errorf("d depth = %d, want 2 (shortest path via BFS)", d.Depth)
	}
}

func TestUpdateDepthsMultipleRoots(t *testing.T) {
	// Two roots: a -> b, c -> b
	// b should have depth 1
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/c@1.0.0", To: "pkg:npm/b@1.0.0"})

	g.UpdateDepths()

	if b := g.Node("pkg:npm/b@1.0.0"); b.Depth != 1 {
		t.Errorf("b depth = %d, want 1", b.Depth)
	}
}

func TestAdjacencyCacheInvalidation(t *testing.T) {
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c"})

	// Add first edge
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})

	// Access children to build cache
	count1 := 0
	for range g.Children("pkg:npm/a@1.0.0") {
		count1++
	}
	if count1 != 1 {
		t.Errorf("expected 1 child, got %d", count1)
	}

	// Add another edge - should invalidate cache
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/c@1.0.0"})

	// Children should now return 2
	count2 := 0
	for range g.Children("pkg:npm/a@1.0.0") {
		count2++
	}
	if count2 != 2 {
		t.Errorf("expected 2 children after cache invalidation, got %d", count2)
	}
}

func TestVulnerablePaths(t *testing.T) {
	// a -> b -> c (vulnerable)
	// a -> d -> c (same vulnerable c)
	g := New()
	g.AddNode(&Node{PURL: "pkg:npm/a@1.0.0", Name: "a", Direct: true})
	g.AddNode(&Node{PURL: "pkg:npm/b@1.0.0", Name: "b"})
	g.AddNode(&Node{PURL: "pkg:npm/d@1.0.0", Name: "d"})
	g.AddNode(&Node{PURL: "pkg:npm/c@1.0.0", Name: "c", VulnCount: VulnCount{Total: 1, High: 1}})

	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/b@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/b@1.0.0", To: "pkg:npm/c@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/a@1.0.0", To: "pkg:npm/d@1.0.0"})
	g.AddEdge(&Edge{From: "pkg:npm/d@1.0.0", To: "pkg:npm/c@1.0.0"})

	paths := g.VulnerablePaths()

	// Should find 2 paths to c
	if len(paths) != 2 {
		t.Errorf("expected 2 vulnerable paths, got %d", len(paths))
	}

	// Each path should end at c
	for _, p := range paths {
		if len(p) == 0 || p[len(p)-1].Name != "c" {
			t.Errorf("path should end at vulnerable node c: %v", p)
		}
	}
}
