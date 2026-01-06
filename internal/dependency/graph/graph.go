package graph

import (
	"cmp"
	"context"
	"iter"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
)

// Depth constants for node positioning in the dependency graph.
const (
	// DepthSyntheticRoot marks synthetic root nodes (e.g., the main module itself).
	// These nodes represent the project being scanned rather than actual dependencies.
	DepthSyntheticRoot = -1

	// DepthDisconnected marks nodes with no path from any root.
	// This typically means the node was discovered (e.g., in go.sum or a binary)
	// but no dependency path could be resolved to it.
	DepthDisconnected = 999
)

// FileReader provides access to files for edge resolution.
// This abstraction allows resolvers to work with workspaces, git commits, or other sources.
type FileReader interface {
	ReadFile(path string) ([]byte, error)
}

// EdgeResolver computes dependency relationships for a specific ecosystem.
// Implementations parse lockfiles, manifests, or other sources to determine
// which packages depend on which.
type EdgeResolver interface {
	// Ecosystem returns the ecosystem this resolver handles (e.g., "Go", "npm").
	Ecosystem() string

	// ResolveEdges adds edges to the graph based on ecosystem-specific logic.
	// It receives the graph (with nodes already populated), and a file reader
	// for accessing lockfiles and manifests.
	//
	// The resolver should:
	//  1. Identify relevant lockfiles/manifests in the file system
	//  2. Parse dependency relationships from those files
	//  3. Add edges to the graph via g.AddEdge()
	//  4. Update node depths based on the resolved tree
	//
	// Errors are typically non-fatal; resolvers should add as many edges as
	// possible even if some files fail to parse.
	ResolveEdges(ctx context.Context, g *Graph, files FileReader) error
}

// Graph represents a dependency graph with nodes (packages) and edges (dependencies).
type Graph struct {
	nodes map[string]*Node // keyed by PURL
	edges []*Edge
	roots []string // PURLs of direct dependencies

	// Adjacency caches for O(1) lookups (built lazily on first access)
	childrenIndex map[string][]string // PURL -> list of child PURLs
	parentsIndex  map[string][]string // PURL -> list of parent PURLs
}

// Node represents a package in the dependency graph.
type Node struct {
	// PURL is the Package URL identifier for this package.
	PURL string `json:"purl"`

	// Name is the package name (extracted from PURL or package metadata).
	Name string `json:"name"`

	// Version is the package version.
	Version string `json:"version"`

	// Ecosystem is the package ecosystem (e.g., "npm", "go", "pypi").
	Ecosystem string `json:"ecosystem"`

	// Package is the underlying extractor package, if available.
	Package *extractor.Package `json:"-"`

	// Direct indicates whether this is a direct dependency.
	Direct bool `json:"direct"`

	// Depth is the shortest path length from any root node.
	// Values:
	//   - 0: Direct dependency (root node)
	//   - 1+: Transitive dependency (N hops from nearest root)
	//   - [DepthSyntheticRoot] (-1): Synthetic root node (e.g., the main module itself)
	//   - [DepthDisconnected] (999): Disconnected node (no path from any root)
	//
	// Note: Depth is computed by [Graph.UpdateDepths]. Before that call,
	// non-direct nodes default to depth 1.
	Depth int `json:"depth"`

	// Locations lists file paths where this dependency was declared.
	Locations []string `json:"locations,omitempty"`

	// Vulns contains vulnerability findings for this package.
	Vulns []vulnerability.Finding `json:"vulns,omitempty"`

	// VulnCount summarizes vulnerability counts by severity.
	VulnCount VulnCount `json:"vuln_count"`
}

// VulnCount summarizes vulnerability counts by severity level.
type VulnCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
	Total    int `json:"total"`
}

// Edge represents a dependency relationship between two packages.
type Edge struct {
	// From is the PURL of the dependent package (parent).
	From string `json:"from"`

	// To is the PURL of the dependency (child).
	To string `json:"to"`

	// Constraint is the version constraint, if known (e.g., "^1.0.0", ">=2.0").
	Constraint string `json:"constraint,omitempty"`

	// Scope indicates the dependency scope.
	Scope Scope `json:"scope,omitempty"`
}

// Scope indicates the context in which a dependency is used.
type Scope string

const (
	// ScopeRuntime is for dependencies needed at runtime.
	ScopeRuntime Scope = "runtime"

	// ScopeDev is for development-only dependencies.
	ScopeDev Scope = "dev"

	// ScopeOptional is for optional dependencies.
	ScopeOptional Scope = "optional"

	// ScopeBuild is for build-time dependencies.
	ScopeBuild Scope = "build"

	// ScopeTest is for test dependencies.
	ScopeTest Scope = "test"
)

// Path represents a sequence of nodes from root to target.
type Path []*Node

// String returns a human-readable representation of the path.
func (p Path) String() string {
	if len(p) == 0 {
		return ""
	}
	result := p[0].Name
	for _, n := range p[1:] {
		result += " -> " + n.Name
	}
	return result
}

// PURLs returns the PURLs of all nodes in the path.
func (p Path) PURLs() []string {
	purls := make([]string, len(p))
	for i, n := range p {
		purls[i] = n.PURL
	}
	return purls
}

// Len returns the path length (number of edges, not nodes).
func (p Path) Len() int {
	if len(p) == 0 {
		return 0
	}
	return len(p) - 1
}

// Contains reports whether the path contains a node with the given PURL.
func (p Path) Contains(purl string) bool {
	for _, n := range p {
		if n.PURL == purl {
			return true
		}
	}
	return false
}

// New creates an empty graph.
func New() *Graph {
	return &Graph{
		nodes: make(map[string]*Node),
	}
}

// FromInventory constructs a graph from inventory extraction results.
// The direct map indicates which PURLs are direct dependencies.
func FromInventory(pkgs []*extractor.Package, direct map[string]bool) *Graph {
	g := New()

	for _, pkg := range pkgs {
		purlObj := pkg.PURL()
		if purlObj == nil {
			continue
		}
		purl := purlObj.String()
		if purl == "" {
			continue
		}

		isDirect := false
		if direct != nil {
			isDirect = direct[purl]
		}

		node := &Node{
			PURL:      purl,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem(),
			Package:   pkg,
			Direct:    isDirect,
			Locations: pkg.Locations,
		}

		if isDirect {
			node.Depth = 0
			g.roots = append(g.roots, purl)
		} else {
			node.Depth = 1 // Default; would need resolver data for accurate depth
		}

		g.nodes[purl] = node
	}

	return g
}

// AddNode adds a node to the graph. If a node with the same PURL exists, it is replaced.
func (g *Graph) AddNode(n *Node) {
	if n == nil || n.PURL == "" {
		return
	}
	g.nodes[n.PURL] = n
	if n.Direct {
		// Check if already in roots
		for _, r := range g.roots {
			if r == n.PURL {
				return
			}
		}
		g.roots = append(g.roots, n.PURL)
	}
}

// AddEdge adds an edge to the graph.
func (g *Graph) AddEdge(e *Edge) {
	if e == nil || e.From == "" || e.To == "" {
		return
	}
	g.edges = append(g.edges, e)
	// Invalidate adjacency caches
	g.childrenIndex = nil
	g.parentsIndex = nil
}

// buildAdjacencyIndices builds the children and parents indices for O(1) lookups.
// This is called lazily on first access to Children() or Parents().
func (g *Graph) buildAdjacencyIndices() {
	if g.childrenIndex != nil && g.parentsIndex != nil {
		return // Already built
	}

	g.childrenIndex = make(map[string][]string)
	g.parentsIndex = make(map[string][]string)

	for _, e := range g.edges {
		g.childrenIndex[e.From] = append(g.childrenIndex[e.From], e.To)
		g.parentsIndex[e.To] = append(g.parentsIndex[e.To], e.From)
	}
}

// Node returns the node with the given PURL, or nil if not found.
func (g *Graph) Node(purl string) *Node {
	return g.nodes[purl]
}

// Nodes returns an iterator over all nodes in the graph.
func (g *Graph) Nodes() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for _, n := range g.nodes {
			if !yield(n) {
				return
			}
		}
	}
}

// NodesSorted returns nodes sorted by PURL for deterministic output.
func (g *Graph) NodesSorted() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		purls := make([]string, 0, len(g.nodes))
		for purl := range g.nodes {
			purls = append(purls, purl)
		}
		slices.Sort(purls)
		for _, purl := range purls {
			if !yield(g.nodes[purl]) {
				return
			}
		}
	}
}

// Edges returns an iterator over all edges in the graph.
func (g *Graph) Edges() iter.Seq[*Edge] {
	return func(yield func(*Edge) bool) {
		for _, e := range g.edges {
			if !yield(e) {
				return
			}
		}
	}
}

// Roots returns an iterator over root (direct dependency) nodes.
func (g *Graph) Roots() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for _, purl := range g.roots {
			if n := g.nodes[purl]; n != nil {
				if !yield(n) {
					return
				}
			}
		}
	}
}

// Direct returns an iterator over direct dependency nodes.
func (g *Graph) Direct() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for _, n := range g.nodes {
			if n.Direct {
				if !yield(n) {
					return
				}
			}
		}
	}
}

// Transitive returns an iterator over transitive (non-direct) dependency nodes.
func (g *Graph) Transitive() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for _, n := range g.nodes {
			if !n.Direct {
				if !yield(n) {
					return
				}
			}
		}
	}
}

// Children returns an iterator over nodes that are direct dependencies of the given PURL.
// Uses cached adjacency index for O(1) lookup after first access.
func (g *Graph) Children(purl string) iter.Seq[*Node] {
	g.buildAdjacencyIndices()
	return func(yield func(*Node) bool) {
		for _, childPURL := range g.childrenIndex[purl] {
			if n := g.nodes[childPURL]; n != nil {
				if !yield(n) {
					return
				}
			}
		}
	}
}

// Parents returns an iterator over nodes that depend on the given PURL.
// Uses cached adjacency index for O(1) lookup after first access.
func (g *Graph) Parents(purl string) iter.Seq[*Node] {
	g.buildAdjacencyIndices()
	return func(yield func(*Node) bool) {
		for _, parentPURL := range g.parentsIndex[purl] {
			if n := g.nodes[parentPURL]; n != nil {
				if !yield(n) {
					return
				}
			}
		}
	}
}

// Descendants returns an iterator over all transitive dependencies of the given PURL.
func (g *Graph) Descendants(purl string) iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		visited := make(map[string]bool)
		var visit func(string) bool
		visit = func(p string) bool {
			for child := range g.Children(p) {
				if visited[child.PURL] {
					continue
				}
				visited[child.PURL] = true
				if !yield(child) {
					return false
				}
				if !visit(child.PURL) {
					return false
				}
			}
			return true
		}
		visit(purl)
	}
}

// Ancestors returns an iterator over all packages that transitively depend on the given PURL.
func (g *Graph) Ancestors(purl string) iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		visited := make(map[string]bool)
		var visit func(string) bool
		visit = func(p string) bool {
			for parent := range g.Parents(p) {
				if visited[parent.PURL] {
					continue
				}
				visited[parent.PURL] = true
				if !yield(parent) {
					return false
				}
				if !visit(parent.PURL) {
					return false
				}
			}
			return true
		}
		visit(purl)
	}
}

// PathsTo finds all paths from root nodes to the target PURL.
func (g *Graph) PathsTo(target string) []Path {
	if g.nodes[target] == nil {
		return nil
	}

	var paths []Path

	// BFS from target back to roots
	type pathState struct {
		purl string
		path []*Node
	}

	queue := []pathState{{purl: target, path: []*Node{g.nodes[target]}}}
	visited := make(map[string]bool)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		node := g.nodes[current.purl]
		if node == nil {
			continue
		}

		if node.Direct {
			// Found a path to a root - reverse it
			reversed := make(Path, len(current.path))
			for i, n := range current.path {
				reversed[len(current.path)-1-i] = n
			}
			paths = append(paths, reversed)
			continue
		}

		// Create a unique key for this path state to avoid revisiting
		pathKey := current.purl
		if visited[pathKey] {
			continue
		}
		visited[pathKey] = true

		// Continue searching up to parents
		for parent := range g.Parents(current.purl) {
			// Avoid cycles
			if pathContains(current.path, parent.PURL) {
				continue
			}
			newPath := make([]*Node, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = parent
			queue = append(queue, pathState{purl: parent.PURL, path: newPath})
		}
	}

	// If no edges exist, check if target is a direct dependency
	if len(paths) == 0 && g.nodes[target] != nil && g.nodes[target].Direct {
		paths = append(paths, Path{g.nodes[target]})
	}

	return paths
}

func pathContains(path []*Node, purl string) bool {
	for _, n := range path {
		if n.PURL == purl {
			return true
		}
	}
	return false
}

// PathsBetween finds all paths from source to target.
func (g *Graph) PathsBetween(source, target string) []Path {
	if g.nodes[source] == nil || g.nodes[target] == nil {
		return nil
	}

	var paths []Path
	var dfs func(current string, path []*Node)

	dfs = func(current string, path []*Node) {
		node := g.nodes[current]
		if node == nil {
			return
		}

		newPath := append(path, node)

		if current == target {
			result := make(Path, len(newPath))
			copy(result, newPath)
			paths = append(paths, result)
			return
		}

		for child := range g.Children(current) {
			// Avoid cycles
			if pathContains(newPath, child.PURL) {
				continue
			}
			dfs(child.PURL, newPath)
		}
	}

	dfs(source, nil)
	return paths
}

// Stats returns statistics about the graph.
func (g *Graph) Stats() Stats {
	stats := Stats{
		TotalNodes: len(g.nodes),
		Ecosystems: make(map[string]int),
	}

	for _, n := range g.nodes {
		if n.Direct {
			stats.DirectNodes++
		} else {
			stats.TransitiveNodes++
		}

		if n.Depth > stats.MaxDepth {
			stats.MaxDepth = n.Depth
		}

		if n.VulnCount.Total > 0 {
			stats.VulnerableNodes++
		}

		if n.Ecosystem != "" {
			stats.Ecosystems[n.Ecosystem]++
		}
	}

	return stats
}

// Stats contains summary statistics about a graph.
type Stats struct {
	TotalNodes      int            `json:"total_nodes"`
	DirectNodes     int            `json:"direct_nodes"`
	TransitiveNodes int            `json:"transitive_nodes"`
	MaxDepth        int            `json:"max_depth"`
	VulnerableNodes int            `json:"vulnerable_nodes"`
	Ecosystems      map[string]int `json:"ecosystems"`
}

// VulnerableNodes returns an iterator over nodes that have vulnerabilities.
func (g *Graph) VulnerableNodes() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for _, n := range g.nodes {
			if n.VulnCount.Total > 0 {
				if !yield(n) {
					return
				}
			}
		}
	}
}

// VulnerablePaths returns all unique paths from root nodes to vulnerable packages.
// This is useful for understanding which dependency chains expose vulnerabilities.
//
// Paths are deduplicated by package name sequence (not version), so if the same
// logical path exists with different versions, only one is returned.
//
// Example use case: finding which direct dependencies transitively pull in
// a vulnerable package, to identify the best remediation target.
func (g *Graph) VulnerablePaths() []Path {
	var paths []Path
	seen := make(map[string]bool)

	for vuln := range g.VulnerableNodes() {
		for _, path := range g.PathsTo(vuln.PURL) {
			// Deduplicate paths
			key := pathKey(path)
			if !seen[key] {
				seen[key] = true
				paths = append(paths, path)
			}
		}
	}

	return paths
}

// pathKey returns a unique key for a path based on the sequence of node names.
// Two paths with identical node name sequences are considered duplicates,
// even if versions differ.
func pathKey(p Path) string {
	if len(p) == 0 {
		return ""
	}
	names := make([]string, len(p))
	for i, node := range p {
		names[i] = node.Name
	}
	return strings.Join(names, "→")
}

// AnnotateVulns adds vulnerability information to graph nodes.
func (g *Graph) AnnotateVulns(findings []vulnerability.Finding, advisories map[string]vulnerability.Advisory) {
	// Group findings by PURL
	vulnsByPURL := make(map[string][]vulnerability.Finding)
	for _, f := range findings {
		purl := f.Dependency.PURL
		vulnsByPURL[purl] = append(vulnsByPURL[purl], f)
	}

	// Apply to nodes
	for purl, vulns := range vulnsByPURL {
		if node := g.nodes[purl]; node != nil {
			node.Vulns = vulns
			node.VulnCount = countVulns(vulns, advisories)
		}
	}
}

func countVulns(findings []vulnerability.Finding, advisories map[string]vulnerability.Advisory) VulnCount {
	count := VulnCount{Total: len(findings)}

	for _, f := range findings {
		adv, ok := advisories[f.AdvisoryID]
		if !ok {
			count.Unknown++
			continue
		}

		switch adv.Severity.Level.String() {
		case "CRITICAL":
			count.Critical++
		case "HIGH":
			count.High++
		case "MEDIUM":
			count.Medium++
		case "LOW":
			count.Low++
		default:
			count.Unknown++
		}
	}

	return count
}

// Filter returns a new graph containing only nodes matching the predicate.
// Edges are included if both endpoints match.
func (g *Graph) Filter(pred func(*Node) bool) *Graph {
	filtered := New()

	for _, n := range g.nodes {
		if pred(n) {
			filtered.AddNode(n)
		}
	}

	for _, e := range g.edges {
		if filtered.nodes[e.From] != nil && filtered.nodes[e.To] != nil {
			filtered.AddEdge(e)
		}
	}

	return filtered
}

// Subgraph returns a subgraph rooted at the given PURL, including all descendants.
func (g *Graph) Subgraph(root string) *Graph {
	if g.nodes[root] == nil {
		return New()
	}

	sub := New()
	rootNode := g.nodes[root]

	// Clone root node as direct
	newRoot := *rootNode
	newRoot.Direct = true
	sub.AddNode(&newRoot)

	// Add all descendants
	for desc := range g.Descendants(root) {
		sub.AddNode(desc)
	}

	// Add relevant edges
	for _, e := range g.edges {
		if sub.nodes[e.From] != nil && sub.nodes[e.To] != nil {
			sub.AddEdge(e)
		}
	}

	return sub
}

// Size returns the number of nodes in the graph.
func (g *Graph) Size() int {
	return len(g.nodes)
}

// Empty reports whether the graph has no nodes.
func (g *Graph) Empty() bool {
	return len(g.nodes) == 0
}

// Clone returns a deep copy of the graph.
func (g *Graph) Clone() *Graph {
	clone := New()

	for _, n := range g.nodes {
		nodeCopy := *n
		// Deep copy slices
		if n.Locations != nil {
			nodeCopy.Locations = slices.Clone(n.Locations)
		}
		if n.Vulns != nil {
			nodeCopy.Vulns = slices.Clone(n.Vulns)
		}
		clone.AddNode(&nodeCopy)
	}

	for _, e := range g.edges {
		edgeCopy := *e
		clone.AddEdge(&edgeCopy)
	}

	return clone
}

// Sort returns nodes sorted by the given comparison function.
func (g *Graph) Sort(cmp func(a, b *Node) int) []*Node {
	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	slices.SortFunc(nodes, cmp)
	return nodes
}

// SortByVulns returns nodes sorted by vulnerability count (highest first).
func (g *Graph) SortByVulns() []*Node {
	return g.Sort(func(a, b *Node) int {
		// Sort by total vulns descending
		if a.VulnCount.Total != b.VulnCount.Total {
			return cmp.Compare(b.VulnCount.Total, a.VulnCount.Total)
		}
		// Then by critical
		if a.VulnCount.Critical != b.VulnCount.Critical {
			return cmp.Compare(b.VulnCount.Critical, a.VulnCount.Critical)
		}
		// Then by name for stability
		return cmp.Compare(a.Name, b.Name)
	})
}

// SortByDepth returns nodes sorted by depth (direct first, then transitive).
func (g *Graph) SortByDepth() []*Node {
	return g.Sort(func(a, b *Node) int {
		if a.Depth != b.Depth {
			return cmp.Compare(a.Depth, b.Depth)
		}
		return cmp.Compare(a.Name, b.Name)
	})
}

// UpdateDepths recalculates node depths using BFS from direct dependencies.
// This should be called after edges have been added to ensure depth values
// reflect the actual graph structure. Direct dependencies have depth 0,
// their immediate dependencies have depth 1, and so on.
// Disconnected nodes (not reachable from any direct dependency) get [DepthDisconnected].
func (g *Graph) UpdateDepths() {
	// Reset all depths
	for node := range g.Nodes() {
		if node.Direct {
			node.Depth = 0
		} else {
			node.Depth = DepthSyntheticRoot // Mark as unvisited
		}
	}

	// BFS from all direct nodes to set depths
	visited := make(map[string]bool)
	type queueItem struct {
		purl  string
		depth int
	}
	var queue []queueItem

	// Start from all direct nodes (depth 0)
	for node := range g.Nodes() {
		if node.Direct {
			queue = append(queue, queueItem{node.PURL, 0})
			visited[node.PURL] = true
		}
	}

	// BFS traversal
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for child := range g.Children(current.purl) {
			if visited[child.PURL] {
				continue
			}
			visited[child.PURL] = true
			newDepth := current.depth + 1
			if child.Depth < 0 || newDepth < child.Depth {
				child.Depth = newDepth
			}
			queue = append(queue, queueItem{child.PURL, newDepth})
		}
	}

	// Any remaining nodes with negative depth are disconnected
	for node := range g.Nodes() {
		if node.Depth < 0 {
			node.Depth = DepthDisconnected
		}
	}
}

// ToID converts a Node to a dependency.ID for compatibility with other packages.
// Note: dependency.ID doesn't include Version; version is embedded in the PURL.
func (n *Node) ToID() dependency.ID {
	return dependency.ID{
		Name:      n.Name,
		Ecosystem: n.Ecosystem,
		PURL:      n.PURL,
	}
}
