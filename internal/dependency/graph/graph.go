// Package graph provides dependency graph operations.
//
// The graph package uses Protocol Buffer types from graphv1 as its internal
// representation, enabling seamless serialization and RPC without conversion.
// The Graph struct provides utility methods for traversal, filtering, and analysis.
package graph

import (
	"cmp"
	"context"
	"iter"
	"maps"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Re-export proto types for convenience.
// These allow consumers to use graph.Node instead of graphv1.Node.
type (
	Node               = graphv1.Node
	Edge               = graphv1.Edge
	VulnerabilityCount = graphv1.VulnerabilityCount
	Scope              = graphv1.Scope
)

// Scope constants re-exported from proto for convenience.
const (
	ScopeUnspecified = graphv1.Scope_SCOPE_UNSPECIFIED
	ScopeRuntime     = graphv1.Scope_SCOPE_RUNTIME
	ScopeDev         = graphv1.Scope_SCOPE_DEV
	ScopeOptional    = graphv1.Scope_SCOPE_OPTIONAL
	ScopeBuild       = graphv1.Scope_SCOPE_BUILD
	ScopeTest        = graphv1.Scope_SCOPE_TEST
)

// Depth constants for node positioning in the dependency graph.
const (
	// DepthSyntheticRoot marks synthetic root nodes (e.g., the main module itself).
	// These nodes represent the project being scanned rather than actual dependencies.
	DepthSyntheticRoot int32 = -1

	// DepthDisconnected marks nodes with no path from any root.
	// This typically means the node was discovered (e.g., in go.sum or a binary)
	// but no dependency path could be resolved to it.
	DepthDisconnected int32 = 999
)

// ecosystemFromPURLType returns the ecosystem display name for PURL types that
// OSV-SCALIBR doesn't handle (returns empty string). This fills gaps for
// ecosystems like GitHub Actions that Deputy supports but SCALIBR doesn't.
// The name comes from the ecosystem registry so graph nodes carry the same
// spelling as the rest of Deputy.
func ecosystemFromPURLType(purlType string) string {
	if purlType == purlx.TypeGitHubActions {
		return ecosystem.Display(ecosystem.GitHubActions)
	}
	return ""
}

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
// It uses proto types internally for seamless serialization.
type Graph struct {
	nodes map[string]*Node // keyed by PURL
	edges []*Edge
	roots []string // PURLs of direct dependencies

	// Adjacency caches for O(1) lookups (built lazily on first access)
	childrenIndex map[string][]string // PURL -> list of child PURLs
	parentsIndex  map[string][]string // PURL -> list of parent PURLs

	// packages stores the original extractor packages for nodes that have them.
	// This is not serialized but allows access to the underlying package data.
	packages map[string]*extractor.Package
}

// Path represents a sequence of nodes from root to target.
type Path []*Node

// String returns a human-readable representation of the path.
func (p Path) String() string {
	if len(p) == 0 {
		return ""
	}
	var result strings.Builder
	result.WriteString(p[0].GetName())
	for _, n := range p[1:] {
		result.WriteString(" -> " + n.GetName())
	}
	return result.String()
}

// PURLs returns the PURLs of all nodes in the path.
func (p Path) PURLs() []string {
	purls := make([]string, len(p))
	for i, n := range p {
		purls[i] = n.GetPurl()
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
		if n.GetPurl() == purl {
			return true
		}
	}
	return false
}

// ToProto converts a Path to a graphv1.DependencyPath proto message.
func (p Path) ToProto() *graphv1.DependencyPath {
	if len(p) == 0 {
		return nil
	}
	nodes := make([]*graphv1.PathNode, len(p))
	for i, n := range p {
		nodes[i] = &graphv1.PathNode{
			Purl:    n.GetPurl(),
			Name:    n.GetName(),
			Version: n.GetVersion(),
		}
	}
	return &graphv1.DependencyPath{
		Nodes:  nodes,
		Length: int32(p.Len()),
	}
}

// PathsToProto converts multiple paths to proto DependencyPath messages.
func PathsToProto(paths []Path) []*graphv1.DependencyPath {
	if len(paths) == 0 {
		return nil
	}
	out := make([]*graphv1.DependencyPath, len(paths))
	for i, p := range paths {
		out[i] = p.ToProto()
	}
	return out
}

// PathFromProto converts a proto DependencyPath to a Path.
func PathFromProto(p *graphv1.DependencyPath) Path {
	if p == nil || len(p.Nodes) == 0 {
		return nil
	}
	path := make(Path, len(p.Nodes))
	for i, n := range p.Nodes {
		path[i] = &Node{
			Purl:    n.Purl,
			Name:    n.Name,
			Version: n.Version,
		}
	}
	return path
}

// PathsFromProto converts proto DependencyPaths to a Path slice.
func PathsFromProto(paths []*graphv1.DependencyPath) []Path {
	if len(paths) == 0 {
		return nil
	}
	out := make([]Path, len(paths))
	for i, p := range paths {
		out[i] = PathFromProto(p)
	}
	return out
}

// New creates an empty graph.
func New() *Graph {
	return &Graph{
		nodes:    make(map[string]*Node),
		packages: make(map[string]*extractor.Package),
	}
}

// FromInventory constructs a graph from inventory extraction results.
// The direct map indicates which packages are direct dependencies. For Go packages,
// the map keys are module roots (e.g., "github.com/google/osv-scalibr"). For other
// ecosystems, keys are PURL strings.
func FromInventory(pkgs []*extractor.Package, direct map[string]bool) *Graph {
	g := New()

	for _, pkg := range pkgs {
		purlObj := pkg.PURL()
		if purlObj == nil {
			continue
		}
		if purlObj.Type == "golang" && compare.IsRelativePathModule(goPackageModulePath(pkg, purlObj.Namespace, purlObj.Name)) {
			continue
		}
		purl := purlObj.String()
		if purl == "" {
			continue
		}

		isDirect := false
		if direct != nil {
			// For Go packages, check both exact module path and module root.
			// The direct map may contain:
			//   - Exact module paths with true (direct) or false (indirect)
			//   - Module roots with true (for subpackage matching)
			//
			// We first check the exact module path, then fall back to module root.
			// This handles Go submodules correctly: if go.mod has "foo" as direct
			// but "foo/loader" as indirect, "foo/loader" should be indirect.
			if purlObj.Type == "golang" {
				// Reconstruct module path from PURL namespace + name
				modulePath := goPackageModulePath(pkg, purlObj.Namespace, purlObj.Name)
				// First check exact module path (handles submodules correctly)
				if val, exists := direct[modulePath]; exists {
					isDirect = val
				} else {
					// Fall back to module root for subpackage import paths
					moduleRoot := compare.GetModuleRoot(modulePath)
					isDirect = direct[moduleRoot]
				}
			} else {
				// For non-Go ecosystems, use PURL string as key
				isDirect = direct[purl]
			}
		}

		var depth int32 = 1
		if isDirect {
			depth = 0
		}

		// Get ecosystem from SCALIBR, falling back to custom mapping for
		// PURL types SCALIBR doesn't recognize (e.g., GitHub Actions)
		ecosystem := pkg.Ecosystem().String()
		if ecosystem == "" {
			ecosystem = ecosystemFromPURLType(purlObj.Type)
		}

		node := &Node{
			Purl:      purl,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: ecosystem,
			Direct:    isDirect,
			Depth:     depth,
			Locations: dependency.PackagePaths(pkg),
		}

		g.nodes[purl] = node
		g.packages[purl] = pkg

		if isDirect {
			g.roots = append(g.roots, purl)
		}
	}

	return g
}

func goPackageModulePath(pkg *extractor.Package, namespace, name string) string {
	if pkg != nil && pkg.Name != "" {
		return pkg.Name
	}
	if namespace != "" {
		return namespace + "/" + name
	}
	return name
}

// AddNode adds a node to the graph. If a node with the same PURL exists, it is replaced.
func (g *Graph) AddNode(n *Node) {
	if n == nil || n.GetPurl() == "" {
		return
	}
	g.nodes[n.GetPurl()] = n
	if n.GetDirect() {
		// Check if already in roots
		if slices.Contains(g.roots, n.GetPurl()) {
			return
		}
		g.roots = append(g.roots, n.GetPurl())
	}
}

// AddEdge adds an edge to the graph.
func (g *Graph) AddEdge(e *Edge) {
	if e == nil || e.GetFrom() == "" || e.GetTo() == "" {
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
		g.childrenIndex[e.GetFrom()] = append(g.childrenIndex[e.GetFrom()], e.GetTo())
		g.parentsIndex[e.GetTo()] = append(g.parentsIndex[e.GetTo()], e.GetFrom())
	}
}

// Node returns the node with the given PURL, or nil if not found.
func (g *Graph) Node(purl string) *Node {
	return g.nodes[purl]
}

// Package returns the underlying extractor package for a node, if available.
func (g *Graph) Package(purl string) *extractor.Package {
	return g.packages[purl]
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
			if n.GetDirect() {
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
			if !n.GetDirect() {
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
				if visited[child.GetPurl()] {
					continue
				}
				visited[child.GetPurl()] = true
				if !yield(child) {
					return false
				}
				if !visit(child.GetPurl()) {
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
				if visited[parent.GetPurl()] {
					continue
				}
				visited[parent.GetPurl()] = true
				if !yield(parent) {
					return false
				}
				if !visit(parent.GetPurl()) {
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

		if node.GetDirect() {
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
			if pathContains(current.path, parent.GetPurl()) {
				continue
			}
			newPath := make([]*Node, len(current.path)+1)
			copy(newPath, current.path)
			newPath[len(current.path)] = parent
			queue = append(queue, pathState{purl: parent.GetPurl(), path: newPath})
		}
	}

	// If no edges exist, check if target is a direct dependency
	if len(paths) == 0 && g.nodes[target] != nil && g.nodes[target].GetDirect() {
		paths = append(paths, Path{g.nodes[target]})
	}

	return paths
}

func pathContains(path []*Node, purl string) bool {
	for _, n := range path {
		if n.GetPurl() == purl {
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
			if pathContains(newPath, child.GetPurl()) {
				continue
			}
			dfs(child.GetPurl(), newPath)
		}
	}

	dfs(source, nil)
	return paths
}

// Stats returns statistics about the graph as a proto message.
func (g *Graph) Stats() *graphv1.GraphStats {
	stats := &graphv1.GraphStats{
		TotalNodes: int32(len(g.nodes)),
		Ecosystems: make(map[string]int32),
	}

	// Track import status counts (only populated in extended mode)
	var hasImportStatus bool
	importCounts := &graphv1.ImportStatusCounts{}

	for _, n := range g.nodes {
		depth := n.GetDepth()

		if n.GetDirect() {
			stats.DirectNodes++
		} else {
			stats.TransitiveNodes++
		}

		// Track max resolved depth. Disconnected nodes carry the internal
		// DepthDisconnected sentinel and synthetic roots carry -1; neither is a
		// dependency depth, so neither may leak into the reported maximum.
		if depth != DepthDisconnected && depth >= 0 && depth > stats.MaxDepth {
			stats.MaxDepth = depth
		}

		// Count disconnected nodes
		if depth == DepthDisconnected {
			stats.DisconnectedNodes++
		}

		if n.GetVulnerabilityCount().GetTotal() > 0 {
			stats.VulnerableNodes++
		}

		if eco := n.GetEcosystem(); eco != "" {
			stats.Ecosystems[eco]++
		}

		// Count import statuses (extended mode feature)
		switch n.GetImportStatus() {
		case graphv1.ImportStatus_IMPORT_STATUS_IMPORTED:
			importCounts.Imported++
			hasImportStatus = true
		case graphv1.ImportStatus_IMPORT_STATUS_REQUIRED:
			importCounts.Required++
			hasImportStatus = true
		case graphv1.ImportStatus_IMPORT_STATUS_DECLARED:
			importCounts.Declared++
			hasImportStatus = true
		}
	}

	// Only include import status counts if any nodes have import status set
	if hasImportStatus {
		stats.ImportStatusCounts = importCounts
	}

	// Kept equal to MaxDepth for wire compatibility with releases where
	// max_depth still included the disconnected sentinel.
	stats.MaxConnectedDepth = stats.MaxDepth

	return stats
}

// VulnerableNodes returns an iterator over nodes that have vulnerabilities.
func (g *Graph) VulnerableNodes() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for _, n := range g.nodes {
			if n.GetVulnerabilityCount().GetTotal() > 0 {
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
		for _, path := range g.PathsTo(vuln.GetPurl()) {
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
		names[i] = node.GetName()
	}
	return strings.Join(names, "→")
}

// AnnotateVulns adds vulnerability information to graph nodes.
func (g *Graph) AnnotateVulns(findings []vulnerability.Finding, advisories map[string]*vulnerabilityv1.Advisory) {
	// Group findings by PURL
	vulnsByPURL := make(map[string][]vulnerability.Finding)
	for _, f := range findings {
		purl := f.Dependency.PURL
		vulnsByPURL[purl] = append(vulnsByPURL[purl], f)
	}

	// Apply to nodes
	for purl, vulns := range vulnsByPURL {
		if node := g.nodes[purl]; node != nil {
			node.VulnerabilityCount = countVulns(vulns, advisories)
		}
	}
}

func countVulns(findings []vulnerability.Finding, advisories map[string]*vulnerabilityv1.Advisory) *VulnerabilityCount {
	count := &VulnerabilityCount{Total: int32(len(findings))}

	for _, f := range findings {
		adv, ok := advisories[f.AdvisoryID]
		if !ok {
			count.Unknown++
			continue
		}

		if adv.Severity == nil {
			count.Unknown++
			continue
		}

		switch adv.Severity.Level {
		case vulnerability.SeverityCritical:
			count.Critical++
		case vulnerability.SeverityHigh:
			count.High++
		case vulnerability.SeverityMedium:
			count.Medium++
		case vulnerability.SeverityLow:
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
			if pkg := g.packages[n.GetPurl()]; pkg != nil {
				filtered.packages[n.GetPurl()] = pkg
			}
		}
	}

	for _, e := range g.edges {
		if filtered.nodes[e.GetFrom()] != nil && filtered.nodes[e.GetTo()] != nil {
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
	newRoot := CloneNode(rootNode)
	newRoot.Direct = true
	sub.AddNode(newRoot)
	if pkg := g.packages[root]; pkg != nil {
		sub.packages[root] = pkg
	}

	// Add all descendants
	for desc := range g.Descendants(root) {
		sub.AddNode(desc)
		if pkg := g.packages[desc.GetPurl()]; pkg != nil {
			sub.packages[desc.GetPurl()] = pkg
		}
	}

	// Add relevant edges
	for _, e := range g.edges {
		if sub.nodes[e.GetFrom()] != nil && sub.nodes[e.GetTo()] != nil {
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
		clone.AddNode(CloneNode(n))
	}

	// Copy package references (shallow)
	maps.Copy(clone.packages, g.packages)

	for _, e := range g.edges {
		clone.AddEdge(CloneEdge(e))
	}

	return clone
}

// CloneNode creates a deep copy of a node.
func CloneNode(n *Node) *Node {
	if n == nil {
		return nil
	}
	clone := &Node{
		Purl:      n.Purl,
		Name:      n.Name,
		Version:   n.Version,
		Ecosystem: n.Ecosystem,
		Direct:    n.Direct,
		Depth:     n.Depth,
	}
	if n.Locations != nil {
		clone.Locations = slices.Clone(n.Locations)
	}
	if n.VulnerabilityCount != nil {
		clone.VulnerabilityCount = &VulnerabilityCount{
			Critical: n.VulnerabilityCount.Critical,
			High:     n.VulnerabilityCount.High,
			Medium:   n.VulnerabilityCount.Medium,
			Low:      n.VulnerabilityCount.Low,
			Unknown:  n.VulnerabilityCount.Unknown,
			Total:    n.VulnerabilityCount.Total,
		}
	}
	if n.Vulnerabilities != nil {
		clone.Vulnerabilities = slices.Clone(n.Vulnerabilities)
	}
	return clone
}

// CloneEdge creates a copy of an edge.
func CloneEdge(e *Edge) *Edge {
	if e == nil {
		return nil
	}
	return &Edge{
		From:       e.From,
		To:         e.To,
		Constraint: e.Constraint,
		Scope:      e.Scope,
	}
}

// Sort returns nodes sorted by the given comparison function.
func (g *Graph) Sort(cmpFunc func(a, b *Node) int) []*Node {
	nodes := make([]*Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, n)
	}
	slices.SortFunc(nodes, cmpFunc)
	return nodes
}

// SortByVulns returns nodes sorted by vulnerability count (highest first).
func (g *Graph) SortByVulns() []*Node {
	return g.Sort(func(a, b *Node) int {
		// Sort by total vulns descending
		aTotal := a.GetVulnerabilityCount().GetTotal()
		bTotal := b.GetVulnerabilityCount().GetTotal()
		if aTotal != bTotal {
			return cmp.Compare(bTotal, aTotal)
		}
		// Then by critical
		aCrit := a.GetVulnerabilityCount().GetCritical()
		bCrit := b.GetVulnerabilityCount().GetCritical()
		if aCrit != bCrit {
			return cmp.Compare(bCrit, aCrit)
		}
		// Then by name for stability
		return cmp.Compare(a.GetName(), b.GetName())
	})
}

// SortByDepth returns nodes sorted by depth (direct first, then transitive).
func (g *Graph) SortByDepth() []*Node {
	return g.Sort(func(a, b *Node) int {
		if a.GetDepth() != b.GetDepth() {
			return cmp.Compare(a.GetDepth(), b.GetDepth())
		}
		return cmp.Compare(a.GetName(), b.GetName())
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
		if node.GetDirect() {
			node.Depth = 0
		} else {
			node.Depth = DepthSyntheticRoot // Mark as unvisited
		}
	}

	// BFS from all direct nodes to set depths
	visited := make(map[string]bool)
	type queueItem struct {
		purl  string
		depth int32
	}
	var queue []queueItem

	// Start from all direct nodes (depth 0)
	for node := range g.Nodes() {
		if node.GetDirect() {
			queue = append(queue, queueItem{node.GetPurl(), 0})
			visited[node.GetPurl()] = true
		}
	}

	// BFS traversal
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for child := range g.Children(current.purl) {
			if visited[child.GetPurl()] {
				continue
			}
			visited[child.GetPurl()] = true
			newDepth := current.depth + 1
			if child.Depth < 0 || newDepth < child.Depth {
				child.Depth = newDepth
			}
			queue = append(queue, queueItem{child.GetPurl(), newDepth})
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
func ToID(n *Node) dependency.ID {
	return dependency.ID{
		Name:      n.GetName(),
		Ecosystem: n.GetEcosystem(),
		PURL:      n.GetPurl(),
	}
}

// GetNodesSlice returns all nodes as a slice (for proto serialization).
func (g *Graph) GetNodesSlice() []*Node {
	nodes := make([]*Node, 0, len(g.nodes))
	for n := range g.NodesSorted() {
		nodes = append(nodes, n)
	}
	return nodes
}

// GetEdgesSlice returns all edges as a slice (for proto serialization).
func (g *Graph) GetEdgesSlice() []*Edge {
	return g.edges
}

// GetRoots returns the root PURLs (for proto serialization).
func (g *Graph) GetRoots() []string {
	return g.roots
}

// FromProto constructs a Graph from proto components.
// This is useful when deserializing a graph from RPC responses.
func FromProto(nodes []*Node, edges []*Edge, roots []string) *Graph {
	g := New()
	for _, n := range nodes {
		g.AddNode(n)
	}
	for _, e := range edges {
		g.AddEdge(e)
	}
	// Override roots if provided (some nodes may have Direct=true but not be in roots)
	if len(roots) > 0 {
		g.roots = roots
	}
	return g
}
