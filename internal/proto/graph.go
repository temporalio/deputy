package proto

import (
	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	"github.com/picatz/deputy/internal/dependency/graph"
)

// ScopeToProto converts internal graph.Scope to proto graphv1.Scope.
func ScopeToProto(s graph.Scope) graphv1.Scope {
	switch s {
	case graph.ScopeRuntime:
		return graphv1.Scope_SCOPE_RUNTIME
	case graph.ScopeDev:
		return graphv1.Scope_SCOPE_DEV
	case graph.ScopeOptional:
		return graphv1.Scope_SCOPE_OPTIONAL
	case graph.ScopeBuild:
		return graphv1.Scope_SCOPE_BUILD
	case graph.ScopeTest:
		return graphv1.Scope_SCOPE_TEST
	default:
		return graphv1.Scope_SCOPE_UNSPECIFIED
	}
}

// ScopeFromProto converts proto graphv1.Scope to internal graph.Scope.
func ScopeFromProto(s graphv1.Scope) graph.Scope {
	switch s {
	case graphv1.Scope_SCOPE_RUNTIME:
		return graph.ScopeRuntime
	case graphv1.Scope_SCOPE_DEV:
		return graph.ScopeDev
	case graphv1.Scope_SCOPE_OPTIONAL:
		return graph.ScopeOptional
	case graphv1.Scope_SCOPE_BUILD:
		return graph.ScopeBuild
	case graphv1.Scope_SCOPE_TEST:
		return graph.ScopeTest
	default:
		return ""
	}
}

// NodeToProto converts an internal graph.Node to proto graphv1.Node.
func NodeToProto(n *graph.Node) *graphv1.Node {
	if n == nil {
		return nil
	}
	return &graphv1.Node{
		Purl:      n.PURL,
		Name:      n.Name,
		Version:   n.Version,
		Ecosystem: n.Ecosystem,
		Direct:    n.Direct,
		Depth:     int32(n.Depth),
		Locations: n.Locations,
		VulnCount: VulnCountToProto(n.VulnCount),
	}
}

// NodeFromProto converts a proto graphv1.Node to internal graph.Node.
func NodeFromProto(n *graphv1.Node) *graph.Node {
	if n == nil {
		return nil
	}
	return &graph.Node{
		PURL:      n.Purl,
		Name:      n.Name,
		Version:   n.Version,
		Ecosystem: n.Ecosystem,
		Direct:    n.Direct,
		Depth:     int(n.Depth),
		Locations: n.Locations,
		VulnCount: VulnCountFromProto(n.VulnCount),
	}
}

// NodesToProto converts a slice of internal nodes to proto.
func NodesToProto(nodes []*graph.Node) []*graphv1.Node {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]*graphv1.Node, len(nodes))
	for i, n := range nodes {
		out[i] = NodeToProto(n)
	}
	return out
}

// NodesFromProto converts proto nodes to internal nodes.
func NodesFromProto(nodes []*graphv1.Node) []*graph.Node {
	if len(nodes) == 0 {
		return nil
	}
	out := make([]*graph.Node, len(nodes))
	for i, n := range nodes {
		out[i] = NodeFromProto(n)
	}
	return out
}

// EdgeToProto converts an internal graph.Edge to proto graphv1.Edge.
func EdgeToProto(e *graph.Edge) *graphv1.Edge {
	if e == nil {
		return nil
	}
	return &graphv1.Edge{
		From:       e.From,
		To:         e.To,
		Constraint: e.Constraint,
		Scope:      ScopeToProto(e.Scope),
	}
}

// EdgeFromProto converts a proto graphv1.Edge to internal graph.Edge.
func EdgeFromProto(e *graphv1.Edge) *graph.Edge {
	if e == nil {
		return nil
	}
	return &graph.Edge{
		From:       e.From,
		To:         e.To,
		Constraint: e.Constraint,
		Scope:      ScopeFromProto(e.Scope),
	}
}

// EdgesToProto converts a slice of internal edges to proto.
func EdgesToProto(edges []*graph.Edge) []*graphv1.Edge {
	if len(edges) == 0 {
		return nil
	}
	out := make([]*graphv1.Edge, len(edges))
	for i, e := range edges {
		out[i] = EdgeToProto(e)
	}
	return out
}

// EdgesFromProto converts proto edges to internal edges.
func EdgesFromProto(edges []*graphv1.Edge) []*graph.Edge {
	if len(edges) == 0 {
		return nil
	}
	out := make([]*graph.Edge, len(edges))
	for i, e := range edges {
		out[i] = EdgeFromProto(e)
	}
	return out
}

// VulnCountToProto converts internal VulnCount to proto.
func VulnCountToProto(vc graph.VulnCount) *graphv1.VulnCount {
	return &graphv1.VulnCount{
		Critical: int32(vc.Critical),
		High:     int32(vc.High),
		Medium:   int32(vc.Medium),
		Low:      int32(vc.Low),
		Unknown:  int32(vc.Unknown),
		Total:    int32(vc.Total),
	}
}

// VulnCountFromProto converts proto VulnCount to internal.
func VulnCountFromProto(vc *graphv1.VulnCount) graph.VulnCount {
	if vc == nil {
		return graph.VulnCount{}
	}
	return graph.VulnCount{
		Critical: int(vc.Critical),
		High:     int(vc.High),
		Medium:   int(vc.Medium),
		Low:      int(vc.Low),
		Unknown:  int(vc.Unknown),
		Total:    int(vc.Total),
	}
}

// GraphStatsToProto converts internal graph.Stats to proto graphv1.GraphStats.
func GraphStatsToProto(s graph.Stats) *graphv1.GraphStats {
	ecosystems := make(map[string]int32)
	for k, v := range s.Ecosystems {
		ecosystems[k] = int32(v)
	}
	return &graphv1.GraphStats{
		TotalNodes:      int32(s.TotalNodes),
		DirectNodes:     int32(s.DirectNodes),
		TransitiveNodes: int32(s.TransitiveNodes),
		MaxDepth:        int32(s.MaxDepth),
		VulnerableNodes: int32(s.VulnerableNodes),
		Ecosystems:      ecosystems,
	}
}

// GraphStatsFromProto converts proto GraphStats to internal.
func GraphStatsFromProto(s *graphv1.GraphStats) graph.Stats {
	if s == nil {
		return graph.Stats{}
	}
	ecosystems := make(map[string]int)
	for k, v := range s.Ecosystems {
		ecosystems[k] = int(v)
	}
	return graph.Stats{
		TotalNodes:      int(s.TotalNodes),
		DirectNodes:     int(s.DirectNodes),
		TransitiveNodes: int(s.TransitiveNodes),
		MaxDepth:        int(s.MaxDepth),
		VulnerableNodes: int(s.VulnerableNodes),
		Ecosystems:      ecosystems,
	}
}

// PathToProto converts an internal graph.Path to proto graphv1.DependencyPath.
func PathToProto(p graph.Path) *graphv1.DependencyPath {
	if len(p) == 0 {
		return nil
	}
	nodes := make([]*graphv1.PathNode, len(p))
	for i, n := range p {
		nodes[i] = &graphv1.PathNode{
			Purl:    n.PURL,
			Name:    n.Name,
			Version: n.Version,
		}
	}
	return &graphv1.DependencyPath{
		Nodes:  nodes,
		Length: int32(p.Len()),
	}
}

// PathsToProto converts multiple paths to proto.
func PathsToProto(paths []graph.Path) []*graphv1.DependencyPath {
	if len(paths) == 0 {
		return nil
	}
	out := make([]*graphv1.DependencyPath, len(paths))
	for i, p := range paths {
		out[i] = PathToProto(p)
	}
	return out
}

// GraphToProto converts an entire graph to proto BuildGraphResponse fields.
// Returns nodes, edges, and roots for populating the response.
func GraphToProto(g *graph.Graph) (nodes []*graphv1.Node, edges []*graphv1.Edge, roots []string) {
	if g == nil {
		return nil, nil, nil
	}

	// Collect nodes
	for n := range g.NodesSorted() {
		nodes = append(nodes, NodeToProto(n))
	}

	// Collect edges
	for e := range g.Edges() {
		edges = append(edges, EdgeToProto(e))
	}

	// Collect roots
	for r := range g.Roots() {
		roots = append(roots, r.PURL)
	}

	return nodes, edges, roots
}
