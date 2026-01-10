package proto

import (
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	"github.com/picatz/deputy/internal/dependency/graph"
)

// Note: graph.Node, graph.Edge, graph.VulnerabilityCount, and graph.Scope are now
// type aliases for their graphv1 counterparts. Path conversion methods are
// now on the graph.Path type itself (ToProto, PathsToProto, etc.).

// DependencyGraphToScanProto converts a graph.Graph to scanv1.DependencyGraph.
// This is used when embedding the graph in ScanResponse.
func DependencyGraphToScanProto(g *graph.Graph) *scanv1.DependencyGraph {
	if g == nil {
		return nil
	}

	return &scanv1.DependencyGraph{
		Nodes: g.GetNodesSlice(),
		Edges: g.GetEdgesSlice(),
		Roots: g.GetRoots(),
		Stats: g.Stats(),
	}
}

// DependencyGraphFromScanProto converts scanv1.DependencyGraph to graph.Graph.
func DependencyGraphFromScanProto(dg *scanv1.DependencyGraph) *graph.Graph {
	if dg == nil {
		return nil
	}

	return graph.FromProto(dg.Nodes, dg.Edges, dg.Roots)
}
