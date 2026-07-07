package mcp

import (
	"testing"

	"github.com/temporalio/deputy/internal/dependency/graph"
)

// TestGraphNodeProtoOmitsDepthForDisconnectedNodes pins the wire contract
// that a disconnected node carries no depth: the internal sentinel is not a
// distance and must not surface as one.
func TestGraphNodeProtoOmitsDepthForDisconnectedNodes(t *testing.T) {
	connected := graphNodeProto(&graph.Node{Name: "a", Depth: 2})
	if connected.Depth == nil || connected.GetDepth() != 2 {
		t.Fatalf("connected node depth = %v, want 2", connected.Depth)
	}
	disconnected := graphNodeProto(&graph.Node{Name: "b", Depth: graph.DepthDisconnected})
	if !disconnected.Disconnected {
		t.Fatal("expected disconnected marker")
	}
	if disconnected.Depth != nil {
		t.Fatalf("disconnected node depth = %d, want absent", disconnected.GetDepth())
	}
}
