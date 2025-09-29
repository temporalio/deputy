package sast

import "testing"

func TestReachability(t *testing.T) {
	graph := NewGraph()
	entry := SymbolID{Dialect: "go", Package: "main", Name: "main"}
	a := SymbolID{Dialect: "go", Package: "main", Name: "a"}
	b := SymbolID{Dialect: "go", Package: "main", Name: "b"}

	graph.AddSymbol(Symbol{ID: entry, Kind: SymbolKindFunction})
	graph.AddSymbol(Symbol{ID: a, Kind: SymbolKindFunction})
	graph.AddSymbol(Symbol{ID: b, Kind: SymbolKindFunction})
	graph.AddEdge(EdgeKindCall, entry, a)
	graph.AddEdge(EdgeKindCall, a, b)

	snapshot := graph.Snapshot()
	cfg := ReachabilityConfig{Snapshot: snapshot, Edge: EdgeKindCall, Entrypoint: []SymbolID{entry}}

	res := Reachability(cfg, b)
	if !res.Reachable {
		t.Fatalf("expected b reachable")
	}
	if len(res.Path) != 3 {
		t.Fatalf("expected path length 3, got %d", len(res.Path))
	}
	res2 := Reachability(cfg, SymbolID{Dialect: "go", Package: "main", Name: "missing"})
	if res2.Reachable {
		t.Fatalf("expected missing to be unreachable")
	}
}
