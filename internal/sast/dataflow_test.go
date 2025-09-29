package sast

import "testing"

func TestTaintEngineSimpleFlow(t *testing.T) {
	graph := NewGraph()
	source := SymbolID{Dialect: "ruby", Package: "app", Name: "source"}
	mid := SymbolID{Dialect: "ruby", Package: "app", Name: "mid"}
	sink := SymbolID{Dialect: "ruby", Package: "app", Name: "sink"}

	graph.AddSymbol(Symbol{ID: source})
	graph.AddSymbol(Symbol{ID: mid})
	graph.AddSymbol(Symbol{ID: sink})
	graph.AddEdgeWithAttributes(EdgeKindCall, source, mid, EdgeAttributes{Confidence: EdgeConfidenceCertain})
	graph.AddEdgeWithAttributes(EdgeKindCall, mid, sink, EdgeAttributes{Confidence: EdgeConfidenceProbable})

	snapshot := graph.Snapshot()
	engine := NewTaintEngine(snapshot)
	cfg := TaintConfig{
		Kind:    TaintKind("poc"),
		Sources: []SourceMatcher{{Dialect: "ruby", Symbol: "source"}},
		Sinks:   []SinkMatcher{{Dialect: "ruby", Symbol: "sink"}},
	}
	flows := engine.Analyze(cfg)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	flow := flows[0]
	if flow.Source != source || flow.Sink != sink {
		t.Fatalf("unexpected flow %v", flow)
	}
	if len(flow.Path) != 3 {
		t.Fatalf("expected path length 3, got %d", len(flow.Path))
	}
}

func TestTaintEngineSanitizerStopsFlow(t *testing.T) {
	graph := NewGraph()
	source := SymbolID{Dialect: "ruby", Package: "app", Name: "params"}
	sanitizer := SymbolID{Dialect: "ruby", Package: "app", Name: "sanitize"}
	sink := SymbolID{Dialect: "ruby", Package: "app", Name: "render"}

	graph.AddSymbol(Symbol{ID: source})
	graph.AddSymbol(Symbol{ID: sanitizer})
	graph.AddSymbol(Symbol{ID: sink})
	graph.AddEdgeWithAttributes(EdgeKindCall, source, sanitizer, EdgeAttributes{Confidence: EdgeConfidenceCertain})
	graph.AddEdgeWithAttributes(EdgeKindCall, sanitizer, sink, EdgeAttributes{Confidence: EdgeConfidenceCertain})

	snapshot := graph.Snapshot()
	engine := NewTaintEngine(snapshot)
	cfg := TaintConfig{
		Kind:    TaintKind("xss"),
		Sources: []SourceMatcher{{Symbol: "params"}},
		Sinks:   []SinkMatcher{{Symbol: "render", Sanitizers: []SourceMatcher{{Symbol: "sanitize"}}}},
	}
	flows := engine.Analyze(cfg)
	if len(flows) != 0 {
		t.Fatalf("expected sanitizer to block flow")
	}
}

func TestTaintEngineParameterFlow(t *testing.T) {
	graph := NewGraph()
	callerParam := SymbolID{Dialect: "ruby", Package: "app", Name: "caller#param:0", Recv: "Caller"}
	calleeParam := SymbolID{Dialect: "ruby", Package: "app", Name: "callee#param:0", Recv: "Callee"}
	calleeMethod := SymbolID{Dialect: "ruby", Package: "app", Name: "callee", Recv: "Callee"}
	sink := SymbolID{Dialect: "ruby", Package: "app", Name: "danger", Recv: "Callee"}

	graph.AddSymbol(Symbol{ID: callerParam})
	graph.AddSymbol(Symbol{ID: calleeParam})
	graph.AddSymbol(Symbol{ID: calleeMethod})
	graph.AddSymbol(Symbol{ID: sink})

	graph.AddEdgeWithAttributes(EdgeKindCall, callerParam, calleeParam, EdgeAttributes{Confidence: EdgeConfidenceCertain, Metadata: map[string]any{"arg_flow": true, "from_index": 0, "to_index": 0}})
	graph.AddEdgeWithAttributes(EdgeKindCall, calleeParam, calleeMethod, EdgeAttributes{Confidence: EdgeConfidenceCertain})
	graph.AddEdgeWithAttributes(EdgeKindCall, calleeMethod, sink, EdgeAttributes{Confidence: EdgeConfidenceCertain})

	engine := NewTaintEngine(graph.Snapshot())
	cfg := TaintConfig{
		Kind:    TaintKind("param"),
		Sources: []SourceMatcher{{Symbol: "caller#param:0"}},
		Sinks:   []SinkMatcher{{Symbol: "danger"}},
	}
	flows := engine.Analyze(cfg)
	if len(flows) != 1 {
		t.Fatalf("expected flow via parameter mapping, got %d", len(flows))
	}
	if flows[0].Source != callerParam || flows[0].Sink != sink {
		t.Fatalf("unexpected flow %v", flows[0])
	}
}
