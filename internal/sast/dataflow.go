package sast

import (
	"container/list"
	"strings"
)

// TaintKind classifies taint flows so separate analyses (command injection,
// XSS, SSRF) can run concurrently.
type TaintKind string

// SourceMatcher describes how to match taint sources in the graph.
type SourceMatcher struct {
	Dialect string
	Package string
	Symbol  string
}

// SinkMatcher describes how to match sinks; BlockIfSanitized prevents flows
// when a sanitizer is observed on the path.
type SinkMatcher struct {
	Dialect    string
	Package    string
	Symbol     string
	Sanitizers []SourceMatcher
}

// PropagatorMatcher allows widening taint across intermediate functions.
type PropagatorMatcher struct {
	Dialect string
	Package string
	Symbol  string
}

// TaintConfig groups configuration for a specific taint analysis run.
type TaintConfig struct {
	Kind        TaintKind
	Sources     []SourceMatcher
	Sinks       []SinkMatcher
	Propagators []PropagatorMatcher
	MaxDepth    int
}

// TaintFlow represents a single flow from a source to a sink including the
// traversed path.
type TaintFlow struct {
	Kind   TaintKind
	Source SymbolID
	Sink   SymbolID
	Path   []SymbolID
}

// TaintEngine executes taint propagation on a graph snapshot.
type TaintEngine struct {
	snapshot Snapshot
}

// NewTaintEngine constructs a taint engine for the provided snapshot.
func NewTaintEngine(snapshot Snapshot) *TaintEngine {
	return &TaintEngine{snapshot: snapshot}
}

// Analyze runs taint analysis with the provided configuration and returns flows.
func (e *TaintEngine) Analyze(cfg TaintConfig) []TaintFlow {
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = 25
	}
	sources := e.matchSources(cfg.Sources)
	if len(sources) == 0 {
		return nil
	}
	sinks := e.matchSinks(cfg.Sinks)
	if len(sinks) == 0 {
		return nil
	}
	propagators := e.matchSet(cfg.Propagators)

	flows := []TaintFlow{}
	for _, source := range sources {
		flowPaths := e.propagate(cfg, source, sinks, propagators)
		flows = append(flows, flowPaths...)
	}
	return dedupeFlows(flows)
}

func (e *TaintEngine) matchSources(matchers []SourceMatcher) []SymbolID {
	if len(matchers) == 0 {
		return nil
	}
	var ids []SymbolID
	symbols := e.snapshot.Symbols()
	for _, sym := range symbols {
		for _, m := range matchers {
			if matchSymbol(sym.ID, m.Dialect, m.Package, m.Symbol) {
				ids = append(ids, sym.ID)
				break
			}
		}
	}
	return ids
}

func (e *TaintEngine) matchSinks(matchers []SinkMatcher) map[string]SinkMatcher {
	out := make(map[string]SinkMatcher)
	symbols := e.snapshot.Symbols()
	for _, sym := range symbols {
		for _, m := range matchers {
			if matchSymbol(sym.ID, m.Dialect, m.Package, m.Symbol) {
				out[sym.ID.String()] = m
				break
			}
		}
	}
	return out
}

func (e *TaintEngine) matchSet(matchers []PropagatorMatcher) map[string]struct{} {
	set := make(map[string]struct{})
	if len(matchers) == 0 {
		return set
	}
	symbols := e.snapshot.Symbols()
	for _, sym := range symbols {
		for _, m := range matchers {
			if matchSymbol(sym.ID, m.Dialect, m.Package, m.Symbol) {
				set[sym.ID.String()] = struct{}{}
				break
			}
		}
	}
	return set
}

func matchSymbol(id SymbolID, dialect, pkg, name string) bool {
	if dialect != "" && !strings.EqualFold(id.Dialect, dialect) {
		return false
	}
	if pkg != "" && !strings.Contains(id.Package, pkg) {
		return false
	}
	if name != "" && !strings.EqualFold(id.Name, name) {
		return false
	}
	return true
}

func (e *TaintEngine) propagate(cfg TaintConfig, source SymbolID, sinks map[string]SinkMatcher, propagators map[string]struct{}) []TaintFlow {
	type frame struct {
		id    SymbolID
		path  []SymbolID
		depth int
	}
	queue := list.New()
	queue.PushBack(frame{id: source, path: []SymbolID{source}})
	visited := map[string]int{source.String(): 0}
	flows := []TaintFlow{}

	for queue.Len() > 0 {
		elem := queue.Front()
		queue.Remove(elem)
		current := elem.Value.(frame)
		if current.depth >= cfg.MaxDepth {
			continue
		}
		if sinkMatcher, ok := sinks[current.id.String()]; ok {
			if !e.pathSanitized(current.path, sinkMatcher.Sanitizers) {
				flows = append(flows, TaintFlow{Kind: cfg.Kind, Source: source, Sink: current.id, Path: current.path})
			}
			continue
		}
		for _, edge := range e.snapshot.OutgoingEdges(EdgeKindCall, current.id) {
			if edge.Attributes.Confidence == EdgeConfidencePossible && !allowPossible(edge, propagators) {
				continue
			}
			nextDepth := current.depth + 1
			if prevDepth, ok := visited[edge.To.String()]; ok && prevDepth <= nextDepth {
				continue
			}
			visited[edge.To.String()] = nextDepth
			path := append([]SymbolID(nil), current.path...)
			path = append(path, edge.To)
			queue.PushBack(frame{id: edge.To, path: path, depth: nextDepth})
		}
	}

	return flows
}

func allowPossible(edge Edge, propagators map[string]struct{}) bool {
	if len(propagators) == 0 {
		return true
	}
	if _, ok := propagators[edge.To.String()]; ok {
		return true
	}
	if _, ok := propagators[edge.From.String()]; ok {
		return true
	}
	return false
}

func (e *TaintEngine) pathSanitized(path []SymbolID, sanitizers []SourceMatcher) bool {
	if len(sanitizers) == 0 {
		return false
	}
	for _, id := range path {
		for _, s := range sanitizers {
			if matchSymbol(id, s.Dialect, s.Package, s.Symbol) {
				return true
			}
		}
	}
	return false
}

func dedupeFlows(in []TaintFlow) []TaintFlow {
	if len(in) <= 1 {
		return in
	}
	seen := make(map[string]TaintFlow)
	for _, flow := range in {
		key := flow.Source.String() + "->" + flow.Sink.String() + "::" + string(flow.Kind)
		if existing, ok := seen[key]; ok {
			if len(flow.Path) < len(existing.Path) {
				seen[key] = flow
			}
			continue
		}
		seen[key] = flow
	}
	out := make([]TaintFlow, 0, len(seen))
	for _, flow := range seen {
		out = append(out, flow)
	}
	return out
}
