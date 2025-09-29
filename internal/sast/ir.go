package sast

import (
	"fmt"
	"sort"
	"sync"
)

// SymbolKind distinguishes the semantic category of a symbol. The engine keeps
// the set relatively small; dialects can attach richer semantics via symbol
// attributes.
type SymbolKind string

const (
	SymbolKindFunction SymbolKind = "function"
	SymbolKindMethod   SymbolKind = "method"
	SymbolKindType     SymbolKind = "type"
	SymbolKindPackage  SymbolKind = "package"
	SymbolKindField    SymbolKind = "field"
	SymbolKindCallsite SymbolKind = "callsite"
)

// Location represents a best-effort mapping back to source code positions.
// Line and Column are 1-based to align with Go tooling conventions.
type Location struct {
	File   string
	Line   int
	Column int
}

// SymbolID canonicalises symbol identity across dialects. Dialects should
// ensure that two symbols with the same ID represent the same logical entity.
type SymbolID struct {
	Dialect string
	Package string
	Name    string
	Recv    string
}

// String returns a stable string form safe for use as a map key.
func (id SymbolID) String() string {
	if id.Recv != "" {
		return fmt.Sprintf("%s::%s.%s.%s", id.Dialect, id.Package, id.Recv, id.Name)
	}
	return fmt.Sprintf("%s::%s.%s", id.Dialect, id.Package, id.Name)
}

// Symbol holds metadata for the logical entity represented in the IR.
type Symbol struct {
	ID         SymbolID
	Kind       SymbolKind
	Display    string
	Locations  []Location
	Attributes map[string]any
}

// EdgeKind classifies relationships between symbols. Call edges power
// reachability, while import or inheritance edges can be leveraged by more
// advanced analyses.
type EdgeKind string

const (
	EdgeKindCall     EdgeKind = "call"
	EdgeKindImport   EdgeKind = "import"
	EdgeKindContains EdgeKind = "contains"
)

// EdgeConfidence expresses how certain the analysis is that an edge represents
// a real control flow transfer.
type EdgeConfidence string

const (
	EdgeConfidenceUnknown  EdgeConfidence = ""
	EdgeConfidenceCertain  EdgeConfidence = "certain"
	EdgeConfidenceProbable EdgeConfidence = "probable"
	EdgeConfidencePossible EdgeConfidence = "possible"
)

func confidenceWeight(c EdgeConfidence) int {
	switch c {
	case EdgeConfidenceCertain:
		return 3
	case EdgeConfidenceProbable:
		return 2
	case EdgeConfidencePossible:
		return 1
	default:
		return 0
	}
}

// EdgeAttributes records additional metadata for a graph edge.
type EdgeAttributes struct {
	Confidence EdgeConfidence
	Metadata   map[string]any
}

func (a EdgeAttributes) normalized() EdgeAttributes {
	out := a
	if out.Confidence == EdgeConfidenceUnknown {
		out.Confidence = EdgeConfidenceCertain
	}
	if out.Metadata == nil {
		out.Metadata = nil
	}
	return out
}

func (a EdgeAttributes) dominates(b EdgeAttributes) bool {
	return confidenceWeight(a.Confidence) > confidenceWeight(b.Confidence)
}

func (a EdgeAttributes) clone() EdgeAttributes {
	clone := a.normalized()
	if len(clone.Metadata) == 0 {
		return clone
	}
	copyMap := make(map[string]any, len(clone.Metadata))
	for k, v := range clone.Metadata {
		copyMap[k] = v
	}
	clone.Metadata = copyMap
	return clone
}

func mergeMetadata(dst map[string]any, src map[string]any) map[string]any {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = make(map[string]any, len(src))
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// Edge represents an immutable edge inside a snapshot.
type Edge struct {
	Kind       EdgeKind
	From       SymbolID
	To         SymbolID
	Attributes EdgeAttributes
}

// symbolNode tracks outgoing edges for a symbol inside a Graph.
type symbolNode struct {
	symbol Symbol
	edges  map[EdgeKind]map[string]EdgeAttributes
}

// Graph is a concurrent safe property graph over symbols. Dialects merge their
// graphs into an Engine level graph which is then used for reachability
// analysis.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]*symbolNode
}

// NewGraph allocates an empty graph instance.
func NewGraph() *Graph {
	return &Graph{nodes: make(map[string]*symbolNode)}
}

// AddSymbol inserts or updates a symbol. The latest non-empty display name wins
// to favor user friendly labels.
func (g *Graph) AddSymbol(symbol Symbol) Symbol {
	g.mu.Lock()
	defer g.mu.Unlock()
	key := symbol.ID.String()
	n, ok := g.nodes[key]
	if !ok {
		g.nodes[key] = &symbolNode{
			symbol: symbol,
			edges:  make(map[EdgeKind]map[string]EdgeAttributes),
		}
		return symbol
	}
	if symbol.Display != "" {
		n.symbol.Display = symbol.Display
	}
	if symbol.Kind != "" {
		n.symbol.Kind = symbol.Kind
	}
	if len(symbol.Locations) > 0 {
		n.symbol.Locations = append(n.symbol.Locations, symbol.Locations...)
	}
	if symbol.Attributes != nil {
		if n.symbol.Attributes == nil {
			n.symbol.Attributes = make(map[string]any, len(symbol.Attributes))
		}
		for k, v := range symbol.Attributes {
			n.symbol.Attributes[k] = v
		}
	}
	return n.symbol
}

// AddEdge records a relationship without additional attributes.
func (g *Graph) AddEdge(kind EdgeKind, from, to SymbolID) {
	g.AddEdgeWithAttributes(kind, from, to, EdgeAttributes{})
}

// AddEdgeWithAttributes records a relationship together with analysis metadata.
func (g *Graph) AddEdgeWithAttributes(kind EdgeKind, from, to SymbolID, attrs EdgeAttributes) {
	g.mu.Lock()
	defer g.mu.Unlock()
	fromNode := g.ensureNode(from)
	toNode := g.ensureNode(to)
	normalized := attrs.normalized().clone()
	if _, ok := fromNode.edges[kind]; !ok {
		fromNode.edges[kind] = make(map[string]EdgeAttributes)
	}
	existing, ok := fromNode.edges[kind][toNode.symbol.ID.String()]
	if !ok {
		fromNode.edges[kind][toNode.symbol.ID.String()] = normalized
		return
	}
	existing = existing.normalized()
	if normalized.dominates(existing) {
		normalized.Metadata = mergeMetadata(normalized.Metadata, existing.Metadata)
		fromNode.edges[kind][toNode.symbol.ID.String()] = normalized
		return
	}
	if confidenceWeight(normalized.Confidence) == confidenceWeight(existing.Confidence) {
		existing.Metadata = mergeMetadata(existing.Metadata, normalized.Metadata)
		fromNode.edges[kind][toNode.symbol.ID.String()] = existing
	}
}

// ensureNode creates a placeholder symbol if required.
func (g *Graph) ensureNode(id SymbolID) *symbolNode {
	key := id.String()
	n, ok := g.nodes[key]
	if ok {
		return n
	}
	n = &symbolNode{symbol: Symbol{ID: id}, edges: make(map[EdgeKind]map[string]EdgeAttributes)}
	g.nodes[key] = n
	return n
}

// Merge unionises another graph into the receiver. Metadata follows the same
// rules as AddSymbol/AddEdgeWithAttributes.
func (g *Graph) Merge(other *Graph) {
	if other == nil {
		return
	}
	other.mu.RLock()
	defer other.mu.RUnlock()
	for _, n := range other.nodes {
		g.AddSymbol(n.symbol)
		for kind, edges := range n.edges {
			for id, attrs := range edges {
				from := n.symbol.ID
				toNode := other.nodes[id]
				if toNode == nil {
					continue
				}
				g.AddEdgeWithAttributes(kind, from, toNode.symbol.ID, attrs)
			}
		}
	}
}

// Snapshot creates an immutable view of the graph useful for long running
// traversals without holding internal locks.
type Snapshot struct {
	symbols map[string]Symbol
	edges   map[string]map[EdgeKind][]Edge
}

// Snapshot returns the current graph state without blocking writers for the
// duration of the traversal.
func (g *Graph) Snapshot() Snapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	s := Snapshot{
		symbols: make(map[string]Symbol, len(g.nodes)),
		edges:   make(map[string]map[EdgeKind][]Edge, len(g.nodes)),
	}
	for id, node := range g.nodes {
		s.symbols[id] = node.symbol
		if len(node.edges) == 0 {
			continue
		}
		edgeMap := make(map[EdgeKind][]Edge, len(node.edges))
		for kind, successors := range node.edges {
			edges := make([]Edge, 0, len(successors))
			for succ, attrs := range successors {
				if target, ok := g.nodes[succ]; ok {
					edges = append(edges, Edge{
						Kind:       kind,
						From:       node.symbol.ID,
						To:         target.symbol.ID,
						Attributes: attrs.clone(),
					})
				}
			}
			sort.Slice(edges, func(i, j int) bool {
				if edges[i].To.String() == edges[j].To.String() {
					return confidenceWeight(edges[i].Attributes.Confidence) > confidenceWeight(edges[j].Attributes.Confidence)
				}
				return edges[i].To.String() < edges[j].To.String()
			})
			edgeMap[kind] = edges
		}
		s.edges[id] = edgeMap
	}
	return s
}

// Symbols exposes all symbols in a snapshot.
func (s Snapshot) Symbols() []Symbol {
	out := make([]Symbol, 0, len(s.symbols))
	for _, sym := range s.symbols {
		out = append(out, sym)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ID.String() < out[j].ID.String()
	})
	return out
}

// Successors returns the ordered successor list for the given symbol ID and
// edge kind. Missing entries yield an empty slice.
func (s Snapshot) Successors(kind EdgeKind, id SymbolID) []SymbolID {
	key := id.String()
	edgeMap, ok := s.edges[key]
	if !ok {
		return nil
	}
	edges := edgeMap[kind]
	out := make([]SymbolID, 0, len(edges))
	for _, edge := range edges {
		out = append(out, edge.To)
	}
	return out
}

// OutgoingEdges returns the detailed edge list for a symbol and kind.
func (s Snapshot) OutgoingEdges(kind EdgeKind, id SymbolID) []Edge {
	key := id.String()
	if edgeMap, ok := s.edges[key]; ok {
		return edgeMap[kind]
	}
	return nil
}

// Symbol returns the symbol metadata for the provided ID, or false when the ID
// is unknown to the snapshot.
func (s Snapshot) Symbol(id SymbolID) (Symbol, bool) {
	sym, ok := s.symbols[id.String()]
	return sym, ok
}
