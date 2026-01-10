package graph

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Format specifies the output format for graph rendering.
type Format string

const (
	// FormatDOT renders as Graphviz DOT format.
	FormatDOT Format = "dot"

	// FormatMermaid renders as Mermaid.js flowchart format.
	FormatMermaid Format = "mermaid"

	// FormatD3 renders as D3.js force-directed graph JSON.
	FormatD3 Format = "d3"

	// FormatText renders as ASCII tree format.
	FormatText Format = "text"

	// FormatJSON renders as JSON (full graph structure).
	FormatJSON Format = "json"
)

// RenderOption configures graph rendering behavior.
type RenderOption func(*renderConfig)

type renderConfig struct {
	maxDepth       int
	highlightVulns bool
	minSeverity    string
	filterPred     func(*Node) bool
	collapsed      map[string]bool
	showVersions   bool
	showVulnCounts bool
	direction      string // TB, LR, etc. for Mermaid/DOT
}

func defaultRenderConfig() *renderConfig {
	return &renderConfig{
		maxDepth:       -1, // unlimited
		showVersions:   true,
		showVulnCounts: true,
		direction:      "TB",
		collapsed:      make(map[string]bool),
	}
}

// WithMaxDepth limits rendering to nodes within the given depth from roots.
func WithMaxDepth(n int) RenderOption {
	return func(c *renderConfig) {
		c.maxDepth = n
	}
}

// WithHighlightVulns highlights vulnerable nodes in the output.
func WithHighlightVulns(minSeverity string) RenderOption {
	return func(c *renderConfig) {
		c.highlightVulns = true
		c.minSeverity = minSeverity
	}
}

// WithFilter includes only nodes matching the predicate.
func WithFilter(pred func(*Node) bool) RenderOption {
	return func(c *renderConfig) {
		c.filterPred = pred
	}
}

// WithCollapsed collapses subtrees rooted at the given PURLs.
func WithCollapsed(purls ...string) RenderOption {
	return func(c *renderConfig) {
		for _, p := range purls {
			c.collapsed[p] = true
		}
	}
}

// WithVersions controls whether versions are shown in node labels.
func WithVersions(show bool) RenderOption {
	return func(c *renderConfig) {
		c.showVersions = show
	}
}

// WithVulnCounts controls whether vulnerability counts are shown.
func WithVulnCounts(show bool) RenderOption {
	return func(c *renderConfig) {
		c.showVulnCounts = show
	}
}

// WithDirection sets the graph direction (TB, LR, BT, RL).
func WithDirection(dir string) RenderOption {
	return func(c *renderConfig) {
		c.direction = dir
	}
}

// Render writes the graph in the specified format.
func (g *Graph) Render(w io.Writer, format Format, opts ...RenderOption) error {
	cfg := defaultRenderConfig()
	for _, opt := range opts {
		opt(cfg)
	}

	switch format {
	case FormatDOT:
		return g.renderDOT(w, cfg)
	case FormatMermaid:
		return g.renderMermaid(w, cfg)
	case FormatD3:
		return g.renderD3(w, cfg)
	case FormatText:
		return g.renderText(w, cfg)
	case FormatJSON:
		return g.renderJSON(w, cfg)
	default:
		return fmt.Errorf("unsupported format: %s", format)
	}
}

// ToDOT returns the graph in Graphviz DOT format.
func (g *Graph) ToDOT(opts ...RenderOption) string {
	var b strings.Builder
	_ = g.Render(&b, FormatDOT, opts...)
	return b.String()
}

// ToMermaid returns the graph in Mermaid.js format.
func (g *Graph) ToMermaid(opts ...RenderOption) string {
	var b strings.Builder
	_ = g.Render(&b, FormatMermaid, opts...)
	return b.String()
}

// ToD3JSON returns the graph as D3.js force-directed JSON.
func (g *Graph) ToD3JSON(opts ...RenderOption) []byte {
	var b strings.Builder
	_ = g.Render(&b, FormatD3, opts...)
	return []byte(b.String())
}

// ToText returns the graph as an ASCII tree.
func (g *Graph) ToText(opts ...RenderOption) string {
	var b strings.Builder
	_ = g.Render(&b, FormatText, opts...)
	return b.String()
}

func (g *Graph) renderDOT(w io.Writer, cfg *renderConfig) error {
	fmt.Fprintf(w, "digraph dependencies {\n")
	fmt.Fprintf(w, "  rankdir=%s;\n", cfg.direction)
	fmt.Fprintf(w, "  node [shape=box, fontname=\"Helvetica\"];\n")
	fmt.Fprintf(w, "  edge [arrowsize=0.7];\n")
	fmt.Fprintf(w, "\n")

	nodes := g.filteredNodes(cfg)
	nodeIDs := make(map[string]string)

	// Generate node definitions
	for i, n := range nodes {
		id := fmt.Sprintf("n%d", i)
		nodeIDs[n.GetPurl()] = id

		label := g.nodeLabel(n, cfg)
		attrs := []string{fmt.Sprintf("label=%q", label)}

		// Styling based on vulnerability status
		if cfg.highlightVulns && n.GetVulnerabilityCount().GetTotal() > 0 {
			if n.GetVulnerabilityCount().GetCritical() > 0 {
				attrs = append(attrs, "color=red", "penwidth=2")
			} else if n.GetVulnerabilityCount().GetHigh() > 0 {
				attrs = append(attrs, "color=orange", "penwidth=2")
			} else {
				attrs = append(attrs, "color=yellow", "penwidth=1.5")
			}
		}

		// Direct dependencies styled differently
		if n.GetDirect() {
			attrs = append(attrs, "style=bold")
		}

		fmt.Fprintf(w, "  %s [%s];\n", id, strings.Join(attrs, ", "))
	}

	fmt.Fprintf(w, "\n")

	// Generate edges
	for _, e := range g.edges {
		fromID, fromOK := nodeIDs[e.GetFrom()]
		toID, toOK := nodeIDs[e.GetTo()]
		if fromOK && toOK {
			fmt.Fprintf(w, "  %s -> %s;\n", fromID, toID)
		}
	}

	fmt.Fprintf(w, "}\n")
	return nil
}

func (g *Graph) renderMermaid(w io.Writer, cfg *renderConfig) error {
	fmt.Fprintf(w, "flowchart %s\n", cfg.direction)

	nodes := g.filteredNodes(cfg)
	nodeIDs := make(map[string]string)

	// Generate node definitions with subgraphs for ecosystems
	ecosystems := make(map[string][]*Node)
	for _, n := range nodes {
		eco := n.GetEcosystem()
		if eco == "" {
			eco = "other"
		}
		ecosystems[eco] = append(ecosystems[eco], n)
	}

	id := 0
	for eco, ecoNodes := range ecosystems {
		fmt.Fprintf(w, "    subgraph %s[%s]\n", sanitizeMermaidID(eco), eco)
		for _, n := range ecoNodes {
			nodeID := fmt.Sprintf("n%d", id)
			nodeIDs[n.GetPurl()] = nodeID
			id++

			label := g.nodeLabel(n, cfg)
			shape := g.mermaidNodeShape(n, cfg)
			fmt.Fprintf(w, "        %s%s\n", nodeID, shape(label))
		}
		fmt.Fprintf(w, "    end\n")
	}

	// Generate edges
	for _, e := range g.edges {
		fromID, fromOK := nodeIDs[e.GetFrom()]
		toID, toOK := nodeIDs[e.GetTo()]
		if fromOK && toOK {
			fmt.Fprintf(w, "    %s --> %s\n", fromID, toID)
		}
	}

	// Style vulnerable nodes
	if cfg.highlightVulns {
		var critical, high, medium []string
		for _, n := range nodes {
			nodeID := nodeIDs[n.GetPurl()]
			if n.GetVulnerabilityCount().GetCritical() > 0 {
				critical = append(critical, nodeID)
			} else if n.GetVulnerabilityCount().GetHigh() > 0 {
				high = append(high, nodeID)
			} else if n.GetVulnerabilityCount().GetMedium() > 0 || n.GetVulnerabilityCount().GetLow() > 0 {
				medium = append(medium, nodeID)
			}
		}
		if len(critical) > 0 {
			fmt.Fprintf(w, "    style %s fill:#f99,stroke:#900\n", strings.Join(critical, ","))
		}
		if len(high) > 0 {
			fmt.Fprintf(w, "    style %s fill:#fc9,stroke:#f60\n", strings.Join(high, ","))
		}
		if len(medium) > 0 {
			fmt.Fprintf(w, "    style %s fill:#ff9,stroke:#cc0\n", strings.Join(medium, ","))
		}
	}

	return nil
}

func (g *Graph) mermaidNodeShape(n *Node, cfg *renderConfig) func(string) string {
	if n.GetDirect() {
		// Stadium shape for direct deps
		return func(label string) string {
			return fmt.Sprintf("([%s])", escapeMermaid(label))
		}
	}
	if cfg.highlightVulns && n.GetVulnerabilityCount().GetTotal() > 0 {
		// Hexagon for vulnerable
		return func(label string) string {
			return fmt.Sprintf("{{%s}}", escapeMermaid(label))
		}
	}
	// Default rectangle
	return func(label string) string {
		return fmt.Sprintf("[%s]", escapeMermaid(label))
	}
}

func (g *Graph) renderD3(w io.Writer, cfg *renderConfig) error {
	nodes := g.filteredNodes(cfg)
	nodeIndices := make(map[string]int)

	fmt.Fprintf(w, "{\n")
	fmt.Fprintf(w, "  \"nodes\": [\n")

	for i, n := range nodes {
		nodeIndices[n.GetPurl()] = i
		if i > 0 {
			fmt.Fprintf(w, ",\n")
		}

		group := 1
		if n.GetDirect() {
			group = 0
		}
		if n.GetVulnerabilityCount().GetCritical() > 0 {
			group = 4
		} else if n.GetVulnerabilityCount().GetHigh() > 0 {
			group = 3
		} else if n.GetVulnerabilityCount().GetTotal() > 0 {
			group = 2
		}

		fmt.Fprintf(w, "    {\"id\": %q, \"name\": %q, \"version\": %q, \"group\": %d, \"vulns\": %d}",
			n.GetPurl(), n.GetName(), n.GetVersion(), group, n.GetVulnerabilityCount().GetTotal())
	}

	fmt.Fprintf(w, "\n  ],\n")
	fmt.Fprintf(w, "  \"links\": [\n")

	first := true
	for _, e := range g.edges {
		srcIdx, srcOK := nodeIndices[e.GetFrom()]
		tgtIdx, tgtOK := nodeIndices[e.GetTo()]
		if srcOK && tgtOK {
			if !first {
				fmt.Fprintf(w, ",\n")
			}
			first = false
			fmt.Fprintf(w, "    {\"source\": %d, \"target\": %d}", srcIdx, tgtIdx)
		}
	}

	fmt.Fprintf(w, "\n  ]\n")
	fmt.Fprintf(w, "}\n")
	return nil
}

func (g *Graph) renderText(w io.Writer, cfg *renderConfig) error {
	// Find roots and render as tree
	roots := make([]*Node, 0)
	for n := range g.Roots() {
		if cfg.filterPred == nil || cfg.filterPred(n) {
			roots = append(roots, n)
		}
	}

	// Sort roots for deterministic output
	slices.SortFunc(roots, func(a, b *Node) int {
		return strings.Compare(a.GetName(), b.GetName())
	})

	for i, root := range roots {
		g.renderTextNode(w, root, "", i == len(roots)-1, make(map[string]bool), cfg, 0)
	}

	return nil
}

func (g *Graph) renderTextNode(w io.Writer, n *Node, prefix string, isLast bool, visited map[string]bool, cfg *renderConfig, depth int) {
	if cfg.maxDepth >= 0 && depth > cfg.maxDepth {
		return
	}

	if visited[n.GetPurl()] {
		// Indicate cycle
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		fmt.Fprintf(w, "%s%s%s (circular)\n", prefix, connector, n.GetName())
		return
	}
	visited[n.GetPurl()] = true

	connector := "├── "
	if isLast {
		connector = "└── "
	}
	if depth == 0 {
		connector = ""
	}

	label := g.nodeLabel(n, cfg)
	fmt.Fprintf(w, "%s%s%s\n", prefix, connector, label)

	// Get children
	var children []*Node
	for child := range g.Children(n.GetPurl()) {
		if cfg.filterPred == nil || cfg.filterPred(child) {
			children = append(children, child)
		}
	}

	// Sort children for deterministic output
	slices.SortFunc(children, func(a, b *Node) int {
		return strings.Compare(a.GetName(), b.GetName())
	})

	// Compute new prefix
	newPrefix := prefix
	if depth > 0 {
		if isLast {
			newPrefix += "    "
		} else {
			newPrefix += "│   "
		}
	}

	// Check if collapsed
	if cfg.collapsed[n.GetPurl()] && len(children) > 0 {
		fmt.Fprintf(w, "%s└── ... (%d dependencies)\n", newPrefix, len(children))
		return
	}

	for i, child := range children {
		g.renderTextNode(w, child, newPrefix, i == len(children)-1, visited, cfg, depth+1)
	}

	delete(visited, n.GetPurl())
}

// jsonNode is the JSON representation of a graph node.
type jsonNode struct {
	PURL      string        `json:"purl"`
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Ecosystem string        `json:"ecosystem"`
	Direct    bool          `json:"direct"`
	Depth     int           `json:"depth"`
	VulnerabilityCount jsonVulnerabilityCount `json:"vulnerability_count"`
	Locations []string      `json:"locations,omitempty"`
}

// jsonVulnerabilityCount is the JSON representation of vulnerability counts.
type jsonVulnerabilityCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Total    int `json:"total"`
}

// jsonEdge is the JSON representation of a graph edge.
type jsonEdge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Constraint string `json:"constraint,omitempty"`
	Scope      string `json:"scope,omitempty"`
}

// jsonGraph is the JSON representation of the entire graph.
type jsonGraph struct {
	Nodes []jsonNode `json:"nodes"`
	Edges []jsonEdge `json:"edges"`
}

func (g *Graph) renderJSON(w io.Writer, cfg *renderConfig) error {
	nodes := g.filteredNodes(cfg)
	nodeSet := make(map[string]bool)
	for _, n := range nodes {
		nodeSet[n.GetPurl()] = true
	}

	// Build JSON nodes
	jsonNodes := make([]jsonNode, 0, len(nodes))
	for _, n := range nodes {
		jsonNodes = append(jsonNodes, jsonNode{
			PURL:      n.GetPurl(),
			Name:      n.GetName(),
			Version:   n.GetVersion(),
			Ecosystem: n.GetEcosystem(),
			Direct:    n.GetDirect(),
			Depth:     int(n.GetDepth()),
			VulnerabilityCount: jsonVulnerabilityCount{
				Critical: int(n.GetVulnerabilityCount().GetCritical()),
				High:     int(n.GetVulnerabilityCount().GetHigh()),
				Medium:   int(n.GetVulnerabilityCount().GetMedium()),
				Low:      int(n.GetVulnerabilityCount().GetLow()),
				Total:    int(n.GetVulnerabilityCount().GetTotal()),
			},
			Locations: n.GetLocations(),
		})
	}

	// Build JSON edges (only for nodes in the filtered set)
	var jsonEdges []jsonEdge
	for _, e := range g.edges {
		if nodeSet[e.GetFrom()] && nodeSet[e.GetTo()] {
			jsonEdges = append(jsonEdges, jsonEdge{
				From:       e.GetFrom(),
				To:         e.GetTo(),
				Constraint: e.GetConstraint(),
				Scope:      e.GetScope().String(),
			})
		}
	}

	output := jsonGraph{
		Nodes: jsonNodes,
		Edges: jsonEdges,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func (g *Graph) filteredNodes(cfg *renderConfig) []*Node {
	var nodes []*Node
	for _, n := range g.nodes {
		if cfg.maxDepth >= 0 && int(n.GetDepth()) > cfg.maxDepth {
			continue
		}
		if cfg.filterPred != nil && !cfg.filterPred(n) {
			continue
		}
		nodes = append(nodes, n)
	}

	// Sort for deterministic output
	slices.SortFunc(nodes, func(a, b *Node) int {
		return strings.Compare(a.GetPurl(), b.GetPurl())
	})

	return nodes
}

func (g *Graph) nodeLabel(n *Node, cfg *renderConfig) string {
	label := n.GetName()
	if cfg.showVersions && n.GetVersion() != "" {
		label += "@" + n.GetVersion()
	}
	if cfg.showVulnCounts && n.GetVulnerabilityCount().GetTotal() > 0 {
		label += fmt.Sprintf(" [%dV]", n.GetVulnerabilityCount().GetTotal())
	}
	return label
}

func sanitizeMermaidID(s string) string {
	// Mermaid IDs can't contain special characters
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			return r
		}
		return '_'
	}, s)
}

func escapeMermaid(s string) string {
	// Escape characters that have special meaning in Mermaid
	s = strings.ReplaceAll(s, `"`, `#quot;`)
	s = strings.ReplaceAll(s, `<`, `#lt;`)
	s = strings.ReplaceAll(s, `>`, `#gt;`)
	return s
}
