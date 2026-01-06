package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"slices"
	"strings"

	"github.com/charmbracelet/lipgloss"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/auth"
	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/dependency/graph"
	"github.com/picatz/deputy/internal/gitutil"
	gitx "github.com/picatz/deputy/internal/gitutil"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GraphFormat represents supported graph output formats.
type GraphFormat string

const (
	GraphFormatText    GraphFormat = "text"
	GraphFormatJSON    GraphFormat = "json"
	GraphFormatDOT     GraphFormat = "dot"
	GraphFormatMermaid GraphFormat = "mermaid"
	GraphFormatD3      GraphFormat = "d3"
)

// GraphResult captures graph command output for machine consumption.
type GraphResult struct {
	Repo      string      `json:"repo"`
	Ref       string      `json:"ref"`
	Commit    string      `json:"commit"`
	Generated string      `json:"generated"`
	Stats     graph.Stats `json:"stats"`
	Graph     *graph.Graph
}

// AddGraphCommand registers the graph subcommand.
func AddGraphCommand(root *cobra.Command) {
	var (
		ref, format, outPath string
		ecos                 []string
		maxDepth             int
		onlyDirect           bool
		onlyVulnerable       bool
		showVersions         bool
		showVulnCounts       bool
		direction            string
		focusPkg             string
		statsOnly            bool
	)

	cmd := &cobra.Command{
		Use:           "graph [repo]",
		Short:         "Visualize the dependency graph",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Visualize the dependency graph of a repository.

This command generates a dependency graph showing relationships between
packages. It supports multiple output formats for different use cases:

OUTPUT FORMATS:
  text     ASCII tree view (default, CLI-friendly)
  json     Full graph structure as JSON
  dot      Graphviz DOT format (for rendering with dot/neato)
  mermaid  Mermaid.js flowchart (for Markdown/documentation)
  d3       D3.js force-directed graph JSON (for web visualization)

The graph shows:
  - Direct dependencies (marked or styled distinctly)
  - Transitive dependencies and their relationships
  - Vulnerability counts when available (via --show-vulns)`,
		Example: `BASIC USAGE:
  # Show dependency tree for current repo
  deputy graph

  # Show graph for a remote repo
  deputy graph https://github.com/example/repo

FILTERING:
  # Only direct dependencies
  deputy graph --direct

  # Limit depth (e.g., show 2 levels)
  deputy graph --depth 2

  # Focus on a specific package and its dependencies
  deputy graph --focus lodash

  # Filter by ecosystem
  deputy graph --ecosystems go

OUTPUT FORMATS:
  # Generate Graphviz DOT (can pipe to dot)
  deputy graph --format dot > deps.dot
  deputy graph --format dot | dot -Tpng -o deps.png

  # Generate Mermaid for documentation
  deputy graph --format mermaid >> README.md

  # JSON for programmatic use
  deputy graph --format json | jq '.stats'

  # Quick stats only
  deputy graph --stats`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			repoPath := ""
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				repoPath = args[0]
			}
			if repoPath == "" {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			if ref == "" {
				ref = "HEAD"
			}

			result, err := buildGraph(ctx, repoPath, ref, ecos)
			if err != nil {
				return err
			}

			// Apply filters
			g := result.Graph
			if onlyDirect {
				g = g.Filter(func(n *graph.Node) bool { return n.Direct })
			}
			if onlyVulnerable {
				g = g.Filter(func(n *graph.Node) bool { return n.VulnCount.Total > 0 })
			}
			if focusPkg != "" {
				// Find best matching node using ranked matching (same as "graph why")
				if match := findBestMatchingNode(g, focusPkg); match != nil {
					g = g.Subgraph(match.PURL)
				}
			}

			// Prepare output writer
			var w io.Writer = cmd.OutOrStdout()
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			// Stats only mode
			if statsOnly {
				return writeGraphStats(w, g.Stats(), format)
			}

			// Build render options
			var opts []graph.RenderOption
			if maxDepth >= 0 {
				opts = append(opts, graph.WithMaxDepth(maxDepth))
			}
			opts = append(opts, graph.WithVersions(showVersions))
			opts = append(opts, graph.WithVulnCounts(showVulnCounts))
			if direction != "" {
				opts = append(opts, graph.WithDirection(strings.ToUpper(direction)))
			}

			// Render based on format
			switch GraphFormat(strings.ToLower(format)) {
			case GraphFormatText, "":
				// For text format, check if we have a tree structure (edges)
				// If not, fall back to a flat list view
				hasEdges := false
				for range g.Edges() {
					hasEdges = true
					break
				}
				if hasEdges {
					return g.Render(w, graph.FormatText, opts...)
				}
				// Flat list fallback for inventories without edge data
				return writeGraphFlatList(w, g, showVersions, showVulnCounts)
			case GraphFormatJSON:
				return g.Render(w, graph.FormatJSON, opts...)
			case GraphFormatDOT:
				return g.Render(w, graph.FormatDOT, opts...)
			case GraphFormatMermaid:
				return g.Render(w, graph.FormatMermaid, opts...)
			case GraphFormatD3:
				return g.Render(w, graph.FormatD3, opts...)
			default:
				return flags.UnsupportedFormatError("--format", format, "text|json|dot|mermaid|d3")
			}
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", []string{"all"}, "Ecosystems to include")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | json | dot | mermaid | d3")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().IntVarP(&maxDepth, "depth", "d", -1, "Maximum depth to display (-1 for unlimited)")
	cmd.Flags().BoolVar(&onlyDirect, "direct", false, "Show only direct dependencies")
	cmd.Flags().BoolVar(&onlyVulnerable, "vulnerable", false, "Show only packages with vulnerabilities")
	cmd.Flags().BoolVar(&showVersions, "versions", true, "Show package versions in output")
	cmd.Flags().BoolVar(&showVulnCounts, "show-vulns", false, "Show vulnerability counts per package")
	cmd.Flags().StringVar(&direction, "direction", "TB", "Graph direction: TB (top-bottom), LR (left-right), BT, RL")
	cmd.Flags().StringVar(&focusPkg, "focus", "", "Focus on a specific package (shows its subgraph)")
	cmd.Flags().BoolVar(&statsOnly, "stats", false, "Show only graph statistics")

	// Add subcommands
	addGraphWhyCommand(cmd)
	addGraphNeedsCommand(cmd)

	root.AddCommand(cmd)
}

// addGraphWhyCommand adds the "graph why" subcommand.
func addGraphWhyCommand(parent *cobra.Command) {
	var (
		ref     string
		ecos    []string
		all     bool
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "why <package> [target]",
		Short: "Show why a package is in the dependency graph",
		Long: `Show the dependency path(s) explaining why a package is included.

This command traces the dependency chain from your direct dependencies to
the specified package, answering "why is X in my dependencies?"

By default, shows only the shortest path. Use --all to see all paths.

Similar to 'go mod why' but works across all ecosystems.`,
		Example: `  # Why is lodash in my dependencies?
  deputy graph why lodash

  # Why is a specific version included?
  deputy graph why lodash@4.17.21

  # Show all dependency paths (not just shortest)
  deputy graph why lodash --all

  # Check a remote repository
  deputy graph why express github.com/example/repo`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			pkg := args[0]

			target := "."
			if len(args) > 1 {
				target = args[1]
			}
			if target == "." {
				var err error
				target, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			result, err := buildGraph(ctx, target, ref, ecos)
			if err != nil {
				return err
			}

			g := result.Graph

			// Find matching node(s) with ranked matching
			matches := findMatchingNodes(g, pkg)

			if len(matches) == 0 {
				w := cmd.OutOrStdout()
				fmt.Fprintf(w, "Package %q not found in dependency graph.\n", pkg)
				// Provide helpful guidance for Go stdlib package searches
				if isGoStdlibPackage(pkg) {
					fmt.Fprintln(w)
					fmt.Fprintf(w, "%s %s %s\n",
						graphStyleTipIcon.Render("☀"),
						graphStyleTipLabel.Render("Tip:"),
						graphStyleTipText.Render("Individual Go standard library packages"),
					)
					fmt.Fprintf(w, "   %s\n",
						graphStyleTipText.Render("(net/http, database/sql, etc.) are part of the Go runtime."),
					)
					fmt.Fprintf(w, "   %s %s %s\n",
						graphStyleTipText.Render("Try"),
						graphStyleTipHighlight.Render("deputy graph why stdlib"),
						graphStyleTipText.Render("to see the Go version your project uses."),
					)
					fmt.Fprintf(w, "   %s%s%s\n",
						graphStyleTipText.Render("Go runtime vulnerabilities are tracked under "),
						graphStyleTipHighlight.Render("stdlib"),
						graphStyleTipText.Render("."),
					)
				}
				return nil
			}

			w := cmd.OutOrStdout()

			// JSON output mode
			if jsonOut {
				return writeWhyJSON(w, g, matches)
			}

			for i, match := range matches {
				if i > 0 {
					fmt.Fprintln(w)
				}
				renderWhyOutput(w, g, match, all)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", []string{"all"}, "Ecosystems to include")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Show all dependency paths (not just shortest)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")

	parent.AddCommand(cmd)
}

// renderWhyOutput renders the "why" output for a single package match.
func renderWhyOutput(w io.Writer, g *graph.Graph, match *graph.Node, showAll bool) {
	fmt.Fprintln(w, formatPackageHeader(match.Name, match.Version))

	// Direct dependency - simple case
	if match.Direct {
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render("(direct dependency)"))
		return
	}

	paths := g.PathsTo(match.PURL)
	if len(paths) == 0 {
		// Show where this package was detected if we have location info
		if len(match.Locations) > 0 {
			// Determine source type from location path
			sourceDesc := describePackageSource(match.Locations)
			fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(fmt.Sprintf("(found in %s, no dependency path through source code)", sourceDesc)))
			for _, loc := range match.Locations {
				fmt.Fprintf(w, "  %s\n", graphStyleMeta.Render(loc))
			}
		} else {
			fmt.Fprintf(w, "%s\n", graphStyleMeta.Render("(no dependency path found)"))
		}
		return
	}

	// Sort paths by length (shortest first)
	slices.SortFunc(paths, func(a, b graph.Path) int {
		return len(a) - len(b)
	})

	// Deduplicate paths that have same structure
	paths = deduplicatePaths(paths)

	// Analyze the paths to generate a smart summary
	shortestHops := len(paths[0]) - 1

	// Count unique direct dependencies (roots) that lead to this package
	directDeps := collectUniqueRoots(paths)

	// Generate contextual summary based on path structure
	renderWhySummary(w, paths, shortestHops, directDeps)

	// Determine how many paths to show
	pathsToShow := paths
	truncated := false
	if !showAll && len(paths) > 5 {
		pathsToShow = paths[:5]
		truncated = true
	}

	// Render paths based on complexity
	if shortestHops == 1 && allPathsSameDepth(paths, 2) {
		// All paths are 1-hop: show compact list of direct deps
		renderCompactDirectDeps(w, directDeps)
	} else {
		// Mixed depths or deeper: show tree structure
		renderGroupedPaths(w, pathsToShow)
	}

	// Truncation notice
	if truncated {
		fmt.Fprintln(w)
		remaining := len(paths) - len(pathsToShow)
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(fmt.Sprintf("... and %d more paths (use --all to show)", remaining)))
	}
}

// collectUniqueRoots returns the unique root nodes (direct dependencies) from paths.
func collectUniqueRoots(paths []graph.Path) []*graph.Node {
	seen := make(map[string]bool)
	var roots []*graph.Node
	for _, path := range paths {
		if len(path) > 0 {
			root := path[0]
			if !seen[root.PURL] {
				seen[root.PURL] = true
				roots = append(roots, root)
			}
		}
	}
	return roots
}

// allPathsSameDepth checks if all paths have the same length.
func allPathsSameDepth(paths []graph.Path, depth int) bool {
	for _, path := range paths {
		if len(path) != depth {
			return false
		}
	}
	return true
}

// renderWhySummary generates a contextual summary line.
func renderWhySummary(w io.Writer, paths []graph.Path, shortestHops int, directDeps []*graph.Node) {
	hopWord := "hop"
	if shortestHops != 1 {
		hopWord = "hops"
	}

	depWord := "dependency"
	if len(directDeps) != 1 {
		depWord = "dependencies"
	}

	if shortestHops == 1 && allPathsSameDepth(paths, 2) {
		// All 1-hop paths: emphasize which direct deps require this
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(
			fmt.Sprintf("(required by %d direct %s)", len(directDeps), depWord)))
	} else if len(directDeps) == 1 {
		// All paths through one direct dep
		if len(paths) == 1 {
			fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(
				fmt.Sprintf("(%d %s via %s)", shortestHops, hopWord, shortName(directDeps[0].Name))))
		} else {
			fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(
				fmt.Sprintf("(%d paths via %s, shortest %d %s)", len(paths), shortName(directDeps[0].Name), shortestHops, hopWord)))
		}
	} else {
		// Multiple direct deps with varying depths
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(
			fmt.Sprintf("(%d paths via %d direct %s, shortest %d %s)", len(paths), len(directDeps), depWord, shortestHops, hopWord)))
	}
}

// shortName returns the last segment of a package path for brevity.
func shortName(name string) string {
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		return name[idx+1:]
	}
	return name
}

// renderCompactDirectDeps renders a compact list of direct dependencies with source info.
func renderCompactDirectDeps(w io.Writer, deps []*graph.Node) {
	for _, dep := range deps {
		label := formatNodeLabelWithSource(dep)
		fmt.Fprintf(w, "  %s %s\n", graphStyleArrow.Render("←"), label)
	}
}

// renderGroupedPaths groups paths by their root node and renders them as merged trees.
// This avoids repeating the same root multiple times when multiple paths share it.
func renderGroupedPaths(w io.Writer, paths []graph.Path) {
	if len(paths) == 0 {
		return
	}

	// Group paths by root PURL
	groups := make(map[string][]graph.Path)
	var rootOrder []string // preserve order of first occurrence

	for _, path := range paths {
		if len(path) == 0 {
			continue
		}
		rootPURL := path[0].PURL
		if _, exists := groups[rootPURL]; !exists {
			rootOrder = append(rootOrder, rootPURL)
		}
		groups[rootPURL] = append(groups[rootPURL], path)
	}

	// Render each group
	for i, rootPURL := range rootOrder {
		if i > 0 {
			fmt.Fprintln(w) // blank line between root groups
		}
		groupPaths := groups[rootPURL]
		renderPathGroup(w, groupPaths)
	}
}

// renderPathGroup renders a group of paths that share the same root as a tree.
func renderPathGroup(w io.Writer, paths []graph.Path) {
	if len(paths) == 0 {
		return
	}

	// Build a tree structure from paths
	root := buildPathTree(paths)
	renderPathTree(w, root, "", true)
}

// pathTreeNode represents a node in the merged path tree.
type pathTreeNode struct {
	node     *graph.Node
	children []*pathTreeNode
}

// buildPathTree builds a tree structure from multiple paths.
func buildPathTree(paths []graph.Path) *pathTreeNode {
	if len(paths) == 0 || len(paths[0]) == 0 {
		return nil
	}

	// Create root from first path's first node
	root := &pathTreeNode{node: paths[0][0]}

	// Add each path to the tree
	for _, path := range paths {
		addPathToTree(root, path[1:]) // skip root, already added
	}

	return root
}

// addPathToTree adds a path (excluding root) to a tree node.
func addPathToTree(parent *pathTreeNode, path graph.Path) {
	if len(path) == 0 {
		return
	}

	// Find or create child for first node in remaining path
	var child *pathTreeNode
	for _, c := range parent.children {
		if c.node.PURL == path[0].PURL {
			child = c
			break
		}
	}

	if child == nil {
		child = &pathTreeNode{node: path[0]}
		parent.children = append(parent.children, child)
	}

	// Recurse for remaining path
	addPathToTree(child, path[1:])
}

// renderPathTree renders a path tree with proper tree characters.
// prefix is the indentation prefix for the current level (spaces and vertical bars).
func renderPathTree(w io.Writer, node *pathTreeNode, prefix string, isRoot bool) {
	if node == nil {
		return
	}

	if isRoot {
		// Root node - include source location
		label := formatNodeLabelWithSource(node.node)
		fmt.Fprintf(w, "%s\n", label)
		// Render children from root
		renderChildren(w, node.children, "")
	} else {
		label := formatNodeLabel(node.node)
		fmt.Fprintf(w, "%s%s\n", prefix, label)
	}
}

// renderChildren renders child nodes with proper tree structure.
func renderChildren(w io.Writer, children []*pathTreeNode, prefix string) {
	for i, child := range children {
		isLast := i == len(children)-1

		var connector, nextPrefix string
		if isLast {
			connector = graphStyleArrow.Render("└── ")
			nextPrefix = prefix + "    "
		} else {
			connector = graphStyleArrow.Render("├── ")
			nextPrefix = prefix + graphStyleArrow.Render("│") + "   "
		}

		label := formatNodeLabel(child.node)
		fmt.Fprintf(w, "%s%s%s\n", prefix, connector, label)

		// Recurse for grandchildren
		if len(child.children) > 0 {
			renderChildren(w, child.children, nextPrefix)
		}
	}
}

// renderDependencyPath renders a single dependency path as a visual chain.
// Kept for backward compatibility but renderGroupedPaths is preferred.
func renderDependencyPath(w io.Writer, path graph.Path) {
	// Use a clean vertical layout similar to go mod why
	// Each node on its own line with proper indentation showing depth
	for i, node := range path {
		label := formatNodeLabel(node)

		if i == 0 {
			// First node (root/direct dependency)
			fmt.Fprintf(w, "%s\n", label)
		} else {
			// Build indent based on depth
			indent := strings.Repeat("    ", i-1)
			arrow := graphStyleArrow.Render("└── ")
			fmt.Fprintf(w, "%s%s%s\n", indent, arrow, label)
		}
	}
}

// Graph output styles - defined here for consistency across graph commands.
// These provide better contrast than the default ui.Style* for dependency paths.
var (
	// graphStyleName renders package names in bold white.
	graphStyleName = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	// graphStyleVersion renders versions in a readable cyan-gray (not faint).
	graphStyleVersion = lipgloss.NewStyle().Foreground(lipgloss.Color("#88AAAA"))
	// graphStyleAt renders the @ separator in dim gray.
	graphStyleAt = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	// graphStyleDirect renders the (direct) marker.
	graphStyleDirect = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	// graphStyleArrow renders tree arrows with slightly more visibility.
	graphStyleArrow = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	// graphStyleMeta renders metadata like path counts in dim text.
	graphStyleMeta = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	// graphStyleTipIcon renders the lightbulb icon in yellow.
	graphStyleTipIcon = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	// graphStyleTipLabel renders the "Tip:" label in bold yellow.
	graphStyleTipLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00")).Bold(true)
	// graphStyleTipText renders tip content in a softer color.
	graphStyleTipText = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA"))
	// graphStyleTipHighlight renders highlighted text within tips.
	graphStyleTipHighlight = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
)

// formatPackageHeader formats a package name and version as a header line.
func formatPackageHeader(name, version string) string {
	result := graphStyleName.Render(name)
	if version != "" {
		result += graphStyleAt.Render("@")
		result += graphStyleVersion.Render(version)
	}
	return result
}

// formatNodeLabel formats a node for display with name and version.
func formatNodeLabel(node *graph.Node) string {
	result := graphStyleName.UnsetBold().Render(node.Name)
	if node.Version != "" {
		result += graphStyleAt.Render("@")
		result += graphStyleVersion.Render(node.Version)
	}
	if node.Direct {
		result += graphStyleDirect.Render(" (direct)")
	}
	return result
}

// formatNodeLabelWithSource formats a node label including its source file location.
// Used for root nodes to show where the dependency is declared.
func formatNodeLabelWithSource(node *graph.Node) string {
	label := formatNodeLabel(node)

	// Add source location if available
	if len(node.Locations) > 0 {
		source := formatSourceLocation(node.Locations[0])
		if source != "" {
			label += graphStyleMeta.Render(" [" + source + "]")
		}
	}
	return label
}

// formatSourceLocation formats a location path for display.
// Simplifies common paths like "go.mod" or shows just the filename.
func formatSourceLocation(loc string) string {
	if loc == "" {
		return ""
	}
	// For common lockfiles, just return the filename
	if strings.HasSuffix(loc, "go.mod") {
		return "go.mod"
	}
	if strings.HasSuffix(loc, "go.sum") {
		return "go.sum"
	}
	if strings.HasSuffix(loc, "package-lock.json") {
		return "package-lock.json"
	}
	if strings.HasSuffix(loc, "yarn.lock") {
		return "yarn.lock"
	}
	if strings.HasSuffix(loc, "pnpm-lock.yaml") {
		return "pnpm-lock.yaml"
	}
	// For other files (like binaries), show the path
	return loc
}

// isGoStdlibPackage checks if a query looks like a Go standard library package.
// This is used to provide helpful guidance when users search for packages like
// "net/http" or "database/sql" which are part of the Go runtime, not separate modules.
func isGoStdlibPackage(query string) bool {
	query = strings.ToLower(strings.TrimSpace(query))
	// Common Go stdlib packages and their short names
	stdlibPkgs := []string{
		"net/http", "net", "http",
		"database/sql", "sql",
		"encoding/json", "json",
		"fmt", "io", "os", "time", "strings", "bytes",
		"context", "sync", "crypto", "reflect", "runtime",
		"log", "log/slog", "slog",
		"testing", "flag", "path", "filepath",
		"bufio", "sort", "strconv", "unicode",
		"archive", "compress", "container", "debug",
		"embed", "errors", "expvar", "hash", "html",
		"image", "index", "math", "mime", "plugin",
		"regexp", "text", "unsafe",
	}
	for _, pkg := range stdlibPkgs {
		if query == pkg {
			return true
		}
	}
	// Also match paths that look like stdlib (no dots, single slash)
	if !strings.Contains(query, ".") && strings.Count(query, "/") == 1 {
		return true
	}
	return false
}

// containsPathSegment checks if query appears as a path segment in name.
// For example, "yaml" is a segment in "gopkg.in/yaml.v3" (between / and .).
func containsPathSegment(name, query string) bool {
	// Look for /query. or /query/ patterns
	segment := "/" + query + "."
	if strings.Contains(name, segment) {
		return true
	}
	segment = "/" + query + "/"
	if strings.Contains(name, segment) {
		return true
	}
	return false
}

// matchRank represents how well a query matches a package.
type matchRank int

const (
	matchNone       matchRank = iota // No match
	matchSubstring                   // Query is substring of name (disabled - too loose)
	matchPathMatch                   // Query is a path segment (e.g., /yaml/ or /yaml. or ends with /yaml)
	matchNameSuffix                  // Name ends with -query (e.g., go-yaml matches "yaml")
	matchExact                       // Exact name match (strongest)
)

// findMatchingNodes finds nodes matching the query with ranked matching.
// Returns nodes sorted by match quality (best matches first).
func findMatchingNodes(g *graph.Graph, query string) []*graph.Node {
	queryLower := strings.ToLower(query)

	type rankedMatch struct {
		node *graph.Node
		rank matchRank
	}

	var matches []rankedMatch

	for node := range g.Nodes() {
		nameLower := strings.ToLower(node.Name)
		rank := matchNone

		// Check for exact match first
		if nameLower == queryLower {
			rank = matchExact
		} else if strings.HasSuffix(nameLower, "-"+queryLower) {
			// Hyphen suffix: go-yaml matches "yaml"
			rank = matchNameSuffix
		} else if strings.HasSuffix(nameLower, "/"+queryLower) {
			// Path suffix: golang.org/x/net matches "net"
			rank = matchPathMatch
		} else if containsPathSegment(nameLower, queryLower) {
			// Path segment: gopkg.in/yaml.v3 matches "yaml", otelhttp matches "net"
			rank = matchPathMatch
		}

		// Substring matching is too loose - skip it for precision
		// Users can use more specific queries

		if rank > matchNone {
			matches = append(matches, rankedMatch{node: node, rank: rank})
		}
	}

	// Sort by rank (best first), then by name for determinism
	slices.SortFunc(matches, func(a, b rankedMatch) int {
		if a.rank != b.rank {
			return int(b.rank) - int(a.rank) // Higher rank first
		}
		return strings.Compare(a.node.Name, b.node.Name)
	})

	// Extract just the nodes
	result := make([]*graph.Node, len(matches))
	for i, m := range matches {
		result[i] = m.node
	}

	return result
}

// findBestMatchingNode finds the single best matching node for a query.
// Used by commands that expect a single result (like "needs").
func findBestMatchingNode(g *graph.Graph, query string) *graph.Node {
	matches := findMatchingNodes(g, query)
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

// deduplicatePaths removes paths that are effectively duplicates
// (same sequence of package names, possibly different versions).
func deduplicatePaths(paths []graph.Path) []graph.Path {
	seen := make(map[string]bool)
	var result []graph.Path

	for _, path := range paths {
		// Create a key from package names
		var parts []string
		for _, node := range path {
			parts = append(parts, node.Name)
		}
		key := strings.Join(parts, " -> ")

		if !seen[key] {
			seen[key] = true
			result = append(result, path)
		}
	}

	return result
}

// describePackageSource analyzes location paths to describe where a package was found.
// This helps users understand why a package appears in the inventory even without
// a dependency path through source code (e.g., from compiled binaries).
func describePackageSource(locations []string) string {
	for _, loc := range locations {
		// Check for Go binary (executable files with no lockfile extension)
		if !strings.HasSuffix(loc, ".mod") &&
			!strings.HasSuffix(loc, ".sum") &&
			!strings.HasSuffix(loc, ".lock") &&
			!strings.HasSuffix(loc, ".json") &&
			!strings.HasSuffix(loc, ".yaml") &&
			!strings.HasSuffix(loc, ".yml") &&
			!strings.HasSuffix(loc, ".toml") {
			// Likely a binary file
			return "compiled binary"
		}
		if strings.HasSuffix(loc, "go.mod") {
			return "go.mod"
		}
		if strings.HasSuffix(loc, "go.sum") {
			return "go.sum"
		}
		if strings.HasSuffix(loc, "package-lock.json") {
			return "package-lock.json"
		}
		if strings.HasSuffix(loc, "yarn.lock") {
			return "yarn.lock"
		}
		if strings.HasSuffix(loc, "pnpm-lock.yaml") {
			return "pnpm-lock.yaml"
		}
		if strings.HasSuffix(loc, "Cargo.lock") {
			return "Cargo.lock"
		}
		if strings.HasSuffix(loc, "Gemfile.lock") {
			return "Gemfile.lock"
		}
	}
	return "unknown source"
}

// writeWhyJSON outputs the why information as JSON.
func writeWhyJSON(w io.Writer, g *graph.Graph, matches []*graph.Node) error {
	type pathNode struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl"`
		Direct  bool   `json:"direct,omitempty"`
	}
	type whyResult struct {
		Package   string       `json:"package"`
		Version   string       `json:"version,omitempty"`
		PURL      string       `json:"purl"`
		Direct    bool         `json:"direct"`
		Locations []string     `json:"locations,omitempty"`
		Source    string       `json:"source,omitempty"`
		Paths     [][]pathNode `json:"paths"`
	}

	var results []whyResult
	for _, match := range matches {
		r := whyResult{
			Package:   match.Name,
			Version:   match.Version,
			PURL:      match.PURL,
			Direct:    match.Direct,
			Locations: match.Locations,
		}

		// Add source description when locations are available
		if len(match.Locations) > 0 {
			r.Source = describePackageSource(match.Locations)
		}

		paths := g.PathsTo(match.PURL)
		for _, path := range paths {
			var jsonPath []pathNode
			for _, node := range path {
				jsonPath = append(jsonPath, pathNode{
					Name:    node.Name,
					Version: node.Version,
					PURL:    node.PURL,
					Direct:  node.Direct,
				})
			}
			r.Paths = append(r.Paths, jsonPath)
		}
		results = append(results, r)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

// addGraphNeedsCommand adds the "graph needs" subcommand.
func addGraphNeedsCommand(parent *cobra.Command) {
	var (
		ref     string
		ecos    []string
		jsonOut bool
	)

	cmd := &cobra.Command{
		Use:   "needs <package> [target]",
		Short: "Show what packages depend on a given package",
		Long: `Show all packages that depend on (need) the specified package.

This command performs a reverse lookup, finding all packages that have
the specified package as a dependency. Useful for understanding the
impact of upgrading or removing a package.`,
		Example: `  # What needs lodash?
  deputy graph needs lodash

  # Check impact of a vulnerable package
  deputy graph needs vulnerable-pkg

  # Check a remote repository
  deputy graph needs express github.com/example/repo`,
		Args: cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			pkg := args[0]

			target := "."
			if len(args) > 1 {
				target = args[1]
			}
			if target == "." {
				var err error
				target, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			result, err := buildGraph(ctx, target, ref, ecos)
			if err != nil {
				return err
			}

			g := result.Graph

			// Find best matching node
			match := findBestMatchingNode(g, pkg)
			if match == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Package %q not found in dependency graph.\n", pkg)
				return nil
			}

			w := cmd.OutOrStdout()

			// Collect ancestors (packages that depend on this one)
			var ancestors []*graph.Node
			for ancestor := range g.Ancestors(match.PURL) {
				ancestors = append(ancestors, ancestor)
			}

			// Check direct parents via edges
			var parents []*graph.Node
			for parent := range g.Parents(match.PURL) {
				parents = append(parents, parent)
			}

			// JSON output
			if jsonOut {
				return writeNeedsJSON(w, match, ancestors, parents)
			}

			// Header
			fmt.Fprintln(w, formatPackageHeader(match.Name, match.Version))

			// No dependents
			if len(ancestors) == 0 && len(parents) == 0 {
				fmt.Fprintf(w, "%s\n", graphStyleMeta.Render("(no dependents found)"))
				return nil
			}

			// Use parents if ancestors is empty (shallow graph)
			dependents := ancestors
			if len(dependents) == 0 {
				dependents = parents
			}

			// Sort by direct first, then by name
			slices.SortFunc(dependents, func(a, b *graph.Node) int {
				// Direct deps first
				if a.Direct != b.Direct {
					if a.Direct {
						return -1
					}
					return 1
				}
				return strings.Compare(a.Name, b.Name)
			})

			// Count direct vs transitive
			directCount := 0
			for _, d := range dependents {
				if d.Direct {
					directCount++
				}
			}
			transitiveCount := len(dependents) - directCount

			// Summary
			if transitiveCount > 0 {
				fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(fmt.Sprintf("(%d dependents: %d direct, %d transitive)", len(dependents), directCount, transitiveCount)))
			} else {
				fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(fmt.Sprintf("(%d dependents)", len(dependents))))
			}

			// List dependents
			for _, dep := range dependents {
				fmt.Fprintf(w, "  %s\n", formatNodeLabel(dep))
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", []string{"all"}, "Ecosystems to include")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")

	parent.AddCommand(cmd)
}

// writeNeedsJSON outputs the needs information as JSON.
func writeNeedsJSON(w io.Writer, match *graph.Node, ancestors, parents []*graph.Node) error {
	type dependent struct {
		Name    string `json:"name"`
		Version string `json:"version,omitempty"`
		PURL    string `json:"purl"`
		Direct  bool   `json:"direct,omitempty"`
	}
	type needsResult struct {
		Package    string      `json:"package"`
		Version    string      `json:"version,omitempty"`
		PURL       string      `json:"purl"`
		Dependents []dependent `json:"dependents"`
	}

	result := needsResult{
		Package: match.Name,
		Version: match.Version,
		PURL:    match.PURL,
	}

	// Use ancestors if available, otherwise parents
	deps := ancestors
	if len(deps) == 0 {
		deps = parents
	}

	for _, d := range deps {
		result.Dependents = append(result.Dependents, dependent{
			Name:    d.Name,
			Version: d.Version,
			PURL:    d.PURL,
			Direct:  d.Direct,
		})
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// buildGraph constructs the dependency graph for the given repository.
func buildGraph(ctx context.Context, repoPath, ref string, ecosystems []string) (*GraphResult, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.graph",
		trace.WithAttributes(
			attribute.String("deputy.target.path", repoPath),
			attribute.String("deputy.target.ref", ref),
		))
	defer span.End()

	var (
		src *repository.Source
		err error
	)

	// Open or clone repository
	if fi, statErr := os.Stat(repoPath); statErr == nil && fi.IsDir() {
		src, err = repository.Open(repoPath)
		if err != nil {
			otel.SetSpanError(span, err)
			return nil, err
		}
	}
	if src == nil {
		u := gitutil.ToHTTPSGitURL(repoPath)
		if u == "" {
			return nil, fmt.Errorf("could not interpret target %q as local path or remote Git URL", repoPath)
		}
		gitAuth, _ := auth.GitAuthForURL(ctx, u)
		rn, resolveErr := gitutil.ResolveReferenceName(ctx, u, gitAuth, ref)
		if resolveErr == nil && rn.String() != "" {
			ref = rn.String()
		}
		cloneOpts := &git.CloneOptions{
			URL:          u,
			Depth:        1,
			SingleBranch: true,
			Tags:         git.NoTags,
			Auth:         gitAuth,
		}
		if rn.String() != "" {
			cloneOpts.ReferenceName = rn
		}
		src, err = repository.Clone(ctx, cloneOpts, true)
		if err != nil && cloneOpts.ReferenceName != "" {
			cloneOpts.ReferenceName = ""
			src, err = repository.Clone(ctx, cloneOpts, true)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to clone remote repo %s: %w", u, err)
		}
	}
	defer src.Close()

	repo := src.Repo
	ws := src.Workspace

	effRef := refOrHEAD(ref)
	var (
		pkgs       []*extractor.Package
		targetHash *plumbing.Hash
	)
	scanOpts := inv.ScanOptions{Ecosystems: ecosystems}

	if strings.EqualFold(effRef, "HEAD") {
		pkgs, err = inv.ScanPackagesWorking(ctx, ws, scanOpts)
	} else {
		targetHash, err = gitx.ResolveRevisionEnhanced(repo, effRef)
		if err != nil {
			return nil, err
		}
		pkgs, err = inv.ScanPackagesAtCommitSnapshot(ctx, repo, *targetHash, scanOpts)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to collect inventory: %w", err)
	}

	// Determine direct dependencies
	goDirect := map[string]bool{"stdlib": true}
	var manifestRes scan.ManifestResolver
	switch {
	case strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0"):
		goDirect = compare.CollectGoDirectModulesFromWorkspace(ws)
		manifestRes = scan.NewWorkspaceManifestResolver(ws)
	case targetHash != nil:
		if direct, err := compare.CollectGoDirectModulesFromCommit(repo, *targetHash); err == nil {
			goDirect = direct
		}
		manifestRes = scan.NewGitManifestResolver(repo, *targetHash)
	default:
		goDirect = compare.CollectGoDirectModulesFromWorkspace(ws)
		manifestRes = scan.NewWorkspaceManifestResolver(ws)
	}

	pkgInputs := scan.PackagesToInputs(pkgs, scan.PackageInputOptions{GoDirect: goDirect, Resolver: manifestRes})
	pkgDirect := scan.BuildPackageDirectMap(pkgInputs)

	// Build the graph from inventory
	g := graph.FromInventory(pkgs, pkgDirect)

	// Resolve edges using ecosystem-specific resolvers
	// Each resolver parses lockfiles for its ecosystem to determine dependency relationships.
	// Strategy varies by ecosystem:
	//   - Go: vendor -> proxy -> git (no lockfile with deps, fetch go.mod)
	//   - npm: parse package-lock.json (contains full tree)
	//   - Cargo: parse Cargo.lock (contains full tree)
	//   - PyPI: parse poetry.lock/uv.lock (contains edges)
	//   - RubyGems: parse Gemfile.lock (contains edges)
	fileReader := graph.NewWorkspaceFileReader(ws)

	// Create resolver registry with Go proxy+git enabled for accurate resolution
	registry := graph.NewResolverRegistry(
		graph.WithGoProxyEnabled(""), // Use default proxy.golang.org
		graph.WithGoGitEnabled(),     // Enable git fetch for private modules
	)

	// Resolve all ecosystems (each resolver handles its own files)
	// Errors are logged but don't fail the overall operation - partial resolution is acceptable
	if err := registry.ResolveAll(ctx, g, fileReader); err != nil {
		slog.Debug("some resolvers failed during edge resolution", "error", err)
	}

	// Get commit hash for metadata
	commitHash := ""
	switch {
	case strings.EqualFold(effRef, "HEAD"):
		if head, err := repo.Head(); err == nil {
			commitHash = head.Hash().String()
		}
	case targetHash != nil:
		commitHash = targetHash.String()
	}

	span.SetAttributes(attribute.Int("deputy.graph.nodes", g.Size()))
	otel.SetSpanOK(span)

	return &GraphResult{
		Repo:      repoPath,
		Ref:       shortGitRef(effRef),
		Commit:    commitHash,
		Generated: timeNowUTC(),
		Stats:     g.Stats(),
		Graph:     g,
	}, nil
}

// writeGraphFlatList outputs the graph as a flat list when no edge data is available.
func writeGraphFlatList(w io.Writer, g *graph.Graph, showVersions, showVulnCounts bool) error {
	stats := g.Stats()

	// Header
	fmt.Fprintf(w, "%s\n\n", ui.StyleHeader.Render("Dependencies"))

	// Group by ecosystem
	byEco := make(map[string][]*graph.Node)
	for node := range g.NodesSorted() {
		eco := node.Ecosystem
		if eco == "" {
			eco = "other"
		}
		byEco[eco] = append(byEco[eco], node)
	}

	// Sort ecosystems
	ecos := make([]string, 0, len(byEco))
	for eco := range byEco {
		ecos = append(ecos, eco)
	}
	slices.Sort(ecos)

	for _, eco := range ecos {
		nodes := byEco[eco]
		fmt.Fprintf(w, "%s (%d)\n", ui.StyleHeader.Render(eco), len(nodes))
		for i, node := range nodes {
			prefix := "├── "
			if i == len(nodes)-1 {
				prefix = "└── "
			}

			label := node.Name
			if showVersions && node.Version != "" {
				label += "@" + node.Version
			}
			if showVulnCounts && node.VulnCount.Total > 0 {
				label += fmt.Sprintf(" [%dV]", node.VulnCount.Total)
			}
			if node.Direct {
				label += " (direct)"
			}
			fmt.Fprintf(w, "  %s%s\n", prefix, label)
		}
		fmt.Fprintln(w)
	}

	// Summary
	fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("Summary"))
	fmt.Fprintf(w, "  %d total (%d direct, %d transitive)\n", stats.TotalNodes, stats.DirectNodes, stats.TransitiveNodes)

	return nil
}

// writeGraphStats outputs graph statistics in the requested format.
func writeGraphStats(w io.Writer, stats graph.Stats, format string) error {
	switch GraphFormat(strings.ToLower(format)) {
	case GraphFormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(stats)
	default:
		// Text format - CLI friendly
		fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("Dependency Graph Statistics"))
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "  Total packages:      %d\n", stats.TotalNodes)
		fmt.Fprintf(w, "  Direct dependencies: %d\n", stats.DirectNodes)
		fmt.Fprintf(w, "  Transitive:          %d\n", stats.TransitiveNodes)
		fmt.Fprintf(w, "  Max depth:           %d\n", stats.MaxDepth)
		if stats.VulnerableNodes > 0 {
			fmt.Fprintf(w, "  Vulnerable packages: %d\n", stats.VulnerableNodes)
		}
		fmt.Fprintf(w, "\n")
		if len(stats.Ecosystems) > 0 {
			fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("By Ecosystem"))
			// Sort ecosystems for deterministic output
			ecos := make([]string, 0, len(stats.Ecosystems))
			for eco := range stats.Ecosystems {
				ecos = append(ecos, eco)
			}
			slices.Sort(ecos)
			for _, eco := range ecos {
				fmt.Fprintf(w, "  %-20s %d\n", eco+":", stats.Ecosystems[eco])
			}
		}
		return nil
	}
}
