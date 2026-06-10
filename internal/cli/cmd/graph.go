package cmd

import (
	"fmt"
	"io"
	"os"
	"path"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/charmbracelet/lipgloss"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/spf13/cobra"
	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	"github.com/temporalio/deputy/internal/cli/flags"
	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/services"
	ui "github.com/temporalio/deputy/internal/ui"
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

// AddGraphCommand registers the graph subcommand.
// Uses the service layer for graph operations, supporting both local and remote modes.
func AddGraphCommand(root *cobra.Command, c *services.Clients) {
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
		extended             bool
		onlyDeclared         bool
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
  - Vulnerability counts when available (via --show-vulns)

EXTENDED MODE (--extended):
  By default, deputy shows packages that end up in your final build.
  Extended mode adds "phantom" dependencies from the full module graph:

  IMPORTED  - Packages actively imported by your code (runtime risk)
  REQUIRED  - Packages in go.mod but not directly imported (medium risk)
  DECLARED  - Packages in full module graph but not selected (latent risk)

  Use cases for extended mode:
  - Supply chain risk: "What COULD be pulled in if a dependency changes?"
  - Proactive scanning: Find vulnerabilities before they affect you
  - OSSF MAL detection: Check for malicious packages in any declared dep
  - Audit: Understand the full dependency surface area`,
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

EXTENDED MODE (supply chain analysis):
  # Show full module graph including phantom dependencies
  deputy graph --extended

  # Show only declared-but-unused dependencies (latent risk)
  deputy graph --extended --declared

  # JSON output with import status for each package
  deputy graph --extended --format json | jq '.nodes[] | select(.import_status == "IMPORT_STATUS_DECLARED")'

  # Quick stats showing import status breakdown
  deputy graph --extended --stats

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

			target := ""
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				target = args[0]
			}
			if target == "" {
				var err error
				target, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			if ref == "" {
				ref = "HEAD"
			}

			// Build graph via service layer
			req := &graphv1.BuildGraphRequest{
				Target: target,
				Options: &graphv1.GraphOptions{
					Ecosystems:   normalizeEcosystems(ecos),
					ExcludePaths: excludePathsFromCmd(cmd),
					Ref:          ref,
					UseProxy:     true,
					UseGit:       true,
					Extended:     extended,
				},
			}

			resp, err := c.Graph.BuildGraph(ctx, connect.NewRequest(req))
			if err != nil {
				return fmt.Errorf("failed to build graph: %w", err)
			}

			// Convert proto response to internal graph
			g := graph.FromProto(resp.Msg.Nodes, resp.Msg.Edges, resp.Msg.Roots)
			if g == nil {
				return fmt.Errorf("failed to parse graph response")
			}

			// Apply filters
			if onlyDirect {
				g = g.Filter(func(n *graph.Node) bool { return n.Direct })
			}
			if onlyVulnerable {
				g = g.Filter(func(n *graph.Node) bool { return n.VulnerabilityCount.GetTotal() > 0 })
			}
			if onlyDeclared {
				// Filter to show only declared-but-unused dependencies (phantom deps)
				g = g.FilterByImportStatus(graph.ImportStatusDeclared)
			}
			if focusPkg != "" {
				// Find best matching node using ranked matching (same as "graph why")
				if match := findBestMatchingNode(g, focusPkg); match != nil {
					g = g.Subgraph(match.Purl)
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
	addExcludePathFlag(cmd)
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | json | dot | mermaid | d3")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().IntVarP(&maxDepth, "depth", "d", -1, "Maximum depth to display (-1 for unlimited)")
	cmd.Flags().BoolVar(&onlyDirect, "direct", false, "Show only direct dependencies")
	cmd.Flags().BoolVar(&onlyVulnerable, "vulnerable", false, "Show only packages with vulnerabilities")
	cmd.Flags().BoolVar(&showVersions, "versions", true, "Show package versions in output")
	cmd.Flags().BoolVar(&showVulnCounts, "show-vulns", false, "Show vulnerability counts per package")
	cmd.Flags().StringVar(&direction, "direction", "TB", "Graph direction: TB (top-bottom), LR (left-right), BT, RL")
	cmd.Flags().StringVar(&focusPkg, "focus", "", "Focus on a specific package (shows its subgraph)")
	cmd.Flags().BoolVar(&extended, "extended", false, "Include full module graph (declared but unused dependencies)")
	cmd.Flags().BoolVar(&onlyDeclared, "declared", false, "Show only declared-but-unused dependencies (requires --extended)")
	cmd.Flags().BoolVar(&statsOnly, "stats", false, "Show only graph statistics")

	// Add subcommands
	addGraphWhyCommand(cmd, c)
	addGraphNeedsCommand(cmd, c)

	root.AddCommand(cmd)
}

// addGraphWhyCommand adds the "graph why" subcommand.
func addGraphWhyCommand(parent *cobra.Command, c *services.Clients) {
	var (
		ref      string
		ecos     []string
		all      bool
		jsonOut  bool
		listOnly bool
	)

	cmd := &cobra.Command{
		Use:   "why <package> [target]",
		Short: "Show why a package is in the dependency graph",
		Long: `Show the dependency path(s) explaining why a package is included.

This command traces the dependency chain from your direct dependencies to
the specified package, answering "why is X in my dependencies?"

By default, shows only the shortest path. Use --all to see all paths.
Use --list to see all packages matching your query without path analysis.

Similar to 'go mod why' but works across all ecosystems.`,
		Example: `  # Why is lodash in my dependencies?
  deputy graph why lodash

  # Why is a specific version included?
  deputy graph why lodash@4.17.21

  # Show all dependency paths (not just shortest)
  deputy graph why lodash --all

  # List all packages matching a query (no path analysis)
  deputy graph why cobra --list

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

			w := cmd.OutOrStdout()

			// Build the graph to find all matches
			buildReq := &graphv1.BuildGraphRequest{
				Target: target,
				Options: &graphv1.GraphOptions{
					Ecosystems:   normalizeEcosystems(ecos),
					ExcludePaths: excludePathsFromCmd(cmd),
					Ref:          ref,
					UseProxy:     true,
					UseGit:       true,
				},
			}

			buildResp, err := c.Graph.BuildGraph(ctx, connect.NewRequest(buildReq))
			if err != nil {
				return fmt.Errorf("failed to build graph: %w", err)
			}

			g := graph.FromProto(buildResp.Msg.Nodes, buildResp.Msg.Edges, buildResp.Msg.Roots)
			if g == nil {
				return fmt.Errorf("failed to parse graph response")
			}

			// Find all matching packages
			matches := findMatchingNodes(g, pkg)

			if len(matches) == 0 {
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

			// --list mode: show all matching packages without path analysis
			if listOnly {
				return renderMatchList(w, matches, pkg)
			}

			// JSON output mode
			if jsonOut {
				return writeWhyJSON(w, g, matches)
			}

			// Text output - show paths for ALL matching packages (exploratory mode)
			return renderWhyAllMatches(w, g, matches, pkg, all)
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", []string{"all"}, "Ecosystems to include")
	addExcludePathFlag(cmd)
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Show all dependency paths (not just shortest)")
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")
	cmd.Flags().BoolVarP(&listOnly, "list", "l", false, "List all matching packages (no path analysis)")

	parent.AddCommand(cmd)
}

// renderMatchList renders a list of matching packages without path analysis.
// Used by --list mode to show what packages match a query.
func renderMatchList(w io.Writer, matches []*graph.Node, query string) error {
	// Header
	fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(fmt.Sprintf("Packages matching %q (%d found):", query, len(matches))))
	fmt.Fprintln(w)

	// List matches with their match quality indicated
	queryLower := strings.ToLower(query)
	for _, m := range matches {
		score := matchScore(m.Name, queryLower)
		var indicator string
		switch score {
		case 3:
			indicator = graphStyleMatchExact.Render("★") // exact match
		case 2:
			indicator = graphStyleMatchName.Render("●") // final segment match
		default:
			indicator = graphStyleMatchSubstring.Render("○") // substring match
		}

		name := m.Name
		if m.Version != "" {
			name += graphStyleAt.Render("@") + graphStyleVersion.Render(m.Version)
		}
		if m.Direct {
			name += " " + ui.StyleDirect.Render("[direct]")
		}

		fmt.Fprintf(w, "  %s %s\n", indicator, name)
	}

	// Legend with dimmed symbols (all uniformly muted since it's informational)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%s\n",
		graphStyleMeta.Render("Legend: ★ exact  ● name match  ○ substring"))

	return nil
}

// renderWhyAllMatches renders paths for all matching packages.
// This is the exploratory mode - shows everything that matches so users can explore.
func renderWhyAllMatches(w io.Writer, g *graph.Graph, matches []*graph.Node, query string, showAll bool) error {
	// Header showing how many matches
	if len(matches) > 1 {
		fmt.Fprintf(w, "%s\n\n", graphStyleMeta.Render(fmt.Sprintf("%d packages match %q:", len(matches), query)))
	}

	// Render each match with its paths
	for i, match := range matches {
		if i > 0 {
			fmt.Fprintln(w) // Blank line between matches
		}

		// Get paths for this match
		paths := g.PathsTo(match.Purl)

		// Sort by length
		slices.SortFunc(paths, func(a, b graph.Path) int {
			return len(a) - len(b)
		})

		// Deduplicate
		paths = deduplicatePaths(paths)

		// Header with package name
		fmt.Fprintln(w, formatPackageHeader(match.Name, match.Version))

		if len(paths) == 0 {
			// No paths found - show where it was found and why no path exists
			if match.Direct {
				fmt.Fprintf(w, "%s\n", ui.StyleDirect.Render("[direct dependency]"))
				renderNodeLocations(w, match)
			} else {
				// Disconnected node - explain where it came from
				renderDisconnectedNode(w, match)
			}
			continue
		}

		shortestHops := len(paths[0]) - 1

		// Direct dependency (0 hops)
		if shortestHops == 0 {
			fmt.Fprintf(w, "%s\n", ui.StyleDirect.Render("[direct dependency]"))
			continue
		}

		// Analyze and render paths
		directDeps := collectUniqueRoots(paths)
		renderWhySummary(w, paths, shortestHops, directDeps)

		pathsToShow := paths
		truncated := false
		if !showAll && len(paths) > 5 {
			pathsToShow = paths[:5]
			truncated = true
		}

		if shortestHops == 1 && allPathsSameDepth(paths, 2) {
			// Compact format for 1-hop dependencies
			renderCompactDirectDeps(w, directDeps)
		} else {
			// Tree format
			fmt.Fprintln(w)
			renderGroupedPaths(w, pathsToShow)
		}

		if truncated {
			fmt.Fprintln(w)
			remaining := len(paths) - len(pathsToShow)
			fmt.Fprintf(w, "%s\n", graphStyleMeta.Render(fmt.Sprintf("... and %d more paths (use --all to show)", remaining)))
		}
	}

	return nil
}

// renderNodeLocations renders the source locations for a node.
func renderNodeLocations(w io.Writer, node *graph.Node) {
	if len(node.Locations) > 0 {
		for _, loc := range node.Locations {
			fmt.Fprintf(w, "  %s %s\n", graphStyleArrow.Render("←"), graphStyleMeta.Render(loc))
		}
	}
}

// renderDisconnectedNode explains why a node has no dependency path.
// This happens for packages found in vendored binaries, separate go.mod files, etc.
func renderDisconnectedNode(w io.Writer, node *graph.Node) {
	if len(node.Locations) == 0 {
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render("[no dependency path found]"))
		return
	}

	// Categorize the locations to provide helpful context
	var binaries, goMods, others []string
	for _, loc := range node.Locations {
		switch {
		case strings.Contains(loc, ".bin") || strings.HasSuffix(loc, ".exe") || !strings.Contains(loc, "."):
			// Binary files (no extension or .bin directory)
			binaries = append(binaries, loc)
		case strings.HasSuffix(loc, "go.mod") || strings.HasSuffix(loc, "go.sum"):
			goMods = append(goMods, loc)
		default:
			others = append(others, loc)
		}
	}

	// Render with context-specific messaging
	if len(binaries) > 0 {
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render("[found in vendored binary]"))
		for _, loc := range binaries {
			fmt.Fprintf(w, "  %s %s\n", graphStyleArrow.Render("←"), graphStyleTipHighlight.Render(loc))
		}
	}
	if len(goMods) > 0 {
		if len(binaries) > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render("[found in separate module]"))
		for _, loc := range goMods {
			fmt.Fprintf(w, "  %s %s\n", graphStyleArrow.Render("←"), graphStyleTipHighlight.Render(loc))
		}
	}
	if len(others) > 0 {
		if len(binaries) > 0 || len(goMods) > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s\n", graphStyleMeta.Render("[found in]"))
		for _, loc := range others {
			fmt.Fprintf(w, "  %s %s\n", graphStyleArrow.Render("←"), graphStyleTipHighlight.Render(loc))
		}
	}
}

// normalizeEcosystems converts the CLI ecosystems flag to the service format.
// If "all" is specified, returns nil (meaning all ecosystems).
func normalizeEcosystems(ecos []string) []string {
	if len(ecos) == 1 && strings.EqualFold(ecos[0], "all") {
		return nil
	}
	return ecos
}

// collectUniqueRoots returns the unique root nodes (direct dependencies) from paths.
func collectUniqueRoots(paths []graph.Path) []*graph.Node {
	seen := make(map[string]bool)
	var roots []*graph.Node
	for _, path := range paths {
		if len(path) > 0 {
			root := path[0]
			if !seen[root.Purl] {
				seen[root.Purl] = true
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

	// Helper to format numbers with highlighting
	num := func(n int) string {
		return graphStyleNumber.Render(fmt.Sprintf("%d", n))
	}
	meta := graphStyleMeta.Render

	if shortestHops == 1 && allPathsSameDepth(paths, 2) {
		// All 1-hop paths: emphasize which direct deps require this
		fmt.Fprintf(w, "%s%s%s\n",
			meta("(required by "), num(len(directDeps)), meta(" direct "+depWord+")"))
	} else if len(directDeps) == 1 {
		// All paths through one direct dep
		if len(paths) == 1 {
			fmt.Fprintf(w, "%s%s%s\n",
				meta("("), num(shortestHops), meta(" "+hopWord+" via "+shortName(directDeps[0].Name)+")"))
		} else {
			fmt.Fprintf(w, "%s%s%s%s%s\n",
				meta("("), num(len(paths)), meta(" paths via "+shortName(directDeps[0].Name)+", shortest "),
				num(shortestHops), meta(" "+hopWord+")"))
		}
	} else {
		// Multiple direct deps with varying depths
		fmt.Fprintf(w, "%s%s%s%s%s%s%s\n",
			meta("("), num(len(paths)), meta(" paths via "), num(len(directDeps)),
			meta(" direct "+depWord+", shortest "), num(shortestHops), meta(" "+hopWord+")"))
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

// renderGroupedPaths renders the shortest path per direct dependency as a tree.
// This provides a clear, non-redundant view while maintaining visual structure.
func renderGroupedPaths(w io.Writer, paths []graph.Path) {
	if len(paths) == 0 {
		return
	}

	// Group paths by root PURL, keeping only the shortest per root
	shortestByRoot := make(map[string]graph.Path)
	var rootOrder []string // preserve order of first occurrence

	for _, path := range paths {
		if len(path) == 0 {
			continue
		}
		rootPURL := path[0].Purl
		existing, exists := shortestByRoot[rootPURL]
		if !exists {
			rootOrder = append(rootOrder, rootPURL)
			shortestByRoot[rootPURL] = path
		} else if len(path) < len(existing) {
			shortestByRoot[rootPURL] = path
		}
	}

	// Render each shortest path as a simple tree
	for i, rootPURL := range rootOrder {
		if i > 0 {
			fmt.Fprintln(w) // blank line between paths
		}
		path := shortestByRoot[rootPURL]
		renderPathAsTree(w, path)
	}
}

// renderPathAsTree renders a single path as a vertical tree.
func renderPathAsTree(w io.Writer, path graph.Path) {
	if len(path) == 0 {
		return
	}

	// Root node (direct dependency)
	fmt.Fprintln(w, formatNodeLabelWithSource(path[0]))

	// Remaining nodes as tree
	for i := 1; i < len(path); i++ {
		node := path[i]
		isLast := i == len(path)-1
		indent := strings.Repeat("    ", i-1)

		var label string
		if isLast {
			label = formatNodeLabelHighlighted(node)
		} else {
			label = formatNodeLabel(node)
		}

		fmt.Fprintf(w, "%s%s%s\n", indent, graphStyleArrow.Render("└── "), label)
	}
}

// Graph output styles - defined here for consistency across graph commands.
// Designed for visual hierarchy: header stands out, tree fades into background,
// target package highlighted at leaf nodes.
var (
	// graphStyleName renders the target package name in bold white (header only).
	graphStyleName = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF")).Bold(true)
	// graphStyleVersion renders versions in a subdued cyan-gray.
	graphStyleVersion = lipgloss.NewStyle().Foreground(lipgloss.Color("#88AAAA"))
	// graphStyleAt renders the @ separator in dim gray.
	graphStyleAt = lipgloss.NewStyle().Foreground(lipgloss.Color("#555555"))
	// graphStyleArrow renders tree connectors very dim (visual structure, not content).
	graphStyleArrow = lipgloss.NewStyle().Foreground(lipgloss.Color("#444444"))
	// graphStyleMeta renders metadata like path counts in dim text.
	graphStyleMeta = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	// graphStyleNumber renders numbers in summary text - stands out from dim text.
	graphStyleNumber = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA"))
	// graphStyleTreeNode renders intermediary tree nodes in subdued color.
	graphStyleTreeNode = lipgloss.NewStyle().Foreground(lipgloss.Color("#888888"))
	// graphStyleTreeVersion renders versions in tree nodes even more subdued.
	graphStyleTreeVersion = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
	// graphStyleTarget renders the target package (leaf nodes) - stands out in tree.
	graphStyleTarget = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))
	// graphStyleTargetVersion renders target package version.
	graphStyleTargetVersion = lipgloss.NewStyle().Foreground(lipgloss.Color("#88AAAA"))
	// graphStyleTipIcon renders the lightbulb icon in yellow.
	graphStyleTipIcon = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	// graphStyleTipLabel renders the "Tip:" label in bold yellow.
	graphStyleTipLabel = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00")).Bold(true)
	// graphStyleTipText renders tip content in a softer color.
	graphStyleTipText = lipgloss.NewStyle().Foreground(lipgloss.Color("#AAAAAA"))
	// graphStyleTipHighlight renders highlighted text within tips.
	graphStyleTipHighlight = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFFFFF"))

	// Match quality indicator styles for --list output
	// graphStyleMatchExact renders ★ for exact matches - bright yellow, stands out.
	graphStyleMatchExact = lipgloss.NewStyle().Foreground(lipgloss.Color("#FFCC00"))
	// graphStyleMatchName renders ● for name/segment matches - softer yellow.
	graphStyleMatchName = lipgloss.NewStyle().Foreground(lipgloss.Color("#BBAA66"))
	// graphStyleMatchSubstring renders ○ for substring matches - dim gray.
	graphStyleMatchSubstring = lipgloss.NewStyle().Foreground(lipgloss.Color("#666666"))
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
// Uses subdued colors for tree nodes to reduce visual noise.
func formatNodeLabel(node *graph.Node) string {
	result := graphStyleTreeNode.Render(node.Name)
	if node.Version != "" {
		result += graphStyleAt.Render("@")
		result += graphStyleTreeVersion.Render(node.Version)
	}
	if node.Direct {
		result += " " + ui.StyleDirect.Render("[direct]")
	}
	return result
}

// formatNodeLabelHighlighted formats a node with emphasis (for target packages).
// Used for leaf nodes in the tree - the package being searched for.
func formatNodeLabelHighlighted(node *graph.Node) string {
	result := graphStyleTarget.Render(node.Name)
	if node.Version != "" {
		result += graphStyleAt.Render("@")
		result += graphStyleTargetVersion.Render(node.Version)
	}
	return result
}

// formatNodeLabelWithSource formats a node label including its source file location.
// Used for root nodes (direct dependencies) - slightly more prominent than tree nodes.
func formatNodeLabelWithSource(node *graph.Node) string {
	// Root nodes use white text (not bold) - more prominent than tree nodes
	result := lipgloss.NewStyle().Foreground(lipgloss.Color("#DDDDDD")).Render(node.Name)
	if node.Version != "" {
		result += graphStyleAt.Render("@")
		result += graphStyleVersion.Render(node.Version)
	}
	if node.Direct {
		result += " " + ui.StyleDirect.Render("[direct]")
	}

	// Add source location if available
	if len(node.Locations) > 0 {
		source := formatSourceLocation(node.Locations[0])
		if source != "" {
			result += graphStyleMeta.Render(" [" + source + "]")
		}
	}
	return result
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
	if slices.Contains(stdlibPkgs, query) {
		return true
	}
	// Also match paths that look like stdlib (no dots, single slash)
	if !strings.Contains(query, ".") && strings.Count(query, "/") == 1 {
		return true
	}
	return false
}

// findMatchingNodes finds nodes matching the query pattern.
// Supports glob patterns via path.Match or simple substring matching.
// Results are sorted with best matches first: exact matches, then final segment
// matches, then substring matches, all sorted alphabetically within each tier.
//
// Examples:
//   - "cobra" matches any package containing "cobra", prefers github.com/spf13/cobra
//   - "*/cobra" matches packages ending with /cobra
//   - "spf13/*" matches all packages under spf13
func findMatchingNodes(g *graph.Graph, query string) []*graph.Node {
	queryLower := strings.ToLower(query)
	isGlob := strings.ContainsAny(query, "*?[")

	var matches []*graph.Node

	for node := range g.Nodes() {
		nameLower := strings.ToLower(node.Name)

		if isGlob {
			// Use path.Match for glob patterns
			if matched, _ := path.Match(queryLower, nameLower); matched {
				matches = append(matches, node)
			}
		} else {
			// Simple substring matching - case insensitive
			if strings.Contains(nameLower, queryLower) {
				matches = append(matches, node)
			}
		}
	}

	// Sort by match quality: exact > final segment > substring, then alphabetically
	slices.SortFunc(matches, func(a, b *graph.Node) int {
		scoreA := matchScore(a.Name, queryLower)
		scoreB := matchScore(b.Name, queryLower)
		if scoreA != scoreB {
			return scoreB - scoreA // Higher score first
		}
		return strings.Compare(a.Name, b.Name)
	})

	return matches
}

// matchScore returns a quality score for how well a package name matches a query.
// Higher scores indicate better matches:
//   - 3: exact match (name equals query)
//   - 2: final segment match (query matches the last path component)
//   - 1: substring match
func matchScore(name, queryLower string) int {
	nameLower := strings.ToLower(name)

	// Exact match
	if nameLower == queryLower {
		return 3
	}

	// Final segment match (e.g., "cobra" matches "github.com/spf13/cobra")
	// Also handles versioned paths like "go-git/v5" → match "go-git"
	finalSegment := nameLower
	if idx := strings.LastIndex(nameLower, "/"); idx >= 0 {
		finalSegment = nameLower[idx+1:]
	}
	// Strip version suffix for comparison (v5, v2, etc.)
	if strings.HasPrefix(finalSegment, "v") && len(finalSegment) <= 3 {
		// This is a version segment like /v5, check the segment before it
		if idx := strings.LastIndex(strings.TrimSuffix(nameLower, "/"+finalSegment), "/"); idx >= 0 {
			finalSegment = strings.TrimSuffix(nameLower, "/"+finalSegment)[idx+1:]
		} else {
			finalSegment = strings.TrimSuffix(nameLower, "/"+finalSegment)
		}
	}
	if finalSegment == queryLower {
		return 2
	}

	// Substring match
	return 1
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

// writeWhyJSON outputs the why information as JSON using proto types.
func writeWhyJSON(w io.Writer, g *graph.Graph, matches []*graph.Node) error {
	// Build a list of WhyDependencyResponse protos for each match
	var results []*graphv1.WhyDependencyResponse
	for _, match := range matches {
		resp := &graphv1.WhyDependencyResponse{
			Dependency: match.Purl,
			Found:      true,
		}

		paths := g.PathsTo(match.Purl)
		for _, path := range paths {
			depPath := &graphv1.DependencyPath{
				Length: int32(len(path) - 1), // edges = nodes - 1
			}
			for _, node := range path {
				depPath.Nodes = append(depPath.Nodes, &graphv1.PathNode{
					Purl:    node.Purl,
					Name:    node.Name,
					Version: node.Version,
				})
			}
			resp.Paths = append(resp.Paths, depPath)
		}
		results = append(results, resp)
	}

	// Use protojson for consistent formatting
	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}

	// Marshal as a list wrapper since proto doesn't have a native list type
	// Create a wrapper response for multiple matches
	wrapper := &graphv1.WhyDependencyListResponse{
		Results: results,
	}

	data, err := opts.Marshal(wrapper)
	if err != nil {
		return fmt.Errorf("marshal why results: %w", err)
	}

	_, err = w.Write(data)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// addGraphNeedsCommand adds the "graph needs" subcommand.
func addGraphNeedsCommand(parent *cobra.Command, c *services.Clients) {
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

			// Build graph via service layer
			req := &graphv1.BuildGraphRequest{
				Target: target,
				Options: &graphv1.GraphOptions{
					Ecosystems:   normalizeEcosystems(ecos),
					ExcludePaths: excludePathsFromCmd(cmd),
					Ref:          ref,
					UseProxy:     true,
					UseGit:       true,
				},
			}

			resp, err := c.Graph.BuildGraph(ctx, connect.NewRequest(req))
			if err != nil {
				return fmt.Errorf("failed to build graph: %w", err)
			}

			g := graph.FromProto(resp.Msg.Nodes, resp.Msg.Edges, resp.Msg.Roots)
			if g == nil {
				return fmt.Errorf("failed to parse graph response")
			}

			// Find best matching node
			match := findBestMatchingNode(g, pkg)
			if match == nil {
				fmt.Fprintf(cmd.OutOrStdout(), "Package %q not found in dependency graph.\n", pkg)
				return nil
			}

			w := cmd.OutOrStdout()

			// Collect ancestors (packages that depend on this one)
			var ancestors []*graph.Node
			for ancestor := range g.Ancestors(match.Purl) {
				ancestors = append(ancestors, ancestor)
			}

			// Check direct parents via edges
			var parents []*graph.Node
			for parent := range g.Parents(match.Purl) {
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
	addExcludePathFlag(cmd)
	cmd.Flags().BoolVar(&jsonOut, "json", false, "Output as JSON")

	parent.AddCommand(cmd)
}

// writeNeedsJSON outputs the needs information as JSON using proto types.
func writeNeedsJSON(w io.Writer, match *graph.Node, ancestors, parents []*graph.Node) error {
	resp := &graphv1.NeedsDependencyResponse{
		Package: match.Name,
		Version: match.Version,
		Purl:    match.Purl,
	}

	// Use ancestors if available, otherwise parents
	deps := ancestors
	if len(deps) == 0 {
		deps = parents
	}

	for _, d := range deps {
		resp.Dependents = append(resp.Dependents, &graphv1.Node{
			Name:    d.Name,
			Version: d.Version,
			Purl:    d.Purl,
			Direct:  d.Direct,
		})
	}

	opts := protojson.MarshalOptions{
		Multiline:       true,
		Indent:          "  ",
		EmitUnpopulated: false,
		UseProtoNames:   true,
	}

	data, err := opts.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal needs result: %w", err)
	}

	_, err = w.Write(data)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
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
			if showVulnCounts && node.VulnerabilityCount.GetTotal() > 0 {
				label += fmt.Sprintf(" [%dV]", node.VulnerabilityCount.GetTotal())
			}
			if node.Direct {
				label += " " + ui.StyleDirect.Render("[direct]")
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
func writeGraphStats(w io.Writer, stats *graphv1.GraphStats, format string) error {
	switch GraphFormat(strings.ToLower(format)) {
	case GraphFormatJSON:
		opts := protojson.MarshalOptions{
			Multiline:       true,
			Indent:          "  ",
			EmitUnpopulated: false,
			UseProtoNames:   true,
		}
		data, err := opts.Marshal(stats)
		if err != nil {
			return err
		}
		_, err = w.Write(data)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte("\n"))
		return err
	default:
		// Text format - CLI friendly
		fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("Dependency Graph Statistics"))
		fmt.Fprintf(w, "\n")
		fmt.Fprintf(w, "  Total packages:      %d\n", stats.GetTotalNodes())
		fmt.Fprintf(w, "  Direct dependencies: %d\n", stats.GetDirectNodes())
		fmt.Fprintf(w, "  Transitive:          %d\n", stats.GetTransitiveNodes())
		// Show max connected depth (meaningful for actual dependency analysis)
		// rather than max_depth which includes disconnected nodes (depth=999)
		fmt.Fprintf(w, "  Max depth:           %d\n", stats.GetMaxConnectedDepth())
		if stats.GetDisconnectedNodes() > 0 {
			fmt.Fprintf(w, "  Disconnected:        %d\n", stats.GetDisconnectedNodes())
		}
		if stats.GetVulnerableNodes() > 0 {
			fmt.Fprintf(w, "  Vulnerable packages: %d\n", stats.GetVulnerableNodes())
		}
		fmt.Fprintf(w, "\n")

		// Import status breakdown (extended mode only)
		if importCounts := stats.GetImportStatusCounts(); importCounts != nil {
			fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("By Import Status (Extended Mode)"))
			fmt.Fprintf(w, "  Imported (in binary): %d\n", importCounts.GetImported())
			fmt.Fprintf(w, "  Required (in go.mod): %d\n", importCounts.GetRequired())
			fmt.Fprintf(w, "  Declared (phantom):   %d\n", importCounts.GetDeclared())
			fmt.Fprintf(w, "\n")
		}

		if len(stats.GetEcosystems()) > 0 {
			fmt.Fprintf(w, "%s\n", ui.StyleHeader.Render("By Ecosystem"))
			// Sort ecosystems for deterministic output
			ecos := make([]string, 0, len(stats.GetEcosystems()))
			for eco := range stats.GetEcosystems() {
				ecos = append(ecos, eco)
			}
			slices.Sort(ecos)
			for _, eco := range ecos {
				fmt.Fprintf(w, "  %-20s %d\n", eco+":", stats.GetEcosystems()[eco])
			}
		}
		return nil
	}
}
