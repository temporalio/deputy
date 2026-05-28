package remediation

import (
	"slices"
	"strings"

	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// PathInfo contains dependency path information for a vulnerability.
type PathInfo struct {
	// VulnID is the vulnerability identifier (e.g., CVE-2024-1234).
	VulnID string

	// VulnerablePackage is the name of the vulnerable package.
	VulnerablePackage string

	// ShortestPath is the shortest dependency path to the vulnerable package.
	// The first element is a direct dependency; the last is the vulnerable package.
	ShortestPath []PathNode

	// PathCount is the total number of paths to this vulnerable package.
	PathCount int

	// DirectDependencies lists the direct dependencies that lead to this vulnerability.
	// Updating any of these may resolve the vulnerability.
	DirectDependencies []string

	// Depth is the shortest distance from a direct dependency.
	Depth int
}

// PathNode represents a package in a dependency path.
type PathNode struct {
	Name    string
	Version string
	PURL    string
	Direct  bool
}

// EnrichedRecommendation extends a fix recommendation with graph context.
type EnrichedRecommendation struct {
	Command

	// PathInfo contains dependency path information when available.
	PathInfo *PathInfo

	// ImpactedPackages lists other packages that depend on the vulnerable package.
	// This helps assess the "blast radius" of an upgrade.
	ImpactedPackages []string

	// UpstreamFix indicates whether the fix requires updating an upstream
	// direct dependency rather than the vulnerable package itself.
	UpstreamFix bool

	// UpstreamPackage is the direct dependency to update when UpstreamFix is true.
	UpstreamPackage string

	// Explanation provides a human-readable explanation of the fix strategy.
	Explanation string
}

// EnrichWithGraph adds graph context to fix recommendations.
// If the graph is nil, recommendations are returned unchanged.
func EnrichWithGraph(cmds []Command, g *graph.Graph, cons []vulnerability.Consolidated) []EnrichedRecommendation {
	enriched := make([]EnrichedRecommendation, len(cmds))

	for i, cmd := range cmds {
		enriched[i] = EnrichedRecommendation{
			Command: cmd,
		}

		if g == nil {
			continue
		}

		// Find the consolidated vuln for this command's package
		var cv *vulnerability.Consolidated
		for j := range cons {
			if cons[j].Package == extractPackageName(cmd.Command) {
				cv = &cons[j]
				break
			}
		}

		if cv == nil {
			continue
		}

		// Build path info
		pathInfo := buildPathInfo(g, cv)
		if pathInfo != nil {
			enriched[i].PathInfo = pathInfo

			// If vulnerable package is transitive, find the direct dep to update
			if !cmd.IsDirect && len(pathInfo.DirectDependencies) > 0 {
				enriched[i].UpstreamFix = true
				enriched[i].UpstreamPackage = pathInfo.DirectDependencies[0]
				enriched[i].Explanation = buildExplanation(pathInfo)
			}
		}

		// Find impacted packages (reverse dependencies)
		enriched[i].ImpactedPackages = findImpactedPackages(g, cv.Package)
	}

	return enriched
}

// buildPathInfo constructs PathInfo for a vulnerability using the graph.
func buildPathInfo(g *graph.Graph, cv *vulnerability.Consolidated) *PathInfo {
	if g == nil || cv == nil {
		return nil
	}

	// Find the node for this package
	var vulnNode *graph.Node
	for node := range g.Nodes() {
		if node.Name == cv.Package {
			vulnNode = node
			break
		}
	}

	if vulnNode == nil {
		return nil
	}

	paths := g.PathsTo(vulnNode.Purl)
	if len(paths) == 0 {
		// Direct dependency case
		if vulnNode.Direct {
			return &PathInfo{
				VulnID:             cv.PrimaryID,
				VulnerablePackage:  cv.Package,
				ShortestPath:       []PathNode{{Name: cv.Package, Version: cv.Version, PURL: vulnNode.Purl, Direct: true}},
				PathCount:          1,
				DirectDependencies: []string{cv.Package},
				Depth:              0,
			}
		}
		return nil
	}

	// Sort paths by length
	slices.SortFunc(paths, func(a, b graph.Path) int {
		return len(a) - len(b)
	})

	shortest := paths[0]

	// Extract path nodes
	pathNodes := make([]PathNode, len(shortest))
	for i, n := range shortest {
		pathNodes[i] = PathNode{
			Name:    n.Name,
			Version: n.Version,
			PURL:    n.Purl,
			Direct:  n.Direct,
		}
	}

	// Collect unique direct dependencies from all paths
	directDeps := make(map[string]bool)
	for _, p := range paths {
		if len(p) > 0 && p[0].Direct {
			directDeps[p[0].Name] = true
		}
	}

	directDepList := make([]string, 0, len(directDeps))
	for d := range directDeps {
		directDepList = append(directDepList, d)
	}
	slices.Sort(directDepList)

	return &PathInfo{
		VulnID:             cv.PrimaryID,
		VulnerablePackage:  cv.Package,
		ShortestPath:       pathNodes,
		PathCount:          len(paths),
		DirectDependencies: directDepList,
		Depth:              len(shortest) - 1,
	}
}

// buildExplanation generates a human-readable explanation for a fix path.
func buildExplanation(info *PathInfo) string {
	if info == nil {
		return ""
	}

	if info.Depth == 0 {
		return info.VulnerablePackage + " is a direct dependency"
	}

	var sb strings.Builder
	sb.WriteString(info.VulnerablePackage)
	sb.WriteString(" is a transitive dependency (")

	if info.PathCount == 1 {
		sb.WriteString("1 path")
	} else {
		sb.WriteString(strings.Replace(string(rune(info.PathCount+'0')), "\x00", "", -1))
		sb.WriteString(" paths")
	}

	sb.WriteString(", depth ")
	sb.WriteString(strings.Replace(string(rune(info.Depth+'0')), "\x00", "", -1))
	sb.WriteString(")")

	if len(info.DirectDependencies) == 1 {
		sb.WriteString(". Update ")
		sb.WriteString(info.DirectDependencies[0])
		sb.WriteString(" to pull in the fix.")
	} else if len(info.DirectDependencies) > 1 {
		sb.WriteString(". Can be fixed via: ")
		sb.WriteString(strings.Join(info.DirectDependencies, ", "))
	}

	return sb.String()
}

// findImpactedPackages returns packages that depend on the given package.
func findImpactedPackages(g *graph.Graph, pkg string) []string {
	if g == nil {
		return nil
	}

	// Find the node
	var targetNode *graph.Node
	for node := range g.Nodes() {
		if node.Name == pkg {
			targetNode = node
			break
		}
	}

	if targetNode == nil {
		return nil
	}

	var impacted []string
	for parent := range g.Parents(targetNode.Purl) {
		impacted = append(impacted, parent.Name)
	}

	slices.Sort(impacted)
	return impacted
}

// extractPackageName attempts to extract a package name from a remediation command.
// This is a heuristic and may not work for all command formats.
func extractPackageName(cmd string) string {
	// Common patterns:
	// "go get package@version" -> "package"
	// "npm install package@version" -> "package"

	parts := strings.Fields(cmd)
	for i, part := range parts {
		// Skip command words
		if part == "go" || part == "get" || part == "npm" || part == "install" ||
			part == "pip" || part == "gem" || part == "cargo" || part == "add" {
			continue
		}
		// Skip flags
		if strings.HasPrefix(part, "-") {
			continue
		}
		// Found a package reference - strip version
		if idx := strings.LastIndex(part, "@"); idx > 0 {
			return part[:idx]
		}
		// For "go get -u package" patterns, the package might be at the end
		if i > 0 {
			return part
		}
	}
	return ""
}

// RecommendationsWithContext generates fix recommendations with full graph context.
// This is the main entry point for graph-aware remediation.
func RecommendationsWithContext(cons []vulnerability.Consolidated, g *graph.Graph) []EnrichedRecommendation {
	cmds, _ := CommandsFromConsolidated(cons)
	return EnrichWithGraph(cmds, g, cons)
}
