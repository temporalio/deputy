// Package graphquery contains matching helpers for dependency graph commands
// and MCP tools.
package graphquery

import (
	"path"
	"slices"
	"strings"

	packageurl "github.com/package-url/packageurl-go"
	"golang.org/x/mod/semver"

	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/purlx"
)

// FindMatchingNodes returns graph nodes matching query, sorted by match quality.
//
// Query accepts package names, name@version, glob patterns, and PURLs. PURL
// matching compares parsed identity fields and version equivalence, so PURLs
// emitted by scans round-trip even when versions contain escaped characters.
func FindMatchingNodes(g *graph.Graph, query string) []*graph.Node {
	if g == nil {
		return nil
	}
	parsedQuery := parsePackageQuery(query)
	if parsedQuery.name == "" && !parsedQuery.hasPURL && !parsedQuery.isGlob {
		return nil
	}

	type rankedMatch struct {
		node *graph.Node
		rank int
	}

	var matches []rankedMatch
	for node := range g.Nodes() {
		rank := purlMatchRank(node, parsedQuery)
		if rank == 0 {
			if parsedQuery.hasVersion && !VersionsEquivalent(node.Version, parsedQuery.version) {
				continue
			}
			rank = nameMatchRank(node.Name, parsedQuery)
			if rank > 0 && parsedQuery.hasVersion {
				rank++
			}
		}
		if rank > 0 {
			matches = append(matches, rankedMatch{node: node, rank: rank})
		}
	}

	slices.SortFunc(matches, func(a, b rankedMatch) int {
		if a.rank != b.rank {
			return b.rank - a.rank
		}
		if cmp := strings.Compare(a.node.Name, b.node.Name); cmp != 0 {
			return cmp
		}
		return strings.Compare(a.node.Purl, b.node.Purl)
	})

	result := make([]*graph.Node, len(matches))
	for i, match := range matches {
		result[i] = match.node
	}
	return result
}

// FindBestMatchingNode returns the highest ranked node for query.
func FindBestMatchingNode(g *graph.Graph, query string) *graph.Node {
	matches := FindMatchingNodes(g, query)
	if len(matches) == 0 {
		return nil
	}
	return matches[0]
}

// NoDependentsMessage explains a found package with no reverse dependency
// edges in the current graph.
func NoDependentsMessage(match *graph.Node, resolveTransitives bool) string {
	switch {
	case match == nil:
		return "Package was not found in the dependency graph"
	case match.Direct:
		return "Package is a direct/root dependency; no other discovered package depends on it"
	case match.Depth == graph.DepthDisconnected:
		return "Package is present in the inventory but disconnected from dependency roots; no dependent packages were resolved"
	case !resolveTransitives:
		return "No dependent packages were resolved in the local dependency graph; retry with resolveTransitives=true if registry-backed transitive edges are needed"
	default:
		return "No dependent packages were resolved in the dependency graph"
	}
}

// NoDependencyPathMessage explains a found package with no path from a
// direct/root dependency in the current graph.
func NoDependencyPathMessage(match *graph.Node, resolveTransitives, extended bool) string {
	switch {
	case match == nil:
		return "Package was not found in the dependency graph"
	case match.Direct:
		return "Package is a direct/root dependency"
	case importStatusString(match.GetImportStatus()) != "":
		return "Package is present as a " + importStatusString(match.GetImportStatus()) + " dependency, but no dependency path from a direct/root dependency was resolved"
	case match.Depth == graph.DepthDisconnected && !resolveTransitives:
		return "Package is present in the inventory but disconnected from dependency roots; retry with registry-backed transitive resolution when precise transitive edges are needed"
	case match.Depth == graph.DepthDisconnected && !extended && strings.EqualFold(match.GetEcosystem(), "go"):
		return "Package is present in the Go inventory but no dependency path was resolved; retry with extended graph metadata to include Go import status"
	case match.Depth == graph.DepthDisconnected:
		return "Package is present in the inventory but no dependency path from a direct/root dependency was resolved"
	default:
		return "Package is present in the dependency graph, but no dependency path from a direct/root dependency was resolved"
	}
}

func importStatusString(status graph.ImportStatus) string {
	switch status {
	case graph.ImportStatusImported:
		return "imported"
	case graph.ImportStatusRequired:
		return "required"
	case graph.ImportStatusDeclared:
		return "declared"
	default:
		return ""
	}
}

// ResolveTargetPURLs returns graph node PURLs matching target identity and,
// when provided, an equivalent target version.
func ResolveTargetPURLs(g *graph.Graph, target packageurl.PackageURL) []string {
	if g == nil {
		return nil
	}
	hasVersion := target.Version != ""

	var matches []string
	for node := range g.Nodes() {
		if node.Purl == "" {
			continue
		}
		parsedNode, err := purlx.ParseLoose(node.Purl)
		if err != nil {
			continue
		}
		if !samePURLIdentity(parsedNode, target) {
			continue
		}
		if hasVersion && !VersionsEquivalent(parsedNode.Version, target.Version) {
			continue
		}
		matches = append(matches, node.Purl)
	}
	return matches
}

// NameMatchScore returns the name-only match score used by CLI list rendering.
// Scores are 3 for exact, 2 for final-segment, 1 for substring, and 0 for no
// match.
func NameMatchScore(name, query string) int {
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" || strings.ContainsAny(query, "*?[") {
		return 0
	}
	return nameMatchScore(name, query)
}

type packageQuery struct {
	name       string
	version    string
	hasVersion bool
	purl       packageurl.PackageURL
	hasPURL    bool
	isGlob     bool
}

func parsePackageQuery(query string) packageQuery {
	query = strings.TrimSpace(query)
	if parsed, err := purlx.ParseLoose(query); err == nil {
		return packageQuery{
			name:       purlPackageName(parsed),
			version:    parsed.Version,
			hasVersion: parsed.Version != "",
			purl:       parsed,
			hasPURL:    true,
		}
	}

	name, version, hasVersion := splitPackageVersion(query)
	return packageQuery{
		name:       name,
		version:    version,
		hasVersion: hasVersion,
		isGlob:     strings.ContainsAny(query, "*?["),
	}
}

func purlPackageName(purl packageurl.PackageURL) string {
	if purl.Namespace == "" {
		return purl.Name
	}
	return purl.Namespace + "/" + purl.Name
}

func splitPackageVersion(query string) (string, string, bool) {
	query = strings.TrimSpace(query)
	i := strings.LastIndexByte(query, '@')
	if i <= 0 || i == len(query)-1 {
		return query, "", false
	}
	return strings.TrimSpace(query[:i]), strings.TrimSpace(query[i+1:]), true
}

func purlMatchRank(node *graph.Node, query packageQuery) int {
	if !query.hasPURL || node.Purl == "" {
		return 0
	}
	parsedNode, err := purlx.ParseLoose(node.Purl)
	if err != nil {
		return 0
	}
	if !samePURLIdentity(parsedNode, query.purl) {
		return 0
	}
	if query.hasVersion {
		if !VersionsEquivalent(parsedNode.Version, query.version) {
			return 0
		}
		return 5
	}
	return 4
}

func samePURLIdentity(a, b packageurl.PackageURL) bool {
	return strings.EqualFold(a.Type, b.Type) &&
		strings.EqualFold(a.Namespace, b.Namespace) &&
		strings.EqualFold(a.Name, b.Name)
}

func nameMatchRank(nodeName string, query packageQuery) int {
	nameLower := strings.ToLower(strings.TrimSpace(nodeName))
	queryLower := strings.ToLower(strings.TrimSpace(query.name))
	if queryLower == "" {
		return 0
	}
	if query.isGlob {
		if matched, _ := path.Match(queryLower, nameLower); matched {
			return 3
		}
		return 0
	}
	return nameMatchScore(nameLower, queryLower)
}

func nameMatchScore(name, queryLower string) int {
	nameLower := strings.ToLower(strings.TrimSpace(name))
	if nameLower == "" || queryLower == "" {
		return 0
	}
	if nameLower == queryLower {
		return 3
	}
	if logicalFinalSegment(nameLower) == queryLower {
		return 2
	}
	if strings.Contains(nameLower, "/"+queryLower+".") ||
		strings.Contains(nameLower, "/"+queryLower+"/") ||
		strings.Contains(nameLower, queryLower) {
		return 1
	}
	return 0
}

func logicalFinalSegment(name string) string {
	finalSegment := name
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		finalSegment = name[idx+1:]
	}
	if strings.HasPrefix(finalSegment, "v") && len(finalSegment) <= 3 {
		base := strings.TrimSuffix(name, "/"+finalSegment)
		if idx := strings.LastIndex(base, "/"); idx >= 0 {
			return base[idx+1:]
		}
		return base
	}
	return finalSegment
}

// VersionsEquivalent reports whether two versions refer to the same package
// release. It accepts Go semver values with or without a leading v.
func VersionsEquivalent(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == b {
		return true
	}
	aSemver := semverComparable(a)
	bSemver := semverComparable(b)
	return semver.IsValid(aSemver) && semver.IsValid(bSemver) && semver.Compare(aSemver, bSemver) == 0
}

func semverComparable(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
