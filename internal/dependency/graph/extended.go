// Package graph provides extended dependency graph capabilities.
package graph

import (
	"bufio"
	"context"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"strings"
	"sync"

	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	"golang.org/x/mod/modfile"
)

// ImportStatus re-exports the proto enum for convenience.
type ImportStatus = graphv1.ImportStatus

// ImportStatus constants re-exported from proto.
const (
	ImportStatusUnspecified = graphv1.ImportStatus_IMPORT_STATUS_UNSPECIFIED
	ImportStatusImported    = graphv1.ImportStatus_IMPORT_STATUS_IMPORTED
	ImportStatusRequired    = graphv1.ImportStatus_IMPORT_STATUS_REQUIRED
	ImportStatusDeclared    = graphv1.ImportStatus_IMPORT_STATUS_DECLARED
)

// ImportStatusCounts re-exports the proto type for convenience.
type ImportStatusCounts = graphv1.ImportStatusCounts

// ModGraphEdge represents a single edge from `go mod graph` output.
// Format: "parent@version child@version"
type ModGraphEdge struct {
	// From is the requiring module (parent).
	FromModule  string
	FromVersion string

	// To is the required module (child).
	ToModule  string
	ToVersion string
}

// ModGraph represents the full module requirement graph from `go mod graph`.
// This includes all modules that could potentially be pulled in, not just
// those selected by MVS for the current build.
type ModGraph struct {
	// Edges contains all requirement relationships.
	Edges []ModGraphEdge

	// Modules maps module path to a list of versions seen in the graph.
	// Multiple versions can exist because different modules may require
	// different versions before MVS selects one.
	Modules map[string][]string

	// MainModule is the root module (the project being scanned).
	MainModule string
}

// ParseGoModGraph builds the module requirement graph by reading go.mod and go.sum files
// and fetching transitive dependencies from the module proxy.
// This approach does not require the Go CLI to be installed.
func ParseGoModGraph(ctx context.Context, dir string) (*ModGraph, error) {
	// Read go.mod
	goModPath := filepath.Join(dir, "go.mod")
	goModData, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	mf, err := modfile.ParseLax(goModPath, goModData, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	if mf.Module == nil {
		return nil, fmt.Errorf("no module directive in go.mod")
	}

	// Read go.sum to get module versions for reference (not authoritative, see GoListMAll docs)
	goSumPath := filepath.Join(dir, "go.sum")
	goSumData, err := os.ReadFile(goSumPath)
	if err != nil {
		// go.sum may not exist if no dependencies
		goSumData = nil
	}

	// Build the graph using proxy fetching
	return BuildModGraphFromFiles(ctx, mf, goSumData)
}

// ParseGoModGraphOutput parses the output of `go mod graph`.
// Each line is "parent@version child@version" or "parent child" for the main module.
func ParseGoModGraphOutput(output string) (*ModGraph, error) {
	graph := &ModGraph{
		Modules: make(map[string][]string),
	}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		fromMod, fromVer := parseModuleVersion(parts[0])
		toMod, toVer := parseModuleVersion(parts[1])

		// Track the main module (appears as parent without version on first line)
		if graph.MainModule == "" && fromVer == "" {
			graph.MainModule = fromMod
		}

		edge := ModGraphEdge{
			FromModule:  fromMod,
			FromVersion: fromVer,
			ToModule:    toMod,
			ToVersion:   toVer,
		}
		graph.Edges = append(graph.Edges, edge)

		// Track all module versions seen
		if fromVer != "" {
			addModuleVersion(graph.Modules, fromMod, fromVer)
		}
		if toVer != "" {
			addModuleVersion(graph.Modules, toMod, toVer)
		}
	}

	return graph, scanner.Err()
}

// parseModuleVersion splits "module@version" into (module, version).
// Returns (module, "") if no version is present (main module case).
func parseModuleVersion(s string) (string, string) {
	idx := strings.LastIndex(s, "@")
	if idx == -1 {
		return s, ""
	}
	return s[:idx], s[idx+1:]
}

// addModuleVersion adds a version to the module's version list if not already present.
func addModuleVersion(modules map[string][]string, mod, ver string) {
	for _, existing := range modules[mod] {
		if existing == ver {
			return
		}
	}
	modules[mod] = append(modules[mod], ver)
}

// GoListMAll returns a best-effort approximation of modules that may be in the build.
//
// IMPORTANT: go.sum is NOT equivalent to `go list -m all`. go.sum is a security cache
// of cryptographic checksums, not a dependency list. It may contain:
//   - Modules from historical dependencies that are no longer used
//   - Multiple versions of the same module (from different transitive paths)
//   - Modules that were fetched but are not in the final build
//
// For accurate build list, use `go list -m all` when the Go CLI is available.
// This function provides a CLI-free approximation by parsing go.sum and selecting
// the highest version seen for each module (which often matches MVS selection,
// but is not guaranteed).
//
// See: https://words.filippo.io/gosum/ - "go.sum Is Not a Lockfile"
func GoListMAll(ctx context.Context, dir string) (map[string]string, error) {
	// Read go.sum
	goSumPath := filepath.Join(dir, "go.sum")
	goSumData, err := os.ReadFile(goSumPath)
	if err != nil {
		// go.sum may not exist if no dependencies
		return make(map[string]string), nil
	}

	// Also read go.mod to get the main module name
	goModPath := filepath.Join(dir, "go.mod")
	goModData, err := os.ReadFile(goModPath)
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	mf, err := modfile.ParseLax(goModPath, goModData, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	modules := ParseGoSum(string(goSumData))

	// Add the main module (no version)
	if mf.Module != nil {
		modules[mf.Module.Mod.Path] = ""
	}

	return modules, nil
}

// ParseGoSum parses a go.sum file and returns a map of module path to version.
//
// go.sum format: module version h1:hash (and module version/go.mod h1:hash)
// Each module may have two entries: one for the module content and one for its go.mod.
//
// Note: go.sum is a checksum cache, not a dependency list. It may contain modules
// that are no longer used. When multiple versions exist for the same module,
// we keep the highest version as a best approximation of MVS selection.
func ParseGoSum(content string) map[string]string {
	modules := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		modulePath := parts[0]
		version := parts[1]

		// Skip /go.mod entries, we only want the actual module versions
		if strings.HasSuffix(version, "/go.mod") {
			version = strings.TrimSuffix(version, "/go.mod")
		}

		// If multiple versions exist, keep the highest (best approximation of MVS selection)
		if existing, ok := modules[modulePath]; ok {
			// Simple comparison - keep the one that's "larger" (typically newer)
			if version > existing {
				modules[modulePath] = version
			}
		} else {
			modules[modulePath] = version
		}
	}

	return modules
}

// BuildModGraphFromFiles builds a ModGraph by parsing go.mod, go.sum, and
// fetching transitive dependency information from the module proxy.
// This is equivalent to `go mod graph` but doesn't require the Go CLI.
func BuildModGraphFromFiles(ctx context.Context, mf *modfile.File, goSumData []byte) (*ModGraph, error) {
	graph := &ModGraph{
		Modules:    make(map[string][]string),
		MainModule: mf.Module.Mod.Path,
	}

	// Parse go.sum to get all known modules and their versions
	allModules := make(map[string]string)
	if goSumData != nil {
		allModules = ParseGoSum(string(goSumData))
	}

	// Add direct dependencies from go.mod as initial edges
	for _, req := range mf.Require {
		edge := ModGraphEdge{
			FromModule:  mf.Module.Mod.Path,
			FromVersion: "", // Main module has no version
			ToModule:    req.Mod.Path,
			ToVersion:   req.Mod.Version,
		}
		graph.Edges = append(graph.Edges, edge)
		addModuleVersion(graph.Modules, req.Mod.Path, req.Mod.Version)

		// If a version is in go.mod but not go.sum, add it
		if _, ok := allModules[req.Mod.Path]; !ok {
			allModules[req.Mod.Path] = req.Mod.Version
		}
	}

	// Create a proxy client to fetch go.mod files
	proxyClient := NewGoProxyClient("")

	// Fetch go.mod for each module to build the full graph
	// We use a work queue to process modules breadth-first
	type workItem struct {
		modulePath string
		version    string
	}

	// Track what we've processed to avoid cycles
	processed := make(map[string]bool)

	// Start with direct dependencies
	var queue []workItem
	for _, req := range mf.Require {
		queue = append(queue, workItem{req.Mod.Path, req.Mod.Version})
	}

	// Limit concurrency for proxy fetches
	const maxConcurrency = 10
	sem := make(chan struct{}, maxConcurrency)

	// Mutex for thread-safe graph updates
	var mu sync.Mutex

	// Process queue with concurrent fetching
	var wg sync.WaitGroup
	for len(queue) > 0 {
		// Process current batch
		batch := queue
		queue = nil

		for _, item := range batch {
			key := item.modulePath + "@" + item.version
			if processed[key] {
				continue
			}
			processed[key] = true

			wg.Add(1)
			go func(mod, ver string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				// Fetch the go.mod from proxy
				depMod, err := proxyClient.FetchGoMod(ctx, mod, ver)
				if err != nil {
					// Module not available on proxy (private module, etc.)
					return
				}

				mu.Lock()
				defer mu.Unlock()

				// Add edges from this module to its dependencies
				for _, req := range depMod.Require {
					if req.Indirect {
						continue // Only direct deps of this module
					}

					childVersion := req.Mod.Version
					// Use the version from go.sum if available (MVS selected version)
					if v, ok := allModules[req.Mod.Path]; ok {
						childVersion = v
					}

					edge := ModGraphEdge{
						FromModule:  mod,
						FromVersion: ver,
						ToModule:    req.Mod.Path,
						ToVersion:   childVersion,
					}
					graph.Edges = append(graph.Edges, edge)
					addModuleVersion(graph.Modules, req.Mod.Path, childVersion)

					// Add to queue if we haven't processed it yet
					childKey := req.Mod.Path + "@" + childVersion
					if !processed[childKey] {
						queue = append(queue, workItem{req.Mod.Path, childVersion})
					}
				}
			}(item.modulePath, item.version)
		}

		// Wait for batch to complete before processing next level
		wg.Wait()
	}

	return graph, nil
}

// ParseGoListMAll parses the output of `go list -m all`.
// Each line is "module version" or just "module" for the main module.
func ParseGoListMAll(output string) map[string]string {
	modules := make(map[string]string)

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) >= 2 {
			modules[parts[0]] = parts[1]
		} else if len(parts) == 1 {
			// Main module (no version)
			modules[parts[0]] = ""
		}
	}

	return modules
}

// ExtendedGraphResult contains the results of extended graph analysis.
type ExtendedGraphResult struct {
	// FullGraph is the complete module requirement graph.
	FullGraph *ModGraph

	// SelectedModules are modules in the final build (go list -m all).
	SelectedModules map[string]string

	// DeclaredOnlyModules are modules in the graph but not selected by MVS.
	// These are "phantom" dependencies - latent supply chain risk.
	DeclaredOnlyModules map[string][]string
}

// AnalyzeExtendedGraph runs both `go mod graph` and `go list -m all` to
// determine which modules are declared vs. actually selected.
func AnalyzeExtendedGraph(ctx context.Context, dir string) (*ExtendedGraphResult, error) {
	// Get full module requirement graph
	modGraph, err := ParseGoModGraph(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("parsing go mod graph: %w", err)
	}

	// Get modules in final build
	selected, err := GoListMAll(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("running go list -m all: %w", err)
	}

	// Find modules that appear in graph but not in final selection
	declaredOnly := make(map[string][]string)
	for mod, versions := range modGraph.Modules {
		if _, isSelected := selected[mod]; !isSelected {
			declaredOnly[mod] = versions
		}
	}

	return &ExtendedGraphResult{
		FullGraph:           modGraph,
		SelectedModules:     selected,
		DeclaredOnlyModules: declaredOnly,
	}, nil
}

// MergeExtendedIntoGraph adds declared-only modules to an existing graph,
// marking them with IMPORT_STATUS_DECLARED.
//
// This enriches a standard graph (from inventory extraction) with the
// full supply chain surface area visible in `go mod graph`.
func MergeExtendedIntoGraph(g *Graph, extended *ExtendedGraphResult) {
	if extended == nil || extended.FullGraph == nil {
		return
	}

	// Mark existing nodes with their import status
	for node := range g.Nodes() {
		if node.Ecosystem != "Go" {
			continue
		}
		// Existing nodes are at least REQUIRED (in go.mod)
		if node.ImportStatus == ImportStatusUnspecified {
			node.ImportStatus = ImportStatusRequired
		}
	}

	// Add declared-only modules as new nodes with DECLARED status
	for mod, versions := range extended.DeclaredOnlyModules {
		// Use the first (or only) version seen
		version := ""
		if len(versions) > 0 {
			version = versions[0]
		}

		purl := goModuleToPURL(mod, version)
		if g.Node(purl) != nil {
			continue // Already exists
		}

		node := &Node{
			Purl:         purl,
			Name:         mod,
			Version:      version,
			Ecosystem:    "Go",
			Direct:       false,
			Depth:        DepthDisconnected, // Not connected to main graph
			ImportStatus: ImportStatusDeclared,
		}
		g.AddNode(node)
	}

	// Build a set of existing edges for O(1) lookup during edge addition.
	// This avoids O(n*m) complexity when merging many edges.
	existingEdges := make(map[string]bool, len(g.edges))
	for _, e := range g.edges {
		existingEdges[edgeKey(e.From, e.To)] = true
	}

	// Add edges from the full module graph for declared modules
	for _, edge := range extended.FullGraph.Edges {
		fromPURL := goModuleToPURL(edge.FromModule, edge.FromVersion)
		toPURL := goModuleToPURL(edge.ToModule, edge.ToVersion)

		// Only add edges where at least one end is a declared-only module
		fromNode := g.Node(fromPURL)
		toNode := g.Node(toPURL)

		if fromNode == nil || toNode == nil {
			continue
		}

		// Check if we already have this edge using O(1) lookup
		key := edgeKey(fromPURL, toPURL)
		if existingEdges[key] {
			continue
		}

		if fromNode.ImportStatus == ImportStatusDeclared ||
			toNode.ImportStatus == ImportStatusDeclared {
			g.AddEdge(&Edge{
				From:  fromPURL,
				To:    toPURL,
				Scope: ScopeRuntime,
			})
			existingEdges[key] = true
		}
	}
}

// edgeKey creates a unique string key for an edge for use in maps.
func edgeKey(from, to string) string {
	return from + "\x00" + to
}

// CountImportStatuses returns counts of nodes by import status.
func (g *Graph) CountImportStatuses() *ImportStatusCounts {
	counts := &ImportStatusCounts{}

	for node := range g.Nodes() {
		switch node.ImportStatus {
		case ImportStatusImported:
			counts.Imported++
		case ImportStatusRequired:
			counts.Required++
		case ImportStatusDeclared:
			counts.Declared++
		}
	}

	return counts
}

// FilterByImportStatus returns a new graph containing only nodes with
// the specified import statuses.
func (g *Graph) FilterByImportStatus(statuses ...ImportStatus) *Graph {
	statusSet := make(map[ImportStatus]bool)
	for _, s := range statuses {
		statusSet[s] = true
	}

	return g.Filter(func(n *Node) bool {
		return statusSet[n.ImportStatus]
	})
}

// DeclaredOnlyNodes returns an iterator over nodes with DECLARED import status.
// These are "phantom" dependencies - in the module graph but not the final build.
func (g *Graph) DeclaredOnlyNodes() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for node := range g.Nodes() {
			if node.ImportStatus == ImportStatusDeclared {
				if !yield(node) {
					return
				}
			}
		}
	}
}

// RequiredOnlyNodes returns an iterator over nodes with REQUIRED import status.
// These are in go.mod but may not be directly imported by user code.
func (g *Graph) RequiredOnlyNodes() iter.Seq[*Node] {
	return func(yield func(*Node) bool) {
		for node := range g.Nodes() {
			if node.ImportStatus == ImportStatusRequired {
				if !yield(node) {
					return
				}
			}
		}
	}
}
