package graph

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// NpmResolver resolves dependency edges for npm/yarn/pnpm packages by parsing lockfiles.
// Unlike Go modules, npm lockfiles contain the complete dependency tree with explicit
// parent-child relationships, making edge resolution precise without external fetches.
//
// Supported lockfiles:
//   - package-lock.json (npm v2/v3 format with "packages" field)
//   - yarn.lock (parsed as flat list, edges from package.json)
//   - pnpm-lock.yaml (parsed as structured YAML)
//
// Note: This resolver does not use deps.dev because npm lockfiles already contain
// the complete dependency graph. deps.dev would be redundant and slower.
type NpmResolver struct {
	// maxConcurrency limits parallel operations (not currently used for npm).
	maxConcurrency int
}

// NpmResolverOption configures an NpmResolver.
type NpmResolverOption func(*NpmResolver)

// WithNpmConcurrency sets the maximum concurrency for npm resolution.
func WithNpmConcurrency(n int) NpmResolverOption {
	return func(r *NpmResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// NewNpmResolver creates a new npm edge resolver.
func NewNpmResolver(opts ...NpmResolverOption) *NpmResolver {
	r := &NpmResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "npm" as the ecosystem identifier.
func (r *NpmResolver) Ecosystem() string {
	return "npm"
}

// ResolveEdges parses npm/yarn/pnpm lockfiles to add dependency edges to the graph.
func (r *NpmResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Find all lockfiles
	lockFiles, err := r.findLockFiles(files)
	if err != nil {
		return fmt.Errorf("finding npm lockfiles: %w", err)
	}

	if len(lockFiles) == 0 {
		return nil
	}

	// Process each lockfile based on its type
	for _, lockFile := range lockFiles {
		var processErr error
		switch lockFile.lockType {
		case lockfileNpm:
			processErr = r.processPackageLock(ctx, g, files, lockFile.path)
		case lockfileYarn:
			processErr = r.processYarnLock(ctx, g, files, lockFile.path)
		case lockfilePnpm:
			processErr = r.processPnpmLock(ctx, g, files, lockFile.path)
		}
		if processErr != nil {
			// Log but continue - partial resolution is better than none
			continue
		}
	}

	// Update depths based on resolved edges
	g.UpdateDepths()

	return nil
}

// lockfileType indicates the type of lockfile.
type lockfileType int

const (
	lockfileNpm lockfileType = iota
	lockfileYarn
	lockfilePnpm
)

// lockfileInfo contains information about a discovered lockfile.
type lockfileInfo struct {
	path     string
	lockType lockfileType
}

// findLockFiles locates all npm/yarn/pnpm lockfiles accessible via the FileReader.
func (r *NpmResolver) findLockFiles(files FileReader) ([]lockfileInfo, error) {
	var lockFiles []lockfileInfo

	// Try common locations with priority order
	// We prefer package-lock.json over yarn.lock over pnpm-lock.yaml when multiple exist
	commonPaths := []struct {
		path     string
		lockType lockfileType
	}{
		{"package-lock.json", lockfileNpm},
		{"npm-shrinkwrap.json", lockfileNpm},
		{"yarn.lock", lockfileYarn},
		{"pnpm-lock.yaml", lockfilePnpm},
		{"pnpm-lock.yml", lockfilePnpm},
	}

	for _, p := range commonPaths {
		if data, err := files.ReadFile(p.path); err == nil && len(data) > 0 {
			lockFiles = append(lockFiles, lockfileInfo{path: p.path, lockType: p.lockType})
		}
	}

	// If the FileReader also implements fs.FS, walk for nested lockfiles
	if fsReader, ok := files.(fs.FS); ok {
		_ = fs.WalkDir(fsReader, ".", func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "node_modules" || name == "vendor" || name == "testdata" {
					return fs.SkipDir
				}
				return nil
			}
			base := path.Base(filePath)
			var lockType lockfileType
			switch base {
			case "package-lock.json", "npm-shrinkwrap.json":
				lockType = lockfileNpm
			case "yarn.lock":
				lockType = lockfileYarn
			case "pnpm-lock.yaml", "pnpm-lock.yml":
				lockType = lockfilePnpm
			default:
				return nil
			}

			// Avoid duplicates
			for _, existing := range lockFiles {
				if existing.path == filePath {
					return nil
				}
			}
			lockFiles = append(lockFiles, lockfileInfo{path: filePath, lockType: lockType})
			return nil
		})
	}

	return lockFiles, nil
}

// packageLockJSON represents the npm package-lock.json format (v2/v3).
type packageLockJSON struct {
	Name            string                      `json:"name"`
	Version         string                      `json:"version"`
	LockfileVersion int                         `json:"lockfileVersion"`
	Packages        map[string]packageLockEntry `json:"packages"`
	Dependencies    map[string]legacyDep        `json:"dependencies"` // v1 format fallback
}

// packageLockEntry represents an entry in the "packages" field (v2/v3 format).
type packageLockEntry struct {
	Version              string            `json:"version"`
	Resolved             string            `json:"resolved"`
	Dev                  bool              `json:"dev"`
	Optional             bool              `json:"optional"`
	Peer                 bool              `json:"peer"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// legacyDep represents a dependency in the v1 "dependencies" format.
type legacyDep struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Optional     bool                  `json:"optional"`
	Requires     map[string]string     `json:"requires"`
	Dependencies map[string]*legacyDep `json:"dependencies"`
}

// processPackageLock parses a package-lock.json and adds edges to the graph.
func (r *NpmResolver) processPackageLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	var lock packageLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	// Get root package name for creating edges
	rootName := lock.Name
	if rootName == "" {
		// Try to get from package.json in same directory
		dir := path.Dir(lockPath)
		if dir == "." {
			dir = ""
		}
		pkgJSONPath := path.Join(dir, "package.json")
		if pkgData, err := files.ReadFile(pkgJSONPath); err == nil {
			var pkg struct {
				Name string `json:"name"`
			}
			if json.Unmarshal(pkgData, &pkg) == nil {
				rootName = pkg.Name
			}
		}
	}

	// Create a synthetic root node if we have the name
	var rootPURL string
	if rootName != "" {
		rootPURL = npmPkgToPURL(rootName, lock.Version)
		if g.Node(rootPURL) == nil {
			g.AddNode(&Node{
				Purl:      rootPURL,
				Name:      rootName,
				Version:   lock.Version,
				Ecosystem: "npm",
				Direct:    true,
				Depth:     DepthSyntheticRoot,
			})
		}
		if !containsRoot(g.roots, rootPURL) {
			g.roots = append(g.roots, rootPURL)
		}
	}

	// Use the modern "packages" format if available (v2/v3)
	if len(lock.Packages) > 0 {
		return r.resolveFromPackages(g, lock.Packages, rootPURL)
	}

	// Fall back to legacy "dependencies" format (v1)
	if len(lock.Dependencies) > 0 {
		return r.resolveFromLegacyDeps(g, lock.Dependencies, rootPURL)
	}

	return nil
}

// resolveFromPackages processes the v2/v3 "packages" format.
// Keys are paths relative to node_modules, e.g.:
//   - "" (empty string) = root package
//   - "node_modules/lodash" = direct dependency
//   - "node_modules/express/node_modules/debug" = nested dependency
func (r *NpmResolver) resolveFromPackages(g *Graph, packages map[string]packageLockEntry, rootPURL string) error {
	// Build a map of package paths to PURLs
	pathToPURL := make(map[string]string)

	// Get root package's dependencies to determine what's truly direct
	// (npm hoists transitive deps to node_modules/, but they're not direct)
	rootEntry := packages[""]
	rootDeps := make(map[string]bool)
	for name := range rootEntry.Dependencies {
		rootDeps[name] = true
	}
	for name := range rootEntry.DevDependencies {
		rootDeps[name] = true
	}
	for name := range rootEntry.PeerDependencies {
		rootDeps[name] = true
	}
	for name := range rootEntry.OptionalDependencies {
		rootDeps[name] = true
	}

	// First pass: map all package paths to PURLs
	for pkgPath, entry := range packages {
		if pkgPath == "" {
			// Root package
			if rootPURL != "" {
				pathToPURL[pkgPath] = rootPURL
			}
			continue
		}

		name := extractNpmPackageName(pkgPath)
		if name == "" {
			continue
		}

		purl := npmPkgToPURL(name, entry.Version)
		pathToPURL[pkgPath] = purl

		// A package is direct if:
		// 1. It's in the root's dependencies (not just hoisted to node_modules/)
		// 2. It's at the top level (not nested under another package)
		isDirect := isDirectNpmDep(pkgPath) && rootDeps[name]

		node := g.Node(purl)
		if node == nil {
			// Check if node exists with different version
			node = r.findNodeByName(g, name)
		}
		if node == nil {
			// Create new node
			g.AddNode(&Node{
				Purl:      purl,
				Name:      name,
				Version:   entry.Version,
				Ecosystem: "npm",
				Direct:    isDirect,
				Depth:     DepthDisconnected, // Will be calculated later
			})
			if isDirect && !containsRoot(g.roots, purl) {
				g.roots = append(g.roots, purl)
			}
		} else {
			// Update existing node's direct status
			if isDirect {
				node.Direct = true
				if !containsRoot(g.roots, node.Purl) {
					g.roots = append(g.roots, node.Purl)
				}
			}
		}
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Second pass: create edges based on dependencies
	for pkgPath, entry := range packages {
		parentPURL := pathToPURL[pkgPath]
		if parentPURL == "" {
			continue
		}

		// Add edges for all dependency types
		allDeps := make(map[string]string)
		maps.Copy(allDeps, entry.Dependencies)
		maps.Copy(allDeps, entry.DevDependencies)
		maps.Copy(allDeps, entry.PeerDependencies)
		maps.Copy(allDeps, entry.OptionalDependencies)

		for depName, depVersion := range allDeps {
			// Find the resolved version in node_modules
			// npm hoists dependencies, so we need to find the actual resolved version
			childPURL := r.findResolvedPackage(g, packages, pathToPURL, pkgPath, depName, depVersion)
			if childPURL == "" {
				// Try direct PURL construction
				childPURL = npmPkgToPURL(depName, depVersion)
			}

			childNode := g.Node(childPURL)
			if childNode == nil {
				childNode = r.findNodeByName(g, depName)
			}
			if childNode == nil {
				continue
			}

			edgeKey := parentPURL + "->" + childNode.Purl
			if !edgeSet[edgeKey] {
				scope := ScopeRuntime
				if entry.Dev {
					scope = ScopeDev
				} else if entry.Optional {
					scope = ScopeOptional
				}

				g.AddEdge(&Edge{
					From:       parentPURL,
					To:         childNode.Purl,
					Constraint: depVersion,
					Scope:      scope,
				})
				edgeSet[edgeKey] = true
			}
		}
	}

	return nil
}

// findResolvedPackage finds the PURL for a dependency by walking up the node_modules tree.
func (r *NpmResolver) findResolvedPackage(g *Graph, packages map[string]packageLockEntry, pathToPURL map[string]string, parentPath, depName, depVersion string) string {
	// npm hoists packages to the highest level possible
	// Walk from the current path up to the root, looking for the dependency

	// First, check if there's a nested version specific to this package
	if parentPath != "" {
		nestedPath := parentPath + "/node_modules/" + depName
		if purl, ok := pathToPURL[nestedPath]; ok {
			return purl
		}
	}

	// Check hoisted location (direct in node_modules)
	directPath := "node_modules/" + depName
	if purl, ok := pathToPURL[directPath]; ok {
		return purl
	}

	// Fall back to constructing PURL with specified version
	return npmPkgToPURL(depName, depVersion)
}

// resolveFromLegacyDeps processes the v1 "dependencies" format.
func (r *NpmResolver) resolveFromLegacyDeps(g *Graph, deps map[string]legacyDep, rootPURL string) error {
	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process each direct dependency
	for name, dep := range deps {
		purl := npmPkgToPURL(name, dep.Version)

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, name)
		}
		if node == nil {
			node = &Node{
				Purl:      purl,
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "npm",
				Direct:    true,
				Depth:     0,
			}
			g.AddNode(node)
		}
		node.Direct = true
		if !containsRoot(g.roots, purl) {
			g.roots = append(g.roots, purl)
		}

		// Add edge from root
		if rootPURL != "" {
			edgeKey := rootPURL + "->" + purl
			if !edgeSet[edgeKey] {
				g.AddEdge(&Edge{
					From:  rootPURL,
					To:    purl,
					Scope: scopeFromDep(&dep),
				})
				edgeSet[edgeKey] = true
			}
		}

		// Process nested dependencies recursively
		r.processLegacyDepTree(g, &dep, purl, edgeSet)
	}

	return nil
}

// processLegacyDepTree recursively processes nested dependencies in v1 format.
func (r *NpmResolver) processLegacyDepTree(g *Graph, parent *legacyDep, parentPURL string, edgeSet map[string]bool) {
	// Process "requires" - these are the direct dependencies of this package
	for name, version := range parent.Requires {
		childPURL := npmPkgToPURL(name, version)

		childNode := g.Node(childPURL)
		if childNode == nil {
			childNode = r.findNodeByName(g, name)
		}
		if childNode == nil {
			childNode = &Node{
				Purl:      childPURL,
				Name:      name,
				Version:   version,
				Ecosystem: "npm",
				Depth:     DepthDisconnected,
			}
			g.AddNode(childNode)
		}

		edgeKey := parentPURL + "->" + childNode.Purl
		if !edgeSet[edgeKey] {
			g.AddEdge(&Edge{
				From:  parentPURL,
				To:    childNode.Purl,
				Scope: ScopeRuntime,
			})
			edgeSet[edgeKey] = true
		}
	}

	// Process nested "dependencies" - these override hoisted versions
	for name, nested := range parent.Dependencies {
		childPURL := npmPkgToPURL(name, nested.Version)

		childNode := g.Node(childPURL)
		if childNode == nil {
			childNode = &Node{
				Purl:      childPURL,
				Name:      name,
				Version:   nested.Version,
				Ecosystem: "npm",
				Depth:     DepthDisconnected,
			}
			g.AddNode(childNode)
		}

		edgeKey := parentPURL + "->" + childPURL
		if !edgeSet[edgeKey] {
			g.AddEdge(&Edge{
				From:  parentPURL,
				To:    childPURL,
				Scope: scopeFromDep(nested),
			})
			edgeSet[edgeKey] = true
		}

		// Recurse into nested dependencies
		r.processLegacyDepTree(g, nested, childPURL, edgeSet)
	}
}

// findNodeByName finds a node by its package name, ignoring version.
func (r *NpmResolver) findNodeByName(g *Graph, name string) *Node {
	lowerName := strings.ToLower(name)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerName {
			return node
		}
	}
	return nil
}

// npmPkgToPURL converts an npm package name and version to a Package URL.
// Handles scoped packages: @scope/name -> pkg:npm/@scope/name@version
func npmPkgToPURL(name, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:npm/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:npm/%s", name)
}

// extractNpmPackageName extracts the package name from a package-lock.json path.
// Examples:
//   - "node_modules/lodash" -> "lodash"
//   - "node_modules/@types/node" -> "@types/node"
//   - "node_modules/express/node_modules/debug" -> "debug"
func extractNpmPackageName(pkgPath string) string {
	if pkgPath == "" {
		return ""
	}

	// Find the last node_modules segment
	const nodeModules = "node_modules/"
	idx := strings.LastIndex(pkgPath, nodeModules)
	if idx == -1 {
		return ""
	}

	// Get everything after the last "node_modules/"
	name := pkgPath[idx+len(nodeModules):]

	// Handle scoped packages (@scope/name) - name includes the full @scope/name
	// For regular packages, name is just the package name
	return name
}

// isDirectNpmDep checks if a package path represents a direct dependency.
// Direct dependencies are immediately under node_modules/ with no nesting.
func isDirectNpmDep(pkgPath string) bool {
	// Count how many times "node_modules" appears
	count := strings.Count(pkgPath, "node_modules")

	// Direct deps have exactly one "node_modules" segment
	if count != 1 {
		return false
	}

	// Check path format: should be "node_modules/<name>" or "node_modules/@scope/<name>"
	after := strings.TrimPrefix(pkgPath, "node_modules/")
	if strings.HasPrefix(after, "@") {
		// Scoped package: @scope/name - should have exactly one slash after @
		if strings.Count(after, "/") == 1 {
			return true
		}
	} else {
		// Regular package: no slashes
		if !strings.Contains(after, "/") {
			return true
		}
	}

	return false
}

// scopeFromDep determines the scope from a legacy dependency entry.
func scopeFromDep(dep *legacyDep) Scope {
	if dep.Dev {
		return ScopeDev
	}
	if dep.Optional {
		return ScopeOptional
	}
	return ScopeRuntime
}

// ============================================================================
// yarn.lock parsing
// ============================================================================

// yarnPackageVersionRe matches version lines in yarn.lock.
// Format v1: `version "0.0.1"`
// Format v2: `version: 0.0.1`
var yarnPackageVersionRe = regexp.MustCompile(`^ {2}"?version"?:? "?([\w\-.+]+)"?$`)

// yarnDependencyRe matches dependency lines in yarn.lock.
// Format: `    "package-name" "^1.0.0"` or `    package-name "^1.0.0"`
var yarnDependencyRe = regexp.MustCompile(`^ {4}"?([^"]+)"? "([^"]+)"$`)

// yarnPackageEntry represents a parsed yarn.lock package entry.
type yarnPackageEntry struct {
	name         string
	version      string
	dependencies map[string]string // name -> version constraint
	dev          bool
}

// processYarnLock parses a yarn.lock file and adds edges to the graph.
func (r *NpmResolver) processYarnLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	// Parse yarn.lock into package entries
	entries, err := parseYarnLock(data)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	if len(entries) == 0 {
		return nil
	}

	// Get root package info from package.json
	dir := path.Dir(lockPath)
	if dir == "." {
		dir = ""
	}
	pkgJSONPath := path.Join(dir, "package.json")
	rootName, rootVersion, rootDeps := r.parsePackageJSON(files, pkgJSONPath)

	// Create synthetic root node if we have the name
	var rootPURL string
	if rootName != "" {
		rootPURL = npmPkgToPURL(rootName, rootVersion)
		if g.Node(rootPURL) == nil {
			g.AddNode(&Node{
				Purl:      rootPURL,
				Name:      rootName,
				Version:   rootVersion,
				Ecosystem: "npm",
				Direct:    true,
				Depth:     DepthSyntheticRoot,
			})
		}
		if !containsRoot(g.roots, rootPURL) {
			g.roots = append(g.roots, rootPURL)
		}
	}

	// Build a map of package name -> PURL for resolved versions
	nameToPURL := make(map[string]string)
	for _, entry := range entries {
		if entry.name != "" && entry.version != "" {
			purl := npmPkgToPURL(entry.name, entry.version)
			nameToPURL[entry.name] = purl

			// Ensure node exists
			node := g.Node(purl)
			if node == nil {
				node = r.findNodeByName(g, entry.name)
			}
			if node == nil {
				isDirect := rootDeps[entry.name]
				g.AddNode(&Node{
					Purl:      purl,
					Name:      entry.name,
					Version:   entry.version,
					Ecosystem: "npm",
					Direct:    isDirect,
					Depth:     DepthDisconnected,
				})
				if isDirect && !containsRoot(g.roots, purl) {
					g.roots = append(g.roots, purl)
				}
			} else if rootDeps[entry.name] {
				node.Direct = true
				if !containsRoot(g.roots, node.Purl) {
					g.roots = append(g.roots, node.Purl)
				}
			}
		}
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Create edges from root to direct deps
	if rootPURL != "" {
		for depName := range rootDeps {
			if childPURL, ok := nameToPURL[depName]; ok {
				edgeKey := rootPURL + "->" + childPURL
				if !edgeSet[edgeKey] {
					g.AddEdge(&Edge{
						From:  rootPURL,
						To:    childPURL,
						Scope: ScopeRuntime,
					})
					edgeSet[edgeKey] = true
				}
			}
		}
	}

	// Create edges based on yarn.lock dependencies
	for _, entry := range entries {
		if entry.name == "" || entry.version == "" {
			continue
		}
		parentPURL := npmPkgToPURL(entry.name, entry.version)

		for depName, depConstraint := range entry.dependencies {
			// Find the resolved version in our entries
			childPURL, ok := nameToPURL[depName]
			if !ok {
				// Try to find in graph by name
				if node := r.findNodeByName(g, depName); node != nil {
					childPURL = node.Purl
				} else {
					continue
				}
			}

			edgeKey := parentPURL + "->" + childPURL
			if !edgeSet[edgeKey] {
				scope := ScopeRuntime
				if entry.dev {
					scope = ScopeDev
				}
				g.AddEdge(&Edge{
					From:       parentPURL,
					To:         childPURL,
					Constraint: depConstraint,
					Scope:      scope,
				})
				edgeSet[edgeKey] = true
			}
		}
	}

	return nil
}

// parseYarnLock parses yarn.lock content into package entries.
func parseYarnLock(data []byte) ([]yarnPackageEntry, error) {
	var entries []yarnPackageEntry
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var current *yarnPackageEntry
	inDependencies := false

	for scanner.Scan() {
		line := scanner.Text()

		// Skip empty lines and comments
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Skip metadata blocks
		if trimmed == "__metadata:" {
			current = nil
			continue
		}

		// New package header (starts at column 0, not indented)
		if !strings.HasPrefix(line, " ") {
			if current != nil && current.name != "" && current.version != "" {
				entries = append(entries, *current)
			}
			current = &yarnPackageEntry{
				name:         extractYarnPackageName(line),
				dependencies: make(map[string]string),
			}
			inDependencies = false
			continue
		}

		if current == nil {
			continue
		}

		// Check for version line
		if matches := yarnPackageVersionRe.FindStringSubmatch(line); matches != nil {
			current.version = matches[1]
			continue
		}

		// Check for dependencies section start
		if strings.HasPrefix(line, "  dependencies:") || strings.HasPrefix(line, "  \"dependencies\":") {
			inDependencies = true
			continue
		}

		// Check for other section start (ends dependencies)
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "    ") {
			if strings.Contains(line, ":") {
				inDependencies = false
			}
			continue
		}

		// Parse dependency entries (4-space indent)
		if inDependencies {
			if matches := yarnDependencyRe.FindStringSubmatch(line); matches != nil {
				current.dependencies[matches[1]] = matches[2]
			}
		}
	}

	// Don't forget the last entry
	if current != nil && current.name != "" && current.version != "" {
		entries = append(entries, *current)
	}

	return entries, scanner.Err()
}

// extractYarnPackageName extracts the package name from a yarn.lock header line.
// Format: `"@scope/name@^1.0.0":` or `name@^1.0.0:`
func extractYarnPackageName(header string) string {
	str := strings.TrimPrefix(header, "\"")
	str = strings.TrimSuffix(str, ":")
	str, _, _ = strings.Cut(str, ",")

	isScoped := strings.HasPrefix(str, "@")
	if isScoped {
		str = strings.TrimPrefix(str, "@")
	}

	name, right, _ := strings.Cut(str, "@")

	// Handle npm: aliases like @nicolo-ribaudo/chokidar-2@npm:2.1.8
	if strings.HasPrefix(right, "npm:") && strings.Contains(right, "@") {
		return extractYarnPackageName(strings.TrimPrefix(right, "npm:"))
	}

	if isScoped {
		name = "@" + name
	}
	return name
}

// parsePackageJSON reads package.json and returns name, version, and direct deps map.
func (r *NpmResolver) parsePackageJSON(files FileReader, pkgJSONPath string) (string, string, map[string]bool) {
	deps := make(map[string]bool)

	data, err := files.ReadFile(pkgJSONPath)
	if err != nil {
		return "", "", deps
	}

	var pkg struct {
		Name                 string            `json:"name"`
		Version              string            `json:"version"`
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}

	if err := json.Unmarshal(data, &pkg); err != nil {
		return "", "", deps
	}

	for name := range pkg.Dependencies {
		deps[name] = true
	}
	for name := range pkg.DevDependencies {
		deps[name] = true
	}
	for name := range pkg.PeerDependencies {
		deps[name] = true
	}
	for name := range pkg.OptionalDependencies {
		deps[name] = true
	}

	return pkg.Name, pkg.Version, deps
}

// ============================================================================
// pnpm-lock.yaml parsing
// ============================================================================

// pnpmLockfile represents the pnpm-lock.yaml structure.
type pnpmLockfile struct {
	LockfileVersion string                     `yaml:"lockfileVersion"`
	Dependencies    map[string]string          `yaml:"dependencies"`
	DevDependencies map[string]string          `yaml:"devDependencies"`
	Packages        map[string]pnpmLockPackage `yaml:"packages"`
}

// pnpmLockPackage represents a package entry in pnpm-lock.yaml.
type pnpmLockPackage struct {
	Name         string            `yaml:"name"`
	Version      string            `yaml:"version"`
	Dev          bool              `yaml:"dev"`
	Optional     bool              `yaml:"optional"`
	Dependencies map[string]string `yaml:"dependencies"`
	Resolution   struct {
		Integrity string `yaml:"integrity"`
	} `yaml:"resolution"`
}

// processPnpmLock parses a pnpm-lock.yaml file and adds edges to the graph.
func (r *NpmResolver) processPnpmLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	var lock pnpmLockfile
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	if len(lock.Packages) == 0 {
		return nil
	}

	// Get root package info from package.json
	dir := path.Dir(lockPath)
	if dir == "." {
		dir = ""
	}
	pkgJSONPath := path.Join(dir, "package.json")
	rootName, rootVersion, rootDeps := r.parsePackageJSON(files, pkgJSONPath)

	// Create synthetic root node
	var rootPURL string
	if rootName != "" {
		rootPURL = npmPkgToPURL(rootName, rootVersion)
		if g.Node(rootPURL) == nil {
			g.AddNode(&Node{
				Purl:      rootPURL,
				Name:      rootName,
				Version:   rootVersion,
				Ecosystem: "npm",
				Direct:    true,
				Depth:     DepthSyntheticRoot,
			})
		}
		if !containsRoot(g.roots, rootPURL) {
			g.roots = append(g.roots, rootPURL)
		}
	}

	// Parse lockfile version for format differences
	lockVersion := parsePnpmLockVersion(lock.LockfileVersion)

	// Build package map: path -> (name, version, PURL)
	type pkgInfo struct {
		name    string
		version string
		purl    string
		dev     bool
	}
	pkgMap := make(map[string]pkgInfo)

	for pkgPath, pkg := range lock.Packages {
		name, version := extractPnpmPackageNameVersion(pkgPath, lockVersion, pkg)
		if name == "" || version == "" {
			continue
		}

		purl := npmPkgToPURL(name, version)
		pkgMap[pkgPath] = pkgInfo{name: name, version: version, purl: purl, dev: pkg.Dev}

		// Ensure node exists
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, name)
		}
		if node == nil {
			isDirect := rootDeps[name]
			g.AddNode(&Node{
				Purl:      purl,
				Name:      name,
				Version:   version,
				Ecosystem: "npm",
				Direct:    isDirect,
				Depth:     DepthDisconnected,
			})
			if isDirect && !containsRoot(g.roots, purl) {
				g.roots = append(g.roots, purl)
			}
		} else if rootDeps[name] {
			node.Direct = true
			if !containsRoot(g.roots, node.Purl) {
				g.roots = append(g.roots, node.Purl)
			}
		}
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Create edges from root to direct deps
	if rootPURL != "" {
		for depName := range rootDeps {
			// Find the resolved version
			for _, info := range pkgMap {
				if info.name == depName {
					edgeKey := rootPURL + "->" + info.purl
					if !edgeSet[edgeKey] {
						g.AddEdge(&Edge{
							From:  rootPURL,
							To:    info.purl,
							Scope: ScopeRuntime,
						})
						edgeSet[edgeKey] = true
					}
					break
				}
			}
		}
	}

	// Create edges based on pnpm dependencies
	for pkgPath, pkg := range lock.Packages {
		info, ok := pkgMap[pkgPath]
		if !ok {
			continue
		}

		for depName, depVersion := range pkg.Dependencies {
			// Find the child package
			childPURL := ""
			for _, childInfo := range pkgMap {
				if childInfo.name == depName {
					childPURL = childInfo.purl
					break
				}
			}
			if childPURL == "" {
				// Try graph lookup
				if node := r.findNodeByName(g, depName); node != nil {
					childPURL = node.Purl
				} else {
					continue
				}
			}

			edgeKey := info.purl + "->" + childPURL
			if !edgeSet[edgeKey] {
				scope := ScopeRuntime
				if info.dev {
					scope = ScopeDev
				} else if pkg.Optional {
					scope = ScopeOptional
				}
				g.AddEdge(&Edge{
					From:       info.purl,
					To:         childPURL,
					Constraint: depVersion,
					Scope:      scope,
				})
				edgeSet[edgeKey] = true
			}
		}
	}

	return nil
}

// parsePnpmLockVersion parses the lockfile version as a float.
func parsePnpmLockVersion(v string) float64 {
	// Remove quotes if present
	v = strings.Trim(v, "'\"")
	var version float64
	fmt.Sscanf(v, "%f", &version)
	return version
}

// extractPnpmPackageNameVersion extracts name and version from a pnpm package path.
// Format varies by version:
//   - v5: /name/version or /@scope/name/version
//   - v6+: /name@version or /@scope/name@version
//   - v9: 'name@version' or '@scope/name@version'
func extractPnpmPackageNameVersion(pkgPath string, lockVersion float64, pkg pnpmLockPackage) (string, string) {
	// Package entry may have explicit name/version
	if pkg.Name != "" && pkg.Version != "" {
		return pkg.Name, pkg.Version
	}

	// Skip file: dependencies
	if strings.HasPrefix(pkgPath, "file:") {
		return "", ""
	}

	// v9 format: 'name@version' or '@scope/name@version'
	if lockVersion >= 9.0 {
		pkgPath = strings.Trim(pkgPath, "'")
		isScoped := strings.HasPrefix(pkgPath, "@")
		if isScoped {
			pkgPath = strings.TrimPrefix(pkgPath, "@")
		}
		name, version, _ := strings.Cut(pkgPath, "@")
		if isScoped {
			name = "@" + name
		}
		// Handle peer dep suffixes like "acorn@8.7.0_peer@1.0.0"
		if idx := strings.Index(version, "_"); idx != -1 {
			version = version[:idx]
		}
		return name, version
	}

	// v5/v6 format: /name/version or /@scope/name/version
	parts := strings.Split(strings.TrimPrefix(pkgPath, "/"), "/")
	if len(parts) < 2 {
		return "", ""
	}

	var name, version string
	if strings.HasPrefix(parts[0], "@") {
		// Scoped: /@scope/name/version or /@scope/name@version
		if len(parts) >= 3 {
			name = parts[0] + "/" + parts[1]
			version = parts[2]
		} else if len(parts) == 2 {
			// Could be @scope/name@version format
			name = parts[0] + "/" + strings.Split(parts[1], "@")[0]
			if atIdx := strings.LastIndex(parts[1], "@"); atIdx > 0 {
				version = parts[1][atIdx+1:]
			}
		}
	} else {
		// Unscoped: /name/version or /name@version
		if len(parts) >= 2 && !strings.Contains(parts[0], "@") {
			name = parts[0]
			version = parts[1]
		} else {
			// name@version format
			name = strings.Split(parts[0], "@")[0]
			if atIdx := strings.Index(parts[0], "@"); atIdx > 0 {
				version = parts[0][atIdx+1:]
			}
		}
	}

	// Handle peer dep suffixes
	if idx := strings.Index(version, "_"); idx != -1 {
		version = version[:idx]
	}

	// Validate version starts with a digit
	if version == "" || (len(version) > 0 && version[0] < '0' || version[0] > '9') {
		return "", ""
	}

	return name, version
}

// Ensure NpmResolver implements EdgeResolver.
var _ EdgeResolver = (*NpmResolver)(nil)
