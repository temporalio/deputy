package graph

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
)

// CargoResolver resolves dependency edges for Rust/Cargo packages by parsing Cargo.lock.
// Cargo.lock contains the complete dependency graph with exact versions and dependencies.
//
// Supported files:
//   - Cargo.lock (dependency lockfile with full graph)
//   - Cargo.toml (manifest for direct dependency detection)
//
// The resolver parses Cargo.lock's [[package]] sections which list each package's
// dependencies explicitly, making edge resolution precise without external fetches.
type CargoResolver struct {
	maxConcurrency int
}

// CargoResolverOption configures a CargoResolver.
type CargoResolverOption func(*CargoResolver)

// WithCargoConcurrency sets the maximum concurrency for Cargo resolution.
func WithCargoConcurrency(n int) CargoResolverOption {
	return func(r *CargoResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// NewCargoResolver creates a new Cargo edge resolver.
func NewCargoResolver(opts ...CargoResolverOption) *CargoResolver {
	r := &CargoResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "crates.io" as the ecosystem identifier.
func (r *CargoResolver) Ecosystem() string {
	return "crates.io"
}

// ResolveEdges parses Cargo.lock to add dependency edges to the graph.
func (r *CargoResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Find all Cargo.lock files
	lockFiles, err := r.findLockFiles(files)
	if err != nil {
		return fmt.Errorf("finding Cargo.lock files: %w", err)
	}

	if len(lockFiles) == 0 {
		return nil
	}

	// Process each lockfile
	for _, lockPath := range lockFiles {
		if err := r.processCargoLock(ctx, g, files, lockPath); err != nil {
			continue
		}
	}

	g.UpdateDepths()

	return nil
}

// findLockFiles locates all Cargo.lock files.
func (r *CargoResolver) findLockFiles(files FileReader) ([]string, error) {
	var lockPaths []string

	commonPaths := []string{
		"Cargo.lock",
	}

	for _, p := range commonPaths {
		if data, err := files.ReadFile(p); err == nil && len(data) > 0 {
			lockPaths = append(lockPaths, p)
		}
	}

	if fsReader, ok := files.(fs.FS); ok {
		_ = fs.WalkDir(fsReader, ".", func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "target" || name == "vendor" || name == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			if d.Name() == "Cargo.lock" {
				for _, existing := range lockPaths {
					if existing == filePath {
						return nil
					}
				}
				lockPaths = append(lockPaths, filePath)
			}
			return nil
		})
	}

	return lockPaths, nil
}

// cargoLock represents the Cargo.lock file format.
type cargoLock struct {
	Version  int            `toml:"version"`
	Packages []cargoPackage `toml:"package"`
}

// cargoPackage represents a [[package]] entry in Cargo.lock.
type cargoPackage struct {
	Name         string   `toml:"name"`
	Version      string   `toml:"version"`
	Source       string   `toml:"source"`
	Checksum     string   `toml:"checksum"`
	Dependencies []string `toml:"dependencies"`
}

// cargoToml represents the Cargo.toml manifest.
type cargoToml struct {
	Package struct {
		Name    string `toml:"name"`
		Version string `toml:"version"`
	} `toml:"package"`
	Dependencies         map[string]interface{} `toml:"dependencies"`
	DevDependencies      map[string]interface{} `toml:"dev-dependencies"`
	BuildDependencies    map[string]interface{} `toml:"build-dependencies"`
	Workspace            cargoWorkspace         `toml:"workspace"`
}

type cargoWorkspace struct {
	Dependencies map[string]interface{} `toml:"dependencies"`
}

// processCargoLock parses a Cargo.lock and adds edges to the graph.
func (r *CargoResolver) processCargoLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	var lock cargoLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	// Read Cargo.toml to determine direct dependencies
	dir := path.Dir(lockPath)
	if dir == "." {
		dir = ""
	}
	tomlPath := path.Join(dir, "Cargo.toml")
	directDeps := r.parseCargoToml(files, tomlPath)

	// Build package map: name@version -> cargoPackage
	pkgMap := make(map[string]cargoPackage)
	for _, pkg := range lock.Packages {
		key := pkg.Name + "@" + pkg.Version
		pkgMap[key] = pkg
	}

	// Create root node if we have package info
	var rootPURL string
	tomlData, _ := files.ReadFile(tomlPath)
	if len(tomlData) > 0 {
		var manifest cargoToml
		if toml.Unmarshal(tomlData, &manifest) == nil && manifest.Package.Name != "" {
			rootPURL = cargoPkgToPURL(manifest.Package.Name, manifest.Package.Version)
			if g.Node(rootPURL) == nil {
				g.AddNode(&Node{
					PURL:      rootPURL,
					Name:      manifest.Package.Name,
					Version:   manifest.Package.Version,
					Ecosystem: "crates.io",
					Direct:    true,
					Depth:     DepthSyntheticRoot,
				})
			}
			if !containsRoot(g.roots, rootPURL) {
				g.roots = append(g.roots, rootPURL)
			}
		}
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process each package
	for _, pkg := range lock.Packages {
		purl := cargoPkgToPURL(pkg.Name, pkg.Version)

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, pkg.Name)
		}
		if node == nil {
			isDirect := directDeps[pkg.Name]
			node = &Node{
				PURL:      purl,
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: "crates.io",
				Direct:    isDirect,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		// Mark as direct if in Cargo.toml
		if directDeps[pkg.Name] {
			node.Direct = true
			if !containsRoot(g.roots, node.PURL) {
				g.roots = append(g.roots, node.PURL)
			}

			// Add edge from root
			if rootPURL != "" {
				edgeKey := rootPURL + "->" + node.PURL
				if !edgeSet[edgeKey] {
					g.AddEdge(&Edge{
						From:  rootPURL,
						To:    node.PURL,
						Scope: ScopeRuntime,
					})
					edgeSet[edgeKey] = true
				}
			}
		}

		// Add edges for dependencies
		for _, dep := range pkg.Dependencies {
			childName, childVersion := parseCargoDepString(dep)
			if childName == "" {
				continue
			}

			// Find the actual version in lockfile
			childPURL := r.findPackageInLock(pkgMap, childName, childVersion)
			if childPURL == "" {
				childPURL = cargoPkgToPURL(childName, childVersion)
			}

			childNode := g.Node(childPURL)
			if childNode == nil {
				childNode = r.findNodeByName(g, childName)
			}
			if childNode == nil {
				continue
			}

			edgeKey := purl + "->" + childNode.PURL
			if !edgeSet[edgeKey] {
				g.AddEdge(&Edge{
					From:  purl,
					To:    childNode.PURL,
					Scope: ScopeRuntime,
				})
				edgeSet[edgeKey] = true
			}
		}
	}

	return nil
}

// parseCargoToml reads Cargo.toml and returns a set of direct dependency names.
func (r *CargoResolver) parseCargoToml(files FileReader, tomlPath string) map[string]bool {
	direct := make(map[string]bool)

	data, err := files.ReadFile(tomlPath)
	if err != nil {
		return direct
	}

	var manifest cargoToml
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return direct
	}

	// Add all dependency types as direct
	for name := range manifest.Dependencies {
		direct[name] = true
	}
	for name := range manifest.DevDependencies {
		direct[name] = true
	}
	for name := range manifest.BuildDependencies {
		direct[name] = true
	}
	for name := range manifest.Workspace.Dependencies {
		direct[name] = true
	}

	return direct
}

// parseCargoDepString parses a dependency string from Cargo.lock.
// Formats:
//   - "name version" -> name, version
//   - "name version (source)" -> name, version
func parseCargoDepString(dep string) (name, version string) {
	dep = strings.TrimSpace(dep)
	if dep == "" {
		return "", ""
	}

	// Remove source suffix if present
	if idx := strings.Index(dep, " ("); idx != -1 {
		dep = dep[:idx]
	}

	// Split name and version
	parts := strings.SplitN(dep, " ", 2)
	if len(parts) >= 1 {
		name = parts[0]
	}
	if len(parts) >= 2 {
		version = parts[1]
	}

	return name, version
}

// findPackageInLock finds the PURL for a dependency in the lockfile.
func (r *CargoResolver) findPackageInLock(pkgMap map[string]cargoPackage, name, version string) string {
	// Try exact match first
	if version != "" {
		key := name + "@" + version
		if _, ok := pkgMap[key]; ok {
			return cargoPkgToPURL(name, version)
		}
	}

	// Find any version of the package
	for key := range pkgMap {
		if strings.HasPrefix(key, name+"@") {
			parts := strings.SplitN(key, "@", 2)
			if len(parts) == 2 {
				return cargoPkgToPURL(name, parts[1])
			}
		}
	}

	return ""
}

// findNodeByName finds a node by its crate name, ignoring version.
func (r *CargoResolver) findNodeByName(g *Graph, name string) *Node {
	lowerName := strings.ToLower(name)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerName {
			return node
		}
	}
	return nil
}

// cargoPkgToPURL converts a crate name and version to a Package URL.
func cargoPkgToPURL(name, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:cargo/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:cargo/%s", name)
}

// Ensure CargoResolver implements EdgeResolver.
var _ EdgeResolver = (*CargoResolver)(nil)
