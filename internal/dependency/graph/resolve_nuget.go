package graph

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/fs"
	"path"
	"strings"

	pb "deps.dev/api/v3"
)

// NuGetResolver resolves dependency edges for .NET/NuGet packages.
// It supports multiple formats:
//   - packages.lock.json (NuGet PackageReference lockfile with full dependency info)
//   - packages.config (legacy NuGet format with package list)
//
// The packages.lock.json format is preferred as it contains resolved versions
// and dependency relationships. The packages.config format only lists packages.
//
// When a DepsDevClient is provided, the resolver can fetch transitive dependency
// information from deps.dev to build more complete graphs.
type NuGetResolver struct {
	depsDevClient  *DepsDevClient
	maxConcurrency int
}

// NuGetResolverOption configures a NuGetResolver.
type NuGetResolverOption func(*NuGetResolver)

// WithNuGetConcurrency sets the maximum concurrency for NuGet resolution.
func WithNuGetConcurrency(n int) NuGetResolverOption {
	return func(r *NuGetResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// WithNuGetDepsDevClient sets the deps.dev client for transitive resolution.
func WithNuGetDepsDevClient(client *DepsDevClient) NuGetResolverOption {
	return func(r *NuGetResolver) {
		r.depsDevClient = client
	}
}

// NewNuGetResolver creates a new NuGet edge resolver.
func NewNuGetResolver(opts ...NuGetResolverOption) *NuGetResolver {
	r := &NuGetResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "NuGet" as the ecosystem identifier.
func (r *NuGetResolver) Ecosystem() string {
	return "NuGet"
}

// ResolveEdges parses NuGet files to add dependency edges to the graph.
func (r *NuGetResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Find all relevant files
	nugetFiles, err := r.findNuGetFiles(files)
	if err != nil {
		return fmt.Errorf("finding NuGet files: %w", err)
	}

	if len(nugetFiles) == 0 {
		return nil
	}

	// Process each file based on its type
	for _, nf := range nugetFiles {
		var processErr error
		switch nf.fileType {
		case nugetFilePackagesLock:
			processErr = r.processPackagesLockJSON(ctx, g, files, nf.path)
		case nugetFilePackagesConfig:
			processErr = r.processPackagesConfig(ctx, g, files, nf.path)
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

// nugetFileType indicates the type of NuGet-related file.
type nugetFileType int

const (
	nugetFilePackagesLock nugetFileType = iota
	nugetFilePackagesConfig
)

// nugetFileInfo contains information about a discovered NuGet file.
type nugetFileInfo struct {
	path     string
	fileType nugetFileType
}

// findNuGetFiles locates all NuGet-related files accessible via the FileReader.
func (r *NuGetResolver) findNuGetFiles(files FileReader) ([]nugetFileInfo, error) {
	var nugetFiles []nugetFileInfo

	// Try common locations
	commonPaths := []struct {
		path     string
		fileType nugetFileType
	}{
		{"packages.lock.json", nugetFilePackagesLock},
		{"packages.config", nugetFilePackagesConfig},
	}

	for _, p := range commonPaths {
		if data, err := files.ReadFile(p.path); err == nil && len(data) > 0 {
			nugetFiles = append(nugetFiles, nugetFileInfo{path: p.path, fileType: p.fileType})
		}
	}

	// If the FileReader also implements fs.FS, walk for nested files
	if fsReader, ok := files.(fs.FS); ok {
		_ = fs.WalkDir(fsReader, ".", func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "bin" || name == "obj" || name == "node_modules" || name == "packages" {
					return fs.SkipDir
				}
				return nil
			}

			base := path.Base(filePath)
			var fileType nugetFileType
			switch base {
			case "packages.lock.json":
				fileType = nugetFilePackagesLock
			case "packages.config":
				fileType = nugetFilePackagesConfig
			default:
				return nil
			}

			// Avoid duplicates
			for _, existing := range nugetFiles {
				if existing.path == filePath {
					return nil
				}
			}
			nugetFiles = append(nugetFiles, nugetFileInfo{path: filePath, fileType: fileType})
			return nil
		})
	}

	return nugetFiles, nil
}

// packagesLockJSON represents the packages.lock.json structure.
type packagesLockJSON struct {
	Version      int                                  `json:"version"`
	Dependencies map[string]map[string]nugetLockInfo `json:"dependencies"`
}

// nugetLockInfo represents a package entry in packages.lock.json.
type nugetLockInfo struct {
	Type         string            `json:"type"`
	Resolved     string            `json:"resolved"`
	ContentHash  string            `json:"contentHash"`
	Dependencies map[string]string `json:"dependencies"`
}

// processPackagesLockJSON parses a packages.lock.json and adds edges to the graph.
func (r *NuGetResolver) processPackagesLockJSON(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	var lock packagesLockJSON
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Build map of package name -> PURL for each target framework
	pkgToPURL := make(map[string]string)

	// Process each target framework
	for _, packages := range lock.Dependencies {
		// First pass: create/update nodes
		for pkgName, info := range packages {
			purl := nugetPkgToPURL(pkgName, info.Resolved)
			pkgToPURL[strings.ToLower(pkgName)] = purl

			node := g.Node(purl)
			if node == nil {
				node = r.findNodeByName(g, pkgName)
			}
			if node == nil {
				isDirect := info.Type == "Direct"
				node = &Node{
					Purl:      purl,
					Name:      pkgName,
					Version:   info.Resolved,
					Ecosystem: "NuGet",
					Direct:    isDirect,
					Depth:     DepthDisconnected,
				}
				g.AddNode(node)
			}

			// Mark as direct if it's a direct dependency
			if info.Type == "Direct" {
				node.Direct = true
				if !containsRoot(g.roots, node.Purl) {
					g.roots = append(g.roots, node.Purl)
				}
			}
		}

		// Second pass: create edges based on dependencies
		for pkgName, info := range packages {
			parentPURL := nugetPkgToPURL(pkgName, info.Resolved)

			for depName, depVersion := range info.Dependencies {
				// Find the resolved version for this dependency
				childPURL := ""
				if resolvedPURL, ok := pkgToPURL[strings.ToLower(depName)]; ok {
					childPURL = resolvedPURL
				} else {
					// Use the constraint version as fallback
					childPURL = nugetPkgToPURL(depName, depVersion)
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
					g.AddEdge(&Edge{
						From:       parentPURL,
						To:         childNode.Purl,
						Constraint: depVersion,
						Scope:      ScopeRuntime,
					})
					edgeSet[edgeKey] = true
				}
			}
		}
	}

	return nil
}

// packagesConfig represents the packages.config XML structure.
type packagesConfig struct {
	XMLName  xml.Name        `xml:"packages"`
	Packages []nugetPackage  `xml:"package"`
}

// nugetPackage represents a package in packages.config.
type nugetPackage struct {
	ID              string `xml:"id,attr"`
	Version         string `xml:"version,attr"`
	TargetFramework string `xml:"targetFramework,attr"`
}

// processPackagesConfig parses a packages.config and adds nodes to the graph.
func (r *NuGetResolver) processPackagesConfig(ctx context.Context, g *Graph, files FileReader, configPath string) error {
	data, err := files.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", configPath, err)
	}

	var config packagesConfig
	if err := xml.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("parsing %s: %w", configPath, err)
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process each package
	for _, pkg := range config.Packages {
		if pkg.ID == "" || pkg.Version == "" {
			continue
		}

		purl := nugetPkgToPURL(pkg.ID, pkg.Version)

		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, pkg.ID)
		}
		if node == nil {
			node = &Node{
				Purl:      purl,
				Name:      pkg.ID,
				Version:   pkg.Version,
				Ecosystem: "NuGet",
				Direct:    true, // packages.config lists direct deps
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		if !containsRoot(g.roots, node.Purl) {
			g.roots = append(g.roots, node.Purl)
		}

		// If we have a deps.dev client, fetch transitive dependencies
		if r.depsDevClient != nil {
			r.resolveTransitiveDeps(ctx, g, pkg.ID, pkg.Version, edgeSet)
		}
	}

	return nil
}

// resolveTransitiveDeps fetches transitive dependencies from deps.dev.
func (r *NuGetResolver) resolveTransitiveDeps(ctx context.Context, g *Graph, name, version string, edgeSet map[string]bool) {
	resp, err := r.depsDevClient.GetDependencies(ctx, pb.System_NUGET, name, version)
	if err != nil {
		return // Non-fatal, skip
	}

	if resp == nil || len(resp.Nodes) == 0 || len(resp.Edges) == 0 {
		return
	}

	// Build node index -> PURL map
	nodePURLs := make(map[uint32]string)
	for i, node := range resp.Nodes {
		if node == nil || node.VersionKey == nil {
			continue
		}
		vk := node.VersionKey
		if vk.System != pb.System_NUGET {
			continue
		}

		purl := nugetPkgToPURL(vk.Name, vk.Version)
		nodePURLs[uint32(i)] = purl

		// Ensure node exists in graph
		if g.Node(purl) == nil {
			g.AddNode(&Node{
				Purl:      purl,
				Name:      vk.Name,
				Version:   vk.Version,
				Ecosystem: "NuGet",
				Direct:    false,
				Depth:     DepthDisconnected,
			})
		}
	}

	// Add edges from deps.dev response
	for _, edge := range resp.Edges {
		fromPURL := nodePURLs[edge.FromNode]
		toPURL := nodePURLs[edge.ToNode]

		if fromPURL == "" || toPURL == "" {
			continue
		}

		edgeKey := fromPURL + "->" + toPURL
		if edgeSet[edgeKey] {
			continue
		}

		// Only add edge if both nodes exist in our graph
		fromNode := g.Node(fromPURL)
		toNode := g.Node(toPURL)

		if fromNode != nil && toNode != nil {
			g.AddEdge(&Edge{
				From:  fromPURL,
				To:    toPURL,
				Scope: ScopeRuntime,
			})
			edgeSet[edgeKey] = true
		}
	}
}

// findNodeByName finds a node by its package name (case-insensitive for NuGet).
func (r *NuGetResolver) findNodeByName(g *Graph, name string) *Node {
	lowerName := strings.ToLower(name)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerName {
			return node
		}
	}
	return nil
}

// nugetPkgToPURL converts a NuGet package name and version to a Package URL.
// Format: pkg:nuget/PackageName@version
func nugetPkgToPURL(name, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:nuget/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:nuget/%s", name)
}

// Ensure NuGetResolver implements EdgeResolver.
var _ EdgeResolver = (*NuGetResolver)(nil)
