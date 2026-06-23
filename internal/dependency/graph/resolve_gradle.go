package graph

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"

	pb "deps.dev/api/v3"
	"github.com/temporalio/deputy/internal/inventory/plugins/java/gradlex"
	"github.com/temporalio/deputy/internal/logs"
)

func init() {
	// Register the BOM resolver initialization function.
	// This is called from maven_bom.go's InitGradleBOMResolver.
	initGradleBOMResolverFunc = func(resolver *MavenBOMResolver) {
		gradlex.RegisterBOMVersionResolver(&gradleBOMResolverAdapter{resolver: resolver})
	}
}

// gradleBOMResolverAdapter adapts MavenBOMResolver to gradlex.BOMVersionResolver.
type gradleBOMResolverAdapter struct {
	resolver *MavenBOMResolver
}

// ResolveBOMVersions implements gradlex.BOMVersionResolver.
func (a *gradleBOMResolverAdapter) ResolveBOMVersions(ctx context.Context, deps []gradlex.MavenDependency, boms []gradlex.GradleBOM) []gradlex.MavenDependency {
	if a.resolver == nil || len(deps) == 0 || len(boms) == 0 {
		return deps
	}

	// Build a combined managed versions map from all BOMs
	managedVersions := make(map[string]string)

	for _, bom := range boms {
		resolved, err := a.resolver.ResolveBOM(ctx, bom.GroupID, bom.ArtifactID, bom.Version)
		if err != nil {
			logs.Debug(ctx, "BOM resolver: failed to resolve BOM",
				"bom", bom.GroupID+":"+bom.ArtifactID+":"+bom.Version,
				"error", err,
			)
			continue
		}

		logs.Debug(ctx, "BOM resolver: resolved BOM",
			"bom", bom.GroupID+":"+bom.ArtifactID+":"+bom.Version,
			"managedDeps", len(resolved.ManagedVersions),
		)

		// Merge managed versions (later BOMs override earlier ones)
		maps.Copy(managedVersions, resolved.ManagedVersions)
	}

	if len(managedVersions) == 0 {
		return deps
	}

	// Resolve versions for dependencies without them
	result := make([]gradlex.MavenDependency, 0, len(deps))
	resolvedCount := 0

	for _, dep := range deps {
		if dep.Version == "" || strings.Contains(dep.Version, "$") {
			// Try to resolve from BOM
			key := dep.GroupID + ":" + dep.ArtifactID
			if version, ok := managedVersions[key]; ok {
				dep.Version = version
				resolvedCount++
				logs.Debug(ctx, "BOM resolver: resolved version",
					"dependency", key,
					"version", version,
				)
			}
		}
		result = append(result, dep)
	}

	if resolvedCount > 0 {
		logs.Debug(ctx, "BOM resolver: resolved dependency versions",
			"resolved", resolvedCount,
			"total", len(deps),
		)
	}

	return result
}

// GradleResolver resolves dependency edges for Gradle projects.
//
// This resolver performs static analysis of Gradle build files and uses deps.dev
// to fetch transitive dependencies. It supports:
//
//   - Multi-module projects via settings.gradle
//   - Version catalogs (libs.versions.toml)
//   - Property substitution from gradle.properties and ext blocks
//   - BOM/platform dependencies
//
// The resolver prioritizes lockfiles when available, falling back to static
// analysis of build scripts with deps.dev resolution for transitives.
type GradleResolver struct {
	depsDevClient  *DepsDevClient
	maxConcurrency int
}

// GradleResolverOption configures a GradleResolver.
type GradleResolverOption func(*GradleResolver)

// WithGradleConcurrency sets the maximum concurrency for Gradle resolution.
func WithGradleConcurrency(n int) GradleResolverOption {
	return func(r *GradleResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// WithGradleDepsDevClient sets the deps.dev client for transitive resolution.
func WithGradleDepsDevClient(client *DepsDevClient) GradleResolverOption {
	return func(r *GradleResolver) {
		r.depsDevClient = client
	}
}

// NewGradleResolver creates a new Gradle edge resolver.
func NewGradleResolver(opts ...GradleResolverOption) *GradleResolver {
	r := &GradleResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "Maven" as the ecosystem identifier.
// Gradle dependencies are Maven packages.
func (r *GradleResolver) Ecosystem() string {
	return "Maven"
}

// ResolveEdges parses Gradle project files and adds dependency edges to the graph.
func (r *GradleResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Check if this is a Gradle project
	isGradle := false
	for _, marker := range []string{"settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"} {
		if data, err := files.ReadFile(marker); err == nil && len(data) > 0 {
			isGradle = true
			break
		}
	}
	if !isGradle {
		return nil
	}

	// Load project configuration
	props, err := r.loadProjectProperties(files)
	if err != nil {
		return fmt.Errorf("loading project properties: %w", err)
	}

	// Extract dependencies from all build files
	deps, err := r.extractDependencies(files, props)
	if err != nil {
		return fmt.Errorf("extracting dependencies: %w", err)
	}

	if len(deps) == 0 {
		return nil
	}

	// Build edge set for deduplication
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process dependencies and resolve transitives
	r.processDependencies(ctx, g, deps, edgeSet)

	// Update depths
	g.UpdateDepths()

	return nil
}

// loadProjectProperties loads version properties from gradle.properties, ext blocks, and version catalogs.
func (r *GradleResolver) loadProjectProperties(files FileReader) (map[string]string, error) {
	props := make(map[string]string)

	// Load gradle.properties
	if data, err := files.ReadFile("gradle.properties"); err == nil {
		maps.Copy(props, gradlex.ParseGradleProperties(data))
	}

	// Load version catalog
	if data, err := files.ReadFile("gradle/libs.versions.toml"); err == nil {
		if catalog, err := gradlex.ParseVersionCatalog(data); err == nil {
			for k, v := range catalog.ToProperties() {
				if _, exists := props[k]; !exists {
					props[k] = v
				}
			}
		}
	}

	// Load ext block from root build.gradle
	for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
		if data, err := files.ReadFile(buildFile); err == nil {
			for k, v := range gradlex.ParseExtBlock(data) {
				if _, exists := props[k]; !exists {
					props[k] = v
				}
			}
			break
		}
	}

	return props, nil
}

// extractDependencies extracts dependencies from all build.gradle files in the project.
func (r *GradleResolver) extractDependencies(files FileReader, props map[string]string) ([]gradlex.MavenDependency, error) {
	var allDeps []gradlex.MavenDependency

	// Find all build.gradle files
	buildFiles := r.findBuildGradleFiles(files)

	for _, buildFile := range buildFiles {
		data, err := files.ReadFile(buildFile)
		if err != nil {
			continue
		}

		// Create file-specific props with ext block
		fileProps := make(map[string]string, len(props))
		maps.Copy(fileProps, props)
		for k, v := range gradlex.ParseExtBlock(data) {
			if _, exists := fileProps[k]; !exists {
				fileProps[k] = v
			}
		}

		deps, err := gradlex.ParseBuildGradle(data, fileProps)
		if err != nil {
			continue
		}
		allDeps = append(allDeps, deps...)
	}

	// Also add libraries from version catalog
	if data, err := files.ReadFile("gradle/libs.versions.toml"); err == nil {
		if catalog, err := gradlex.ParseVersionCatalog(data); err == nil {
			allDeps = append(allDeps, catalog.GetLibraries()...)
		}
	}

	return deduplicateMavenDeps(allDeps), nil
}

// findBuildGradleFiles locates all build.gradle files in the project.
func (r *GradleResolver) findBuildGradleFiles(files FileReader) []string {
	var buildFiles []string

	// Check root
	for _, name := range []string{"build.gradle", "build.gradle.kts"} {
		if data, err := files.ReadFile(name); err == nil && len(data) > 0 {
			buildFiles = append(buildFiles, name)
		}
	}

	// If FileReader implements fs.FS, walk for nested files
	if fsReader, ok := files.(fs.FS); ok {
		_ = fs.WalkDir(fsReader, ".", func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == ".gradle" || name == "build" || name == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}

			base := path.Base(filePath)
			if base == "build.gradle" || base == "build.gradle.kts" {
				// Avoid duplicates
				if slices.Contains(buildFiles, filePath) {
					return nil
				}
				buildFiles = append(buildFiles, filePath)
			}
			return nil
		})
	}

	return buildFiles
}

// processDependencies adds dependency nodes and resolves transitives using deps.dev.
func (r *GradleResolver) processDependencies(ctx context.Context, g *Graph, deps []gradlex.MavenDependency, edgeSet map[string]bool) {
	// First pass: add all direct dependencies as nodes
	for _, dep := range deps {
		if !dep.IsResolved() {
			continue
		}

		purl := mavenPkgToPURL(dep.GroupID, dep.ArtifactID, dep.Version)
		name := dep.Name()

		node := g.Node(purl)
		if node == nil {
			node = &Node{
				Purl:      purl,
				Name:      name,
				Version:   dep.Version,
				Ecosystem: "Maven",
				Direct:    true,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		} else {
			node.Direct = true
		}

		if !containsRoot(g.roots, purl) {
			g.roots = append(g.roots, purl)
		}
	}

	// Second pass: resolve transitives using deps.dev
	if r.depsDevClient == nil {
		return
	}

	// Use semaphore for concurrency control
	sem := make(chan struct{}, r.maxConcurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, dep := range deps {
		if !dep.IsResolved() {
			continue
		}

		wg.Add(1)
		go func(dep gradlex.MavenDependency) {
			defer wg.Done()

			sem <- struct{}{}
			defer func() { <-sem }()

			r.resolveTransitives(ctx, g, dep, edgeSet, &mu)
		}(dep)
	}

	wg.Wait()
}

// resolveTransitives fetches transitive dependencies from deps.dev.
func (r *GradleResolver) resolveTransitives(ctx context.Context, g *Graph, dep gradlex.MavenDependency, edgeSet map[string]bool, mu *sync.Mutex) {
	resp, err := r.depsDevClient.GetDependencies(ctx, pb.System_MAVEN, dep.Name(), dep.Version)
	if err != nil {
		return
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
		if vk.System != pb.System_MAVEN {
			continue
		}

		purl := mavenNameToPURL(vk.Name, vk.Version)
		nodePURLs[uint32(i)] = purl

		mu.Lock()
		if g.Node(purl) == nil {
			g.AddNode(&Node{
				Purl:      purl,
				Name:      vk.Name,
				Version:   vk.Version,
				Ecosystem: "Maven",
				Direct:    false,
				Depth:     DepthDisconnected,
			})
		}
		mu.Unlock()
	}

	// Add edges
	mu.Lock()
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
	mu.Unlock()
}

// deduplicateMavenDeps removes duplicate dependencies.
func deduplicateMavenDeps(deps []gradlex.MavenDependency) []gradlex.MavenDependency {
	seen := make(map[string]bool)
	result := make([]gradlex.MavenDependency, 0, len(deps))

	for _, dep := range deps {
		key := dep.Coordinate()
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, dep)
	}

	return result
}

// Ensure GradleResolver implements EdgeResolver.
var _ EdgeResolver = (*GradleResolver)(nil)

// GradleProjectDependencies extracts all dependencies from a Gradle project.
// This is a convenience function for use outside the resolver context.
func GradleProjectDependencies(ctx context.Context, files FileReader) ([]gradlex.MavenDependency, error) {
	r := NewGradleResolver()
	props, err := r.loadProjectProperties(files)
	if err != nil {
		return nil, err
	}
	return r.extractDependencies(files, props)
}

// ResolveGradleWithDepsdev resolves a Gradle project's dependencies using deps.dev.
// Returns a Graph with all direct and transitive dependencies.
func ResolveGradleWithDepsdev(ctx context.Context, files FileReader, client *DepsDevClient) (*Graph, error) {
	g := New()
	r := NewGradleResolver(
		WithGradleDepsDevClient(client),
		WithGradleConcurrency(20),
	)

	if err := r.ResolveEdges(ctx, g, files); err != nil {
		return nil, err
	}

	return g, nil
}
