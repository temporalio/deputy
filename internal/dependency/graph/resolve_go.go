package graph

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"golang.org/x/mod/modfile"
)

// WorkspaceFileReader adapts a workspace.ReadableFS to the FileReader interface.
// This allows edge resolvers to access files from any workspace implementation.
type WorkspaceFileReader struct {
	fs interface {
		ReadFile(name string) ([]byte, error)
	}
	// Optional: if the underlying type supports fs.FS for walking
	fsFS fs.FS
}

// NewWorkspaceFileReader creates a FileReader from a workspace ReadableFS.
func NewWorkspaceFileReader(ws interface {
	ReadFile(name string) ([]byte, error)
}) *WorkspaceFileReader {
	reader := &WorkspaceFileReader{fs: ws}
	// Check if it also implements fs.FS for directory walking
	if fsfs, ok := ws.(fs.FS); ok {
		reader.fsFS = fsfs
	}
	return reader
}

// ReadFile implements FileReader.
func (w *WorkspaceFileReader) ReadFile(name string) ([]byte, error) {
	return w.fs.ReadFile(name)
}

// Open implements fs.FS for directory walking support.
func (w *WorkspaceFileReader) Open(name string) (fs.File, error) {
	if w.fsFS != nil {
		return w.fsFS.Open(name)
	}
	return nil, fs.ErrNotExist
}

// ReadDir implements fs.ReadDirFS for directory listing.
func (w *WorkspaceFileReader) ReadDir(name string) ([]fs.DirEntry, error) {
	if rdf, ok := w.fsFS.(fs.ReadDirFS); ok {
		return rdf.ReadDir(name)
	}
	return nil, fs.ErrNotExist
}

// GoResolver resolves dependency edges for Go modules by parsing go.mod files.
// It identifies direct dependencies from the require directives and builds
// edges from the root module to its direct dependencies.
//
// For accurate transitive dependency resolution, GoResolver uses a chain of
// fetchers to obtain go.mod files:
//  1. Vendor directory (if present) - local copy, most precise
//  2. Module proxy (proxy.golang.org) - for public modules
//  3. Git repository fetch - for private modules (like GOPRIVATE)
//
// Note: deps.dev doesn't provide dependency graphs for Go modules (Go uses MVS
// at build time rather than a lockfile), so we fetch go.mod files directly.
//
// Performance: Fetches are parallelized for speed while maintaining precision.
type GoResolver struct {
	// proxyClient fetches go.mod files from the Go module proxy.
	proxyClient *GoProxyClient

	// gitFetcher fetches go.mod files directly from Git repositories.
	// Used for private modules not available on the public proxy.
	gitFetcher *GitModuleFetcher

	// useProxy controls whether to fetch from the module proxy.
	// When true, accurate edges are resolved by fetching each dependency's go.mod.
	useProxy bool

	// useGit controls whether to fetch from Git for private modules.
	// When true, modules not on proxy will be fetched directly from Git.
	useGit bool

	// maxConcurrency limits parallel fetcher requests.
	maxConcurrency int

	// privatePatterns contains glob patterns for private module paths.
	// Modules matching these patterns will skip proxy and use Git directly.
	// This is similar to the GOPRIVATE environment variable.
	privatePatterns []string
}

// GoResolverOption configures a GoResolver.
type GoResolverOption func(*GoResolver)

// WithProxy enables fetching go.mod files from the module proxy
// for accurate dependency resolution.
func WithProxy(proxyURL string) GoResolverOption {
	return func(r *GoResolver) {
		r.proxyClient = NewGoProxyClient(proxyURL)
		r.useProxy = true
	}
}

// WithConcurrency sets the maximum number of concurrent proxy requests.
func WithConcurrency(n int) GoResolverOption {
	return func(r *GoResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// WithPrivatePatterns sets glob patterns for private module paths.
// Modules matching any pattern will skip proxy and use Git directly.
// Patterns support path.Match syntax (e.g., "github.com/mycompany/*").
// This is similar to the GOPRIVATE environment variable.
func WithPrivatePatterns(patterns ...string) GoResolverOption {
	return func(r *GoResolver) {
		r.privatePatterns = append(r.privatePatterns, patterns...)
	}
}

// WithGit enables fetching go.mod files directly from Git repositories.
// This is used for private modules that aren't available on the public proxy.
// When enabled, modules matching privatePatterns (or not found on proxy)
// will be fetched directly from their Git repositories.
func WithGit() GoResolverOption {
	return func(r *GoResolver) {
		r.gitFetcher = NewGitModuleFetcher()
		r.useGit = true
	}
}

// NewGoResolver creates a new Go module edge resolver.
// By default, it uses heuristic-based resolution from the local go.mod.
// Use WithProxy() to enable accurate resolution via the module proxy.
func NewGoResolver(opts ...GoResolverOption) *GoResolver {
	r := &GoResolver{
		maxConcurrency: 10, // sensible default
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "Go" as the ecosystem identifier.
func (r *GoResolver) Ecosystem() string {
	return "Go"
}

// ResolveEdges parses go.mod files to add dependency edges to the graph.
// It processes all go.mod files found via the FileReader, extracting both
// direct and indirect dependencies, and creating appropriate edges.
func (r *GoResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Find all go.mod files
	goModFiles, err := r.findGoModFiles(files)
	if err != nil {
		return fmt.Errorf("finding go.mod files: %w", err)
	}

	if len(goModFiles) == 0 {
		return nil
	}

	// Process each go.mod file
	for _, goModPath := range goModFiles {
		if err := r.processGoMod(ctx, g, files, goModPath); err != nil {
			// Log but continue - partial resolution is better than none
			continue
		}
	}

	// Update depths based on resolved edges
	g.UpdateDepths()

	return nil
}

// findGoModFiles locates all go.mod files accessible via the FileReader.
func (r *GoResolver) findGoModFiles(files FileReader) ([]string, error) {
	var goModPaths []string

	// Try common locations
	commonPaths := []string{
		"go.mod",
	}

	for _, p := range commonPaths {
		if data, err := files.ReadFile(p); err == nil && len(data) > 0 {
			goModPaths = append(goModPaths, p)
		}
	}

	// If the FileReader also implements fs.FS, we can walk for nested modules
	if fsReader, ok := files.(fs.FS); ok {
		_ = fs.WalkDir(fsReader, ".", func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "vendor" || name == "node_modules" || name == "testdata" {
					return fs.SkipDir
				}
				return nil
			}
			if path.Base(filePath) == "go.mod" {
				// Avoid duplicates
				for _, existing := range goModPaths {
					if existing == filePath {
						return nil
					}
				}
				goModPaths = append(goModPaths, filePath)
			}
			return nil
		})
	}

	return goModPaths, nil
}

// processGoMod parses a single go.mod file and adds edges to the graph.
func (r *GoResolver) processGoMod(ctx context.Context, g *Graph, files FileReader, goModPath string) error {
	data, err := files.ReadFile(goModPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", goModPath, err)
	}

	mf, err := modfile.ParseLax(goModPath, data, nil)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", goModPath, err)
	}

	if mf.Module == nil {
		return fmt.Errorf("no module directive in %s", goModPath)
	}

	rootModule := mf.Module.Mod.Path

	// Find or create the root module node (this is the project itself)
	rootPURL := goModuleToPURL(rootModule, "")
	rootNode := g.Node(rootPURL)
	if rootNode == nil {
		// Create a synthetic root node for the project
		rootNode = &Node{
			PURL:      rootPURL,
			Name:      rootModule,
			Version:   "(local)",
			Ecosystem: "Go",
			Direct:    true,
			Depth:     DepthSyntheticRoot,
		}
		g.AddNode(rootNode)
	}
	rootNode.Direct = true
	if !containsRoot(g.roots, rootPURL) {
		g.roots = append(g.roots, rootPURL)
	}

	// Add stdlib node if go directive is present
	// The Go runtime (stdlib) is an implicit dependency for all Go projects.
	// Adding it to the graph enables "deputy graph why stdlib" and vulnerability
	// tracking for Go runtime vulnerabilities (CVEs in the standard library).
	if mf.Go != nil && mf.Go.Version != "" {
		stdlibPURL := goStdlibToPURL(mf.Go.Version)
		stdlibNode := g.Node(stdlibPURL)
		if stdlibNode == nil {
			stdlibNode = &Node{
				PURL:      stdlibPURL,
				Name:      "stdlib",
				Version:   mf.Go.Version,
				Ecosystem: "Go",
				Direct:    true,
				Depth:     0, // stdlib is a direct dependency
				Locations: []string{goModPath},
			}
			g.AddNode(stdlibNode)
		}
		if !containsRoot(g.roots, stdlibPURL) {
			g.roots = append(g.roots, stdlibPURL)
		}
		// Add edge from root module to stdlib
		g.AddEdge(&Edge{
			From:       rootPURL,
			To:         stdlibPURL,
			Constraint: mf.Go.Version,
			Scope:      ScopeRuntime,
		})
	}

	// Process all require directives (both direct and indirect)
	for _, req := range mf.Require {
		modulePath := req.Mod.Path
		moduleVersion := req.Mod.Version
		isDirect := !req.Indirect

		depPURL := goModuleToPURL(modulePath, moduleVersion)

		// Find the corresponding node in the graph
		depNode := g.Node(depPURL)
		if depNode == nil {
			// Try to find by module path without version (in case inventory used different version)
			depNode = r.findNodeByModulePath(g, modulePath)
		}

		if depNode == nil {
			// Create the node if it doesn't exist
			depNode = &Node{
				PURL:      depPURL,
				Name:      modulePath,
				Version:   moduleVersion,
				Ecosystem: "Go",
				Direct:    isDirect,
			}
			g.AddNode(depNode)
		}

		// Update direct status and add edge from root to direct deps
		if isDirect {
			depNode.Direct = true
			if !containsRoot(g.roots, depNode.PURL) {
				g.roots = append(g.roots, depNode.PURL)
			}
			g.AddEdge(&Edge{
				From:       rootPURL,
				To:         depNode.PURL,
				Constraint: moduleVersion,
				Scope:      ScopeRuntime,
			})
		}
	}

	// Resolve transitive dependency edges
	// Strategy: vendor -> proxy -> git (parallel fetching for speed)
	// Note: deps.dev doesn't have dependency graphs for Go modules (Go uses MVS
	// at build time, not a lockfile), so we fetch go.mod files directly.
	if r.useProxy && r.proxyClient != nil {
		// Use chain: vendor -> proxy -> git (parallel, accurate resolution)
		r.resolveTransitiveEdgesViaProxy(ctx, g, mf, rootPURL, files)
	} else {
		// No proxy configured - use vendor only (precise, no guessing)
		r.resolveTransitiveEdgesFromVendor(ctx, g, mf, rootPURL, files)
	}

	return nil
}

// ModuleGoModFetcher defines how to fetch a go.mod for a module.
// This abstraction allows using multiple sources: proxy, vendor, local filesystem.
type ModuleGoModFetcher interface {
	// FetchGoMod returns the parsed go.mod for a module at a version.
	// Returns nil, nil if the module is not available from this source.
	FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error)
}

// vendorFetcher reads go.mod files from a vendor directory.
type vendorFetcher struct {
	files FileReader
}

func (f *vendorFetcher) FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error) {
	// Vendor directory structure: vendor/<module-path>/go.mod
	vendorPath := "vendor/" + modulePath + "/go.mod"
	data, err := f.files.ReadFile(vendorPath)
	if err != nil {
		return nil, nil // Not in vendor - not an error, just not available
	}
	return modfile.ParseLax(vendorPath, data, nil)
}

// chainFetcher tries multiple fetchers in order until one succeeds.
type chainFetcher struct {
	fetchers []ModuleGoModFetcher
}

func (f *chainFetcher) FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error) {
	for _, fetcher := range f.fetchers {
		mf, err := fetcher.FetchGoMod(ctx, modulePath, version)
		if err != nil {
			continue // Try next fetcher
		}
		if mf != nil {
			return mf, nil
		}
	}
	return nil, nil // No fetcher could provide the go.mod
}

// resolveTransitiveEdgesViaProxy fetches go.mod files to determine the exact
// dependency chain for each transitive dependency.
//
// Resolution strategy (in order):
// 1. Vendor directory - if present, contains exact go.mod files for all deps
// 2. Module proxy - for public modules, fetch from proxy.golang.org
// 3. Git repository - for private modules, fetch directly from Git
//
// This approach prioritizes precision: we only add edges we can verify.
// No heuristics are used - if we can't determine the exact relationship,
// we don't guess.
//
// Performance: Fetches are parallelized for speed while maintaining BFS order.
func (r *GoResolver) resolveTransitiveEdgesViaProxy(ctx context.Context, g *Graph, mf *modfile.File, rootPURL string, files FileReader) {
	// Build a chain of fetchers: vendor -> proxy -> git
	var fetchers []ModuleGoModFetcher

	// 1. Vendor fetcher (most precise - local copy)
	if files != nil {
		fetchers = append(fetchers, &vendorFetcher{files: files})
	}

	// 2. Proxy fetcher for public modules (filtered by private patterns)
	if r.proxyClient != nil {
		fetchers = append(fetchers, &filteredProxyFetcher{
			proxy:           r.proxyClient,
			privatePatterns: r.privatePatterns,
		})
	}

	// 3. Git fetcher for private modules (fetches directly from repositories)
	if r.gitFetcher != nil && r.useGit {
		fetchers = append(fetchers, &gitModuleFetcherAdapter{fetcher: r.gitFetcher})
	}

	fetcher := &chainFetcher{fetchers: fetchers}

	// Build a map of all modules in the graph (from go.mod)
	allMods := make(map[string]string) // path -> version
	for _, req := range mf.Require {
		allMods[req.Mod.Path] = req.Mod.Version
	}

	// Track which edges we've already added (needs mutex for concurrent access)
	var edgeMu sync.Mutex
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Pre-fetch ALL modules in go.mod concurrently
	// This is much faster than fetching on-demand during BFS
	type fetchResult struct {
		path    string
		version string
		mf      *modfile.File
	}

	concurrency := r.maxConcurrency
	if concurrency <= 0 {
		concurrency = 10
	}

	// Collect all modules to fetch
	var toFetch []struct {
		path    string
		version string
	}
	for _, req := range mf.Require {
		toFetch = append(toFetch, struct {
			path    string
			version string
		}{req.Mod.Path, req.Mod.Version})
	}

	// Fetch in parallel
	results := make(chan fetchResult, len(toFetch))
	sem := make(chan struct{}, concurrency)

	for _, mod := range toFetch {
		go func(path, version string) {
			sem <- struct{}{}
			defer func() { <-sem }()

			depMod, _ := fetcher.FetchGoMod(ctx, path, version)
			results <- fetchResult{path: path, version: version, mf: depMod}
		}(mod.path, mod.version)
	}

	// Collect results into a cache
	modCache := make(map[string]*modfile.File) // key: path@version
	for range toFetch {
		result := <-results
		if result.mf != nil {
			key := result.path + "@" + result.version
			modCache[key] = result.mf
		}
	}

	// Now do BFS using the cached go.mod files (fast, no network)
	type workItem struct {
		modulePath string
		version    string
		parentPURL string
	}

	// Start with direct dependencies
	var queue []workItem
	for _, req := range mf.Require {
		if !req.Indirect {
			queue = append(queue, workItem{
				modulePath: req.Mod.Path,
				version:    req.Mod.Version,
				parentPURL: goModuleToPURL(req.Mod.Path, req.Mod.Version),
			})
		}
	}

	// Process queue (now fast since all go.mod files are cached)
	visited := make(map[string]bool)
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		cacheKey := item.modulePath + "@" + item.version
		if visited[cacheKey] {
			continue
		}
		visited[cacheKey] = true

		// Look up from cache
		depMod := modCache[cacheKey]
		if depMod == nil {
			continue
		}

		// Add edges from this module to its direct dependencies
		for _, req := range depMod.Require {
			if req.Indirect {
				continue // Only direct deps of this module
			}

			childPath := req.Mod.Path
			childVersion := req.Mod.Version

			// Use the version from our go.mod if available (MVS selected version)
			if v, ok := allMods[childPath]; ok {
				childVersion = v
			}

			childPURL := goModuleToPURL(childPath, childVersion)

			edgeMu.Lock()
			edgeKey := item.parentPURL + "->" + childPURL
			if !edgeSet[edgeKey] {
				childNode := g.Node(childPURL)
				if childNode == nil {
					childNode = r.findNodeByModulePath(g, childPath)
				}
				if childNode != nil {
					g.AddEdge(&Edge{
						From:  item.parentPURL,
						To:    childNode.PURL,
						Scope: ScopeRuntime,
					})
					edgeSet[edgeKey] = true
				}
			}
			edgeMu.Unlock()

			// Continue BFS if this module is in our dependency set
			if _, inGraph := allMods[childPath]; inGraph {
				queue = append(queue, workItem{
					modulePath: childPath,
					version:    childVersion,
					parentPURL: childPURL,
				})
			}
		}
	}
}

// filteredProxyFetcher wraps GoProxyClient and skips private modules.
type filteredProxyFetcher struct {
	proxy           *GoProxyClient
	privatePatterns []string
}

func (f *filteredProxyFetcher) FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error) {
	// Skip private modules
	if !IsPublicModule(modulePath) {
		return nil, nil
	}
	for _, pattern := range f.privatePatterns {
		if strings.HasPrefix(modulePath, pattern) {
			return nil, nil
		}
		if strings.Contains(pattern, "*") {
			if matched, _ := path.Match(pattern, modulePath); matched {
				return nil, nil
			}
			prefix := strings.TrimSuffix(pattern, "/*")
			if prefix != pattern && strings.HasPrefix(modulePath, prefix+"/") {
				return nil, nil
			}
		}
	}
	return f.proxy.FetchGoMod(ctx, modulePath, version)
}

// gitModuleFetcherAdapter wraps GitModuleFetcher to implement ModuleGoModFetcher.
type gitModuleFetcherAdapter struct {
	fetcher *GitModuleFetcher
}

func (a *gitModuleFetcherAdapter) FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error) {
	return a.fetcher.FetchGoMod(ctx, modulePath, version)
}

// resolveTransitiveEdgesFromVendor uses only the vendor directory to resolve edges.
// This provides precise resolution when vendor is available, without any guessing.
// If vendor is not present or a module is not vendored, edges are left unresolved.
func (r *GoResolver) resolveTransitiveEdgesFromVendor(ctx context.Context, g *Graph, mf *modfile.File, rootPURL string, files FileReader) {
	if files == nil {
		return // No file access, cannot check vendor
	}

	fetcher := &vendorFetcher{files: files}

	// Build a map of all modules in the graph (from go.mod)
	allMods := make(map[string]string) // path -> version
	for _, req := range mf.Require {
		allMods[req.Mod.Path] = req.Mod.Version
	}

	// Track which edges we've already added
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// BFS through all dependencies
	type workItem struct {
		modulePath string
		version    string
		parentPURL string
	}

	var queue []workItem
	for _, req := range mf.Require {
		if !req.Indirect {
			queue = append(queue, workItem{
				modulePath: req.Mod.Path,
				version:    req.Mod.Version,
				parentPURL: goModuleToPURL(req.Mod.Path, req.Mod.Version),
			})
		}
	}

	visited := make(map[string]bool)
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		cacheKey := item.modulePath + "@" + item.version
		if visited[cacheKey] {
			continue
		}
		visited[cacheKey] = true

		depMod, err := fetcher.FetchGoMod(ctx, item.modulePath, item.version)
		if err != nil || depMod == nil {
			continue // Not in vendor, skip
		}

		for _, req := range depMod.Require {
			if req.Indirect {
				continue
			}

			childPath := req.Mod.Path
			childVersion := req.Mod.Version

			if v, ok := allMods[childPath]; ok {
				childVersion = v
			}

			childPURL := goModuleToPURL(childPath, childVersion)
			edgeKey := item.parentPURL + "->" + childPURL

			if !edgeSet[edgeKey] {
				childNode := g.Node(childPURL)
				if childNode == nil {
					childNode = r.findNodeByModulePath(g, childPath)
				}
				if childNode != nil {
					g.AddEdge(&Edge{
						From:  item.parentPURL,
						To:    childNode.PURL,
						Scope: ScopeRuntime,
					})
					edgeSet[edgeKey] = true
				}
			}

			if _, inGraph := allMods[childPath]; inGraph {
				queue = append(queue, workItem{
					modulePath: childPath,
					version:    childVersion,
					parentPURL: childPURL,
				})
			}
		}
	}
}

// findNodeByModulePath finds a node by its Go module path, ignoring version.
func (r *GoResolver) findNodeByModulePath(g *Graph, modulePath string) *Node {
	lowerPath := strings.ToLower(modulePath)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerPath {
			return node
		}
		// Also check if PURL contains this module
		if strings.Contains(strings.ToLower(node.PURL), lowerPath) {
			return node
		}
	}
	return nil
}

// goModuleToPURL converts a Go module path and version to a Package URL.
// The PURL format matches what osv-scalibr generates: pkg:golang/<full-path>@<version>
func goModuleToPURL(modulePath, version string) string {
	// Strip the 'v' prefix from version if present, as osv-scalibr does
	version = strings.TrimPrefix(version, "v")
	if version != "" {
		return fmt.Sprintf("pkg:golang/%s@%s", modulePath, version)
	}
	return fmt.Sprintf("pkg:golang/%s", modulePath)
}

// goStdlibToPURL converts a Go version to the stdlib Package URL.
// The stdlib PURL format matches what OSV uses for Go runtime vulnerabilities:
// pkg:golang/stdlib@<version> (e.g., pkg:golang/stdlib@1.21.0)
func goStdlibToPURL(goVersion string) string {
	// Go version in go.mod is like "1.21" or "1.21.0"
	// Normalize to ensure consistent PURL format
	version := strings.TrimSpace(goVersion)
	if version == "" {
		return "pkg:golang/stdlib"
	}
	return fmt.Sprintf("pkg:golang/stdlib@%s", version)
}

// containsRoot checks if a PURL is already in the roots slice.
func containsRoot(roots []string, purl string) bool {
	for _, r := range roots {
		if r == purl {
			return true
		}
	}
	return false
}
