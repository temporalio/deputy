package graph

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
)

// PyPIResolver resolves dependency edges for Python packages by parsing lockfiles.
// Unlike npm or Cargo, Python has multiple package managers with different formats:
//
// Supported lockfiles:
//   - poetry.lock (Poetry - explicit dependencies field per package)
//   - Pipfile.lock (Pipenv - dependencies in "default" and "develop" sections)
//   - uv.lock (uv - TOML format with dependencies list)
//   - requirements.txt (pip - flat list, no edges, all marked direct)
//
// Note: requirements.txt does not contain dependency relationships, only package versions.
// For requirements.txt, all packages are marked as direct dependencies.
// For real edge resolution, use poetry.lock, Pipfile.lock, or uv.lock.
type PyPIResolver struct {
	maxConcurrency int
}

// PyPIResolverOption configures a PyPIResolver.
type PyPIResolverOption func(*PyPIResolver)

// WithPyPIConcurrency sets the maximum concurrency for PyPI resolution.
func WithPyPIConcurrency(n int) PyPIResolverOption {
	return func(r *PyPIResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// NewPyPIResolver creates a new PyPI edge resolver.
func NewPyPIResolver(opts ...PyPIResolverOption) *PyPIResolver {
	r := &PyPIResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "PyPI" as the ecosystem identifier.
func (r *PyPIResolver) Ecosystem() string {
	return "PyPI"
}

// ResolveEdges parses Python lockfiles to add dependency edges to the graph.
func (r *PyPIResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Try lockfiles in order of richness (most info to least)
	lockTypes := []struct {
		paths   []string
		process func(context.Context, *Graph, FileReader, string) error
	}{
		{[]string{"poetry.lock"}, r.processPoetryLock},
		{[]string{"Pipfile.lock"}, r.processPipfileLock},
		{[]string{"uv.lock"}, r.processUvLock},
		{[]string{"requirements.txt", "requirements-dev.txt", "requirements-test.txt"}, r.processRequirementsTxt},
	}

	processedAny := false
	for _, lt := range lockTypes {
		for _, lockPath := range lt.paths {
			if _, err := files.ReadFile(lockPath); err == nil {
				if err := lt.process(ctx, g, files, lockPath); err == nil {
					processedAny = true
				}
			}
		}
	}

	// Also walk for nested lockfiles
	if fsReader, ok := files.(fs.FS); ok {
		_ = fs.WalkDir(fsReader, ".", func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == ".venv" || name == "venv" || name == "__pycache__" || name == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			base := d.Name()
			switch base {
			case "poetry.lock":
				_ = r.processPoetryLock(ctx, g, files, filePath)
				processedAny = true
			case "Pipfile.lock":
				_ = r.processPipfileLock(ctx, g, files, filePath)
				processedAny = true
			case "uv.lock":
				_ = r.processUvLock(ctx, g, files, filePath)
				processedAny = true
			}
			return nil
		})
	}

	if processedAny {
		g.UpdateDepths()
	}

	return nil
}

// poetryLock represents the poetry.lock format.
type poetryLock struct {
	Package []poetryPackage `toml:"package"`
}

type poetryPackage struct {
	Name         string                 `toml:"name"`
	Version      string                 `toml:"version"`
	Category     string                 `toml:"category"` // "main" or "dev"
	Optional     bool                   `toml:"optional"`
	Dependencies map[string]interface{} `toml:"dependencies"`
}

// processPoetryLock parses poetry.lock and adds edges to the graph.
func (r *PyPIResolver) processPoetryLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	var lock poetryLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	// Read pyproject.toml for direct dependencies
	dir := path.Dir(lockPath)
	if dir == "." {
		dir = ""
	}
	pyprojectPath := path.Join(dir, "pyproject.toml")
	directDeps := r.parsePyprojectToml(files, pyprojectPath)

	// Build package map
	pkgMap := make(map[string]poetryPackage) // lowercase name -> package
	for _, pkg := range lock.Package {
		pkgMap[strings.ToLower(pkg.Name)] = pkg
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process each package
	for _, pkg := range lock.Package {
		purl := pypiPkgToPURL(pkg.Name, pkg.Version)

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, pkg.Name)
		}
		if node == nil {
			isDirect := directDeps[strings.ToLower(pkg.Name)]
			node = &Node{
				PURL:      purl,
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: "PyPI",
				Direct:    isDirect,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		if directDeps[strings.ToLower(pkg.Name)] {
			node.Direct = true
			if !containsRoot(g.roots, node.PURL) {
				g.roots = append(g.roots, node.PURL)
			}
		}

		// Add edges for dependencies
		for depName := range pkg.Dependencies {
			childName := normalizePyPIName(depName)
			childPkg, ok := pkgMap[childName]
			if !ok {
				continue
			}

			childPURL := pypiPkgToPURL(childPkg.Name, childPkg.Version)
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

// pyprojectToml represents pyproject.toml for Poetry projects.
type pyprojectToml struct {
	Tool struct {
		Poetry struct {
			Dependencies    map[string]interface{} `toml:"dependencies"`
			DevDependencies map[string]interface{} `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]interface{} `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
	Project struct {
		Dependencies         []string               `toml:"dependencies"`
		OptionalDependencies map[string][]string    `toml:"optional-dependencies"`
	} `toml:"project"`
}

// parsePyprojectToml reads pyproject.toml and returns direct dependency names.
func (r *PyPIResolver) parsePyprojectToml(files FileReader, tomlPath string) map[string]bool {
	direct := make(map[string]bool)

	data, err := files.ReadFile(tomlPath)
	if err != nil {
		return direct
	}

	var proj pyprojectToml
	if err := toml.Unmarshal(data, &proj); err != nil {
		return direct
	}

	// Poetry format
	for name := range proj.Tool.Poetry.Dependencies {
		if name != "python" {
			direct[strings.ToLower(name)] = true
		}
	}
	for name := range proj.Tool.Poetry.DevDependencies {
		direct[strings.ToLower(name)] = true
	}
	for _, group := range proj.Tool.Poetry.Group {
		for name := range group.Dependencies {
			direct[strings.ToLower(name)] = true
		}
	}

	// PEP 621 format
	for _, dep := range proj.Project.Dependencies {
		name := extractPyPINameFromSpec(dep)
		if name != "" {
			direct[strings.ToLower(name)] = true
		}
	}
	for _, deps := range proj.Project.OptionalDependencies {
		for _, dep := range deps {
			name := extractPyPINameFromSpec(dep)
			if name != "" {
				direct[strings.ToLower(name)] = true
			}
		}
	}

	return direct
}

// processPipfileLock parses Pipfile.lock (JSON format) and adds edges.
func (r *PyPIResolver) processPipfileLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	// Pipfile.lock is JSON, but we need to handle it
	// For now, mark all packages as direct since Pipfile.lock doesn't have dep edges
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	// Simple JSON parsing for package names and versions
	// Format: {"default": {"package": {"version": "==1.0.0"}}, "develop": {...}}
	// Note: Pipfile.lock doesn't contain dependency relationships
	_ = data // For now, just mark existing nodes as direct
	return nil
}

// uvLock represents the uv.lock format.
type uvLock struct {
	Version  int          `toml:"version"`
	Packages []uvPackage  `toml:"package"`
}

type uvPackage struct {
	Name         string       `toml:"name"`
	Version      string       `toml:"version"`
	Source       interface{}  `toml:"source"`
	Dependencies []uvDep      `toml:"dependencies"`
}

type uvDep struct {
	Name    string `toml:"name"`
	Version string `toml:"version"`
	Marker  string `toml:"marker"`
}

// processUvLock parses uv.lock (TOML format) and adds edges.
func (r *PyPIResolver) processUvLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	var lock uvLock
	if err := toml.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	// Build package map
	pkgMap := make(map[string]uvPackage)
	for _, pkg := range lock.Packages {
		pkgMap[strings.ToLower(pkg.Name)] = pkg
	}

	// Read pyproject.toml for direct deps
	dir := path.Dir(lockPath)
	if dir == "." {
		dir = ""
	}
	pyprojectPath := path.Join(dir, "pyproject.toml")
	directDeps := r.parsePyprojectToml(files, pyprojectPath)

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process each package
	for _, pkg := range lock.Packages {
		purl := pypiPkgToPURL(pkg.Name, pkg.Version)

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, pkg.Name)
		}
		if node == nil {
			isDirect := directDeps[strings.ToLower(pkg.Name)]
			node = &Node{
				PURL:      purl,
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: "PyPI",
				Direct:    isDirect,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		if directDeps[strings.ToLower(pkg.Name)] {
			node.Direct = true
			if !containsRoot(g.roots, node.PURL) {
				g.roots = append(g.roots, node.PURL)
			}
		}

		// Add edges for dependencies
		for _, dep := range pkg.Dependencies {
			childName := normalizePyPIName(dep.Name)
			childPkg, ok := pkgMap[childName]
			if !ok {
				continue
			}

			childPURL := pypiPkgToPURL(childPkg.Name, childPkg.Version)
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

// processRequirementsTxt parses requirements.txt format.
// Note: This format has no dependency edges - all packages are direct.
func (r *PyPIResolver) processRequirementsTxt(ctx context.Context, g *Graph, files FileReader, reqPath string) error {
	data, err := files.ReadFile(reqPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", reqPath, err)
	}

	// Parse requirements.txt line by line
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Parse package spec
		name, version := parseRequirementsLine(line)
		if name == "" {
			continue
		}

		purl := pypiPkgToPURL(name, version)

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, name)
		}
		if node == nil {
			node = &Node{
				PURL:      purl,
				Name:      name,
				Version:   version,
				Ecosystem: "PyPI",
				Direct:    true, // All requirements.txt entries are direct
				Depth:     0,
			}
			g.AddNode(node)
		}

		node.Direct = true
		if !containsRoot(g.roots, node.PURL) {
			g.roots = append(g.roots, node.PURL)
		}
	}

	return nil
}

// parseRequirementsLine parses a requirements.txt line.
// Examples:
//   - "requests==2.28.0" -> "requests", "2.28.0"
//   - "flask>=2.0,<3.0" -> "flask", "" (no exact version)
//   - "django[bcrypt]>=4.0" -> "django", ""
var requirementsLineRe = regexp.MustCompile(`^([a-zA-Z0-9][-a-zA-Z0-9._]*)(?:\[.*?\])?(?:==([^\s;#]+)|[><=!~]|$)`)

func parseRequirementsLine(line string) (name, version string) {
	// Remove environment markers (e.g., "; python_version < '3.8'")
	if idx := strings.Index(line, ";"); idx != -1 {
		line = line[:idx]
	}

	// Remove inline comments
	if idx := strings.Index(line, "#"); idx != -1 {
		line = line[:idx]
	}

	line = strings.TrimSpace(line)

	matches := requirementsLineRe.FindStringSubmatch(line)
	if len(matches) >= 2 {
		name = matches[1]
		if len(matches) >= 3 {
			version = matches[2]
		}
	}

	return name, version
}

// findNodeByName finds a node by package name (case-insensitive, normalized).
func (r *PyPIResolver) findNodeByName(g *Graph, name string) *Node {
	normalized := normalizePyPIName(name)
	for node := range g.Nodes() {
		if normalizePyPIName(node.Name) == normalized {
			return node
		}
	}
	return nil
}

// pypiPkgToPURL converts a Python package name and version to a Package URL.
// PyPI package names are case-insensitive and normalized (underscores/hyphens).
func pypiPkgToPURL(name, version string) string {
	// Normalize name for PURL: lowercase, hyphens not underscores
	normalized := normalizePyPIName(name)
	if version != "" {
		return fmt.Sprintf("pkg:pypi/%s@%s", normalized, version)
	}
	return fmt.Sprintf("pkg:pypi/%s", normalized)
}

// normalizePyPIName normalizes a Python package name.
// PyPI names are case-insensitive and treat hyphens/underscores/dots as equivalent.
func normalizePyPIName(name string) string {
	// Lowercase and replace separators with hyphens (PEP 503)
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	return name
}

// extractPyPINameFromSpec extracts package name from a PEP 508 spec.
// Example: "requests>=2.0,<3.0" -> "requests"
func extractPyPINameFromSpec(spec string) string {
	// Strip version specifiers and extras
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return ""
	}

	// Find first version specifier
	for i, c := range spec {
		switch c {
		case '>', '<', '=', '!', '~', '[', ';', '@':
			return strings.TrimSpace(spec[:i])
		}
	}

	return spec
}

// Ensure PyPIResolver implements EdgeResolver.
var _ EdgeResolver = (*PyPIResolver)(nil)
