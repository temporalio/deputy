package graph

import (
	"context"
	"fmt"
	"io/fs"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// PubResolver resolves dependency edges for Dart/Flutter packages by parsing pubspec.lock.
// The pubspec.lock file contains all resolved dependencies with their exact versions.
//
// Supported files:
//   - pubspec.lock (Dart/Flutter lockfile)
//
// The lockfile indicates whether dependencies are "direct main", "direct dev",
// or "transitive", allowing accurate direct/transitive classification.
type PubResolver struct {
	maxConcurrency int
}

// PubResolverOption configures a PubResolver.
type PubResolverOption func(*PubResolver)

// WithPubConcurrency sets the maximum concurrency for Pub resolution.
func WithPubConcurrency(n int) PubResolverOption {
	return func(r *PubResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// NewPubResolver creates a new Pub edge resolver.
func NewPubResolver(opts ...PubResolverOption) *PubResolver {
	r := &PubResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "Pub" as the ecosystem identifier.
func (r *PubResolver) Ecosystem() string {
	return "Pub"
}

// ResolveEdges parses pubspec.lock to add dependency nodes to the graph.
func (r *PubResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	lockFiles, err := r.findLockFiles(files)
	if err != nil {
		return fmt.Errorf("finding pubspec.lock files: %w", err)
	}

	if len(lockFiles) == 0 {
		return nil
	}

	for _, lockPath := range lockFiles {
		if err := r.processPubspecLock(ctx, g, files, lockPath); err != nil {
			continue
		}
	}

	g.UpdateDepths()

	return nil
}

// findLockFiles locates all pubspec.lock files.
func (r *PubResolver) findLockFiles(files FileReader) ([]string, error) {
	var lockPaths []string

	commonPaths := []string{
		"pubspec.lock",
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
				if name == ".git" || name == ".dart_tool" || name == "build" || name == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			if d.Name() == "pubspec.lock" {
				if slices.Contains(lockPaths, filePath) {
					return nil
				}
				lockPaths = append(lockPaths, filePath)
			}
			return nil
		})
	}

	return lockPaths, nil
}

// pubspecLock represents the pubspec.lock file structure.
type pubspecLock struct {
	Packages map[string]pubspecPackage `yaml:"packages"`
	Sdks     map[string]string         `yaml:"sdks"`
}

// pubspecPackage represents a package entry in pubspec.lock.
type pubspecPackage struct {
	Dependency  string            `yaml:"dependency"`
	Description pubspecDescriptor `yaml:"description"`
	Source      string            `yaml:"source"`
	Version     string            `yaml:"version"`
}

// pubspecDescriptor can be either a string or an object with name/url/ref.
type pubspecDescriptor struct {
	Name        string `yaml:"name"`
	URL         string `yaml:"url"`
	Ref         string `yaml:"resolved-ref"`
	Path        string `yaml:"path"`
	ResolvedRef string `yaml:"resolved-ref"`
}

// UnmarshalYAML handles pubspec descriptor which can be a string or object.
func (d *pubspecDescriptor) UnmarshalYAML(value *yaml.Node) error {
	// Try string first
	var str string
	if err := value.Decode(&str); err == nil {
		d.Name = str
		return nil
	}

	// Try object
	var obj struct {
		Name        string `yaml:"name"`
		URL         string `yaml:"url"`
		Ref         string `yaml:"ref"`
		Path        string `yaml:"path"`
		ResolvedRef string `yaml:"resolved-ref"`
	}
	if err := value.Decode(&obj); err != nil {
		return err
	}
	d.Name = obj.Name
	d.URL = obj.URL
	d.Ref = obj.Ref
	d.Path = obj.Path
	d.ResolvedRef = obj.ResolvedRef
	return nil
}

// processPubspecLock parses a pubspec.lock and adds nodes to the graph.
func (r *PubResolver) processPubspecLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	var lock pubspecLock
	if err := yaml.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parsing %s: %w", lockPath, err)
	}

	// Process each package
	for name, pkg := range lock.Packages {
		purl := pubPkgToPURL(name, pkg.Version)

		// Determine if direct dependency
		isDirect := strings.HasPrefix(pkg.Dependency, "direct")

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, name)
		}
		if node == nil {
			node = &Node{
				Purl:      purl,
				Name:      name,
				Version:   pkg.Version,
				Ecosystem: "Pub",
				Direct:    isDirect,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		// Update node properties
		if isDirect && !node.Direct {
			node.Direct = true
		}

		// Add to roots if direct
		if isDirect && !containsRoot(g.roots, node.Purl) {
			g.roots = append(g.roots, node.Purl)
		}
	}

	return nil
}

// findNodeByName finds a node by package name, ignoring version.
func (r *PubResolver) findNodeByName(g *Graph, name string) *Node {
	lowerName := strings.ToLower(name)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerName {
			return node
		}
	}
	return nil
}

// pubPkgToPURL converts a Pub package name and version to a Package URL.
// Format: pkg:pub/name@version
func pubPkgToPURL(name, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:pub/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:pub/%s", name)
}

// Ensure PubResolver implements EdgeResolver.
var _ EdgeResolver = (*PubResolver)(nil)
