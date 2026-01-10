package graph

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

// Pre-compiled regexes for Gemfile.lock parsing.
// Compiled once at package init to avoid repeated compilation per-file.
var (
	// gemLineRe matches gem specification lines: "    name (version)"
	gemLineRe = regexp.MustCompile(`^    ([a-zA-Z0-9][-a-zA-Z0-9._]*) \(([^)]+)\)$`)
	// depLineRe matches dependency lines: "      name" (with optional version constraint)
	depLineRe = regexp.MustCompile(`^      ([a-zA-Z0-9][-a-zA-Z0-9._]*)`)
	// directGemRe matches direct gem entries in DEPENDENCIES section: "  name"
	directGemRe = regexp.MustCompile(`^  ([a-zA-Z0-9][-a-zA-Z0-9._]*)`)
)

// RubyGemsResolver resolves dependency edges for Ruby packages by parsing Gemfile.lock.
// Gemfile.lock contains the complete dependency tree with exact versions.
//
// Supported files:
//   - Gemfile.lock (Bundler lockfile with full dependency graph)
//   - gems.locked (alternative lockfile name)
//
// The lockfile format groups dependencies under their parent, making
// edge resolution precise without external fetches.
type RubyGemsResolver struct {
	maxConcurrency int
}

// RubyGemsResolverOption configures a RubyGemsResolver.
type RubyGemsResolverOption func(*RubyGemsResolver)

// WithRubyGemsConcurrency sets the maximum concurrency for RubyGems resolution.
func WithRubyGemsConcurrency(n int) RubyGemsResolverOption {
	return func(r *RubyGemsResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// NewRubyGemsResolver creates a new RubyGems edge resolver.
func NewRubyGemsResolver(opts ...RubyGemsResolverOption) *RubyGemsResolver {
	r := &RubyGemsResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "RubyGems" as the ecosystem identifier.
func (r *RubyGemsResolver) Ecosystem() string {
	return "RubyGems"
}

// ResolveEdges parses Gemfile.lock to add dependency edges to the graph.
func (r *RubyGemsResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	lockFiles, err := r.findLockFiles(files)
	if err != nil {
		return fmt.Errorf("finding Gemfile.lock files: %w", err)
	}

	if len(lockFiles) == 0 {
		return nil
	}

	for _, lockPath := range lockFiles {
		if err := r.processGemfileLock(ctx, g, files, lockPath); err != nil {
			continue
		}
	}

	g.UpdateDepths()

	return nil
}

// findLockFiles locates all Gemfile.lock files.
func (r *RubyGemsResolver) findLockFiles(files FileReader) ([]string, error) {
	var lockPaths []string

	commonPaths := []string{
		"Gemfile.lock",
		"gems.locked",
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
				if name == ".git" || name == "vendor" || name == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			base := d.Name()
			if base == "Gemfile.lock" || base == "gems.locked" {
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

// gemSpec represents a parsed gem specification from Gemfile.lock.
type gemSpec struct {
	name         string
	version      string
	dependencies []string // gem names only
}

// processGemfileLock parses a Gemfile.lock and adds edges to the graph.
func (r *RubyGemsResolver) processGemfileLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	// Parse the lockfile
	specs, directGems := r.parseGemfileLock(data)

	// Build gem map: name -> gemSpec
	gemMap := make(map[string]gemSpec)
	for _, spec := range specs {
		gemMap[spec.name] = spec
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process each gem
	for _, spec := range specs {
		purl := gemPkgToPURL(spec.name, spec.version)

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, spec.name)
		}
		if node == nil {
			isDirect := directGems[spec.name]
			node = &Node{
				Purl:      purl,
				Name:      spec.name,
				Version:   spec.version,
				Ecosystem: "RubyGems",
				Direct:    isDirect,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		if directGems[spec.name] {
			node.Direct = true
			if !containsRoot(g.roots, node.Purl) {
				g.roots = append(g.roots, node.Purl)
			}
		}

		// Add edges for dependencies
		for _, depName := range spec.dependencies {
			childSpec, ok := gemMap[depName]
			if !ok {
				continue
			}

			childPURL := gemPkgToPURL(childSpec.name, childSpec.version)
			childNode := g.Node(childPURL)
			if childNode == nil {
				childNode = r.findNodeByName(g, depName)
			}
			if childNode == nil {
				continue
			}

			edgeKey := purl + "->" + childNode.Purl
			if !edgeSet[edgeKey] {
				g.AddEdge(&Edge{
					From:  purl,
					To:    childNode.Purl,
					Scope: ScopeRuntime,
				})
				edgeSet[edgeKey] = true
			}
		}
	}

	return nil
}

// parseGemfileLock parses a Gemfile.lock into gem specs and direct gem list.
// Gemfile.lock format:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    rails (7.0.0)
//	      actioncable (= 7.0.0)
//	      actionmailbox (= 7.0.0)
//	    actioncable (7.0.0)
//	      actionpack (= 7.0.0)
//
//	DEPENDENCIES
//	  rails
//	  pg
func (r *RubyGemsResolver) parseGemfileLock(data []byte) (specs []gemSpec, directGems map[string]bool) {
	directGems = make(map[string]bool)
	scanner := bufio.NewScanner(bytes.NewReader(data))

	var inSpecs bool
	var inDependencies bool
	var currentGem *gemSpec

	for scanner.Scan() {
		line := scanner.Text()

		// Section detection
		if line == "GEM" || line == "PATH" || line == "GIT" {
			inSpecs = false
			inDependencies = false
			continue
		}
		if line == "  specs:" {
			inSpecs = true
			continue
		}
		if line == "DEPENDENCIES" {
			if currentGem != nil {
				specs = append(specs, *currentGem)
				currentGem = nil
			}
			inSpecs = false
			inDependencies = true
			continue
		}
		if line == "PLATFORMS" || line == "BUNDLED WITH" || line == "RUBY VERSION" {
			if currentGem != nil {
				specs = append(specs, *currentGem)
				currentGem = nil
			}
			inSpecs = false
			inDependencies = false
			continue
		}

		// Parse spec section
		if inSpecs {
			// Check for gem line (4 space indent)
			if matches := gemLineRe.FindStringSubmatch(line); matches != nil {
				// Save previous gem
				if currentGem != nil {
					specs = append(specs, *currentGem)
				}
				currentGem = &gemSpec{
					name:    matches[1],
					version: matches[2],
				}
				continue
			}

			// Check for dependency line (6 space indent)
			if currentGem != nil {
				if matches := depLineRe.FindStringSubmatch(line); matches != nil {
					currentGem.dependencies = append(currentGem.dependencies, matches[1])
				}
			}
		}

		// Parse dependencies section
		if inDependencies {
			if matches := directGemRe.FindStringSubmatch(line); matches != nil {
				// Clean up the gem name (remove version constraints)
				gemName := matches[1]
				// Strip trailing ! for git/path sources
				gemName = strings.TrimSuffix(gemName, "!")
				directGems[gemName] = true
			}
		}
	}

	// Don't forget the last gem
	if currentGem != nil {
		specs = append(specs, *currentGem)
	}

	return specs, directGems
}

// findNodeByName finds a node by gem name, ignoring version.
func (r *RubyGemsResolver) findNodeByName(g *Graph, name string) *Node {
	lowerName := strings.ToLower(name)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerName {
			return node
		}
	}
	return nil
}

// gemPkgToPURL converts a gem name and version to a Package URL.
func gemPkgToPURL(name, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:gem/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:gem/%s", name)
}

// Ensure RubyGemsResolver implements EdgeResolver.
var _ EdgeResolver = (*RubyGemsResolver)(nil)
