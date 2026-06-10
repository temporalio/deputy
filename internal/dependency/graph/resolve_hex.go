package graph

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

// Pre-compiled regexes for mix.lock parsing.
// Compiled once at package init to avoid repeated compilation per-file.
var (
	// gitDependencyRe matches git dependency lines:
	//   "name": {:git, "repo", "commit-hash", <other comma-separated values> },
	gitDependencyRe = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:git,\s*"([^"]+)",\s*"([^"]+)",.+\}`)

	// regularDependencyRe matches regular Hex.pm dependency lines:
	//   "name": {:hex, :name, "version", "hash", <other values>},
	regularDependencyRe = regexp.MustCompile(`^\s*"([^"]+)":\s*\{:hex,\s*:([^,]+),\s*"([^"]+)",\s*"([^"]+)",.+\}`)
)

// HexResolver resolves dependency edges for Elixir/Erlang packages by parsing mix.lock.
// The mix.lock file contains all resolved dependencies with their exact versions.
//
// Supported files:
//   - mix.lock (Mix lockfile for Elixir/Erlang projects)
//
// Mix.lock lists all dependencies (direct and transitive) but doesn't
// explicitly encode the dependency tree. Direct dependencies are determined
// from mix.exs, which this resolver does not parse. Instead, it marks all
// dependencies and relies on the inventory for direct/transitive flags.
type HexResolver struct {
	maxConcurrency int
}

// HexResolverOption configures a HexResolver.
type HexResolverOption func(*HexResolver)

// WithHexConcurrency sets the maximum concurrency for Hex resolution.
func WithHexConcurrency(n int) HexResolverOption {
	return func(r *HexResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// NewHexResolver creates a new Hex edge resolver.
func NewHexResolver(opts ...HexResolverOption) *HexResolver {
	r := &HexResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "Hex" as the ecosystem identifier.
func (r *HexResolver) Ecosystem() string {
	return "Hex"
}

// ResolveEdges parses mix.lock to add dependency nodes to the graph.
// Note: mix.lock doesn't encode the dependency tree, so edges aren't resolved
// from this file alone. This resolver ensures all packages are in the graph.
func (r *HexResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	lockFiles, err := r.findLockFiles(files)
	if err != nil {
		return fmt.Errorf("finding mix.lock files: %w", err)
	}

	if len(lockFiles) == 0 {
		return nil
	}

	for _, lockPath := range lockFiles {
		if err := r.processMixLock(ctx, g, files, lockPath); err != nil {
			continue
		}
	}

	g.UpdateDepths()

	return nil
}

// findLockFiles locates all mix.lock files.
func (r *HexResolver) findLockFiles(files FileReader) ([]string, error) {
	var lockPaths []string

	commonPaths := []string{
		"mix.lock",
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
				if name == ".git" || name == "_build" || name == "deps" || name == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			if d.Name() == "mix.lock" {
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

// hexPackage represents a parsed package from mix.lock.
type hexPackage struct {
	name    string
	version string
	hash    string
	isGit   bool
	commit  string
}

// processMixLock parses a mix.lock and adds nodes to the graph.
func (r *HexResolver) processMixLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	// Parse the lockfile
	packages := r.parseMixLock(data)

	// Process each package
	for _, pkg := range packages {
		purl := hexPkgToPURL(pkg.name, pkg.version)

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, pkg.name)
		}
		if node == nil {
			// mix.lock doesn't indicate direct/transitive, so default to false
			// The inventory will set the correct value based on mix.exs
			node = &Node{
				Purl:      purl,
				Name:      pkg.name,
				Version:   pkg.version,
				Ecosystem: "Hex",
				Direct:    false,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}
	}

	return nil
}

// parseMixLock parses a mix.lock file into package specifications.
// mix.lock format (Elixir map literal):
//
//	%{
//	  "castore": {:hex, :castore, "1.0.5", "hash", [:mix], [], "hexpm", "hash2"},
//	  "cowboy": {:hex, :cowboy, "2.10.0", "hash", [:rebar3], [{:cowlib, "~> 2.12", [...]}, ...], "hexpm", "hash2"},
//	  "myapp": {:git, "https://github.com/owner/myapp.git", "abc123", [branch: "main"]},
//	}
func (r *HexResolver) parseMixLock(data []byte) []hexPackage {
	var packages []hexPackage
	scanner := bufio.NewScanner(bytes.NewReader(data))

	for scanner.Scan() {
		line := scanner.Text()

		// Try git dependency pattern
		if matches := gitDependencyRe.FindStringSubmatch(line); matches != nil {
			if len(matches) >= 4 {
				packages = append(packages, hexPackage{
					name:   matches[1],
					isGit:  true,
					commit: matches[3],
				})
			}
			continue
		}

		// Try regular hex dependency pattern
		if matches := regularDependencyRe.FindStringSubmatch(line); matches != nil {
			if len(matches) >= 5 {
				packages = append(packages, hexPackage{
					name:    matches[1],
					version: matches[3],
					hash:    matches[4],
				})
			}
		}
	}

	return packages
}

// findNodeByName finds a node by package name, ignoring version.
func (r *HexResolver) findNodeByName(g *Graph, name string) *Node {
	lowerName := strings.ToLower(name)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerName {
			return node
		}
	}
	return nil
}

// hexPkgToPURL converts a Hex package name and version to a Package URL.
// Format: pkg:hex/name@version
func hexPkgToPURL(name, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:hex/%s@%s", name, version)
	}
	return fmt.Sprintf("pkg:hex/%s", name)
}

// Ensure HexResolver implements EdgeResolver.
var _ EdgeResolver = (*HexResolver)(nil)
