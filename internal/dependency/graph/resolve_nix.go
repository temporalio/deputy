package graph

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/inventory/flakelock"
	"github.com/picatz/deputy/internal/logs"

	// SQLite driver for Nix database.
	_ "modernc.org/sqlite"
)

// NixFlakeResolver resolves dependency edges for Nix flakes from flake.lock files.
// It extracts the dependency graph structure from the lock file's node inputs.
type NixFlakeResolver struct{}

// NewNixFlakeResolver creates a new Nix flake resolver.
func NewNixFlakeResolver() *NixFlakeResolver {
	return &NixFlakeResolver{}
}

// Ecosystem returns "Nix" as the ecosystem identifier.
func (r *NixFlakeResolver) Ecosystem() string {
	return "Nix"
}

// ResolveEdges parses flake.lock files and adds dependency edges to the graph.
// It uses the flake.lock's node structure to determine which inputs depend on others.
func (r *NixFlakeResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Find flake.lock files
	lockPaths := r.findFlakeLocks(files)
	if len(lockPaths) == 0 {
		logs.Debug(ctx, "nix resolver: no flake.lock files found")
		return nil
	}

	for _, lockPath := range lockPaths {
		if err := r.resolveFromLock(ctx, g, files, lockPath); err != nil {
			logs.Debug(ctx, "nix resolver: error processing flake.lock",
				"path", lockPath, "error", err)
			// Continue processing other lock files
		}
	}

	return nil
}

// findFlakeLocks searches for flake.lock files in the file reader.
// It checks common locations.
func (r *NixFlakeResolver) findFlakeLocks(files FileReader) []string {
	candidates := []string{
		"flake.lock",
		"./flake.lock",
	}

	var found []string
	for _, path := range candidates {
		if _, err := files.ReadFile(path); err == nil {
			found = append(found, path)
			break // Usually there's only one flake.lock at the root
		}
	}
	return found
}

// resolveFromLock parses a single flake.lock file and adds edges.
func (r *NixFlakeResolver) resolveFromLock(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", lockPath, err)
	}

	var lock flakelock.FlakeLock
	if err := json.Unmarshal(data, &lock); err != nil {
		return fmt.Errorf("parse %s: %w", lockPath, err)
	}

	// Build a map from node ID to PURL for edge resolution
	nodeIDToPURL := make(map[string]string)

	// First pass: identify PURLs for all nodes
	for nodeID, node := range lock.Nodes {
		if nodeID == lock.Root {
			continue // Skip root node
		}
		if node.Locked == nil {
			continue
		}

		purl := r.nodeToPURL(nodeID, &node)
		if purl != "" {
			nodeIDToPURL[nodeID] = purl
		}
	}

	// Get root node for direct dependency identification
	rootNode, ok := lock.Nodes[lock.Root]
	if !ok {
		return fmt.Errorf("root node %q not found", lock.Root)
	}

	// Mark direct inputs from root
	directInputs := make(map[string]bool)
	for _, ref := range rootNode.Inputs {
		switch v := ref.(type) {
		case string:
			directInputs[v] = true
		case []any:
			if len(v) > 0 {
				if last, ok := v[len(v)-1].(string); ok {
					directInputs[last] = true
				}
			}
		}
	}

	// Update node depths and mark direct dependencies
	for nodeID, nodePURL := range nodeIDToPURL {
		if node := g.Node(nodePURL); node != nil {
			if directInputs[nodeID] {
				node.Depth = 1
				node.Direct = true
			}
		}
	}

	// Second pass: add edges based on node inputs
	for nodeID, node := range lock.Nodes {
		if nodeID == lock.Root {
			continue
		}

		fromPURL := nodeIDToPURL[nodeID]
		if fromPURL == "" {
			continue
		}

		// Process this node's inputs as edges
		for inputName, ref := range node.Inputs {
			var targetNodeID string
			switch v := ref.(type) {
			case string:
				targetNodeID = v
			case []any:
				// Follows reference
				if len(v) > 0 {
					if last, ok := v[len(v)-1].(string); ok {
						targetNodeID = last
					}
				}
			}

			if targetNodeID == "" || targetNodeID == nodeID {
				continue
			}

			toPURL := nodeIDToPURL[targetNodeID]
			if toPURL == "" {
				continue
			}

			// Add edge from this node to its input
			g.AddEdge(&Edge{
				From:  fromPURL,
				To:    toPURL,
				Scope: ScopeRuntime,
			})

			_ = inputName // Available for additional context if needed
		}
	}

	return nil
}

// nodeToPURL generates a PURL for a flake.lock node.
func (r *NixFlakeResolver) nodeToPURL(nodeID string, node *flakelock.Node) string {
	if node.Locked == nil {
		return ""
	}

	locked := node.Locked
	var name, version string

	switch locked.Type {
	case "github":
		if locked.Owner != "" && locked.Repo != "" {
			name = locked.Owner + "/" + locked.Repo
		} else {
			name = nodeID
		}
		version = locked.Rev
	case "gitlab":
		if locked.Owner != "" && locked.Repo != "" {
			name = locked.Owner + "/" + locked.Repo
		} else {
			name = nodeID
		}
		version = locked.Rev
	case "git":
		// For git URLs, use the URL as name
		if locked.URL != "" {
			name = sanitizeURLForPURL(locked.URL)
		} else {
			name = nodeID
		}
		version = locked.Rev
	case "tarball":
		// Use URL hash or nodeID
		if locked.URL != "" {
			name = sanitizeURLForPURL(locked.URL)
		} else {
			name = nodeID
		}
		version = locked.NarHash
	case "path":
		// Local paths
		if locked.Path != "" {
			name = filepath.Base(locked.Path)
		} else {
			name = nodeID
		}
		version = locked.NarHash
	default:
		name = nodeID
		version = locked.Rev
	}

	if name == "" {
		return ""
	}

	if version != "" {
		return fmt.Sprintf("%s:%s/%s@%s", purl.TypeNix, "", name, version)
	}
	return fmt.Sprintf("%s:%s/%s", purl.TypeNix, "", name)
}

// sanitizeURLForPURL converts a URL to a valid PURL name component.
func sanitizeURLForPURL(url string) string {
	// Remove common prefixes
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "git://")
	url = strings.TrimSuffix(url, ".git")

	// Replace problematic characters
	url = strings.ReplaceAll(url, ":", "-")

	return url
}

// Ensure NixFlakeResolver implements EdgeResolver.
var _ EdgeResolver = (*NixFlakeResolver)(nil)

// NixDBResolver resolves dependency edges from the Nix database (db.sqlite).
// This resolver operates on local filesystem only, looking for the database
// at the standard /nix/var/nix/db/db.sqlite location.
type NixDBResolver struct {
	// dbPath is the path to the Nix database. If empty, uses default location.
	dbPath string
}

// NixDBResolverOption configures a NixDBResolver.
type NixDBResolverOption func(*NixDBResolver)

// WithDBPath sets a custom path to the Nix database.
func WithDBPath(path string) NixDBResolverOption {
	return func(r *NixDBResolver) {
		r.dbPath = path
	}
}

// NewNixDBResolver creates a new Nix database resolver.
func NewNixDBResolver(opts ...NixDBResolverOption) *NixDBResolver {
	r := &NixDBResolver{
		dbPath: "/nix/var/nix/db/db.sqlite",
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "Nix" as the ecosystem identifier.
func (r *NixDBResolver) Ecosystem() string {
	return "Nix"
}

// ResolveEdges reads the Nix database to build dependency edges.
// It connects packages in the graph based on their store path references.
func (r *NixDBResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Only run if we have Nix packages in the graph
	hasNixPackages := false
	for node := range g.Nodes() {
		if strings.HasPrefix(node.Purl, "pkg:nix/") {
			hasNixPackages = true
			break
		}
	}
	if !hasNixPackages {
		return nil
	}

	// Check if database exists
	info, err := os.Stat(r.dbPath)
	if err != nil || info.IsDir() {
		logs.Debug(ctx, "nix db resolver: database not found", "path", r.dbPath)
		return nil // Database not available, skip resolution
	}

	// Build a map from store path to PURL for edge resolution
	storePathToPURL := make(map[string]string)
	for node := range g.Nodes() {
		if !strings.HasPrefix(node.Purl, "pkg:nix/") {
			continue
		}
		// Locations contain the store path
		for _, loc := range node.Locations {
			if strings.HasPrefix(loc, "/nix/store/") {
				storePathToPURL[loc] = node.Purl
			}
		}
	}

	if len(storePathToPURL) == 0 {
		logs.Debug(ctx, "nix db resolver: no store paths found in graph")
		return nil
	}

	// Query the database for references
	deps, err := r.queryDependencies(ctx, storePathToPURL)
	if err != nil {
		logs.Debug(ctx, "nix db resolver: query failed", "error", err)
		return nil // Non-fatal
	}

	// Add edges
	edgeCount := 0
	for fromPath, toPaths := range deps {
		fromPURL := storePathToPURL[fromPath]
		if fromPURL == "" {
			continue
		}
		for _, toPath := range toPaths {
			toPURL := storePathToPURL[toPath]
			if toPURL == "" || fromPURL == toPURL {
				continue
			}
			g.AddEdge(&Edge{
				From:  fromPURL,
				To:    toPURL,
				Scope: ScopeRuntime,
			})
			edgeCount++
		}
	}

	logs.Debug(ctx, "nix db resolver: added edges", "count", edgeCount)
	return nil
}

// queryDependencies queries the Nix database for package dependencies.
func (r *NixDBResolver) queryDependencies(ctx context.Context, storePathToPURL map[string]string) (map[string][]string, error) {
	db, err := sql.Open("sqlite", r.dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	// Build path to ID mapping
	pathToID := make(map[string]int64)
	idToPath := make(map[int64]string)

	rows, err := db.QueryContext(ctx, `SELECT id, path FROM ValidPaths`)
	if err != nil {
		return nil, fmt.Errorf("query ValidPaths: %w", err)
	}
	for rows.Next() {
		var id int64
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			continue
		}
		pathToID[path] = id
		idToPath[id] = path
	}
	rows.Close()

	// Query refs only for paths we care about
	deps := make(map[string][]string)
	for storePath := range storePathToPURL {
		if _, ok := pathToID[storePath]; !ok {
			continue
		}
	}

	// Get all relevant refs
	rows, err = db.QueryContext(ctx, `SELECT referrer, reference FROM Refs`)
	if err != nil {
		return nil, fmt.Errorf("query Refs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var referrer, reference int64
		if err := rows.Scan(&referrer, &reference); err != nil {
			continue
		}
		referrerPath := idToPath[referrer]
		referencePath := idToPath[reference]
		if referrerPath != "" && referencePath != "" {
			if _, ok := storePathToPURL[referrerPath]; ok {
				deps[referrerPath] = append(deps[referrerPath], referencePath)
			}
		}
	}

	return deps, rows.Err()
}

// Ensure NixDBResolver implements EdgeResolver.
var _ EdgeResolver = (*NixDBResolver)(nil)
