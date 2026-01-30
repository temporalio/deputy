package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/inventory/flakelock"
	"github.com/picatz/deputy/internal/logs"
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
