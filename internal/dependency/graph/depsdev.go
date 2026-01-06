package graph

import (
	"context"
	"fmt"
	"strings"
	"time"

	pb "deps.dev/api/v3"
	"github.com/picatz/deputy/internal/cache/memory"
	"golang.org/x/mod/modfile"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

const (
	// depsDevEndpoint is the gRPC endpoint for deps.dev API.
	depsDevEndpoint = "api.deps.dev:443"

	// defaultDepsDevCacheSize is the max number of dependency responses to cache.
	defaultDepsDevCacheSize = 4096

	// defaultDepsDevCacheTTL is how long cached responses remain valid.
	// deps.dev data is relatively stable, so a long TTL is appropriate.
	defaultDepsDevCacheTTL = 1 * time.Hour
)

// DepsDevClient fetches dependency information from deps.dev.
// This is significantly faster than fetching individual go.mod files
// because deps.dev has precomputed dependency graphs.
//
// The client uses a bounded LRU cache with TTL to prevent unbounded memory
// growth in long-running processes while maintaining good performance.
type DepsDevClient struct {
	client pb.InsightsClient
	conn   *grpc.ClientConn

	// cache stores fetched dependency data with bounded size and TTL.
	// Key format: "system/name@version"
	cache *memory.TTLCache[string, *pb.Dependencies]
}

// Dependencies is an alias for the deps.dev response type.
type Dependencies = pb.Dependencies

// NewDepsDevClient creates a client for the deps.dev API.
func NewDepsDevClient() (*DepsDevClient, error) {
	creds := credentials.NewClientTLSFromCert(nil, "")
	conn, err := grpc.NewClient(depsDevEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("connecting to deps.dev: %w", err)
	}

	return &DepsDevClient{
		client: pb.NewInsightsClient(conn),
		conn:   conn,
		cache:  memory.NewTTLCache[string, *pb.Dependencies](defaultDepsDevCacheSize, defaultDepsDevCacheTTL),
	}, nil
}

// CacheStats returns cache statistics for monitoring and debugging.
func (c *DepsDevClient) CacheStats() memory.Stats {
	if c == nil || c.cache == nil {
		return memory.Stats{}
	}
	return c.cache.Stats()
}

// Close closes the gRPC connection.
func (c *DepsDevClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// GetDependencies fetches the dependency graph for a package.
// The response contains all transitive dependencies with their relationships.
func (c *DepsDevClient) GetDependencies(ctx context.Context, system pb.System, name, version string) (*pb.Dependencies, error) {
	cacheKey := fmt.Sprintf("%s/%s@%s", system, name, version)

	// Check cache first
	if resp, ok := c.cache.Get(cacheKey); ok {
		return resp, nil
	}

	resp, err := c.client.GetDependencies(ctx, &pb.GetDependenciesRequest{
		VersionKey: &pb.VersionKey{
			System:  system,
			Name:    name,
			Version: version,
		},
	})
	if err != nil {
		return nil, err
	}

	// Store in cache
	c.cache.Set(cacheKey, resp)

	return resp, nil
}

// DepsDevFetcher implements ModuleGoModFetcher using deps.dev.
// Instead of fetching actual go.mod files, it synthesizes them from
// deps.dev dependency data, which is much faster.
type DepsDevFetcher struct {
	client *DepsDevClient
}

// NewDepsDevFetcher creates a fetcher backed by deps.dev.
func NewDepsDevFetcher(client *DepsDevClient) *DepsDevFetcher {
	return &DepsDevFetcher{client: client}
}

// FetchGoMod returns a synthesized go.mod based on deps.dev data.
// This doesn't return actual go.mod content but rather the dependency
// information we need for edge resolution.
func (f *DepsDevFetcher) FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error) {
	// Normalize version for Go
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	resp, err := f.client.GetDependencies(ctx, pb.System_GO, modulePath, version)
	if err != nil {
		return nil, err
	}

	// Synthesize a modfile.File from the deps.dev response
	return synthesizeGoMod(modulePath, version, resp)
}

// synthesizeGoMod creates a modfile.File from deps.dev dependency data.
func synthesizeGoMod(modulePath, version string, resp *pb.Dependencies) (*modfile.File, error) {
	if resp == nil || len(resp.Nodes) == 0 {
		return nil, fmt.Errorf("no dependency data for %s@%s", modulePath, version)
	}

	// Create a synthetic go.mod
	mf := &modfile.File{}
	mf.AddModuleStmt(modulePath)

	// Node 0 is the root (the package itself)
	// Find direct dependencies (edges from node 0)
	directDeps := make(map[uint32]bool)
	for _, edge := range resp.Edges {
		if edge.FromNode == 0 {
			directDeps[edge.ToNode] = true
		}
	}

	// Add require statements for direct dependencies
	for nodeIdx := range directDeps {
		if int(nodeIdx) >= len(resp.Nodes) {
			continue
		}
		node := resp.Nodes[nodeIdx]
		if node == nil || node.VersionKey == nil {
			continue
		}
		vk := node.VersionKey
		if vk.System != pb.System_GO {
			continue
		}

		// Add as a require directive
		_ = mf.AddRequire(vk.Name, vk.Version)
	}

	return mf, nil
}

// DepsDevEdgeResolver resolves edges using deps.dev bulk dependency data.
// This is much faster than individual go.mod fetches because:
// 1. deps.dev has precomputed graphs
// 2. One API call returns all transitive deps
// 3. We can parallelize across direct dependencies
type DepsDevEdgeResolver struct {
	client *DepsDevClient
}

// NewDepsDevEdgeResolver creates an edge resolver using deps.dev.
func NewDepsDevEdgeResolver(client *DepsDevClient) *DepsDevEdgeResolver {
	return &DepsDevEdgeResolver{client: client}
}

// ResolveGoEdges adds edges to the graph using deps.dev data.
// This is much faster than the proxy-based approach because deps.dev
// returns full dependency graphs in single API calls.
func (r *DepsDevEdgeResolver) ResolveGoEdges(ctx context.Context, g *Graph, mf *modfile.File) error {
	if mf == nil || mf.Module == nil {
		return nil
	}

	// Build existing edge set
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process each direct dependency
	for _, req := range mf.Require {
		if req.Indirect {
			continue
		}

		modulePath := req.Mod.Path
		version := req.Mod.Version

		// Normalize version for deps.dev
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}

		// Get the full dependency graph from deps.dev
		resp, err := r.client.GetDependencies(ctx, pb.System_GO, modulePath, version)
		if err != nil {
			continue // Non-fatal, skip this dependency
		}

		if len(resp.Nodes) == 0 || len(resp.Edges) == 0 {
			continue
		}

		// Build node index -> PURL map
		nodePURLs := make(map[uint32]string)
		for i, node := range resp.Nodes {
			if node == nil || node.VersionKey == nil {
				continue
			}
			vk := node.VersionKey
			if vk.System != pb.System_GO {
				continue
			}
			// Create PURL (strip 'v' prefix for consistency with inventory)
			ver := strings.TrimPrefix(vk.Version, "v")
			purl := fmt.Sprintf("pkg:golang/%s@%s", vk.Name, ver)
			nodePURLs[uint32(i)] = purl
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

	return nil
}

// Ensure DepsDevFetcher implements ModuleGoModFetcher
var _ ModuleGoModFetcher = (*DepsDevFetcher)(nil)
