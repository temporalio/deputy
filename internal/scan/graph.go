package scan

import (
	"context"
	"log/slog"

	"github.com/google/osv-scalibr/extractor"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/dependency/graph"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/vulnerability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// GraphBuilder resolves dependency graph edges for scan results.
// It wraps the graph.ResolverRegistry with scan-specific configuration.
type GraphBuilder struct {
	registry *graph.ResolverRegistry
}

// NewGraphBuilder creates a GraphBuilder configured from scan options.
func NewGraphBuilder(opts GraphOptions) *GraphBuilder {
	var registryOpts []graph.RegistryOption

	if opts.UseProxy {
		registryOpts = append(registryOpts, graph.WithGoProxyEnabled(""))
	}
	if opts.UseGit {
		registryOpts = append(registryOpts, graph.WithGoGitEnabled())
	}
	if len(opts.PrivatePatterns) > 0 {
		registryOpts = append(registryOpts, graph.WithGoPrivate(opts.PrivatePatterns...))
	}

	return &GraphBuilder{
		registry: graph.NewResolverRegistry(registryOpts...),
	}
}

// Build constructs a dependency graph from inventory and resolves edges.
// The returned graph includes vulnerability annotations when findings are provided.
func (b *GraphBuilder) Build(
	ctx context.Context,
	pkgs []*extractor.Package,
	direct map[string]bool,
	findings []vulnerability.Finding,
	advisories map[string]vulnerabilityv1.Advisory,
	files graph.FileReader,
) (*graph.Graph, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scan.build_graph",
		trace.WithAttributes(
			attribute.Int("deputy.package.count", len(pkgs)),
		))
	defer span.End()

	// Build graph from inventory
	g := graph.FromInventory(pkgs, direct)

	// Resolve edges using ecosystem-specific resolvers
	if err := b.registry.ResolveAll(ctx, g, files); err != nil {
		// Log but don't fail - partial resolution is acceptable
		slog.Debug("some resolvers failed during edge resolution", "error", err)
	}

	// Update depths after edge resolution
	g.UpdateDepths()

	// Annotate with vulnerability information
	if len(findings) > 0 {
		g.AnnotateVulns(findings, advisories)
	}

	span.SetAttributes(
		attribute.Int("deputy.graph.nodes", g.Size()),
		attribute.Int("deputy.graph.direct", g.Stats().DirectNodes),
		attribute.Int("deputy.graph.vulnerable", g.Stats().VulnerableNodes),
	)

	return g, nil
}

// BuildFromWorkspace is a convenience method that creates a FileReader from a workspace.
func (b *GraphBuilder) BuildFromWorkspace(
	ctx context.Context,
	pkgs []*extractor.Package,
	direct map[string]bool,
	findings []vulnerability.Finding,
	advisories map[string]vulnerabilityv1.Advisory,
	ws workspace.FS,
) (*graph.Graph, error) {
	files := graph.NewWorkspaceFileReader(ws)
	return b.Build(ctx, pkgs, direct, findings, advisories, files)
}

// VulnerablePaths returns all paths from direct dependencies to vulnerable packages.
// This is useful for understanding how vulnerabilities enter the dependency tree.
func VulnerablePaths(g *graph.Graph) []graph.Path {
	if g == nil {
		return nil
	}
	return g.VulnerablePaths()
}

// PathsToVulnerability returns all paths to packages affected by a specific vulnerability ID.
func PathsToVulnerability(g *graph.Graph, vulnID string) []graph.Path {
	if g == nil {
		return nil
	}

	var paths []graph.Path
	for node := range g.VulnerableNodes() {
		for _, f := range node.Vulns {
			if f.AdvisoryID == vulnID {
				paths = append(paths, g.PathsTo(node.PURL)...)
				break
			}
		}
	}
	return paths
}

// ShortestPathToVulnerability returns the shortest path to any package
// affected by the given vulnerability ID.
func ShortestPathToVulnerability(g *graph.Graph, vulnID string) graph.Path {
	paths := PathsToVulnerability(g, vulnID)
	if len(paths) == 0 {
		return nil
	}

	shortest := paths[0]
	for _, p := range paths[1:] {
		if p.Len() < shortest.Len() {
			shortest = p
		}
	}
	return shortest
}
