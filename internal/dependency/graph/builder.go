package graph

import (
	"context"
	"log/slog"

	"github.com/google/osv-scalibr/extractor"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/vulnerability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// BuilderOptions configures graph construction.
type BuilderOptions struct {
	// UseProxy enables fetching module metadata from package registries
	// (e.g., proxy.golang.org for Go).
	UseProxy bool

	// UseGit enables cloning repositories for private module resolution.
	UseGit bool

	// PrivatePatterns specifies glob patterns for private modules
	// (similar to GOPRIVATE).
	PrivatePatterns []string
}

// Builder resolves dependency graph edges from inventory.
// It wraps the ResolverRegistry with configuration options.
type Builder struct {
	registry *ResolverRegistry
}

// NewBuilder creates a Builder configured from options.
func NewBuilder(opts BuilderOptions) *Builder {
	var registryOpts []RegistryOption

	if opts.UseProxy {
		registryOpts = append(registryOpts, WithGoProxyEnabled(""))
	}
	if opts.UseGit {
		registryOpts = append(registryOpts, WithGoGitEnabled())
	}
	if len(opts.PrivatePatterns) > 0 {
		registryOpts = append(registryOpts, WithGoPrivate(opts.PrivatePatterns...))
	}

	return &Builder{
		registry: NewResolverRegistry(registryOpts...),
	}
}

// Build constructs a dependency graph from inventory and resolves edges.
// The returned graph includes vulnerability annotations when findings are provided.
func (b *Builder) Build(
	ctx context.Context,
	pkgs []*extractor.Package,
	direct map[string]bool,
	findings []vulnerability.Finding,
	advisories map[string]*vulnerabilityv1.Advisory,
	files FileReader,
) (*Graph, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.graph.build",
		trace.WithAttributes(
			attribute.Int("deputy.package.count", len(pkgs)),
		))
	defer span.End()

	// Build graph from inventory
	g := FromInventory(pkgs, direct)

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
		attribute.Int("deputy.graph.direct", int(g.Stats().DirectNodes)),
		attribute.Int("deputy.graph.vulnerable", int(g.Stats().VulnerableNodes)),
	)

	return g, nil
}

// BuildFromWorkspace is a convenience method that creates a FileReader from a workspace.
func (b *Builder) BuildFromWorkspace(
	ctx context.Context,
	pkgs []*extractor.Package,
	direct map[string]bool,
	findings []vulnerability.Finding,
	advisories map[string]*vulnerabilityv1.Advisory,
	ws workspace.FS,
) (*Graph, error) {
	files := NewWorkspaceFileReader(ws)
	return b.Build(ctx, pkgs, direct, findings, advisories, files)
}

// PathsToVulnerability returns all paths to packages affected by a specific vulnerability ID.
func PathsToVulnerability(g *Graph, vulnID string) []Path {
	if g == nil {
		return nil
	}

	var paths []Path
	for node := range g.VulnerableNodes() {
		for _, f := range node.GetVulnerabilities() {
			if f.GetAdvisoryId() == vulnID {
				paths = append(paths, g.PathsTo(node.GetPurl())...)
				break
			}
		}
	}
	return paths
}

// ShortestPathToVulnerability returns the shortest path to any package
// affected by the given vulnerability ID.
func ShortestPathToVulnerability(g *Graph, vulnID string) Path {
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
