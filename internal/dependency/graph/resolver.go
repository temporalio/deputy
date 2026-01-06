package graph

import (
	"context"
	"errors"
	"log/slog"

	"github.com/picatz/deputy/internal/ecosystem"
)

// ResolverRegistry manages edge resolvers for multiple ecosystems.
// It provides a unified interface for resolving edges across all supported
// ecosystems in a single pass.
type ResolverRegistry struct {
	resolvers []EdgeResolver
}

// NewResolverRegistry creates a registry with the default set of resolvers.
// For Go, the resolver is configured without proxy/git by default for speed.
// Use WithGoProxy() option to enable accurate transitive resolution.
func NewResolverRegistry(opts ...RegistryOption) *ResolverRegistry {
	r := &ResolverRegistry{}

	// Apply options first to configure resolver settings
	cfg := registryConfig{}
	for _, opt := range opts {
		opt(&cfg)
	}

	// Create Go resolver with appropriate options
	goOpts := []GoResolverOption{}
	if cfg.enableGoProxy {
		goOpts = append(goOpts, WithProxy(cfg.goProxyURL))
	}
	if cfg.enableGoGit {
		goOpts = append(goOpts, WithGit())
	}
	if cfg.goConcurrency > 0 {
		goOpts = append(goOpts, WithConcurrency(cfg.goConcurrency))
	}
	if len(cfg.goPrivatePatterns) > 0 {
		goOpts = append(goOpts, WithPrivatePatterns(cfg.goPrivatePatterns...))
	}

	r.resolvers = []EdgeResolver{
		NewGoResolver(goOpts...),
		NewNpmResolver(),
		NewCargoResolver(),
		NewPyPIResolver(),
		NewRubyGemsResolver(),
	}

	return r
}

// registryConfig holds configuration for the resolver registry.
type registryConfig struct {
	enableGoProxy     bool
	enableGoGit       bool
	goProxyURL        string
	goConcurrency     int
	goPrivatePatterns []string
}

// RegistryOption configures a ResolverRegistry.
type RegistryOption func(*registryConfig)

// WithGoProxy enables Go module proxy fetching for accurate transitive resolution.
// This is slower but provides precise dependency edges.
func WithGoProxyEnabled(proxyURL string) RegistryOption {
	return func(c *registryConfig) {
		c.enableGoProxy = true
		c.goProxyURL = proxyURL
	}
}

// WithGoGitEnabled enables Git fetching for private Go modules.
func WithGoGitEnabled() RegistryOption {
	return func(c *registryConfig) {
		c.enableGoGit = true
	}
}

// WithGoPrivate sets patterns for private Go modules (similar to GOPRIVATE).
func WithGoPrivate(patterns ...string) RegistryOption {
	return func(c *registryConfig) {
		c.goPrivatePatterns = append(c.goPrivatePatterns, patterns...)
	}
}

// WithGoConcurrency sets the concurrency for Go module fetching.
func WithGoResolverConcurrency(n int) RegistryOption {
	return func(c *registryConfig) {
		c.goConcurrency = n
	}
}

// Resolvers returns all registered edge resolvers.
func (r *ResolverRegistry) Resolvers() []EdgeResolver {
	return r.resolvers
}

// Register adds a custom edge resolver to the registry.
// This allows extending graph resolution to additional ecosystems
// without modifying the default registry.
func (r *ResolverRegistry) Register(resolver EdgeResolver) {
	if resolver == nil {
		return
	}
	// Check if resolver for this ecosystem already exists
	eco := normalizeEcosystemName(resolver.Ecosystem())
	for i, existing := range r.resolvers {
		if normalizeEcosystemName(existing.Ecosystem()) == eco {
			// Replace existing resolver
			r.resolvers[i] = resolver
			return
		}
	}
	// Add new resolver
	r.resolvers = append(r.resolvers, resolver)
}

// ForEcosystem returns the resolver for a specific ecosystem, or nil if not found.
func (r *ResolverRegistry) ForEcosystem(ecosystem string) EdgeResolver {
	normalized := normalizeEcosystemName(ecosystem)
	for _, resolver := range r.resolvers {
		if normalizeEcosystemName(resolver.Ecosystem()) == normalized {
			return resolver
		}
	}
	return nil
}

// ResolveAll runs all resolvers on the graph.
// Each resolver processes the ecosystem-specific lockfiles it finds.
// Errors from individual resolvers are logged but don't stop processing,
// allowing partial resolution when some ecosystems fail.
// Returns a combined error if any resolvers failed.
func (r *ResolverRegistry) ResolveAll(ctx context.Context, g *Graph, files FileReader) error {
	var errs []error
	for _, resolver := range r.resolvers {
		if err := resolver.ResolveEdges(ctx, g, files); err != nil {
			slog.Debug("resolver failed",
				"ecosystem", resolver.Ecosystem(),
				"error", err,
			)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// ResolveEcosystem runs only the resolver for a specific ecosystem.
func (r *ResolverRegistry) ResolveEcosystem(ctx context.Context, g *Graph, files FileReader, ecosystem string) error {
	resolver := r.ForEcosystem(ecosystem)
	if resolver == nil {
		return nil // No resolver for this ecosystem
	}
	return resolver.ResolveEdges(ctx, g, files)
}

// normalizeEcosystemName normalizes ecosystem names for comparison.
// Uses ecosystem.Parse for canonical normalization.
func normalizeEcosystemName(name string) string {
	eco := ecosystem.Parse(name)
	if eco.IsSupported() {
		return eco.String()
	}
	return name
}

// SupportedEcosystems returns the list of ecosystems with edge resolution support.
func SupportedEcosystems() []string {
	return []string{
		"Go",
		"npm",
		"Cargo (crates.io)",
		"PyPI",
		"RubyGems",
	}
}
