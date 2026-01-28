package targets

import (
	"cmp"
	"context"
	"errors"
	"slices"
	"sync"
)

var (
	defaultRegistry    = newRegistry()
	ErrNoProvider      = errors.New("targets: no provider matched target")
	ErrNotACollection  = errors.New("targets: target is not a collection")
	ErrListUnsupported = errors.New("targets: provider does not support listing")
)

type registry struct {
	mu        sync.RWMutex
	providers []Provider
}

func newRegistry() *registry { return &registry{} }

func (r *registry) Register(p Provider) {
	if p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.providers = append(r.providers, p)
	slices.SortStableFunc(r.providers, func(a, b Provider) int {
		return cmp.Compare(providerPriority(b), providerPriority(a))
	})
}

func (r *registry) Open(ctx context.Context, target string, opts *OpenOptions) (Materialized, error) {
	r.mu.RLock()
	providers := slices.Clone(r.providers)
	r.mu.RUnlock()
	for _, p := range providers {
		if !p.Detect(ctx, target) {
			continue
		}
		return p.Open(ctx, target, opts)
	}
	return Materialized{}, ErrNoProvider
}

func providerPriority(p Provider) int {
	if prioritized, ok := p.(PriorityProvider); ok {
		return prioritized.Priority()
	}
	return 0
}

// RegisterProvider adds a provider to the default registry.
func RegisterProvider(p Provider) {
	defaultRegistry.Register(p)
}

// Open resolves the provided target using the default registry.
func Open(ctx context.Context, target string, opts *OpenOptions) (Materialized, error) {
	return defaultRegistry.Open(ctx, target, opts)
}

// IsCollection checks if the target is a collection URI using the default registry.
func IsCollection(ctx context.Context, target string) bool {
	return defaultRegistry.IsCollection(ctx, target)
}

// List enumerates targets in a collection using the default registry.
func List(ctx context.Context, target string, opts *ListOptions) (*ListResult, error) {
	return defaultRegistry.List(ctx, target, opts)
}

// IsCollection checks if the target URI represents a collection.
// Returns true if a CollectionProvider detects the target and identifies it as a collection.
func (r *registry) IsCollection(ctx context.Context, target string) bool {
	r.mu.RLock()
	providers := slices.Clone(r.providers)
	r.mu.RUnlock()

	for _, p := range providers {
		if !p.Detect(ctx, target) {
			continue
		}
		if cp, ok := p.(CollectionProvider); ok {
			return cp.IsCollection(ctx, target)
		}
		// Provider detected but doesn't support collections
		return false
	}
	return false
}

// List enumerates targets within a collection.
// Returns ErrNoProvider if no provider matches, ErrNotACollection if the target
// is not a collection URI, or ErrListUnsupported if the provider doesn't support listing.
func (r *registry) List(ctx context.Context, target string, opts *ListOptions) (*ListResult, error) {
	r.mu.RLock()
	providers := slices.Clone(r.providers)
	r.mu.RUnlock()

	for _, p := range providers {
		if !p.Detect(ctx, target) {
			continue
		}
		cp, ok := p.(CollectionProvider)
		if !ok {
			return nil, ErrListUnsupported
		}
		if !cp.IsCollection(ctx, target) {
			return nil, ErrNotACollection
		}
		return cp.List(ctx, target, opts)
	}
	return nil, ErrNoProvider
}
