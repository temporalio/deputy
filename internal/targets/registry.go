package targets

import (
	"context"
	"errors"
	"slices"
	"sync"
)

var (
	defaultRegistry = newRegistry()
	ErrNoProvider   = errors.New("targets: no provider matched target")
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
}

func (r *registry) Open(ctx context.Context, target string, opts map[string]string) (Materialized, error) {
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

// RegisterProvider adds a provider to the default registry.
func RegisterProvider(p Provider) {
	defaultRegistry.Register(p)
}

// Open resolves the provided target using the default registry.
func Open(ctx context.Context, target string, opts map[string]string) (Materialized, error) {
	return defaultRegistry.Open(ctx, target, opts)
}
