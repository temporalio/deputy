package cache

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"sync"
)

// Registry manages a collection of cache sources and provides bulk operations.
type Registry struct {
	mu      sync.RWMutex
	sources map[string]Source
	order   []string // Maintains registration order for consistent iteration
}

// NewRegistry creates a new empty registry.
func NewRegistry() *Registry {
	return &Registry{
		sources: make(map[string]Source),
	}
}

// Register adds a source to the registry.
// If a source with the same name already exists, it is replaced.
func (r *Registry) Register(s Source) {
	r.mu.Lock()
	defer r.mu.Unlock()

	name := s.Name()
	if _, exists := r.sources[name]; !exists {
		r.order = append(r.order, name)
	}
	r.sources[name] = s
}

// Get returns a source by name, or nil if not found.
func (r *Registry) Get(name string) Source {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sources[name]
}

// All returns all registered sources in registration order.
func (r *Registry) All() []Source {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Source, 0, len(r.order))
	for _, name := range r.order {
		if s, ok := r.sources[name]; ok {
			result = append(result, s)
		}
	}
	return result
}

// Names returns the names of all registered sources in registration order.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return slices.Clone(r.order)
}

// Status returns the status of all registered sources.
func (r *Registry) Status(ctx context.Context) ([]SourceStatus, error) {
	sources := r.All()
	statuses := make([]SourceStatus, 0, len(sources))

	for _, s := range sources {
		status, err := s.Status(ctx)
		if err != nil {
			statuses = append(statuses, SourceStatus{
				Name:        s.Name(),
				Description: s.Description(),
				Error:       err.Error(),
			})
			continue
		}
		statuses = append(statuses, *status)
	}

	return statuses, nil
}

// PopulateAll populates all registered sources.
// It returns an error if any source fails, but continues to process remaining sources.
func (r *Registry) PopulateAll(ctx context.Context, opts PopulateOptions) error {
	sources := r.All()
	var errs []error

	for _, s := range sources {
		if err := s.Populate(ctx, opts); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to populate %d source(s): %v", len(errs), errs)
	}
	return nil
}

// Populate populates specific sources by name.
// Unknown source names are returned as errors.
func (r *Registry) Populate(ctx context.Context, names []string, opts PopulateOptions) error {
	var errs []error

	for _, name := range names {
		s := r.Get(name)
		if s == nil {
			errs = append(errs, fmt.Errorf("unknown source: %s", name))
			continue
		}
		if err := s.Populate(ctx, opts); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to populate %d source(s): %v", len(errs), errs)
	}
	return nil
}

// ClearAll clears all registered sources.
// It returns an error if any source fails, but continues to process remaining sources.
func (r *Registry) ClearAll(ctx context.Context) error {
	sources := r.All()
	var errs []error

	for _, s := range sources {
		if err := s.Clear(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", s.Name(), err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to clear %d source(s): %v", len(errs), errs)
	}
	return nil
}

// Clear clears specific sources by name.
// Unknown source names are returned as errors.
func (r *Registry) Clear(ctx context.Context, names []string) error {
	var errs []error

	for _, name := range names {
		s := r.Get(name)
		if s == nil {
			errs = append(errs, fmt.Errorf("unknown source: %s", name))
			continue
		}
		if err := s.Clear(ctx); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("failed to clear %d source(s): %v", len(errs), errs)
	}
	return nil
}

// TotalSize returns the total size of all cached data across all sources.
func (r *Registry) TotalSize(ctx context.Context) (int64, error) {
	statuses, err := r.Status(ctx)
	if err != nil {
		return 0, err
	}

	var total int64
	for _, s := range statuses {
		total += s.Size
	}
	return total, nil
}

// SortedByName returns a copy of statuses sorted alphabetically by name.
func SortedByName(statuses []SourceStatus) []SourceStatus {
	result := slices.Clone(statuses)
	sort.Slice(result, func(i, j int) bool {
		return result[i].Name < result[j].Name
	})
	return result
}
