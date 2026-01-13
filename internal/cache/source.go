// Package cache provides caching primitives for Deputy.
//
// This file defines the Source interface for cacheable data sources,
// enabling a unified cache management system across different data providers.
package cache

import (
	"context"
	"time"
)

// Source represents a cacheable data source that can be managed by the cache system.
// Implementations should handle their own data fetching, storage, and expiration.
type Source interface {
	// Name returns the unique identifier for this source (e.g., "osv", "kev", "epss").
	// This is used for CLI commands and registry lookups.
	Name() string

	// Description returns a human-readable description of what this source provides.
	Description() string

	// Status returns the current cache status including freshness and statistics.
	Status(ctx context.Context) (*SourceStatus, error)

	// Populate downloads and caches the data from the upstream source.
	// If opts.Force is true, the cache is refreshed even if not expired.
	Populate(ctx context.Context, opts PopulateOptions) error

	// Clear removes all cached data for this source.
	Clear(ctx context.Context) error
}

// SourceStatus represents the current state of a cache source.
type SourceStatus struct {
	// Name is the source identifier.
	Name string

	// Description is a human-readable description.
	Description string

	// Available indicates whether the cache exists on disk.
	Available bool

	// Fresh indicates whether the cache is within its TTL.
	Fresh bool

	// EntryCount is the number of entries in the cache (0 if not applicable).
	EntryCount int

	// Size is the total size in bytes of the cached data.
	Size int64

	// LastUpdated is when the cache was last populated.
	LastUpdated time.Time

	// ExpiresAt is when the cache will be considered stale.
	ExpiresAt time.Time

	// TTL is the time-to-live for this cache source.
	TTL time.Duration

	// Error contains the last error message if the source failed.
	Error string

	// OnDemand indicates this source is populated on-demand (e.g., EPSS per-CVE).
	OnDemand bool
}

// PopulateOptions controls how a source populates its cache.
type PopulateOptions struct {
	// Force refreshes the cache even if it's not expired.
	Force bool

	// ProgressWriter receives progress updates during downloads.
	// If nil, no progress is reported.
	ProgressWriter ProgressWriter
}

// ProgressWriter receives progress updates during cache population.
type ProgressWriter interface {
	// SetTotal sets the total number of bytes to be downloaded.
	// If unknown, pass -1.
	SetTotal(total int64)

	// Add reports that n bytes have been downloaded.
	Add(n int64)

	// Done signals that the operation is complete.
	Done()
}
