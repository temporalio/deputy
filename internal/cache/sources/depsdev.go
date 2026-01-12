package sources

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/picatz/deputy/internal/cache"
	"github.com/picatz/deputy/internal/cache/disk"
)

const (
	// deps.dev source constants
	depsdevSourceName        = "depsdev"
	depsdevSourceDescription = "deps.dev license data (on-demand)"
	depsdevCacheSubdir       = "depsdev"
	depsdevTTL               = 7 * 24 * time.Hour
)

// DepsDevSource implements cache.Source for deps.dev license data.
// deps.dev is populated on-demand as packages are queried, not bulk-downloaded.
type DepsDevSource struct{}

// NewDepsDevSource creates a new deps.dev cache source.
func NewDepsDevSource() *DepsDevSource {
	return &DepsDevSource{}
}

// Name returns the source identifier.
func (s *DepsDevSource) Name() string {
	return depsdevSourceName
}

// Description returns a human-readable description.
func (s *DepsDevSource) Description() string {
	return depsdevSourceDescription
}

// Status returns the current cache status.
func (s *DepsDevSource) Status(ctx context.Context) (*cache.SourceStatus, error) {
	status := &cache.SourceStatus{
		Name:        s.Name(),
		Description: s.Description(),
		TTL:         depsdevTTL,
		OnDemand:    true, // deps.dev is populated on-demand per-package
	}

	cacheDir := s.cacheDir()
	if cacheDir == "" {
		status.Error = "cache directory not available"
		return status, nil
	}

	// Count cached license entries and calculate total size
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			// No cache yet
			return status, nil
		}
		status.Error = err.Error()
		return status, nil
	}

	var totalSize int64
	var latestMod time.Time
	count := 0

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		totalSize += info.Size()
		count++
		if info.ModTime().After(latestMod) {
			latestMod = info.ModTime()
		}
	}

	if count > 0 {
		status.Available = true
		status.EntryCount = count
		status.Size = totalSize
		status.LastUpdated = latestMod
		// For on-demand caches, show oldest possible expiration
		status.ExpiresAt = latestMod.Add(depsdevTTL)
		status.Fresh = true // On-demand caches are always "fresh" conceptually
	}

	return status, nil
}

// Populate is a no-op for deps.dev since it's populated on-demand.
func (s *DepsDevSource) Populate(ctx context.Context, opts cache.PopulateOptions) error {
	// deps.dev is populated on-demand per-package, not bulk-downloaded.
	// This is intentionally a no-op.
	return nil
}

// Clear removes the cached deps.dev data.
func (s *DepsDevSource) Clear(ctx context.Context) error {
	dir := s.cacheDir()
	if dir == "" {
		return nil
	}
	slog.DebugContext(ctx, "clearing depsdev cache", "dir", dir)
	return os.RemoveAll(dir)
}

// cacheDir returns the deps.dev cache directory.
func (s *DepsDevSource) cacheDir() string {
	base := disk.BaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, depsdevCacheSubdir)
}
