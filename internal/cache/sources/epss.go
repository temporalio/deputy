package sources

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/temporalio/deputy/internal/cache"
	"github.com/temporalio/deputy/internal/cache/disk"
)

const (
	// EPSS source constants
	epssSourceName        = "epss"
	epssSourceDescription = "FIRST EPSS scores (on-demand)"
	epssCacheSubdir       = "epss"
	epssTTL               = 24 * time.Hour
)

// EPSSSource implements cache.Source for EPSS scores.
// EPSS is populated on-demand as CVEs are queried, not bulk-downloaded.
type EPSSSource struct{}

// NewEPSSSource creates a new EPSS cache source.
func NewEPSSSource() *EPSSSource {
	return &EPSSSource{}
}

// Name returns the source identifier.
func (s *EPSSSource) Name() string {
	return epssSourceName
}

// Description returns a human-readable description.
func (s *EPSSSource) Description() string {
	return epssSourceDescription
}

// Status returns the current cache status.
func (s *EPSSSource) Status(ctx context.Context) (*cache.SourceStatus, error) {
	status := &cache.SourceStatus{
		Name:        s.Name(),
		Description: s.Description(),
		TTL:         epssTTL,
		OnDemand:    true, // EPSS is populated on-demand per-CVE
	}

	cacheDir := s.cacheDir()
	if cacheDir == "" {
		status.Error = "cache directory not available"
		return status, nil
	}

	// Count cached EPSS entries and calculate total size
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
		// For on-demand caches, "expires" doesn't quite apply the same way
		// Show the oldest possible expiration
		status.ExpiresAt = latestMod.Add(epssTTL)
		status.Fresh = true // On-demand caches are always "fresh" conceptually
	}

	return status, nil
}

// Populate is a no-op for EPSS since it's populated on-demand.
func (s *EPSSSource) Populate(ctx context.Context, opts cache.PopulateOptions) error {
	// EPSS is populated on-demand per-CVE, not bulk-downloaded.
	// This is intentionally a no-op.
	return nil
}

// Clear removes the cached EPSS data.
func (s *EPSSSource) Clear(ctx context.Context) error {
	dir := s.cacheDir()
	if dir == "" {
		return nil
	}
	slog.DebugContext(ctx, "clearing epss cache", "dir", dir)
	return os.RemoveAll(dir)
}

// cacheDir returns the EPSS cache directory.
func (s *EPSSSource) cacheDir() string {
	base := disk.BaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, epssCacheSubdir)
}
