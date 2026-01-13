package sources

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/picatz/deputy/internal/cache"
	"github.com/picatz/deputy/internal/cache/disk"
	"github.com/picatz/deputy/internal/network"
	"github.com/picatz/deputy/internal/otel"
)

const (
	// KEV source constants
	kevSourceName        = "kev"
	kevSourceDescription = "CISA Known Exploited Vulnerabilities catalog"
	kevCacheSubdir       = "kev"
	kevCacheFilename     = "catalog.json"
	kevTTL               = time.Hour
	kevCatalogURL        = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

// kevCatalog is the JSON structure of the CISA KEV feed.
type kevCatalog struct {
	Title           string     `json:"title"`
	CatalogVersion  string     `json:"catalogVersion"`
	DateReleased    string     `json:"dateReleased"`
	Count           int        `json:"count"`
	Vulnerabilities []kevEntry `json:"vulnerabilities"`
}

// kevEntry represents a single vulnerability in the CISA KEV catalog.
type kevEntry struct {
	CVEID                      string `json:"cveID"`
	VendorProject              string `json:"vendorProject"`
	Product                    string `json:"product"`
	VulnerabilityName          string `json:"vulnerabilityName"`
	DateAdded                  string `json:"dateAdded"`
	ShortDescription           string `json:"shortDescription"`
	RequiredAction             string `json:"requiredAction"`
	DueDate                    string `json:"dueDate"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	Notes                      string `json:"notes"`
}

// KEVSource implements cache.Source for the CISA KEV catalog.
type KEVSource struct {
	httpClient *http.Client
}

// NewKEVSource creates a new KEV cache source.
// Uses SafeDialer for SSRF protection against DNS rebinding attacks.
func NewKEVSource() *KEVSource {
	return &KEVSource{
		httpClient: network.SafeClient(),
	}
}

// Name returns the source identifier.
func (s *KEVSource) Name() string {
	return kevSourceName
}

// Description returns a human-readable description.
func (s *KEVSource) Description() string {
	return kevSourceDescription
}

// Status returns the current cache status.
func (s *KEVSource) Status(ctx context.Context) (*cache.SourceStatus, error) {
	status := &cache.SourceStatus{
		Name:        s.Name(),
		Description: s.Description(),
		TTL:         kevTTL,
	}

	cachePath := s.cachePath()
	if cachePath == "" {
		status.Error = "cache directory not available"
		return status, nil
	}

	fi, err := os.Stat(cachePath)
	if err != nil {
		if os.IsNotExist(err) {
			return status, nil
		}
		status.Error = err.Error()
		return status, nil
	}

	status.Available = true
	status.Size = fi.Size()
	status.LastUpdated = fi.ModTime()
	status.ExpiresAt = fi.ModTime().Add(kevTTL)
	status.Fresh = time.Since(fi.ModTime()) < kevTTL

	// Try to get entry count from cached data
	if status.Available {
		if count, err := s.countEntries(); err == nil {
			status.EntryCount = count
		}
	}

	return status, nil
}

// Populate downloads the KEV catalog.
func (s *KEVSource) Populate(ctx context.Context, opts cache.PopulateOptions) error {
	ctx, span := otel.StartSpan(ctx, "deputy.cache.kev.populate")
	defer span.End()

	// Check if we need to refresh
	if !opts.Force {
		status, err := s.Status(ctx)
		if err != nil {
			otel.SetSpanError(span, err)
			return err
		}
		if status.Fresh {
			slog.DebugContext(ctx, "kev cache fresh, skipping download")
			otel.SetSpanOK(span)
			return nil
		}
	}

	slog.DebugContext(ctx, "downloading kev catalog", "url", kevCatalogURL)
	if err := s.download(ctx, opts.ProgressWriter); err != nil {
		otel.SetSpanError(span, err)
		return err
	}
	otel.SetSpanOK(span)
	return nil
}

// Clear removes the cached KEV data.
func (s *KEVSource) Clear(ctx context.Context) error {
	dir := s.cacheDir()
	if dir == "" {
		return nil
	}
	slog.DebugContext(ctx, "clearing kev cache", "dir", dir)
	return os.RemoveAll(dir)
}

// cachePath returns the path to the cached catalog file.
func (s *KEVSource) cachePath() string {
	base := disk.BaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, kevCacheSubdir, kevCacheFilename)
}

// cacheDir returns the KEV cache directory.
func (s *KEVSource) cacheDir() string {
	base := disk.BaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, kevCacheSubdir)
}

// countEntries reads the cached catalog and returns the entry count.
func (s *KEVSource) countEntries() (int, error) {
	path := s.cachePath()
	if path == "" {
		return 0, fmt.Errorf("no cache path")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}

	var cat kevCatalog
	if err := json.Unmarshal(data, &cat); err != nil {
		return 0, err
	}

	return len(cat.Vulnerabilities), nil
}

// download fetches the KEV catalog.
func (s *KEVSource) download(ctx context.Context, progress cache.ProgressWriter) error {
	cachePath := s.cachePath()
	if cachePath == "" {
		return fmt.Errorf("cache directory not available")
	}

	dir := filepath.Dir(cachePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, kevCatalogURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	// Set up progress reporting
	if progress != nil {
		progress.SetTotal(resp.ContentLength)
	}

	// Download to temp file
	tmp := cachePath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	var reader io.Reader = resp.Body
	if progress != nil {
		reader = &progressReader{r: reader, progress: progress}
	}

	if _, err := io.Copy(f, reader); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("download: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close temp file: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmp, cachePath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}

	if progress != nil {
		progress.Done()
	}

	// Log download completion with entry count
	if count, err := s.countEntries(); err == nil {
		slog.DebugContext(ctx, "kev cache download complete", "path", cachePath, "entries", count)
	}

	return nil
}
