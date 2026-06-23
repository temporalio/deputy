// Package sources provides cache.Source implementations for Deputy's data sources.
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

	"github.com/temporalio/deputy/internal/cache"
	"github.com/temporalio/deputy/internal/cache/disk"
	"github.com/temporalio/deputy/internal/httputil"
	"github.com/temporalio/deputy/internal/otel"
)

const (
	// OSV source constants
	osvSourceName        = "osv"
	osvSourceDescription = "OSV vulnerability database (GitHub Actions)"
	osvCacheSubdir       = "osv-gha"
	osvZipFilename       = "all.zip"
	osvMetaFilename      = "all.zip.meta.json"
	osvTTL               = 6 * time.Hour
	osvDownloadURL       = "https://storage.googleapis.com/osv-vulnerabilities/GitHub%20Actions/all.zip"
	osvDownloadLimit     = 50 << 20 // 50MB safety cap
)

// osvZipMeta stores HTTP caching headers for conditional requests.
type osvZipMeta struct {
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	DownloadedAt time.Time `json:"downloaded_at"`
}

// OSVSource implements cache.Source for the OSV vulnerability database.
type OSVSource struct {
	httpClient *http.Client
}

// NewOSVSource creates a new OSV cache source.
// Uses SafeDialer for SSRF protection against DNS rebinding attacks.
func NewOSVSource() *OSVSource {
	return &OSVSource{
		httpClient: httputil.NewSafeRetryableClient(30 * time.Second),
	}
}

// Name returns the source identifier.
func (s *OSVSource) Name() string {
	return osvSourceName
}

// Description returns a human-readable description.
func (s *OSVSource) Description() string {
	return osvSourceDescription
}

// Status returns the current cache status.
func (s *OSVSource) Status(ctx context.Context) (*cache.SourceStatus, error) {
	status := &cache.SourceStatus{
		Name:        s.Name(),
		Description: s.Description(),
		TTL:         osvTTL,
	}

	zipPath := s.zipPath()
	if zipPath == "" {
		status.Error = "cache directory not available"
		return status, nil
	}

	fi, err := os.Stat(zipPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Cache doesn't exist yet
			return status, nil
		}
		status.Error = err.Error()
		return status, nil
	}

	status.Available = true
	status.Size = fi.Size()
	status.LastUpdated = fi.ModTime()
	status.ExpiresAt = fi.ModTime().Add(osvTTL)
	status.Fresh = time.Since(fi.ModTime()) < osvTTL

	return status, nil
}

// Populate downloads the OSV vulnerability database.
func (s *OSVSource) Populate(ctx context.Context, opts cache.PopulateOptions) error {
	ctx, span := otel.StartSpan(ctx, "deputy.cache.osv.populate")
	defer span.End()

	// Check if we need to refresh
	if !opts.Force {
		status, err := s.Status(ctx)
		if err != nil {
			otel.SetSpanError(span, err)
			return err
		}
		if status.Fresh {
			slog.DebugContext(ctx, "osv cache fresh, skipping download")
			otel.SetSpanOK(span)
			return nil // Already fresh
		}
	}

	slog.DebugContext(ctx, "downloading osv vulnerability database", "url", osvDownloadURL)
	if err := s.download(ctx, opts.ProgressWriter); err != nil {
		otel.SetSpanError(span, err)
		return err
	}
	otel.SetSpanOK(span)
	return nil
}

// Clear removes the cached OSV data.
func (s *OSVSource) Clear(ctx context.Context) error {
	dir := s.cacheDir()
	if dir == "" {
		return nil
	}
	slog.DebugContext(ctx, "clearing osv cache", "dir", dir)
	return os.RemoveAll(dir)
}

// zipPath returns the path to the cached zip file.
func (s *OSVSource) zipPath() string {
	base := disk.BaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, osvCacheSubdir, osvZipFilename)
}

// cacheDir returns the OSV cache directory.
func (s *OSVSource) cacheDir() string {
	base := disk.BaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, osvCacheSubdir)
}

// metaPath returns the path to the metadata file.
func (s *OSVSource) metaPath() string {
	base := disk.BaseDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, osvCacheSubdir, osvMetaFilename)
}

// readMeta reads the cache metadata.
func (s *OSVSource) readMeta() osvZipMeta {
	var meta osvZipMeta
	path := s.metaPath()
	if path == "" {
		return meta
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return meta
	}
	_ = json.Unmarshal(b, &meta)
	return meta
}

// writeMeta writes the cache metadata.
func (s *OSVSource) writeMeta(meta osvZipMeta) {
	path := s.metaPath()
	if path == "" {
		return
	}
	b, err := json.Marshal(meta)
	if err != nil {
		return
	}
	_ = os.WriteFile(path, b, 0o644)
}

// download fetches the OSV vulnerability database.
func (s *OSVSource) download(ctx context.Context, progress cache.ProgressWriter) error {
	zipPath := s.zipPath()
	if zipPath == "" {
		return fmt.Errorf("cache directory not available")
	}

	dir := filepath.Dir(zipPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cache directory: %w", err)
	}

	// Set timeout if not already set
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 60*time.Second)
		defer cancel()
	}

	// Prepare request with conditional headers
	meta := s.readMeta()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, osvDownloadURL, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if meta.ETag != "" {
		req.Header.Set("If-None-Match", meta.ETag)
	}
	if meta.LastModified != "" {
		req.Header.Set("If-Modified-Since", meta.LastModified)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	// Handle 304 Not Modified
	if resp.StatusCode == http.StatusNotModified {
		slog.DebugContext(ctx, "osv cache not modified (304), refreshing TTL")
		// Update mtime to refresh TTL
		now := time.Now()
		_ = os.Chtimes(zipPath, now, now)
		return nil
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	// Set up progress reporting
	if progress != nil {
		progress.SetTotal(resp.ContentLength)
	}

	// Download to temp file
	tmp := zipPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}

	var reader io.Reader = &io.LimitedReader{R: resp.Body, N: osvDownloadLimit}
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
	if err := os.Rename(tmp, zipPath); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}

	// Update metadata
	s.writeMeta(osvZipMeta{
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		DownloadedAt: time.Now(),
	})

	if progress != nil {
		progress.Done()
	}

	// Log download completion with file size
	if fi, err := os.Stat(zipPath); err == nil {
		slog.DebugContext(ctx, "osv cache download complete", "path", zipPath, "size", fi.Size())
	}

	return nil
}

// progressReader wraps a reader and reports progress.
type progressReader struct {
	r        io.Reader
	progress cache.ProgressWriter
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.r.Read(p)
	if n > 0 && pr.progress != nil {
		pr.progress.Add(int64(n))
	}
	return n, err
}
