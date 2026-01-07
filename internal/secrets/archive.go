// Package secrets provides secret detection and scanning capabilities.
package secrets

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/ulikunitz/xz"
)

// ArchiveFormat represents supported archive formats.
type ArchiveFormat string

const (
	FormatUnknown ArchiveFormat = ""
	FormatZip     ArchiveFormat = "zip"
	FormatTar     ArchiveFormat = "tar"
	FormatTarGz   ArchiveFormat = "tar.gz"
	FormatTarBz2  ArchiveFormat = "tar.bz2"
	FormatTarXz   ArchiveFormat = "tar.xz"
)

// ArchiveFinding extends Finding with archive context.
type ArchiveFinding struct {
	Finding

	// ArchivePath is the path to the archive file.
	ArchivePath string `json:"archivePath"`
	// EntryPath is the path within the archive.
	EntryPath string `json:"entryPath"`
	// Format is the archive format.
	Format ArchiveFormat `json:"format"`
	// Nested indicates if this was found in a nested archive.
	Nested bool `json:"nested,omitempty"`
	// NestingDepth is how many levels of archives deep this finding is.
	NestingDepth int `json:"nestingDepth,omitempty"`
}

// ArchiveScanConfig configures archive scanning behavior.
type ArchiveScanConfig struct {
	// MaxFileSize limits individual file scanning within archives.
	MaxFileSize int64
	// MaxTotalSize limits total bytes read from an archive.
	MaxTotalSize int64
	// MaxFiles limits the number of files scanned in an archive.
	MaxFiles int
	// MaxNestingDepth limits recursive archive scanning depth.
	MaxNestingDepth int
	// MaxCompressionRatio limits the decompression ratio to protect against zip bombs.
	// A ratio of 100 means the uncompressed size can be at most 100x the compressed size.
	// Set to 0 to disable this check (not recommended).
	MaxCompressionRatio float64
	// PathPatterns limits scanning to matching paths (nil = all text files).
	PathPatterns []string
	// ScanBinaryStrings enables string extraction from binary files.
	ScanBinaryStrings bool
	// BinaryMinStringLen is the minimum length for extracted binary strings.
	BinaryMinStringLen int
}

// DefaultArchiveScanConfig returns safe defaults for archive scanning.
func DefaultArchiveScanConfig() ArchiveScanConfig {
	return ArchiveScanConfig{
		MaxFileSize:         10 * 1024 * 1024,  // 10MB per file
		MaxTotalSize:        100 * 1024 * 1024, // 100MB total
		MaxFiles:            10000,             // Max files to scan
		MaxNestingDepth:     3,                 // Max archive nesting
		MaxCompressionRatio: 100,               // Max 100:1 compression ratio (zip bomb protection)
		ScanBinaryStrings:   false,             // Disabled by default for safety
		BinaryMinStringLen:  8,                 // Minimum string length from binaries
		PathPatterns: []string{
			"*.env", "*.yaml", "*.yml", "*.json", "*.conf", "*.config",
			"*.properties", "*.ini", "*.toml", "*.xml", "*.sh", "*.bash",
			"*.txt", "*.md", "*.cfg", "*.cnf", "*.key", "*.pem", "*.crt",
			".env*", ".npmrc", ".pypirc", ".docker/config.json",
			"*credentials*", "*secret*", "*password*", "*token*", "*apikey*",
		},
	}
}

// Validate checks the configuration for errors.
func (c ArchiveScanConfig) Validate() error {
	var errs []error

	if c.MaxFileSize <= 0 {
		errs = append(errs, fmt.Errorf("max file size must be positive, got %d", c.MaxFileSize))
	}
	if c.MaxFileSize > 1<<30 { // 1GB
		errs = append(errs, fmt.Errorf("max file size too large (>1GB): %d", c.MaxFileSize))
	}

	if c.MaxTotalSize <= 0 {
		errs = append(errs, fmt.Errorf("max total size must be positive, got %d", c.MaxTotalSize))
	}
	if c.MaxTotalSize > 10<<30 { // 10GB
		errs = append(errs, fmt.Errorf("max total size too large (>10GB): %d", c.MaxTotalSize))
	}

	if c.MaxFiles <= 0 {
		errs = append(errs, fmt.Errorf("max files must be positive, got %d", c.MaxFiles))
	}
	if c.MaxFiles > 1_000_000 {
		errs = append(errs, fmt.Errorf("max files too large (>1M): %d", c.MaxFiles))
	}

	if c.MaxNestingDepth < 0 {
		errs = append(errs, fmt.Errorf("max nesting depth must be non-negative, got %d", c.MaxNestingDepth))
	}
	if c.MaxNestingDepth > 10 {
		errs = append(errs, fmt.Errorf("max nesting depth too large (>10): %d", c.MaxNestingDepth))
	}

	if c.MaxCompressionRatio < 0 {
		errs = append(errs, fmt.Errorf("max compression ratio must be non-negative, got %f", c.MaxCompressionRatio))
	}

	if c.BinaryMinStringLen < 4 {
		errs = append(errs, fmt.Errorf("binary min string length must be at least 4, got %d", c.BinaryMinStringLen))
	}
	if c.BinaryMinStringLen > 1000 {
		errs = append(errs, fmt.Errorf("binary min string length too large (>1000): %d", c.BinaryMinStringLen))
	}

	return errors.Join(errs...)
}

// ArchiveScanResult contains results from scanning an archive.
type ArchiveScanResult struct {
	// ArchivePath is the path to the scanned archive.
	ArchivePath string `json:"archivePath"`
	// Format is the detected archive format.
	Format ArchiveFormat `json:"format"`
	// EntriesScanned is the number of entries analyzed.
	EntriesScanned int `json:"entriesScanned"`
	// BytesScanned is the total bytes scanned.
	BytesScanned int64 `json:"bytesScanned"`
	// Findings contains all discovered secrets.
	Findings []ArchiveFinding `json:"findings"`
	// Errors contains any non-fatal errors encountered.
	Errors []string `json:"errors,omitempty"`
	// Truncated indicates if scanning was stopped early due to limits.
	Truncated bool `json:"truncated,omitempty"`
	// TruncationReason explains why scanning was truncated.
	TruncationReason string `json:"truncationReason,omitempty"`
}

// ArchiveScanner scans archives for secrets.
type ArchiveScanner struct {
	engine *Engine
	config ArchiveScanConfig
}

// NewArchiveScanner creates a new archive scanner.
func NewArchiveScanner(config ArchiveScanConfig) (*ArchiveScanner, error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid archive scan config: %w", err)
	}

	engine, err := NewEngine()
	if err != nil {
		return nil, fmt.Errorf("creating secrets engine: %w", err)
	}
	return &ArchiveScanner{
		engine: engine,
		config: config,
	}, nil
}

// ScanArchive scans an archive file for secrets.
// The archive is extracted to a temporary directory with os.Root isolation
// for safe traversal, preventing path traversal attacks.
func (s *ArchiveScanner) ScanArchive(ctx context.Context, archivePath string) (*ArchiveScanResult, error) {
	// Detect archive format
	format, err := DetectArchiveFormat(archivePath)
	if err != nil {
		return nil, fmt.Errorf("detecting archive format: %w", err)
	}
	if format == FormatUnknown {
		return nil, fmt.Errorf("unsupported or unrecognized archive format: %s", archivePath)
	}

	result := &ArchiveScanResult{
		ArchivePath: archivePath,
		Format:      format,
	}

	// Open the archive file
	f, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("opening archive: %w", err)
	}
	defer f.Close()

	// Scan based on format
	switch format {
	case FormatZip:
		err = s.scanZip(ctx, archivePath, result, 0)
	case FormatTar, FormatTarGz, FormatTarBz2, FormatTarXz:
		err = s.scanTar(ctx, f, format, archivePath, result, 0)
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}

	if err != nil {
		return result, err
	}

	return result, nil
}

// ScanArchiveReader scans an archive from a reader.
// This is useful for scanning archives from non-file sources (network, memory).
func (s *ArchiveScanner) ScanArchiveReader(ctx context.Context, r io.Reader, format ArchiveFormat, name string) (*ArchiveScanResult, error) {
	result := &ArchiveScanResult{
		ArchivePath: name,
		Format:      format,
	}

	switch format {
	case FormatZip:
		// Zip requires random access, so we need to buffer it
		data, err := io.ReadAll(io.LimitReader(r, s.config.MaxTotalSize))
		if err != nil {
			return nil, fmt.Errorf("reading zip data: %w", err)
		}
		err = s.scanZipReader(ctx, bytes.NewReader(data), int64(len(data)), name, result, 0)
		if err != nil {
			return result, err
		}
	case FormatTar, FormatTarGz, FormatTarBz2, FormatTarXz:
		err := s.scanTar(ctx, r, format, name, result, 0)
		if err != nil {
			return result, err
		}
	default:
		return nil, fmt.Errorf("unsupported archive format: %s", format)
	}

	return result, nil
}

// scanZip scans a zip archive file.
func (s *ArchiveScanner) scanZip(ctx context.Context, path string, result *ArchiveScanResult, depth int) error {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return fmt.Errorf("opening zip: %w", err)
	}
	defer zr.Close()

	return s.scanZipFiles(ctx, zr.File, path, result, depth)
}

// scanZipReader scans a zip archive from a reader.
func (s *ArchiveScanner) scanZipReader(ctx context.Context, r io.ReaderAt, size int64, name string, result *ArchiveScanResult, depth int) error {
	zr, err := zip.NewReader(r, size)
	if err != nil {
		return fmt.Errorf("reading zip: %w", err)
	}

	return s.scanZipFiles(ctx, zr.File, name, result, depth)
}

// scanZipFiles scans files within a zip archive.
func (s *ArchiveScanner) scanZipFiles(ctx context.Context, files []*zip.File, archiveName string, result *ArchiveScanResult, depth int) error {
	for _, f := range files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Check limits
		if result.EntriesScanned >= s.config.MaxFiles {
			result.Truncated = true
			result.TruncationReason = "max files limit reached"
			return nil
		}
		if result.BytesScanned >= s.config.MaxTotalSize {
			result.Truncated = true
			result.TruncationReason = "max total size limit reached"
			return nil
		}

		// Skip directories
		if f.FileInfo().IsDir() {
			continue
		}

		// Security: comprehensive path validation to prevent zip slip and related attacks
		if isUnsafePath(f.Name) {
			result.Errors = append(result.Errors, fmt.Sprintf("skipping unsafe path: %s", f.Name))
			continue
		}

		// Security: check for zip bomb (high compression ratio)
		if s.isZipBomb(f.CompressedSize64, f.UncompressedSize64) {
			result.Errors = append(result.Errors, fmt.Sprintf("skipping potential zip bomb: %s (ratio: %.1f:1)", f.Name, float64(f.UncompressedSize64)/float64(max(f.CompressedSize64, 1))))
			continue
		}

		// Check file size
		if f.UncompressedSize64 > uint64(s.config.MaxFileSize) {
			continue
		}

		// Open the file
		rc, err := f.Open()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("opening %s: %v", f.Name, err))
			continue
		}

		// Read content with size limit
		content, err := io.ReadAll(io.LimitReader(rc, s.config.MaxFileSize))
		rc.Close()
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("reading %s: %v", f.Name, err))
			continue
		}

		result.EntriesScanned++
		result.BytesScanned += int64(len(content))

		// Check for nested archives
		if depth < s.config.MaxNestingDepth {
			nestedFormat := detectFormatFromContent(content, f.Name)
			if nestedFormat != FormatUnknown {
				nestedResult := &ArchiveScanResult{
					ArchivePath: f.Name,
					Format:      nestedFormat,
				}
				if nestedFormat == FormatZip {
					_ = s.scanZipReader(ctx, bytes.NewReader(content), int64(len(content)), f.Name, nestedResult, depth+1)
				} else {
					_ = s.scanTar(ctx, bytes.NewReader(content), nestedFormat, f.Name, nestedResult, depth+1)
				}
				// Mark nested findings
				for _, nf := range nestedResult.Findings {
					nf.Nested = true
					nf.NestingDepth = depth + 1
					result.Findings = append(result.Findings, nf)
				}
				continue
			}
		}

		// Scan the file content
		findings, err := s.scanContent(ctx, content, f.Name, archiveName, depth)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("scanning %s: %v", f.Name, err))
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	return nil
}

// countingReader wraps a reader and counts bytes read for decompression bomb detection.
type countingReader struct {
	r       io.Reader
	count   int64
	limit   int64
	limited bool
}

func newCountingReader(r io.Reader, limit int64) *countingReader {
	return &countingReader{r: r, limit: limit}
}

func (cr *countingReader) Read(p []byte) (int, error) {
	if cr.limit > 0 && cr.count >= cr.limit {
		cr.limited = true
		return 0, io.EOF
	}
	n, err := cr.r.Read(p)
	cr.count += int64(n)
	if cr.limit > 0 && cr.count > cr.limit {
		cr.limited = true
		return n, io.EOF
	}
	return n, err
}

// scanTar scans a tar archive (optionally compressed).
func (s *ArchiveScanner) scanTar(ctx context.Context, r io.Reader, format ArchiveFormat, archiveName string, result *ArchiveScanResult, depth int) error {
	var tarReader *tar.Reader

	// Wrap with counting reader to detect decompression bombs
	// This limits the total decompressed bytes regardless of what headers claim
	countingR := newCountingReader(r, s.config.MaxTotalSize*2) // Allow 2x for overhead

	switch format {
	case FormatTarGz:
		gr, err := gzip.NewReader(countingR)
		if err != nil {
			return fmt.Errorf("opening gzip: %w", err)
		}
		defer gr.Close()
		// Wrap gzip reader with another counter for decompressed output
		decompressedCounter := newCountingReader(gr, s.config.MaxTotalSize)
		tarReader = tar.NewReader(decompressedCounter)
	case FormatTarBz2:
		decompressedCounter := newCountingReader(bzip2.NewReader(countingR), s.config.MaxTotalSize)
		tarReader = tar.NewReader(decompressedCounter)
	case FormatTarXz:
		xr, err := xz.NewReader(countingR)
		if err != nil {
			return fmt.Errorf("opening xz: %w", err)
		}
		decompressedCounter := newCountingReader(xr, s.config.MaxTotalSize)
		tarReader = tar.NewReader(decompressedCounter)
	default:
		// Plain tar (uncompressed)
		tarReader = tar.NewReader(countingR)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("reading tar header: %v", err))
			break
		}

		// Check limits
		if result.EntriesScanned >= s.config.MaxFiles {
			result.Truncated = true
			result.TruncationReason = "max files limit reached"
			return nil
		}
		if result.BytesScanned >= s.config.MaxTotalSize {
			result.Truncated = true
			result.TruncationReason = "max total size limit reached"
			return nil
		}

		// Skip non-regular files (also blocks symlinks which could be used for attacks)
		if header.Typeflag != tar.TypeReg {
			// Log if it's a symlink as these can be used for attacks
			if header.Typeflag == tar.TypeSymlink || header.Typeflag == tar.TypeLink {
				slog.Debug("skipping symlink/hardlink in tar", "name", header.Name, "linkname", header.Linkname)
			}
			continue
		}

		// Security: comprehensive path validation to prevent tar slip and related attacks
		if isUnsafePath(header.Name) {
			result.Errors = append(result.Errors, fmt.Sprintf("skipping unsafe path: %s", header.Name))
			continue
		}

		// Check file size
		if header.Size > s.config.MaxFileSize {
			continue
		}

		// Security: protect against negative sizes (malformed tar headers)
		if header.Size < 0 {
			result.Errors = append(result.Errors, fmt.Sprintf("skipping entry with invalid size: %s", header.Name))
			continue
		}

		// Read content with size limit
		content := make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, content); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("reading %s: %v", header.Name, err))
			continue
		}

		result.EntriesScanned++
		result.BytesScanned += int64(len(content))

		// Check for nested archives
		if depth < s.config.MaxNestingDepth {
			nestedFormat := detectFormatFromContent(content, header.Name)
			if nestedFormat != FormatUnknown {
				nestedResult := &ArchiveScanResult{
					ArchivePath: header.Name,
					Format:      nestedFormat,
				}
				if nestedFormat == FormatZip {
					_ = s.scanZipReader(ctx, bytes.NewReader(content), int64(len(content)), header.Name, nestedResult, depth+1)
				} else {
					_ = s.scanTar(ctx, bytes.NewReader(content), nestedFormat, header.Name, nestedResult, depth+1)
				}
				// Mark nested findings
				for _, nf := range nestedResult.Findings {
					nf.Nested = true
					nf.NestingDepth = depth + 1
					result.Findings = append(result.Findings, nf)
				}
				continue
			}
		}

		// Scan the file content
		findings, err := s.scanContent(ctx, content, header.Name, archiveName, depth)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("scanning %s: %v", header.Name, err))
			continue
		}
		result.Findings = append(result.Findings, findings...)
	}

	return nil
}

// scanContent scans file content for secrets.
func (s *ArchiveScanner) scanContent(ctx context.Context, content []byte, entryPath, archivePath string, depth int) ([]ArchiveFinding, error) {
	// Check path patterns if configured
	if len(s.config.PathPatterns) > 0 && !s.matchesPathPatterns(entryPath) {
		// Check if it's a binary file we should scan
		if !s.config.ScanBinaryStrings || !isBinaryContent(content) {
			return nil, nil
		}
	}

	var findings []ArchiveFinding

	// Handle binary files specially
	if isBinaryContent(content) {
		if s.config.ScanBinaryStrings {
			// Extract strings from binary and scan them
			strings := extractStringsFromBinary(content, s.config.BinaryMinStringLen)
			for _, str := range strings {
				strFindings, err := s.engine.Scan(ctx, []byte(str))
				if err != nil {
					continue
				}
				for _, f := range strFindings {
					f.File = entryPath + " (binary string)"
					findings = append(findings, ArchiveFinding{
						Finding:      f,
						ArchivePath:  archivePath,
						EntryPath:    entryPath,
						Nested:       depth > 0,
						NestingDepth: depth,
					})
				}
			}
		}
		return findings, nil
	}

	// Scan text content
	fileFindings, err := s.engine.ScanFile(ctx, entryPath, content)
	if err != nil {
		return nil, err
	}

	for _, f := range fileFindings {
		findings = append(findings, ArchiveFinding{
			Finding:      f,
			ArchivePath:  archivePath,
			EntryPath:    entryPath,
			Nested:       depth > 0,
			NestingDepth: depth,
		})
	}

	return findings, nil
}

// matchesPathPatterns checks if a path matches any configured pattern.
func (s *ArchiveScanner) matchesPathPatterns(path string) bool {
	base := filepath.Base(path)
	for _, pattern := range s.config.PathPatterns {
		if matched, _ := filepath.Match(pattern, base); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		// Check substring match for non-glob patterns
		if !strings.ContainsAny(pattern, "*?[]") {
			if strings.Contains(strings.ToLower(path), strings.ToLower(pattern)) {
				return true
			}
		}
	}
	return false
}

// isUnsafePath checks if a path is potentially malicious (path traversal, absolute, etc.).
// Returns true if the path should be rejected.
func isUnsafePath(path string) bool {
	// Clean the path first
	cleanPath := filepath.Clean(path)

	// Check for path traversal attempts
	if strings.HasPrefix(cleanPath, "..") || strings.Contains(cleanPath, "/../") {
		return true
	}

	// Check for absolute paths (Unix and Windows)
	if filepath.IsAbs(cleanPath) {
		return true
	}

	// Check for Windows-style absolute paths (C:\, D:\, etc.)
	if len(path) >= 2 && path[1] == ':' {
		return true
	}

	// Check for Windows UNC paths (\\server\share)
	if strings.HasPrefix(path, "\\\\") || strings.HasPrefix(path, "//") {
		return true
	}

	// Check for null bytes (path injection)
	if strings.Contains(path, "\x00") {
		return true
	}

	// Check for suspicious path components
	parts := strings.FieldsFunc(cleanPath, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	for _, part := range parts {
		// ".." anywhere in path components
		if part == ".." {
			return true
		}
		// Device names on Windows (CON, PRN, AUX, NUL, COM1-9, LPT1-9)
		upperPart := strings.ToUpper(part)
		if len(upperPart) >= 3 {
			base := strings.TrimSuffix(upperPart, filepath.Ext(upperPart))
			switch base {
			case "CON", "PRN", "AUX", "NUL":
				return true
			}
			if len(base) == 4 && (strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT")) {
				if base[3] >= '1' && base[3] <= '9' {
					return true
				}
			}
		}
	}

	return false
}

// isZipBomb checks if a zip file entry appears to be a zip bomb based on compression ratio.
// Returns true if the entry should be skipped as a potential zip bomb.
func (s *ArchiveScanner) isZipBomb(compressedSize, uncompressedSize uint64) bool {
	if s.config.MaxCompressionRatio <= 0 {
		return false // Check disabled
	}
	if compressedSize == 0 {
		// Avoid division by zero; empty files are fine
		return uncompressedSize > uint64(s.config.MaxFileSize)
	}
	ratio := float64(uncompressedSize) / float64(compressedSize)
	return ratio > s.config.MaxCompressionRatio
}

// DetectArchiveFormat detects the format of an archive file.
func DetectArchiveFormat(path string) (ArchiveFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return FormatUnknown, err
	}
	defer f.Close()

	// Read magic bytes
	magic := make([]byte, 512)
	n, err := f.Read(magic)
	if err != nil && !errors.Is(err, io.EOF) {
		return FormatUnknown, err
	}
	magic = magic[:n]

	return detectFormatFromContent(magic, path), nil
}

// detectFormatFromContent detects archive format from content and filename.
func detectFormatFromContent(content []byte, name string) ArchiveFormat {
	// Check magic bytes first
	if len(content) >= 4 {
		// ZIP magic: PK\x03\x04
		if content[0] == 'P' && content[1] == 'K' && content[2] == 0x03 && content[3] == 0x04 {
			return FormatZip
		}
		// GZIP magic: \x1f\x8b
		if content[0] == 0x1f && content[1] == 0x8b {
			return FormatTarGz
		}
		// XZ magic: \xfd7zXZ\x00
		if len(content) >= 6 && content[0] == 0xfd && content[1] == '7' && content[2] == 'z' &&
			content[3] == 'X' && content[4] == 'Z' && content[5] == 0x00 {
			return FormatTarXz
		}
		// BZIP2 magic: BZ
		if content[0] == 'B' && content[1] == 'Z' {
			return FormatTarBz2
		}
	}

	// Check for tar by looking for valid tar header
	if len(content) >= 262 {
		// Check tar magic at offset 257
		tarMagic := string(content[257:262])
		if tarMagic == "ustar" {
			return FormatTar
		}
	}

	// Fall back to extension-based detection
	name = strings.ToLower(name)
	switch {
	case strings.HasSuffix(name, ".zip"), strings.HasSuffix(name, ".jar"),
		strings.HasSuffix(name, ".war"), strings.HasSuffix(name, ".ear"):
		return FormatZip
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return FormatTarGz
	case strings.HasSuffix(name, ".tar.bz2"), strings.HasSuffix(name, ".tbz2"):
		return FormatTarBz2
	case strings.HasSuffix(name, ".tar.xz"), strings.HasSuffix(name, ".txz"):
		return FormatTarXz
	case strings.HasSuffix(name, ".tar"):
		return FormatTar
	}

	return FormatUnknown
}

// extractStringsFromBinary extracts printable strings from binary content.
// This is useful for finding secrets embedded in compiled binaries.
func extractStringsFromBinary(content []byte, minLen int) []string {
	if minLen < 4 {
		minLen = 4
	}

	var strings []string
	var current []byte

	for _, b := range content {
		// Check if byte is printable ASCII (0x20-0x7E) or common whitespace
		if (b >= 0x20 && b <= 0x7E) || b == '\t' || b == '\n' || b == '\r' {
			current = append(current, b)
		} else {
			if len(current) >= minLen {
				strings = append(strings, string(current))
			}
			current = current[:0]
		}
	}

	// Don't forget the last string
	if len(current) >= minLen {
		strings = append(strings, string(current))
	}

	return strings
}

// BinarySection represents a section of a binary file.
type BinarySection struct {
	Name   string
	Offset uint64
	Size   uint64
	Data   []byte
}

// ExtractBinarySections extracts relevant sections from binary files.
// This safely extracts read-only data sections that may contain secrets.
func ExtractBinarySections(content []byte) ([]BinarySection, error) {
	var sections []BinarySection

	// Try ELF format
	if elfSections, err := extractELFSections(content); err == nil && len(elfSections) > 0 {
		return elfSections, nil
	}

	// Try Mach-O format
	if machoSections, err := extractMachOSections(content); err == nil && len(machoSections) > 0 {
		return machoSections, nil
	}

	// Try PE format
	if peSections, err := extractPESections(content); err == nil && len(peSections) > 0 {
		return peSections, nil
	}

	return sections, nil
}

// extractELFSections extracts sections from ELF binaries.
func extractELFSections(content []byte) ([]BinarySection, error) {
	r := bytes.NewReader(content)
	ef, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	var sections []BinarySection

	// Extract read-only data sections
	interestingSections := []string{
		".rodata",  // Read-only data
		".data",    // Initialized data
		".rdata",   // Read-only data (alternative name)
		".comment", // Comments (may contain build info)
	}

	for _, sectionName := range interestingSections {
		section := ef.Section(sectionName)
		if section == nil {
			continue
		}

		// Limit section size
		if section.Size > 10*1024*1024 {
			continue
		}

		data, err := section.Data()
		if err != nil {
			continue
		}

		sections = append(sections, BinarySection{
			Name:   sectionName,
			Offset: section.Offset,
			Size:   section.Size,
			Data:   data,
		})
	}

	return sections, nil
}

// extractMachOSections extracts sections from Mach-O binaries.
func extractMachOSections(content []byte) ([]BinarySection, error) {
	r := bytes.NewReader(content)
	mf, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}

	var sections []BinarySection

	// Look for __DATA and __TEXT segments
	for _, section := range mf.Sections {
		// Interested in read-only data sections
		if section.Seg != "__DATA" && section.Seg != "__TEXT" {
			continue
		}

		// Limit section size
		if section.Size > 10*1024*1024 {
			continue
		}

		data, err := section.Data()
		if err != nil {
			continue
		}

		sections = append(sections, BinarySection{
			Name:   fmt.Sprintf("%s.%s", section.Seg, section.Name),
			Offset: uint64(section.Offset),
			Size:   section.Size,
			Data:   data,
		})
	}

	return sections, nil
}

// extractPESections extracts sections from PE binaries.
func extractPESections(content []byte) ([]BinarySection, error) {
	r := bytes.NewReader(content)
	pf, err := pe.NewFile(r)
	if err != nil {
		return nil, err
	}

	var sections []BinarySection

	// Look for read-only data sections
	interestingSections := []string{".rdata", ".data", ".rsrc"}

	for _, section := range pf.Sections {
		// Check if section name matches
		sectionName := strings.TrimRight(section.Name, "\x00")
		found := false
		for _, interesting := range interestingSections {
			if sectionName == interesting {
				found = true
				break
			}
		}
		if !found {
			continue
		}

		// Limit section size
		if uint64(section.Size) > 10*1024*1024 {
			continue
		}

		data, err := section.Data()
		if err != nil {
			continue
		}

		sections = append(sections, BinarySection{
			Name:   sectionName,
			Offset: uint64(section.Offset),
			Size:   uint64(section.Size),
			Data:   data,
		})
	}

	return sections, nil
}

// ScanBinary scans a binary file for secrets in its readable sections.
func (s *ArchiveScanner) ScanBinary(ctx context.Context, path string) ([]Finding, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading binary: %w", err)
	}

	return s.ScanBinaryContent(ctx, content, path)
}

// ScanBinaryContent scans binary content for secrets.
func (s *ArchiveScanner) ScanBinaryContent(ctx context.Context, content []byte, name string) ([]Finding, error) {
	var findings []Finding

	// First, try to extract structured sections
	sections, err := ExtractBinarySections(content)
	if err == nil && len(sections) > 0 {
		slog.Debug("extracted binary sections", "name", name, "sections", len(sections))
		for _, section := range sections {
			// Extract strings from each section
			strings := extractStringsFromBinary(section.Data, s.config.BinaryMinStringLen)
			for _, str := range strings {
				strFindings, err := s.engine.Scan(ctx, []byte(str))
				if err != nil {
					continue
				}
				for _, f := range strFindings {
					f.File = fmt.Sprintf("%s (%s)", name, section.Name)
					findings = append(findings, f)
				}
			}
		}
	} else {
		// Fall back to raw string extraction
		strings := extractStringsFromBinary(content, s.config.BinaryMinStringLen)
		for _, str := range strings {
			strFindings, err := s.engine.Scan(ctx, []byte(str))
			if err != nil {
				continue
			}
			for _, f := range strFindings {
				f.File = name + " (binary)"
				findings = append(findings, f)
			}
		}
	}

	return findings, nil
}

// SafeExtractArchive extracts an archive to a temporary directory with os.Root isolation.
// This provides safe file system access within the extracted directory.
// The returned Root must be closed when done.
func SafeExtractArchive(ctx context.Context, archivePath string, maxSize int64) (*os.Root, string, error) {
	// Create temporary directory
	tempDir, err := os.MkdirTemp("", "deputy-archive-*")
	if err != nil {
		return nil, "", fmt.Errorf("creating temp dir: %w", err)
	}

	// Detect format
	format, err := DetectArchiveFormat(archivePath)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("detecting format: %w", err)
	}

	// Extract archive
	var totalSize int64
	switch format {
	case FormatZip:
		totalSize, err = extractZipSafe(ctx, archivePath, tempDir, maxSize)
	case FormatTar, FormatTarGz, FormatTarBz2, FormatTarXz:
		f, ferr := os.Open(archivePath)
		if ferr != nil {
			os.RemoveAll(tempDir)
			return nil, "", fmt.Errorf("opening archive: %w", ferr)
		}
		defer f.Close()
		totalSize, err = extractTarSafe(ctx, f, format, tempDir, maxSize)
	default:
		os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("unsupported format: %s", format)
	}

	if err != nil {
		os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("extracting archive: %w", err)
	}

	slog.Debug("extracted archive", "path", archivePath, "tempDir", tempDir, "totalSize", totalSize)

	// Open with os.Root for safe access
	root, err := os.OpenRoot(tempDir)
	if err != nil {
		os.RemoveAll(tempDir)
		return nil, "", fmt.Errorf("opening root: %w", err)
	}

	return root, tempDir, nil
}

// extractZipSafe safely extracts a zip archive.
func extractZipSafe(ctx context.Context, zipPath, destDir string, maxSize int64) (int64, error) {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return 0, err
	}
	defer zr.Close()

	var totalSize int64

	for _, f := range zr.File {
		select {
		case <-ctx.Done():
			return totalSize, ctx.Err()
		default:
		}

		// Security: validate path
		cleanPath := filepath.Clean(f.Name)
		if strings.HasPrefix(cleanPath, "..") || filepath.IsAbs(cleanPath) {
			continue // Skip unsafe paths
		}

		destPath := filepath.Join(destDir, cleanPath)

		// Ensure the destination is within the target directory
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue // Skip path traversal attempts
		}

		if f.FileInfo().IsDir() {
			os.MkdirAll(destPath, 0o755)
			continue
		}

		// Check size limit
		if totalSize+int64(f.UncompressedSize64) > maxSize {
			return totalSize, fmt.Errorf("archive exceeds size limit")
		}

		// Create parent directory
		if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
			continue
		}

		// Extract file
		rc, err := f.Open()
		if err != nil {
			continue
		}

		out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, f.Mode().Perm()&0o755)
		if err != nil {
			rc.Close()
			continue
		}

		written, err := io.Copy(out, io.LimitReader(rc, maxSize-totalSize))
		out.Close()
		rc.Close()

		if err != nil {
			continue
		}
		totalSize += written
	}

	return totalSize, nil
}

// extractTarSafe safely extracts a tar archive.
func extractTarSafe(ctx context.Context, r io.Reader, format ArchiveFormat, destDir string, maxSize int64) (int64, error) {
	var tarReader *tar.Reader

	switch format {
	case FormatTarGz:
		gr, err := gzip.NewReader(r)
		if err != nil {
			return 0, err
		}
		defer gr.Close()
		tarReader = tar.NewReader(gr)
	case FormatTarBz2:
		tarReader = tar.NewReader(bzip2.NewReader(r))
	case FormatTarXz:
		xr, err := xz.NewReader(r)
		if err != nil {
			return 0, err
		}
		tarReader = tar.NewReader(xr)
	default:
		tarReader = tar.NewReader(r)
	}

	var totalSize int64

	for {
		select {
		case <-ctx.Done():
			return totalSize, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			break
		}

		// Security: validate path
		cleanPath := filepath.Clean(header.Name)
		if strings.HasPrefix(cleanPath, "..") || filepath.IsAbs(cleanPath) {
			continue
		}

		destPath := filepath.Join(destDir, cleanPath)

		// Ensure the destination is within the target directory
		if !strings.HasPrefix(destPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(destPath, 0o755)
		case tar.TypeReg:
			// Check size limit
			if totalSize+header.Size > maxSize {
				return totalSize, fmt.Errorf("archive exceeds size limit")
			}

			// Create parent directory
			if err := os.MkdirAll(filepath.Dir(destPath), 0o755); err != nil {
				continue
			}

			// Extract file with safe permissions
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode).Perm()&0o755)
			if err != nil {
				continue
			}

			written, err := io.Copy(out, io.LimitReader(tarReader, maxSize-totalSize))
			out.Close()

			if err != nil {
				continue
			}
			totalSize += written
		}
	}

	return totalSize, nil
}

// ScanWithRoot scans files using an os.Root for safe filesystem access.
func (s *ArchiveScanner) ScanWithRoot(ctx context.Context, root *os.Root) ([]Finding, error) {
	var findings []Finding

	// Get the filesystem view from the root
	rootFS := root.FS()

	err := fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip inaccessible entries
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		// Check path patterns
		if len(s.config.PathPatterns) > 0 && !s.matchesPathPatterns(path) {
			return nil
		}

		// Get file info
		info, err := d.Info()
		if err != nil {
			return nil
		}

		// Skip large files
		if info.Size() > s.config.MaxFileSize {
			return nil
		}

		// Read file using the root's FS
		file, err := rootFS.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		content, err := io.ReadAll(io.LimitReader(file, s.config.MaxFileSize))
		if err != nil {
			return nil
		}

		// Handle binary files
		if isBinaryContent(content) {
			if s.config.ScanBinaryStrings {
				binaryFindings, err := s.ScanBinaryContent(ctx, content, path)
				if err == nil {
					findings = append(findings, binaryFindings...)
				}
			}
			return nil
		}

		// Scan text content
		fileFindings, err := s.engine.ScanFile(ctx, path, content)
		if err != nil {
			return nil
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, err
}

// Ensure binary package imports are used
var (
	_ = binary.LittleEndian
)
