// Package secrets provides secret detection capabilities.
package secrets

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// BaselineVersion is the current baseline file format version.
const BaselineVersion = "1.0"

// DefaultBaselinePath is the default path for the baseline file.
const DefaultBaselinePath = ".deputy-secrets-baseline.json"

// Baseline represents a collection of known/accepted secret findings.
// It enables tracking of false positives and intentional test secrets,
// allowing incremental scanning that only reports new secrets.
type Baseline struct {
	// Version of the baseline format.
	Version string `json:"version"`

	// GeneratedAt is when the baseline was last updated.
	GeneratedAt time.Time `json:"generated_at"`

	// Plugins lists which detectors were enabled when generating this baseline.
	// Used for compatibility checking.
	Plugins []string `json:"plugins,omitempty"`

	// Filters lists active filter configurations.
	Filters *BaselineFilters `json:"filters,omitempty"`

	// Results maps file paths to their known findings.
	Results map[string][]BaselineEntry `json:"results"`

	// Custom is for user-defined metadata.
	Custom map[string]any `json:"custom,omitempty"`
}

// BaselineFilters captures filter settings used when creating the baseline.
type BaselineFilters struct {
	// ExcludedPatterns are file glob patterns to skip.
	ExcludedPatterns []string `json:"excluded_patterns,omitempty"`
	// ExcludedTypes are secret types to skip.
	ExcludedTypes []string `json:"excluded_types,omitempty"`
	// MinConfidence is the minimum confidence threshold.
	MinConfidence float64 `json:"min_confidence,omitempty"`
}

// BaselineEntry represents a single known secret finding.
type BaselineEntry struct {
	// Type of secret detected.
	Type string `json:"type"`
	// Line number (1-indexed).
	Line int `json:"line"`
	// Column position (1-indexed).
	Column int `json:"column,omitempty"`
	// Hash is a content-based hash for matching (avoids storing actual secret).
	Hash string `json:"hash"`
	// Reason explains why this is in the baseline (false positive, test data, etc.).
	Reason string `json:"reason,omitempty"`
	// IsVerified indicates if the hash was verified against the file.
	IsVerified bool `json:"is_verified,omitempty"`
	// AddedAt is when this entry was added to the baseline.
	AddedAt time.Time `json:"added_at,omitempty"`
}

// NewBaseline creates a new empty baseline.
func NewBaseline() *Baseline {
	return &Baseline{
		Version:     BaselineVersion,
		GeneratedAt: time.Now().UTC(),
		Results:     make(map[string][]BaselineEntry),
	}
}

// LoadBaseline loads a baseline from a JSON file.
func LoadBaseline(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("baseline file not found: %s", path)
		}
		return nil, fmt.Errorf("reading baseline: %w", err)
	}

	var baseline Baseline
	if err := json.Unmarshal(data, &baseline); err != nil {
		return nil, fmt.Errorf("parsing baseline: %w", err)
	}

	// Validate version
	if baseline.Version == "" {
		return nil, errors.New("baseline file is missing version field")
	}

	// Initialize maps if nil
	if baseline.Results == nil {
		baseline.Results = make(map[string][]BaselineEntry)
	}

	return &baseline, nil
}

// Save writes the baseline to a JSON file.
func (b *Baseline) Save(path string) error {
	b.GeneratedAt = time.Now().UTC()

	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}

	// Write atomically using temp file
	dir := filepath.Dir(path)
	tmpFile, err := os.CreateTemp(dir, ".baseline-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // Clean up on failure

	if _, err := tmpFile.Write(data); err != nil {
		tmpFile.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}

	// Rename to final path
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("renaming baseline file: %w", err)
	}

	return nil
}

// AddFinding adds a finding to the baseline.
func (b *Baseline) AddFinding(f Finding, reason string) {
	entry := BaselineEntry{
		Type:    string(f.Type),
		Line:    f.Line,
		Column:  f.Column,
		Hash:    HashFinding(f),
		Reason:  reason,
		AddedAt: time.Now().UTC(),
	}

	b.Results[f.File] = append(b.Results[f.File], entry)
}

// AddFindings adds multiple findings to the baseline.
func (b *Baseline) AddFindings(findings []Finding, reason string) {
	for _, f := range findings {
		b.AddFinding(f, reason)
	}
}

// Contains checks if a finding is already in the baseline.
func (b *Baseline) Contains(f Finding) bool {
	entries, ok := b.Results[f.File]
	if !ok {
		return false
	}

	hash := HashFinding(f)
	for _, entry := range entries {
		// Match by hash (primary) or type+line (fallback for moved content)
		if entry.Hash == hash {
			return true
		}
		// Fuzzy match: same type and nearby line (within 5 lines)
		if entry.Type == string(f.Type) && abs(entry.Line-f.Line) <= 5 {
			return true
		}
	}

	return false
}

// Filter removes findings that are in the baseline.
// Returns only new findings not present in the baseline.
func (b *Baseline) Filter(findings []Finding) []Finding {
	var newFindings []Finding
	for _, f := range findings {
		if !b.Contains(f) {
			newFindings = append(newFindings, f)
		}
	}
	return newFindings
}

// TotalEntries returns the total number of baseline entries.
func (b *Baseline) TotalEntries() int {
	total := 0
	for _, entries := range b.Results {
		total += len(entries)
	}
	return total
}

// Files returns all files in the baseline.
func (b *Baseline) Files() []string {
	files := make([]string, 0, len(b.Results))
	for file := range b.Results {
		files = append(files, file)
	}
	sort.Strings(files)
	return files
}

// Audit verifies that baseline entries still match the actual file contents.
// Returns entries that no longer match (stale entries).
func (b *Baseline) Audit(rootDir string) ([]AuditResult, error) {
	var results []AuditResult

	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rootFS := root.FS()

	for file, entries := range b.Results {
		cleanPath, err := cleanBaselinePath(file)
		if err != nil {
			for _, entry := range entries {
				results = append(results, AuditResult{
					File:   file,
					Entry:  entry,
					Status: AuditStatusFileDeleted,
				})
			}
			continue
		}

		// Check if file exists
		content, err := fs.ReadFile(rootFS, cleanPath)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, fs.ErrInvalid) {
				// File was deleted - all entries are stale
				for _, entry := range entries {
					results = append(results, AuditResult{
						File:   file,
						Entry:  entry,
						Status: AuditStatusFileDeleted,
					})
				}
				continue
			}
			return nil, fmt.Errorf("reading %s: %w", file, err)
		}

		// Check each entry
		lines := strings.Split(string(content), "\n")
		for _, entry := range entries {
			status := b.auditEntry(entry, lines)
			if status != AuditStatusValid {
				results = append(results, AuditResult{
					File:   file,
					Entry:  entry,
					Status: status,
				})
			}
		}
	}

	return results, nil
}

func cleanBaselinePath(name string) (string, error) {
	trimmed := strings.TrimSpace(name)
	if trimmed == "" {
		return "", fs.ErrInvalid
	}
	if filepath.IsAbs(trimmed) {
		return "", fs.ErrInvalid
	}
	if len(trimmed) >= 2 && trimmed[1] == ':' {
		return "", fs.ErrInvalid
	}
	if strings.HasPrefix(trimmed, "\\\\") || strings.HasPrefix(trimmed, "//") {
		return "", fs.ErrInvalid
	}
	cleanPath := path.Clean(filepath.ToSlash(trimmed))
	cleanPath = strings.TrimPrefix(cleanPath, "./")
	if cleanPath == "" || cleanPath == "." {
		return "", fs.ErrInvalid
	}
	if strings.HasPrefix(cleanPath, "../") || cleanPath == ".." || strings.HasPrefix(cleanPath, "/") {
		return "", fs.ErrInvalid
	}
	return cleanPath, nil
}

// auditEntry checks if a single entry is still valid.
func (b *Baseline) auditEntry(entry BaselineEntry, lines []string) AuditStatus {
	// Line number out of range
	if entry.Line < 1 || entry.Line > len(lines) {
		return AuditStatusLineMoved
	}

	// Check if the line content still matches
	line := lines[entry.Line-1]
	lineHash := hashLine(line)

	// Hash mismatch - content changed
	if !strings.HasPrefix(entry.Hash, lineHash[:8]) {
		return AuditStatusContentChanged
	}

	return AuditStatusValid
}

// AuditStatus represents the result of auditing a baseline entry.
type AuditStatus string

const (
	AuditStatusValid          AuditStatus = "valid"
	AuditStatusFileDeleted    AuditStatus = "file_deleted"
	AuditStatusLineMoved      AuditStatus = "line_moved"
	AuditStatusContentChanged AuditStatus = "content_changed"
)

// AuditResult represents the result of auditing a single entry.
type AuditResult struct {
	File   string
	Entry  BaselineEntry
	Status AuditStatus
}

// Clean removes stale entries from the baseline.
// Returns the number of entries removed.
func (b *Baseline) Clean(rootDir string) (int, error) {
	auditResults, err := b.Audit(rootDir)
	if err != nil {
		return 0, err
	}

	// Build set of entries to remove
	toRemove := make(map[string]map[string]bool) // file -> hash -> true
	for _, result := range auditResults {
		if result.Status != AuditStatusValid {
			if toRemove[result.File] == nil {
				toRemove[result.File] = make(map[string]bool)
			}
			toRemove[result.File][result.Entry.Hash] = true
		}
	}

	// Remove stale entries
	removed := 0
	for file, entries := range b.Results {
		if toRemove[file] == nil {
			continue
		}

		var keepEntries []BaselineEntry
		for _, entry := range entries {
			if !toRemove[file][entry.Hash] {
				keepEntries = append(keepEntries, entry)
			} else {
				removed++
			}
		}

		if len(keepEntries) == 0 {
			delete(b.Results, file)
		} else {
			b.Results[file] = keepEntries
		}
	}

	return removed, nil
}

// Merge combines another baseline into this one.
// Entries from other take precedence on conflicts.
func (b *Baseline) Merge(other *Baseline) {
	for file, entries := range other.Results {
		existing := b.Results[file]

		// Build hash set of existing entries
		hashSet := make(map[string]bool)
		for _, e := range existing {
			hashSet[e.Hash] = true
		}

		// Add new entries
		for _, entry := range entries {
			if !hashSet[entry.Hash] {
				existing = append(existing, entry)
			}
		}

		b.Results[file] = existing
	}
}

// HashFinding creates a content-based hash for a finding.
// This allows matching findings even if line numbers change slightly.
func HashFinding(f Finding) string {
	// Hash components: type, normalized value, surrounding context
	components := []string{
		string(f.Type),
		normalizeValue(f.Value),
	}

	h := sha256.Sum256([]byte(strings.Join(components, "|")))
	return hex.EncodeToString(h[:])
}

// normalizeValue prepares a value for hashing by removing whitespace variations.
func normalizeValue(s string) string {
	// Trim whitespace and normalize
	return strings.TrimSpace(s)
}

// hashLine creates a hash of a line's content.
func hashLine(line string) string {
	h := sha256.Sum256([]byte(strings.TrimSpace(line)))
	return hex.EncodeToString(h[:])
}

// abs returns the absolute value of an integer.
func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// BaselineScanner wraps a Scanner to filter findings against a baseline.
type BaselineScanner struct {
	scanner  Scanner
	baseline *Baseline
}

// NewBaselineScanner creates a scanner that filters findings against a baseline.
func NewBaselineScanner(scanner Scanner, baseline *Baseline) *BaselineScanner {
	return &BaselineScanner{
		scanner:  scanner,
		baseline: baseline,
	}
}

// Scan runs the underlying scanner and filters results against the baseline.
func (bs *BaselineScanner) Scan(ctx context.Context, content []byte) ([]Finding, error) {
	findings, err := bs.scanner.Scan(ctx, content)
	if err != nil {
		return nil, err
	}
	return bs.baseline.Filter(findings), nil
}

// ScanFile runs the underlying scanner and filters results against the baseline.
func (bs *BaselineScanner) ScanFile(ctx context.Context, filename string, content []byte) ([]Finding, error) {
	findings, err := bs.scanner.ScanFile(ctx, filename, content)
	if err != nil {
		return nil, err
	}
	return bs.baseline.Filter(findings), nil
}

// Ensure BaselineScanner implements Scanner.
var _ Scanner = (*BaselineScanner)(nil)

// Allowlist manages a list of patterns/values to ignore.
// This is simpler than a full baseline and works well for known test values.
type Allowlist struct {
	// Patterns are regex patterns to match against secret values.
	Patterns []string `json:"patterns,omitempty"`
	// Hashes are SHA256 hashes of exact values to ignore.
	Hashes []string `json:"hashes,omitempty"`
	// Paths are glob patterns for files to completely skip.
	Paths []string `json:"paths,omitempty"`
	// Types are secret types to completely ignore.
	Types []string `json:"types,omitempty"`
	// Reasons maps entries to their justification.
	Reasons map[string]string `json:"reasons,omitempty"`
}

// NewAllowlist creates a new empty allowlist.
func NewAllowlist() *Allowlist {
	return &Allowlist{
		Reasons: make(map[string]string),
	}
}

// AddPattern adds a regex pattern to ignore.
func (a *Allowlist) AddPattern(pattern, reason string) {
	a.Patterns = append(a.Patterns, pattern)
	if reason != "" && a.Reasons != nil {
		a.Reasons["pattern:"+pattern] = reason
	}
}

// AddHash adds a hash of a value to ignore.
func (a *Allowlist) AddHash(value, reason string) {
	h := sha256.Sum256([]byte(value))
	hash := hex.EncodeToString(h[:])
	a.Hashes = append(a.Hashes, hash)
	if reason != "" && a.Reasons != nil {
		a.Reasons["hash:"+hash[:16]] = reason
	}
}

// AddPath adds a glob pattern for files to skip.
func (a *Allowlist) AddPath(pattern, reason string) {
	a.Paths = append(a.Paths, pattern)
	if reason != "" && a.Reasons != nil {
		a.Reasons["path:"+pattern] = reason
	}
}

// AddType adds a secret type to completely ignore.
func (a *Allowlist) AddType(secretType, reason string) {
	a.Types = append(a.Types, secretType)
	if reason != "" && a.Reasons != nil {
		a.Reasons["type:"+secretType] = reason
	}
}

// ShouldIgnoreFile checks if a file path should be skipped.
func (a *Allowlist) ShouldIgnoreFile(path string) bool {
	for _, pattern := range a.Paths {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
	}
	return false
}

// ShouldIgnoreFinding checks if a finding should be ignored.
func (a *Allowlist) ShouldIgnoreFinding(f Finding) bool {
	// Check type
	for _, t := range a.Types {
		if string(f.Type) == t {
			return true
		}
	}

	// Check hash
	if f.Value != "" {
		h := sha256.Sum256([]byte(f.Value))
		hash := hex.EncodeToString(h[:])
		for _, allowedHash := range a.Hashes {
			if hash == allowedHash {
				return true
			}
		}
	}

	// Check patterns (simple substring match for now)
	for _, pattern := range a.Patterns {
		if strings.Contains(f.Value, pattern) {
			return true
		}
	}

	return false
}

// Filter removes findings that match the allowlist.
func (a *Allowlist) Filter(findings []Finding) []Finding {
	var filtered []Finding
	for _, f := range findings {
		if !a.ShouldIgnoreFinding(f) {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

// LoadAllowlist loads an allowlist from a JSON file.
func LoadAllowlist(path string) (*Allowlist, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var allowlist Allowlist
	if err := json.Unmarshal(data, &allowlist); err != nil {
		return nil, fmt.Errorf("parsing allowlist: %w", err)
	}

	if allowlist.Reasons == nil {
		allowlist.Reasons = make(map[string]string)
	}

	return &allowlist, nil
}

// Save writes the allowlist to a JSON file.
func (a *Allowlist) Save(path string) error {
	data, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// GenerateBaseline scans a directory and creates a baseline from all findings.
// This is useful for onboarding existing projects with known secrets.
func GenerateBaseline(ctx context.Context, scanner Scanner, dir string, reason string) (*Baseline, error) {
	baseline := NewBaseline()

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	rootFS := root.FS()

	err = fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip common non-code directories
			base := d.Name()
			if base == ".git" || base == "node_modules" || base == "vendor" || base == ".venv" {
				return fs.SkipDir
			}
			return nil
		}

		// Skip binary files
		if isBinaryFileCheck(rootFS, path) {
			return nil
		}

		content, err := fs.ReadFile(rootFS, path)
		if err != nil {
			return nil // Skip unreadable files
		}

		// Get relative path
		relPath := filepath.FromSlash(path)

		findings, err := scanner.ScanFile(ctx, relPath, content)
		if err != nil {
			return nil // Skip files that fail to scan
		}

		baseline.AddFindings(findings, reason)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking directory: %w", err)
	}

	return baseline, nil
}

// isBinaryFileCheck checks if a file appears to be binary.
func isBinaryFileCheck(fsys fs.FS, path string) bool {
	// Check by extension first
	ext := strings.ToLower(filepath.Ext(path))
	binaryExts := map[string]bool{
		".exe": true, ".dll": true, ".so": true, ".dylib": true,
		".bin": true, ".dat": true, ".db": true, ".sqlite": true,
		".png": true, ".jpg": true, ".jpeg": true, ".gif": true,
		".ico": true, ".pdf": true, ".zip": true, ".tar": true,
		".gz": true, ".bz2": true, ".7z": true, ".rar": true,
		".mp3": true, ".mp4": true, ".wav": true, ".avi": true,
		".ttf": true, ".otf": true, ".woff": true, ".woff2": true,
		".pyc": true, ".pyo": true, ".class": true, ".o": true,
	}
	if binaryExts[ext] {
		return true
	}

	// Sample first 512 bytes for null characters
	f, err := fsys.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	buf := make([]byte, 512)
	n, err := f.Read(buf)
	if err != nil || n == 0 {
		return false
	}

	// Check for null bytes (common in binary files)
	for _, b := range buf[:n] {
		if b == 0 {
			return true
		}
	}

	return false
}

// BaselineComment represents a special comment in source code that marks
// a line as an allowed secret (inline allowlisting).
// Format: deputy:allowlist:reason
type BaselineComment struct {
	// Pattern to match the comment
	Pattern string
	// Reason extracted from the comment
	Reason string
}

// ParseInlineAllowlist checks if a line contains an inline allowlist comment.
// Returns true if the line (or previous line) allows the secret.
func ParseInlineAllowlist(lines []string, lineNum int) (bool, string) {
	if lineNum < 1 || lineNum > len(lines) {
		return false, ""
	}

	// Check current line for trailing comment
	line := lines[lineNum-1]
	if idx := strings.Index(line, "deputy:allowlist"); idx != -1 {
		reason := extractReason(line[idx:])
		return true, reason
	}

	// Check previous line for comment-only line
	if lineNum > 1 {
		prevLine := strings.TrimSpace(lines[lineNum-2])
		if strings.HasPrefix(prevLine, "//") || strings.HasPrefix(prevLine, "#") {
			if idx := strings.Index(prevLine, "deputy:allowlist"); idx != -1 {
				reason := extractReason(prevLine[idx:])
				return true, reason
			}
		}
	}

	return false, ""
}

// extractReason extracts the reason from an allowlist comment.
func extractReason(comment string) string {
	// Format: deputy:allowlist:reason or deputy:allowlist reason
	comment = strings.TrimPrefix(comment, "deputy:allowlist")
	comment = strings.TrimPrefix(comment, ":")
	comment = strings.TrimSpace(comment)

	// Remove trailing comment markers
	if idx := strings.Index(comment, "*/"); idx != -1 {
		comment = comment[:idx]
	}
	if idx := strings.Index(comment, "-->"); idx != -1 {
		comment = comment[:idx]
	}

	return strings.TrimSpace(comment)
}

// InlineAllowlistScanner wraps a scanner to respect inline allowlist comments.
type InlineAllowlistScanner struct {
	scanner Scanner
}

// NewInlineAllowlistScanner creates a scanner that respects inline comments.
func NewInlineAllowlistScanner(scanner Scanner) *InlineAllowlistScanner {
	return &InlineAllowlistScanner{scanner: scanner}
}

// Scan runs the underlying scanner and filters based on inline comments.
func (s *InlineAllowlistScanner) Scan(ctx context.Context, content []byte) ([]Finding, error) {
	findings, err := s.scanner.Scan(ctx, content)
	if err != nil {
		return nil, err
	}

	// Parse content into lines for comment checking
	scanner := bufio.NewScanner(strings.NewReader(string(content)))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	// Filter findings with inline allowlist
	var filtered []Finding
	for _, f := range findings {
		if allowed, _ := ParseInlineAllowlist(lines, f.Line); !allowed {
			filtered = append(filtered, f)
		}
	}

	return filtered, nil
}

// ScanFile runs the underlying scanner and filters based on inline comments.
func (s *InlineAllowlistScanner) ScanFile(ctx context.Context, filename string, content []byte) ([]Finding, error) {
	findings, err := s.Scan(ctx, content)
	if err != nil {
		return nil, err
	}
	for i := range findings {
		findings[i].File = filename
	}
	return findings, nil
}

// Ensure InlineAllowlistScanner implements Scanner.
var _ Scanner = (*InlineAllowlistScanner)(nil)
