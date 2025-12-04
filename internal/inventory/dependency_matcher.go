package inventory

import (
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"

	fsx "github.com/google/osv-scalibr/extractor/filesystem"
)

// DependencyMatcher wraps the scalibr filesystem extractors used for inventory
// scans and reuses their FileRequired logic to decide whether a path qualifies
// as a dependency manifest or lockfile. It keeps Deputy’s heuristics aligned
// with osv-scalibr instead of relying on bespoke filename lists.
type DependencyMatcher struct {
	extractors []fsx.Extractor
}

// NewDependencyMatcher instantiates the filesystem extractors for the provided
// scan options and captures them for later path checks. The matcher mirrors the
// plugin selection performed during inventory scans, ensuring callers ask the
// same question scalibr would when deciding whether to inspect a file.
func NewDependencyMatcher(opts ScanOptions) (*DependencyMatcher, error) {
	cap := defaultCapabilities(nil)
	cap.DirectFS = true
	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		return nil, err
	}
	plugins = filterInventoryPlugins(plugins)
	extractors := make([]fsx.Extractor, 0, len(plugins))
	for _, p := range plugins {
		if e, ok := p.(fsx.Extractor); ok {
			extractors = append(extractors, e)
		}
	}
	return &DependencyMatcher{extractors: extractors}, nil
}

// Matches reports whether any configured extractor would consider the provided
// path relevant (i.e., its FileRequired method returns true for that file).
func (m *DependencyMatcher) Matches(path string) bool {
	if m == nil || len(m.extractors) == 0 {
		return false
	}
	clean := filepath.ToSlash(strings.TrimSpace(path))
	if clean == "" {
		return false
	}
	clean = strings.TrimPrefix(clean, "./")
	fake := fakeFileAPI{path: clean}
	for _, ex := range m.extractors {
		if ex.FileRequired(fake) {
			return true
		}
	}
	return false
}

// AnyMatch reports whether at least one of the provided paths would be
// consumed by the configured extractors, returning true on the first match.
func (m *DependencyMatcher) AnyMatch(paths []string) bool {
	if m == nil || len(m.extractors) == 0 {
		return false
	}
	return slices.ContainsFunc(paths, m.Matches)
}

// fakeFileAPI implements the scalibr FileAPI interface for path checking.
type fakeFileAPI struct {
	path string
}

// Path returns the file path.
func (f fakeFileAPI) Path() string { return f.path }

// Stat returns a fake file info.
func (f fakeFileAPI) Stat() (fs.FileInfo, error) { return fakeFileInfo{}, nil }

// fakeFileInfo implements fs.FileInfo for testing.
type fakeFileInfo struct{}

func (fakeFileInfo) Name() string       { return "" }
func (fakeFileInfo) Size() int64        { return 0 }
func (fakeFileInfo) Mode() fs.FileMode  { return 0 }
func (fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (fakeFileInfo) IsDir() bool        { return false }
func (fakeFileInfo) Sys() any           { return nil }
