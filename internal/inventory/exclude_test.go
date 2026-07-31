package inventory

import (
	"path/filepath"
	"testing"

	"github.com/temporalio/deputy/internal/repository/workspace"
)

func TestCompileExcludePaths(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		match    []string // dir paths expected to be skipped
		noMatch  []string // dir paths expected to be kept
	}{
		{
			name:     "nil patterns compile to no matcher",
			patterns: nil,
		},
		{
			name:     "blank patterns are ignored",
			patterns: []string{"", "  "},
		},
		{
			name:     "subtree spelling normalizes to directory, matches any depth",
			patterns: []string{".bin/**"},
			match:    []string{".bin", "internal/.bin"},
			noMatch:  []string{"bin", ".binary"},
		},
		{
			name:     "trailing slash normalizes to directory",
			patterns: []string{".bin/"},
			match:    []string{".bin"},
		},
		{
			name:     "bare directory matches itself and at any depth",
			patterns: []string{".bin"},
			match:    []string{".bin", "a/b/.bin"},
			noMatch:  []string{".binary"},
		},
		{
			name:     "slashed path is anchored to the scan root",
			patterns: []string{".github/workflows"},
			match:    []string{".github/workflows"},
			noMatch:  []string{".github", ".github/actions", "x/.github/workflows"},
		},
		{
			name:     "bare name matches top-level and nested",
			patterns: []string{"testdata"},
			match:    []string{"testdata", "a/b/testdata"},
			noMatch:  []string{"testdata2"},
		},
		{
			name:     "explicit **/ prefix matches root and nested",
			patterns: []string{"**/testdata"},
			match:    []string{"testdata", "a/testdata", "a/b/testdata"},
			noMatch:  []string{"testdata2"},
		},
		{
			name:     "multiple patterns union",
			patterns: []string{".bin/**", "vendor"},
			match:    []string{".bin", "vendor"},
			noMatch:  []string{"internal"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			g, err := CompileExcludePaths(tc.patterns)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(tc.match) == 0 && len(tc.noMatch) == 0 {
				if g != nil {
					t.Fatalf("expected nil matcher for patterns %v", tc.patterns)
				}
				return
			}
			if g == nil {
				t.Fatalf("expected matcher for patterns %v, got nil", tc.patterns)
			}
			for _, p := range tc.match {
				if !g.Match(p) {
					t.Errorf("expected %q to be excluded by %v", p, tc.patterns)
				}
			}
			for _, p := range tc.noMatch {
				if g.Match(p) {
					t.Errorf("expected %q NOT to be excluded by %v", p, tc.patterns)
				}
			}
		})
	}
}

func TestCompileExcludePaths_InvalidPattern(t *testing.T) {
	// An unterminated character class is a malformed glob.
	if _, err := CompileExcludePaths([]string{"[bad"}); err == nil {
		t.Fatal("expected error for malformed glob pattern, got nil")
	}
}

func TestCompileScanSkipDirGlob_MatchesRootRelativePaths(t *testing.T) {
	dir := t.TempDir()
	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()

	g, err := compileScanSkipDirGlob(ws, ScanOptions{ExcludePaths: []string{".bin/**"}}, nil)
	if err != nil {
		t.Fatalf("compileScanSkipDirGlob: %v", err)
	}
	if g == nil {
		t.Fatal("expected matcher")
	}
	if !g.Match(filepath.Join(dir, ".bin")) {
		t.Fatalf("expected absolute .bin path to match")
	}
	if !g.Match(".bin") {
		t.Fatalf("expected relative .bin path to match")
	}
	if g.Match(filepath.Join(dir, ".binary")) {
		t.Fatalf("expected .binary path not to match")
	}
}

func TestIsDependencyInstallPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		// Matches: an unambiguous install-tree segment anywhere in the path.
		{".venv/lib/python3.12/site-packages/pkg/Cargo.toml", true}, // via site-packages, not .venv
		{".tox/py312/lib/python3.12/site-packages/req/METADATA", true},
		{"node_modules/left-pad/package.json", true},
		{"a/b/node_modules/c/package.json", true},
		{"pdmproj/__pypackages__/3.12/lib/pkg/PKG-INFO", true},
		{`api\node_modules\pkg\package.json`, true}, // backslash separators normalize
		// Non-matches: the fuzzy venv root and build/cache dirs are NOT excluded
		// on their own (only their unambiguous install children are).
		{".venv/bin/activate", false},
		{"venv/lib/foo", false},
		{"src/__pycache__/mod.pyc", false},
		{"build/out.js", false},
		{"vendor/foo/bar.go", false},
		{"Cargo.toml", false},
		{"go.mod", false},
		{"my-site-packages.txt", false}, // substring, not a path segment
		{"node_modules_backup/x", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := IsDependencyInstallPath(tt.path); got != tt.want {
				t.Errorf("IsDependencyInstallPath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
