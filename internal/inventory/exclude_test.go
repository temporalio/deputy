package inventory

import "testing"

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
