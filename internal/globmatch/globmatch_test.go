package globmatch

import "testing"

func TestMatcher_MatchPath(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		path     string
		want     bool
	}{
		// Bare-name glob matches at any depth (the basename use case).
		{"ext glob top-level", []string{"*.key"}, "secret.key", true},
		{"ext glob nested", []string{"*.key"}, "a/b/c.key", true},
		{"ext glob no match on different ext", []string{"*.key"}, "a/b/c.pem", false},

		// Bare directory name excludes the whole subtree at any depth.
		{"bare dir name itself", []string{"node_modules"}, "node_modules", true},
		{"bare dir name nested file", []string{"node_modules"}, "node_modules/pkg/index.js", true},
		{"bare dir name deep", []string{"node_modules"}, "a/b/node_modules/pkg/x.js", true},
		{"bare dir name whole-segment only", []string{"test"}, "src/contest/x.go", false},

		// "dir/**" — the headline bug: must match nested files, not just one level.
		{"doublestar one level", []string{"vendor/**"}, "vendor/x.go", true},
		{"doublestar deep", []string{"vendor/**"}, "vendor/a/b/c.go", true},
		{"doublestar equals bare dir", []string{"vendor/**"}, "vendor", true},
		{"doublestar trailing-slash spelling", []string{"vendor/"}, "vendor/a/b.go", true},
		{"doublestar bare spelling", []string{"vendor"}, "vendor/a/b.go", true},

		// Slashed pattern is anchored to the root (gitignore semantics).
		{"anchored one level", []string{"config/*.yaml"}, "config/db.yaml", true},
		{"anchored not nested deeper", []string{"config/*.yaml"}, "config/sub/db.yaml", false},
		{"anchored not at other depth", []string{"config/*.yaml"}, "a/config/db.yaml", false},

		// Explicit leading **/ matches any depth including root.
		{"leading doublestar nested", []string{"**/testdata"}, "a/b/testdata/x", true},
		{"leading doublestar root", []string{"**/testdata"}, "testdata/x", true},

		// No false positive across sibling names.
		{"no substring misfire", []string{"vendor"}, "vendored/x.go", false},

		// Empty / blank patterns.
		{"empty patterns", nil, "anything", false},
		{"blank pattern ignored", []string{"   "}, "anything", false},

		// Multiple patterns (any match wins).
		{"multiple any-match", []string{"*.md", "vendor/**"}, "vendor/x.go", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Compile(tc.patterns)
			if err != nil {
				t.Fatalf("Compile(%v): %v", tc.patterns, err)
			}
			if got := m.MatchPath(tc.path); got != tc.want {
				t.Errorf("MatchPath(%q) with %v = %v, want %v", tc.path, tc.patterns, got, tc.want)
			}
		})
	}
}

func TestCompile_InvalidPattern(t *testing.T) {
	if _, err := Compile([]string{"["}); err == nil {
		t.Error("expected error for malformed pattern, got nil")
	}
}

func TestMatcher_Empty(t *testing.T) {
	m, _ := Compile(nil)
	if !m.Empty() {
		t.Error("expected Empty() for no patterns")
	}
	m, _ = Compile([]string{"*.go"})
	if m.Empty() {
		t.Error("expected non-empty matcher")
	}
}
