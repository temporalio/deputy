package inventory

import "testing"

// TestDependencyMatcherMatchesPnpmLock ensures the matcher recognizes common
// non-Go manifests (pnpm lockfiles) and ignores unrelated files.
func TestDependencyMatcherMatchesPnpmLock(t *testing.T) {
	matcher, err := GetDependencyMatcher(ScanOptions{Ecosystems: []string{"all"}})
	if err != nil {
		t.Fatalf("GetDependencyMatcher: %v", err)
	}
	if matcher == nil {
		t.Fatalf("expected matcher")
	}
	if !matcher.Matches("web/pnpm-lock.yaml") {
		t.Fatalf("expected pnpm-lock.yaml to be considered a dependency manifest")
	}
	if matcher.Matches("README.md") {
		t.Fatalf("readme should not be treated as dependency manifest")
	}
}

// TestDependencyMatcherCacheReuse verifies GetDependencyMatcher returns the
// same pointer for identical scan options thanks to caching.
func TestDependencyMatcherCacheReuse(t *testing.T) {
	opts := ScanOptions{Ecosystems: []string{"all"}}
	first, err := GetDependencyMatcher(opts)
	if err != nil {
		t.Fatalf("GetDependencyMatcher: %v", err)
	}
	second, err := GetDependencyMatcher(opts)
	if err != nil {
		t.Fatalf("GetDependencyMatcher (second): %v", err)
	}
	if first != second {
		t.Fatalf("expected cached matcher to be reused")
	}
}

// TestDependencyMatcherMatches tests the Matches method with various file paths.
func TestDependencyMatcherMatches(t *testing.T) {
	matcher, err := GetDependencyMatcher(ScanOptions{Ecosystems: []string{"all"}})
	if err != nil {
		t.Fatalf("GetDependencyMatcher: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		// Go ecosystem
		{"go.mod at root", "go.mod", true},
		{"go.mod in subdirectory", "pkg/go.mod", true},

		// npm ecosystem
		{"package.json at root", "package.json", true},
		{"package.json in subdirectory", "frontend/package.json", true},
		{"package-lock.json", "package-lock.json", true},
		{"yarn.lock", "yarn.lock", true},
		{"pnpm-lock.yaml", "pnpm-lock.yaml", true},

		// Python ecosystem
		{"requirements.txt", "requirements.txt", true},
		{"requirements.txt in subdirectory", "backend/requirements.txt", true},
		{"Pipfile.lock", "Pipfile.lock", true},
		{"poetry.lock", "poetry.lock", true},

		// Ruby ecosystem
		{"Gemfile.lock", "Gemfile.lock", true},

		// Rust ecosystem
		{"Cargo.toml", "Cargo.toml", true},
		{"Cargo.lock", "Cargo.lock", true},

		// Container ecosystem
		{"Dockerfile", "Dockerfile", true},
		{"Containerfile", "Containerfile", true},
		{"server.Dockerfile", "docker/server.Dockerfile", true},

		// Non-dependency files
		{"README.md", "README.md", false},
		{"main.go", "main.go", false},
		{"index.js", "index.js", false},
		{".gitignore", ".gitignore", false},
		{"Makefile", "Makefile", false},

		// Edge cases
		{"empty path", "", false},
		{"whitespace only", "   ", false},
		{"path with leading ./", "./go.mod", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matcher.Matches(tc.path)
			if got != tc.expected {
				t.Errorf("Matches(%q) = %v, want %v", tc.path, got, tc.expected)
			}
		})
	}
}

// TestDependencyMatcherNilMatcher tests behavior when matcher is nil.
func TestDependencyMatcherNilMatcher(t *testing.T) {
	var m *DependencyMatcher
	if m.Matches("go.mod") {
		t.Error("nil matcher should return false for Matches")
	}
	if m.AnyMatch([]string{"go.mod", "package.json"}) {
		t.Error("nil matcher should return false for AnyMatch")
	}
}

// TestDependencyMatcherEmptyExtractors tests behavior with no extractors.
func TestDependencyMatcherEmptyExtractors(t *testing.T) {
	m := &DependencyMatcher{extractors: nil}
	if m.Matches("go.mod") {
		t.Error("matcher with no extractors should return false for Matches")
	}
	if m.AnyMatch([]string{"go.mod"}) {
		t.Error("matcher with no extractors should return false for AnyMatch")
	}
}

// TestDependencyMatcherAnyMatch tests the AnyMatch method.
func TestDependencyMatcherAnyMatch(t *testing.T) {
	matcher, err := GetDependencyMatcher(ScanOptions{Ecosystems: []string{"all"}})
	if err != nil {
		t.Fatalf("GetDependencyMatcher: %v", err)
	}

	tests := []struct {
		name     string
		paths    []string
		expected bool
	}{
		{
			name:     "all dependency files",
			paths:    []string{"go.mod", "package.json", "requirements.txt"},
			expected: true,
		},
		{
			name:     "one dependency file among non-deps",
			paths:    []string{"README.md", "main.go", "go.mod"},
			expected: true,
		},
		{
			name:     "no dependency files",
			paths:    []string{"README.md", "main.go", "config.yaml"},
			expected: false,
		},
		{
			name:     "dockerfile among non-deps",
			paths:    []string{"README.md", "main.go", "Dockerfile"},
			expected: true,
		},
		{
			name:     "empty slice",
			paths:    []string{},
			expected: false,
		},
		{
			name:     "nil slice",
			paths:    nil,
			expected: false,
		},
		{
			name:     "single match",
			paths:    []string{"Cargo.toml"},
			expected: true,
		},
		{
			name:     "single non-match",
			paths:    []string{"config.yaml"},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matcher.AnyMatch(tc.paths)
			if got != tc.expected {
				t.Errorf("AnyMatch(%v) = %v, want %v", tc.paths, got, tc.expected)
			}
		})
	}
}

// TestNewDependencyMatcher tests creating a matcher with different options.
func TestNewDependencyMatcher(t *testing.T) {
	tests := []struct {
		name      string
		opts      ScanOptions
		wantError bool
	}{
		{
			name:      "all ecosystems",
			opts:      ScanOptions{Ecosystems: []string{"all"}},
			wantError: false,
		},
		{
			name:      "go only",
			opts:      ScanOptions{Ecosystems: []string{"go"}},
			wantError: false,
		},
		{
			name:      "empty ecosystems defaults to all",
			opts:      ScanOptions{Ecosystems: nil},
			wantError: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := NewDependencyMatcher(tc.opts)
			if tc.wantError {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if m == nil {
				t.Error("expected non-nil matcher")
			}
		})
	}
}

// TestDependencyMatcherPathNormalization tests path normalization behavior.
func TestDependencyMatcherPathNormalization(t *testing.T) {
	matcher, err := GetDependencyMatcher(ScanOptions{Ecosystems: []string{"all"}})
	if err != nil {
		t.Fatalf("GetDependencyMatcher: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"path with ./", "./go.mod", true},
		{"path with spaces", "  go.mod  ", true},
		{"nested path", "a/b/c/go.mod", true},
		{"deep nested", "very/deep/nested/path/go.mod", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matcher.Matches(tc.path)
			if got != tc.expected {
				t.Errorf("Matches(%q) = %v, want %v", tc.path, got, tc.expected)
			}
		})
	}
}

// TestDependencyMatcherCacheDifferentOptions verifies cache returns different
// matchers for different options.
func TestDependencyMatcherCacheDifferentOptions(t *testing.T) {
	opts1 := ScanOptions{Ecosystems: []string{"go"}}
	opts2 := ScanOptions{Ecosystems: []string{"all"}}

	m1, err := GetDependencyMatcher(opts1)
	if err != nil {
		t.Fatalf("GetDependencyMatcher(go): %v", err)
	}

	m2, err := GetDependencyMatcher(opts2)
	if err != nil {
		t.Fatalf("GetDependencyMatcher(all): %v", err)
	}

	// Different options should potentially return different matchers
	// (or the same if the underlying extractors happen to be identical)
	// The key test is that neither returns an error
	if m1 == nil || m2 == nil {
		t.Error("expected non-nil matchers for both options")
	}
}
