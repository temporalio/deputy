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
