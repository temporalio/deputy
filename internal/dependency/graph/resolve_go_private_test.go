package graph

import "testing"

func TestFilteredProxyFetcher_isPrivate(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		module   string
		want     bool
	}{
		// Non-public modules always bypass the proxy regardless of patterns.
		{"internal module is private", nil, "example.com/foo/internal/bar", true},
		{"public module, no patterns", nil, "github.com/spf13/cobra", false},

		// GOPRIVATE prefix semantics: a pattern matches the path and all sub-paths.
		{"org pattern matches top-level", []string{"github.com/mycompany/*"}, "github.com/mycompany/tool", true},
		{"org pattern matches deep monorepo path", []string{"github.com/mycompany/*"}, "github.com/mycompany/team/internal/setup", true},
		{"bare repo pattern matches sub-paths", []string{"github.com/mycompany/repo"}, "github.com/mycompany/repo/sub/pkg", true},
		{"bare repo pattern matches exact", []string{"github.com/mycompany/repo"}, "github.com/mycompany/repo", true},

		// Boundary: a prefix must align to a path segment, not a substring.
		{"does not misfire on different org", []string{"github.com/acme"}, "github.com/acme-corp/tool", false},
		{"does not misfire on sibling repo", []string{"github.com/acme/repo"}, "github.com/acme/repository/pkg", false},

		// Unrelated module stays public.
		{"unrelated public module", []string{"github.com/mycompany/*"}, "github.com/otherorg/tool", false},

		// Comma-separated list (GOPRIVATE style) within a single pattern entry.
		{"comma list matches second entry", []string{"corp.example.com/*,github.com/mycompany/*"}, "github.com/mycompany/team/repo", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := &filteredProxyFetcher{privatePatterns: tc.patterns}
			if got := f.isPrivate(tc.module); got != tc.want {
				t.Errorf("isPrivate(%q) with patterns %v = %v, want %v", tc.module, tc.patterns, got, tc.want)
			}
		})
	}
}
