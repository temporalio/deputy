package graph

import (
	"context"
	"testing"
)

func TestResolverRegistry_Resolvers(t *testing.T) {
	registry := NewResolverRegistry()
	resolvers := registry.Resolvers()

	// Should have all 5 ecosystem resolvers
	if len(resolvers) != 5 {
		t.Errorf("expected 5 resolvers, got %d", len(resolvers))
	}

	// Verify ecosystems
	ecosystems := make(map[string]bool)
	for _, r := range resolvers {
		ecosystems[r.Ecosystem()] = true
	}

	expected := []string{"Go", "npm", "crates.io", "PyPI", "RubyGems"}
	for _, eco := range expected {
		if !ecosystems[eco] {
			t.Errorf("missing resolver for ecosystem %q", eco)
		}
	}
}

func TestResolverRegistry_ForEcosystem(t *testing.T) {
	registry := NewResolverRegistry()

	tests := []struct {
		query string
		want  string
	}{
		{"Go", "Go"},
		{"go", "Go"},
		{"golang", "Go"},
		{"npm", "npm"},
		{"node", "npm"},
		{"javascript", "npm"},
		{"cargo", "crates.io"},
		{"rust", "crates.io"},
		{"crates.io", "crates.io"},
		{"pypi", "PyPI"},
		{"python", "PyPI"},
		{"pip", "PyPI"},
		{"rubygems", "RubyGems"},
		{"ruby", "RubyGems"},
		{"gem", "RubyGems"},
		{"unknown", ""},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			resolver := registry.ForEcosystem(tt.query)
			if tt.want == "" {
				if resolver != nil {
					t.Errorf("expected nil for %q, got %s", tt.query, resolver.Ecosystem())
				}
				return
			}
			if resolver == nil {
				t.Errorf("expected resolver for %q, got nil", tt.query)
				return
			}
			if resolver.Ecosystem() != tt.want {
				t.Errorf("ForEcosystem(%q) = %s, want %s", tt.query, resolver.Ecosystem(), tt.want)
			}
		})
	}
}

func TestResolverRegistry_WithOptions(t *testing.T) {
	// Test that options are passed to Go resolver
	registry := NewResolverRegistry(
		WithGoProxyEnabled("https://proxy.golang.org"),
		WithGoGitEnabled(),
		WithGoResolverConcurrency(20),
	)

	goResolver := registry.ForEcosystem("go")
	if goResolver == nil {
		t.Fatal("expected Go resolver")
	}
	if goResolver.Ecosystem() != "Go" {
		t.Errorf("expected Go ecosystem, got %s", goResolver.Ecosystem())
	}
}

func TestResolverRegistry_ResolveAll(t *testing.T) {
	registry := NewResolverRegistry()

	files := &mockFileReader{
		files: map[string][]byte{
			"go.mod": []byte(`module example.com/test
go 1.21
require github.com/pkg/errors v0.9.1
`),
		},
	}

	g := New()
	g.AddNode(&Node{
		PURL:      "pkg:golang/github.com/pkg/errors@0.9.1",
		Name:      "github.com/pkg/errors",
		Version:   "0.9.1",
		Ecosystem: "Go",
	})

	err := registry.ResolveAll(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveAll failed: %v", err)
	}

	// Should have processed Go resolver
	node := g.Node("pkg:golang/github.com/pkg/errors@0.9.1")
	if node == nil {
		t.Fatal("expected errors node to exist")
	}
	if !node.Direct {
		t.Error("expected github.com/pkg/errors to be marked as direct")
	}
}

func TestSupportedEcosystems(t *testing.T) {
	ecosystems := SupportedEcosystems()
	if len(ecosystems) != 5 {
		t.Errorf("expected 5 supported ecosystems, got %d", len(ecosystems))
	}
}

func TestNormalizeEcosystemName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"Go", "go"},
		{"go", "go"},
		{"golang", "go"},
		{"GOLANG", "go"},
		{"npm", "npm"},
		{"NPM", "npm"},
		{"node", "npm"},
		{"javascript", "npm"},
		{"cargo", "cargo"},
		{"Cargo", "cargo"},
		{"rust", "cargo"},
		{"crates.io", "cargo"},
		{"pypi", "pypi"},
		{"PyPI", "pypi"},
		{"python", "pypi"},
		{"pip", "pypi"},
		{"rubygems", "rubygems"},
		{"RubyGems", "rubygems"},
		{"ruby", "rubygems"},
		{"gem", "rubygems"},
		{"unknown", "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeEcosystemName(tt.input)
			if got != tt.want {
				t.Errorf("normalizeEcosystemName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
