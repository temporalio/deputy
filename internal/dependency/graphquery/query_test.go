package graphquery

import (
	"slices"
	"strings"
	"testing"

	packageurl "github.com/package-url/packageurl-go"

	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/purlx"
)

func TestFindMatchingNodes(t *testing.T) {
	t.Parallel()

	g := graph.New()
	g.AddNode(&graph.Node{Purl: "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible", Name: "github.com/docker/docker", Version: "28.5.2+incompatible"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/github.com/docker/docker-credential-helpers@0.9.7", Name: "github.com/docker/docker-credential-helpers", Version: "0.9.7"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/go.yaml.in/yaml/v2@2.4.2", Name: "go.yaml.in/yaml/v2", Version: "2.4.2"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/github.com/goccy/go-yaml@1.12.0", Name: "github.com/goccy/go-yaml", Version: "1.12.0"})

	tests := []struct {
		name      string
		query     string
		wantNames []string
	}{
		{
			name:      "exact scan purl with encoded version",
			query:     "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible",
			wantNames: []string{"github.com/docker/docker"},
		},
		{
			name:      "purl accepts unescaped equivalent version",
			query:     "pkg:golang/github.com/docker/docker@28.5.2+incompatible",
			wantNames: []string{"github.com/docker/docker"},
		},
		{
			name:      "name version query",
			query:     "github.com/docker/docker@v28.5.2+incompatible",
			wantNames: []string{"github.com/docker/docker"},
		},
		{
			name:      "substring name query",
			query:     "docker/docker",
			wantNames: []string{"github.com/docker/docker", "github.com/docker/docker-credential-helpers"},
		},
		{
			name:      "glob query",
			query:     "github.com/docker/*",
			wantNames: []string{"github.com/docker/docker", "github.com/docker/docker-credential-helpers"},
		},
		{
			name:      "logical final segment ranks versioned module path first",
			query:     "yaml",
			wantNames: []string{"go.yaml.in/yaml/v2", "github.com/goccy/go-yaml"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FindMatchingNodes(g, tt.query)
			gotNames := make([]string, len(got))
			for i, node := range got {
				gotNames[i] = node.Name
			}
			if !slices.Equal(gotNames, tt.wantNames) {
				t.Fatalf("FindMatchingNodes(%q) = %v, want %v", tt.query, gotNames, tt.wantNames)
			}
		})
	}
}

func TestResolveTargetPURLs(t *testing.T) {
	t.Parallel()

	g := graph.New()
	const dockerPURL = "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible"
	g.AddNode(&graph.Node{Purl: dockerPURL, Name: "github.com/docker/docker", Version: "28.5.2+incompatible"})

	target := parseTestPURL(t, "pkg:golang/github.com/docker/docker@v28.5.2+incompatible")
	got := ResolveTargetPURLs(g, target)
	if !slices.Equal(got, []string{dockerPURL}) {
		t.Fatalf("ResolveTargetPURLs() = %v, want [%s]", got, dockerPURL)
	}
}

func TestNoDependentsMessage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		node               *graph.Node
		resolveTransitives bool
		wantSubstring      string
	}{
		{
			name:          "missing node",
			wantSubstring: "not found",
		},
		{
			name:          "direct dependency",
			node:          &graph.Node{Direct: true},
			wantSubstring: "direct/root dependency",
		},
		{
			name:          "disconnected dependency",
			node:          &graph.Node{Depth: graph.DepthDisconnected},
			wantSubstring: "disconnected from dependency roots",
		},
		{
			name:          "local graph",
			node:          &graph.Node{},
			wantSubstring: "retry with resolveTransitives=true",
		},
		{
			name:               "resolved graph",
			node:               &graph.Node{},
			resolveTransitives: true,
			wantSubstring:      "dependency graph",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NoDependentsMessage(tt.node, tt.resolveTransitives)
			if !strings.Contains(got, tt.wantSubstring) {
				t.Fatalf("NoDependentsMessage() = %q, want substring %q", got, tt.wantSubstring)
			}
		})
	}
}

func TestNameMatchScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, query string
		want        int
	}{
		{name: "github.com/spf13/cobra", query: "github.com/spf13/cobra", want: 3},
		{name: "github.com/spf13/cobra", query: "cobra", want: 2},
		{name: "go.yaml.in/yaml/v2", query: "yaml", want: 2},
		{name: "github.com/goccy/go-yaml", query: "yaml", want: 1},
		{name: "github.com/spf13/cobra", query: "pkg:golang/github.com/spf13/cobra@1.10.0", want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name+" "+tt.query, func(t *testing.T) {
			if got := NameMatchScore(tt.name, tt.query); got != tt.want {
				t.Fatalf("NameMatchScore(%q, %q) = %d, want %d", tt.name, tt.query, got, tt.want)
			}
		})
	}
}

func TestVersionsEquivalent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		a, b string
		want bool
	}{
		{a: "28.5.2+incompatible", b: "v28.5.2+incompatible", want: true},
		{a: "0.9.7", b: "v0.9.7", want: true},
		{a: "0.9.7", b: "0.9.8", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.a+" "+tt.b, func(t *testing.T) {
			if got := VersionsEquivalent(tt.a, tt.b); got != tt.want {
				t.Fatalf("VersionsEquivalent(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func parseTestPURL(t *testing.T, purl string) packageurl.PackageURL {
	t.Helper()
	parsed, err := purlx.ParseLoose(purl)
	if err != nil {
		t.Fatalf("ParseLoose(%q): %v", purl, err)
	}
	return parsed
}
