package cmd

import (
	"bytes"
	"strings"
	"testing"

	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	"github.com/picatz/deputy/internal/dependency/graph"
)

func TestWriteGraphFlatList(t *testing.T) {
	t.Parallel()

	g := graph.New()
	g.AddNode(&graph.Node{
		Purl:      "pkg:npm/lodash@4.17.21",
		Name:      "lodash",
		Version:   "4.17.21",
		Ecosystem: "npm",
		Direct:    true,
	})
	g.AddNode(&graph.Node{
		Purl:      "pkg:npm/express@4.18.2",
		Name:      "express",
		Version:   "4.18.2",
		Ecosystem: "npm",
		Direct:    false,
	})
	g.AddNode(&graph.Node{
		Purl:      "pkg:golang/github.com/spf13/cobra@1.8.0",
		Name:      "github.com/spf13/cobra",
		Version:   "1.8.0",
		Ecosystem: "Go",
		Direct:    true,
	})

	var buf bytes.Buffer
	err := writeGraphFlatList(&buf, g, true, false)
	if err != nil {
		t.Fatalf("writeGraphFlatList error: %v", err)
	}

	output := buf.String()

	// Check that ecosystems are present
	if !strings.Contains(output, "npm") {
		t.Error("expected npm ecosystem in output")
	}
	if !strings.Contains(output, "Go") {
		t.Error("expected Go ecosystem in output")
	}

	// Check that packages are present
	if !strings.Contains(output, "lodash@4.17.21") {
		t.Error("expected lodash in output")
	}
	if !strings.Contains(output, "express@4.18.2") {
		t.Error("expected express in output")
	}
	if !strings.Contains(output, "cobra") {
		t.Error("expected cobra in output")
	}

	// Check that direct dependencies are marked
	if !strings.Contains(output, "(direct)") {
		t.Error("expected (direct) marker in output")
	}

	// Check summary
	if !strings.Contains(output, "3 total") {
		t.Error("expected summary with total count")
	}
}

func TestWriteGraphStats(t *testing.T) {
	t.Parallel()

	stats := &graphv1.GraphStats{
		TotalNodes:      100,
		DirectNodes:     20,
		TransitiveNodes: 80,
		MaxDepth:        5,
		VulnerableNodes: 3,
		Ecosystems: map[string]int32{
			"npm": 60,
			"Go":  40,
		},
	}

	t.Run("text format", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeGraphStats(&buf, stats, "text")
		if err != nil {
			t.Fatalf("writeGraphStats error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, "100") {
			t.Error("expected total nodes in output")
		}
		if !strings.Contains(output, "20") {
			t.Error("expected direct nodes in output")
		}
		if !strings.Contains(output, "npm") {
			t.Error("expected npm ecosystem in output")
		}
	})

	t.Run("json format", func(t *testing.T) {
		var buf bytes.Buffer
		err := writeGraphStats(&buf, stats, "json")
		if err != nil {
			t.Fatalf("writeGraphStats error: %v", err)
		}

		output := buf.String()
		if !strings.Contains(output, `"total_nodes": 100`) {
			t.Error("expected total_nodes in JSON output")
		}
		if !strings.Contains(output, `"direct_nodes": 20`) {
			t.Error("expected direct_nodes in JSON output")
		}
	})
}

func TestGraphFormatConstants(t *testing.T) {
	t.Parallel()

	formats := []GraphFormat{
		GraphFormatText,
		GraphFormatJSON,
		GraphFormatDOT,
		GraphFormatMermaid,
		GraphFormatD3,
	}

	for _, f := range formats {
		if f == "" {
			t.Errorf("empty format constant")
		}
	}
}

func TestDeduplicatePaths(t *testing.T) {
	t.Parallel()

	// Create nodes for testing
	nodeA := &graph.Node{Purl: "pkg:npm/a@1.0.0", Name: "a", Version: "1.0.0"}
	nodeB := &graph.Node{Purl: "pkg:npm/b@1.0.0", Name: "b", Version: "1.0.0"}
	nodeC := &graph.Node{Purl: "pkg:npm/c@1.0.0", Name: "c", Version: "1.0.0"}
	nodeB2 := &graph.Node{Purl: "pkg:npm/b@2.0.0", Name: "b", Version: "2.0.0"} // Same name, different version

	tests := []struct {
		name     string
		input    []graph.Path
		expected int // number of unique paths
	}{
		{
			name:     "no duplicates",
			input:    []graph.Path{{nodeA, nodeB}, {nodeA, nodeC}},
			expected: 2,
		},
		{
			name:     "exact duplicates",
			input:    []graph.Path{{nodeA, nodeB}, {nodeA, nodeB}},
			expected: 1,
		},
		{
			name:     "same structure different versions",
			input:    []graph.Path{{nodeA, nodeB}, {nodeA, nodeB2}},
			expected: 1, // Deduped by name, not version
		},
		{
			name:     "empty input",
			input:    []graph.Path{},
			expected: 0,
		},
		{
			name:     "single path",
			input:    []graph.Path{{nodeA, nodeB, nodeC}},
			expected: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := deduplicatePaths(tt.input)
			if len(result) != tt.expected {
				t.Errorf("deduplicatePaths() returned %d paths, expected %d", len(result), tt.expected)
			}
		})
	}
}

func TestFormatNodeLabel(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		node     *graph.Node
		contains []string
	}{
		{
			name:     "basic node",
			node:     &graph.Node{Name: "lodash", Version: "4.17.21"},
			contains: []string{"lodash", "4.17.21"},
		},
		{
			name:     "direct node",
			node:     &graph.Node{Name: "express", Version: "4.18.2", Direct: true},
			contains: []string{"express", "4.18.2", "(direct)"},
		},
		{
			name:     "no version",
			node:     &graph.Node{Name: "unknown"},
			contains: []string{"unknown"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatNodeLabel(tt.node)
			for _, s := range tt.contains {
				if !strings.Contains(result, s) {
					t.Errorf("formatNodeLabel() = %q, expected to contain %q", result, s)
				}
			}
		})
	}
}

func TestContainsPathSegment(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		query string
		want  bool
	}{
		{"gopkg.in/yaml.v3", "yaml", true},       // /yaml.
		{"go.yaml.in/yaml/v2", "yaml", true},     // /yaml/
		{"github.com/goccy/go-yaml", "yaml", false}, // -yaml not /yaml
		{"sigs.k8s.io/yaml", "yaml", false},      // ends with /yaml, not internal
		{"otelhttp/net/http", "net", true},       // /net/
		{"golang.org/x/net", "net", false},       // ends with /net
		{"express", "express", false},            // no path segments
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.query, func(t *testing.T) {
			got := containsPathSegment(tt.name, tt.query)
			if got != tt.want {
				t.Errorf("containsPathSegment(%q, %q) = %v, want %v", tt.name, tt.query, got, tt.want)
			}
		})
	}
}

func TestFindMatchingNodes(t *testing.T) {
	t.Parallel()

	g := graph.New()
	g.AddNode(&graph.Node{Purl: "pkg:golang/golang.org/x/net@0.47.0", Name: "golang.org/x/net", Version: "0.47.0"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/github.com/goccy/go-yaml@1.12.0", Name: "github.com/goccy/go-yaml", Version: "1.12.0"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/gopkg.in/yaml.v3@3.0.1", Name: "gopkg.in/yaml.v3", Version: "3.0.1"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/sigs.k8s.io/yaml@1.6.0", Name: "sigs.k8s.io/yaml", Version: "1.6.0"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/go.yaml.in/yaml/v2@2.4.2", Name: "go.yaml.in/yaml/v2", Version: "2.4.2"})
	g.AddNode(&graph.Node{Purl: "pkg:npm/express@4.18.2", Name: "express", Version: "4.18.2"})
	g.AddNode(&graph.Node{Purl: "pkg:npm/network-utils@1.0.0", Name: "network-utils", Version: "1.0.0"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp@0.63.0", Name: "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", Version: "0.63.0"})

	tests := []struct {
		query       string
		wantFirst   string // Expected first (best) match name
		wantCount   int    // Expected number of matches (-1 = don't check)
		description string
	}{
		// "net" matches golang.org/x/net and otelhttp (path match), plus network-utils (substring)
		{"net", "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", 3, "path match + substring match"},
		// "yaml" matches go-yaml (hyphen suffix, higher rank) + 3 path matches
		{"yaml", "github.com/goccy/go-yaml", 4, "yaml matches go-yaml first, then path matches"},
		{"go-yaml", "github.com/goccy/go-yaml", 1, "hyphen suffix match"},
		{"gopkg.in/yaml.v3", "gopkg.in/yaml.v3", 1, "exact match"},
		{"express", "express", 1, "exact match for simple name"},
		{"nonexistent", "", 0, "no match returns empty"},
		{"otelhttp", "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", 1, "path suffix match"},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			matches := findMatchingNodes(g, tt.query)

			if tt.wantCount >= 0 && len(matches) != tt.wantCount {
				t.Errorf("findMatchingNodes(%q) returned %d matches, want %d", tt.query, len(matches), tt.wantCount)
			}

			if tt.wantFirst != "" {
				if len(matches) == 0 {
					t.Errorf("findMatchingNodes(%q) returned no matches, want first=%q", tt.query, tt.wantFirst)
				} else if matches[0].Name != tt.wantFirst {
					t.Errorf("findMatchingNodes(%q) first match = %q, want %q", tt.query, matches[0].Name, tt.wantFirst)
				}
			}
		})
	}
}
