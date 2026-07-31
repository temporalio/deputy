package cmd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	graphv1 "github.com/temporalio/deputy/gen/deputy/graph/v1"
	"github.com/temporalio/deputy/internal/dependency/graph"
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
	if !strings.Contains(output, "[direct]") {
		t.Error("expected [direct] marker in output")
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
		if !strings.Contains(output, `"total_nodes":`) {
			t.Errorf("expected total_nodes in JSON output, got:\n%s", output)
		}
		if !strings.Contains(output, `"direct_nodes":`) {
			t.Errorf("expected direct_nodes in JSON output, got:\n%s", output)
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

func TestWriteNeedsJSONIncludesStatusAndCounts(t *testing.T) {
	t.Parallel()

	match := &graph.Node{
		Purl:      "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible",
		Name:      "github.com/docker/docker",
		Version:   "28.5.2+incompatible",
		Ecosystem: "go",
		Direct:    true,
		Depth:     0,
	}

	var buf bytes.Buffer
	if err := writeNeedsJSON(&buf, match, nil, nil, false); err != nil {
		t.Fatalf("writeNeedsJSON error: %v", err)
	}

	got := decodeGraphJSON(t, buf.Bytes())
	if got["found"] != true {
		t.Fatalf("found = %v, want true", got["found"])
	}
	if got["direct"] != true {
		t.Fatalf("direct = %v, want true", got["direct"])
	}
	if got["direct_count"] != float64(0) {
		t.Fatalf("direct_count = %v, want 0", got["direct_count"])
	}
	if got["transitive_count"] != float64(0) {
		t.Fatalf("transitive_count = %v, want 0", got["transitive_count"])
	}
	if message, ok := got["message"].(string); !ok || !strings.Contains(message, "direct/root dependency") {
		t.Fatalf("message = %v, want direct/root dependency explanation", got["message"])
	}
}

func TestWriteNeedsJSONIncludesDependentIdentity(t *testing.T) {
	t.Parallel()

	match := &graph.Node{
		Purl:    "pkg:npm/lodash@4.17.21",
		Name:    "lodash",
		Version: "4.17.21",
	}
	ancestors := []*graph.Node{
		{
			Purl:      "pkg:npm/body-parser@1.20.2",
			Name:      "body-parser",
			Version:   "1.20.2",
			Ecosystem: "npm",
			Depth:     1,
			Locations: []string{"package-lock.json"},
		},
		{
			Purl:      "pkg:npm/express@4.18.2",
			Name:      "express",
			Version:   "4.18.2",
			Ecosystem: "npm",
			Direct:    true,
			Depth:     0,
			Locations: []string{"package.json"},
		},
	}

	var buf bytes.Buffer
	if err := writeNeedsJSON(&buf, match, ancestors, nil, false); err != nil {
		t.Fatalf("writeNeedsJSON error: %v", err)
	}

	got := decodeGraphJSON(t, buf.Bytes())
	if got["direct_count"] != float64(1) {
		t.Fatalf("direct_count = %v, want 1", got["direct_count"])
	}
	if got["transitive_count"] != float64(1) {
		t.Fatalf("transitive_count = %v, want 1", got["transitive_count"])
	}
	dependents, ok := got["dependents"].([]any)
	if !ok {
		t.Fatalf("dependents has type %T, want []any", got["dependents"])
	}
	if len(dependents) != 2 {
		t.Fatalf("dependents length = %d, want 2", len(dependents))
	}
	first, ok := dependents[0].(map[string]any)
	if !ok {
		t.Fatalf("first dependent has type %T, want map[string]any", dependents[0])
	}
	if first["name"] != "express" {
		t.Fatalf("first dependent name = %v, want express", first["name"])
	}
	if first["ecosystem"] != "npm" {
		t.Fatalf("first dependent ecosystem = %v, want npm", first["ecosystem"])
	}
	if first["purl"] != "pkg:npm/express@4.18.2" {
		t.Fatalf("first dependent purl = %v, want pkg:npm/express@4.18.2", first["purl"])
	}
	if first["direct"] != true {
		t.Fatalf("first dependent direct = %v, want true", first["direct"])
	}
}

func TestWriteNeedsNotFoundJSON(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	if err := writeNeedsNotFoundJSON(&buf, " missing-package "); err != nil {
		t.Fatalf("writeNeedsNotFoundJSON error: %v", err)
	}

	got := decodeGraphJSON(t, buf.Bytes())
	if got["package"] != "missing-package" {
		t.Fatalf("package = %v, want missing-package", got["package"])
	}
	if found, ok := got["found"].(bool); !ok || found {
		t.Fatalf("found = %v, want false", got["found"])
	}
	if message, ok := got["message"].(string); !ok || !strings.Contains(message, "not found") {
		t.Fatalf("message = %v, want not found explanation", got["message"])
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

func decodeGraphJSON(t *testing.T, data []byte) map[string]any {
	t.Helper()

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("invalid JSON %q: %v", data, err)
	}
	return got
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
			contains: []string{"express", "4.18.2", "[direct]"},
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

func TestMatchScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		query     string
		wantScore int
	}{
		// Exact matches (score 3)
		{"express", "express", 3},
		{"lodash", "lodash", 3},

		// Final segment matches (score 2)
		{"github.com/spf13/cobra", "cobra", 2},
		{"golang.org/x/net", "net", 2},
		{"sigs.k8s.io/yaml", "yaml", 2},
		// Versioned paths - "go-git" matches github.com/go-git/go-git/v5
		{"github.com/go-git/go-git/v5", "go-git", 2},

		// Substring matches (score 1)
		{"github.com/goccy/go-yaml", "yaml", 1}, // yaml is substring but not final segment
		{"network-utils", "net", 1},             // substring match
		{"gopkg.in/yaml.v3", "yaml", 1},         // yaml.v3 as segment, not yaml alone
	}

	for _, tt := range tests {
		t.Run(tt.name+"_"+tt.query, func(t *testing.T) {
			got := matchScore(tt.name, strings.ToLower(tt.query))
			if got != tt.wantScore {
				t.Errorf("matchScore(%q, %q) = %d, want %d", tt.name, tt.query, got, tt.wantScore)
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
	g.AddNode(&graph.Node{Purl: "pkg:golang/github.com/spf13/cobra@1.10.0", Name: "github.com/spf13/cobra", Version: "1.10.0"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/github.com/muesli/mango-cobra@1.2.0", Name: "github.com/muesli/mango-cobra", Version: "1.2.0"})
	g.AddNode(&graph.Node{Purl: "pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible", Name: "github.com/docker/docker", Version: "28.5.2+incompatible"})

	tests := []struct {
		query       string
		wantFirst   string // Expected first (best) match name
		wantCount   int    // Expected number of matches (-1 = don't check)
		description string
	}{
		// "net" matches golang.org/x/net (final segment), network-utils (substring), otelhttp has /net/ internal
		{"net", "golang.org/x/net", 3, "final segment match preferred over substring"},
		// "yaml" - go.yaml.in/yaml/v2 wins (final segment, alphabetically first), then other matches
		{"yaml", "go.yaml.in/yaml/v2", 4, "final segment yaml wins (alphabetically first)"},
		// "go-yaml" only matches github.com/goccy/go-yaml (substring)
		{"go-yaml", "github.com/goccy/go-yaml", 1, "substring match"},
		// Exact match
		{"gopkg.in/yaml.v3", "gopkg.in/yaml.v3", 1, "exact match"},
		{"express", "express", 1, "exact match for simple name"},
		{"nonexistent", "", 0, "no match returns empty"},
		// Final segment match for otelhttp
		{"otelhttp", "go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp", 1, "final segment match"},
		// "cobra" should prefer spf13/cobra (final segment) over mango-cobra (substring)
		{"cobra", "github.com/spf13/cobra", 2, "final segment cobra wins over substring"},
		// Exact PURLs emitted by scans should round-trip into graph queries.
		{"pkg:golang/github.com/docker/docker@28.5.2%2Bincompatible", "github.com/docker/docker", 1, "scan purl query"},
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
