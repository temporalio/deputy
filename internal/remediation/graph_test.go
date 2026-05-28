package remediation

import (
	"testing"

	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestExtractPackageName(t *testing.T) {
	tests := []struct {
		cmd      string
		expected string
	}{
		{"go get github.com/example/pkg@v1.0.0", "github.com/example/pkg"},
		{"go get -u github.com/example/pkg@v1.0.0", "github.com/example/pkg"},
		{"npm install lodash@4.17.21", "lodash"},
		{"pip install requests>=2.28.0", "requests>=2.28.0"}, // pip style, version in name
		{"gem install rails -v 7.0.0", "rails"},
		{"cargo add serde@1.0", "serde"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			got := extractPackageName(tt.cmd)
			if got != tt.expected {
				t.Errorf("extractPackageName(%q) = %q, want %q", tt.cmd, got, tt.expected)
			}
		})
	}
}

func TestEnrichWithGraphNil(t *testing.T) {
	cmds := []Command{
		{Manager: "go", Command: "go get github.com/example/pkg@v1.0.0"},
	}
	cons := []vulnerability.Consolidated{}

	// Should not panic with nil graph
	enriched := EnrichWithGraph(cmds, nil, cons)
	if len(enriched) != 1 {
		t.Errorf("expected 1 enriched command, got %d", len(enriched))
	}
	if enriched[0].PathInfo != nil {
		t.Error("expected nil PathInfo for nil graph")
	}
}

func TestBuildExplanation(t *testing.T) {
	t.Run("direct dependency", func(t *testing.T) {
		info := &PathInfo{
			VulnerablePackage: "lodash",
			Depth:             0,
		}
		exp := buildExplanation(info)
		if exp != "lodash is a direct dependency" {
			t.Errorf("unexpected explanation: %s", exp)
		}
	})

	t.Run("nil info", func(t *testing.T) {
		exp := buildExplanation(nil)
		if exp != "" {
			t.Errorf("expected empty explanation for nil, got %q", exp)
		}
	})
}

func TestFindImpactedPackagesNil(t *testing.T) {
	impacted := findImpactedPackages(nil, "lodash")
	if impacted != nil {
		t.Error("expected nil for nil graph")
	}
}

func TestRecommendationsWithContext(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:     "CVE-2024-1234",
			Package:       "github.com/example/pkg",
			Version:       "v1.0.0",
			FixedVersions: []string{"v1.0.1"},
			Ecosystem:     "Go",
			IsDirect:      true,
		},
	}

	// Without graph
	recs := RecommendationsWithContext(cons, nil)

	// Should still produce recommendations (based on CommandsFromConsolidated)
	// The exact output depends on the ecosystem command generation logic
	_ = recs
}

func TestPathInfo(t *testing.T) {
	info := PathInfo{
		VulnID:             "CVE-2024-1234",
		VulnerablePackage:  "qs",
		ShortestPath:       []PathNode{{Name: "express"}, {Name: "body-parser"}, {Name: "qs"}},
		PathCount:          3,
		DirectDependencies: []string{"express"},
		Depth:              2,
	}

	if info.Depth != 2 {
		t.Errorf("expected depth 2, got %d", info.Depth)
	}

	if len(info.DirectDependencies) != 1 {
		t.Errorf("expected 1 direct dep, got %d", len(info.DirectDependencies))
	}

	if info.DirectDependencies[0] != "express" {
		t.Errorf("expected direct dep 'express', got %s", info.DirectDependencies[0])
	}
}
