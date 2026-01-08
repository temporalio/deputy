package scan

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestGraphBuilder(t *testing.T) {
	t.Run("disabled by default", func(t *testing.T) {
		opts := GraphOptions{}
		if opts.Enabled {
			t.Error("expected graph to be disabled by default")
		}
	})

	t.Run("builds graph when enabled", func(t *testing.T) {
		opts := GraphOptions{
			Enabled:  true,
			UseProxy: true,
		}
		builder := NewGraphBuilder(opts)
		if builder == nil {
			t.Fatal("expected builder to be non-nil")
		}
	})
}

func TestGraphOptionsInScanOptions(t *testing.T) {
	opts := Options{
		Ecosystems: []string{"go"},
		Graph: GraphOptions{
			Enabled: true,
		},
	}

	if !opts.Graph.Enabled {
		t.Error("expected graph to be enabled")
	}
}

func TestVulnerablePaths(t *testing.T) {
	// Test with nil graph
	paths := VulnerablePaths(nil)
	if paths != nil {
		t.Error("expected nil paths for nil graph")
	}
}

func TestPathsToVulnerability(t *testing.T) {
	// Test with nil graph
	paths := PathsToVulnerability(nil, "CVE-2024-1234")
	if paths != nil {
		t.Error("expected nil paths for nil graph")
	}
}

func TestShortestPathToVulnerability(t *testing.T) {
	// Test with nil graph
	path := ShortestPathToVulnerability(nil, "CVE-2024-1234")
	if path != nil {
		t.Error("expected nil path for nil graph")
	}
}

func TestBuildResultWithGraph(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "example.com/test", Version: "v1.0.0", PURLType: "golang"},
	}
	direct := map[string]bool{"pkg:golang/example.com/test@v1.0.0": true}

	result := buildResult(buildResultInput{
		target:     Target{DisplayPath: "test"},
		pkgs:       pkgs,
		direct:     direct,
		findings:   []vulnerability.Finding{},
		advisories: map[string]vulnerabilityv1.Advisory{},
		queryErr:   nil,
		opts:       Options{},
		graph:      nil,
	})

	if result.Graph != nil {
		t.Error("expected nil graph when not provided")
	}
	if result.PackagesScanned != 1 {
		t.Errorf("expected 1 package, got %d", result.PackagesScanned)
	}
}
