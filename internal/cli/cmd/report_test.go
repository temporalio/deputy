package cmd

import (
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
)

func TestBuildManifestDisplayContext_DedupArtifacts(t *testing.T) {
	list := []analysis.ConsolidatedVulnerability{
		{
			ManifestRefs: []analysis.ManifestReference{{Path: "go.mod", Manager: "go"}},
			Locations:    []string{"go.mod", "go.sum"},
		},
	}

	ctx := buildManifestDisplayContext(list)

	if len(ctx.Sources) != 1 {
		t.Fatalf("expected 1 manifest group, got %d", len(ctx.Sources))
	}
	entries := ctx.Sources[0].Entries
	if len(entries) != 1 {
		t.Fatalf("expected 1 manifest entry, got %d", len(entries))
	}
	if entries[0].Path != "go.mod" {
		t.Fatalf("expected entry path go.mod, got %q", entries[0].Path)
	}
	if len(ctx.Artifacts) != 1 {
		t.Fatalf("expected 1 artifact group, got %d", len(ctx.Artifacts))
	}
	if len(ctx.Artifacts[0].Entries) != 1 {
		t.Fatalf("expected artifact group to contain go.sum, got %d entries", len(ctx.Artifacts[0].Entries))
	}
	if ctx.Artifacts[0].Entries[0] != "go.sum" {
		t.Fatalf("expected artifact go.sum, got %q", ctx.Artifacts[0].Entries[0])
	}
	if ctx.Artifacts[0].Manager != "go" {
		t.Fatalf("expected artifact manager go, got %q", ctx.Artifacts[0].Manager)
	}
}
