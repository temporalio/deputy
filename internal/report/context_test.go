package report

import (
	"slices"
	"testing"

	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestBuildManifestContext(t *testing.T) {
	list := []vulnerability.Consolidated{
		{
			ManifestRefs: []dependency.ManifestRef{
				{Manager: "npm", Path: "package.json", Groups: []string{"dependencies"}},
				{Manager: "npm", Path: "package.json", Groups: []string{"devDependencies"}},
			},
			Locations: []string{"package.json", "src/index.js"},
		},
		{
			ManifestRefs: []dependency.ManifestRef{
				{Manager: "go", Path: "go.mod"},
			},
			Locations: []string{"go.mod", "go.sum"},
		},
	}

	ctx := BuildManifestContext(list)
	if len(ctx.Sources) != 2 {
		t.Fatalf("expected 2 source groups, got %d", len(ctx.Sources))
	}
	if ctx.Sources[0].Manager != "go" {
		t.Fatalf("expected go manager first, got %q", ctx.Sources[0].Manager)
	}
	if ctx.Sources[1].Manager != "npm" {
		t.Fatalf("expected npm manager second, got %q", ctx.Sources[1].Manager)
	}
	if len(ctx.Sources[1].Entries) != 1 {
		t.Fatalf("expected 1 npm entry, got %d", len(ctx.Sources[1].Entries))
	}
	gotGroups := ctx.Sources[1].Entries[0].Groups
	if !slices.Equal(gotGroups, []string{"dependencies", "devDependencies"}) {
		t.Fatalf("unexpected npm groups: %v", gotGroups)
	}

	if len(ctx.Artifacts) == 0 {
		t.Fatalf("expected artifacts")
	}
	foundGoSum := false
	for _, grp := range ctx.Artifacts {
		if slices.Contains(grp.Entries, "go.sum") {
			foundGoSum = true
			break
		}
	}
	if !foundGoSum {
		t.Fatalf("expected go.sum in artifacts")
	}
}
