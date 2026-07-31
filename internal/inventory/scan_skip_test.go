package inventory

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

func TestFilterGitignoredPackageLocationsDropsIgnoredFileOnlyPackages(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.test\n"), 0o644); err != nil {
		t.Fatalf("write .gitignore: %v", err)
	}

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()

	pkgs := []*extractor.Package{
		{
			Name:      "github.com/example/test-binary",
			Version:   "(devel)",
			PURLType:  "golang",
			Locations: []string{"cmd.test"},
		},
		{
			Name:      "github.com/example/manifest",
			Version:   "1.0.0",
			PURLType:  "golang",
			Locations: []string{"go.mod", "cmd.test"},
		},
	}

	ignored, err := compileWorkspaceGitignore(ws)
	if err != nil {
		t.Fatalf("compileWorkspaceGitignore: %v", err)
	}
	got := filterGitignoredPackageLocations(ws, pkgs, ignored)
	if len(got) != 1 {
		t.Fatalf("got %d packages, want 1: %+v", len(got), got)
	}
	if got[0].Name != "github.com/example/manifest" {
		t.Fatalf("remaining package = %q, want github.com/example/manifest", got[0].Name)
	}
	if !slices.Equal(got[0].Locations, []string{"go.mod"}) {
		t.Fatalf("remaining locations = %v, want [go.mod]", got[0].Locations)
	}
	if !slices.Equal(pkgs[1].Locations, []string{"go.mod", "cmd.test"}) {
		t.Fatalf("original package locations were mutated: %v", pkgs[1].Locations)
	}
}
