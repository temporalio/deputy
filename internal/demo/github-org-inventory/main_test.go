package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/repository/workspace"
)

func TestCollectRowsFromPackages(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	pkgs := []*extractor.Package{
		{
			Name:      "github.com/example/foo",
			Version:   "v1.0.0",
			PURLType:  "golang",
			Licenses:  []string{"MIT"},
			Locations: []string{"go.mod"},
		},
		{
			// duplicate to verify de-duplication
			Name:     "github.com/example/foo",
			Version:  "v1.0.0",
			PURLType: "golang",
		},
		{
			Name:     "requests",
			Version:  "2.31.0",
			PURLType: "pypi",
		},
	}

	rows := collectRowsFromPackages(ctx, "demo-repo", pkgs, func(_ context.Context, pkg *extractor.Package) []string {
		if len(pkg.Licenses) > 0 {
			return pkg.Licenses
		}
		return []string{"Apache-2.0"}
	})

	if got := len(rows["go"]); got != 1 {
		t.Fatalf("expected 1 go row, got %d", got)
	}
	goRow := rows["go"][0]
	if goRow.PackageName != "github.com/example/foo" || goRow.Version != "v1.0.0" {
		t.Fatalf("unexpected go row: %+v", goRow)
	}
	if len(goRow.Licenses) != 1 || goRow.Licenses[0] != "MIT" {
		t.Fatalf("expected MIT license, got %+v", goRow.Licenses)
	}

	if got := len(rows["python"]); got != 1 {
		t.Fatalf("expected 1 python row, got %d", got)
	}
	pyRow := rows["python"][0]
	if pyRow.PackageName != "requests" || pyRow.Licenses[0] != "Apache-2.0" {
		t.Fatalf("unexpected python row: %+v", pyRow)
	}
}

func TestInventoryFromWorkspace(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), `module example.com/demo

go 1.22

require github.com/google/uuid v1.6.0
`)
	writeFile(t, filepath.Join(dir, "go.sum"), `github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
`)
	writeFile(t, filepath.Join(dir, "main.go"), `package main

import _ "github.com/google/uuid"

func main() {}
`)

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace.NewDir: %v", err)
	}
	defer ws.Close()

	resolve := func(context.Context, *extractor.Package) []string {
		return []string{"Test-License"}
	}

	rows, err := inventoryFromWorkspace(context.Background(), "demo-repo", ws, []string{"go"}, resolve)
	if err != nil {
		t.Fatalf("inventoryFromWorkspace: %v", err)
	}
	goRows := rows["go"]
	if len(goRows) == 0 {
		t.Fatalf("expected at least one go dependency, got none")
	}
	foundLicense := false
	for _, row := range goRows {
		if len(row.Licenses) > 0 && row.Licenses[0] == "Test-License" {
			foundLicense = true
			break
		}
	}
	if !foundLicense {
		t.Fatalf("expected Test-License to be used for dependencies, got %+v", goRows)
	}
}

func writeFile(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file %s: %v", path, err)
	}
}
