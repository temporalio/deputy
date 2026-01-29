package terraform

import (
	"context"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/picatz/deputy/internal/purlx"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"main.tf", true},
		{"versions.tf.json", true},
		{"modules/db/versions.tf", true},
		{".terraform/lock.hcl", false},
		{"README.md", false},
		{"main.go", false},
	}

	ext := New()
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			api := &mockFileAPI{path: tt.path}
			got := ext.FileRequired(api)
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestExtractor_Extract(t *testing.T) {
	content := `terraform {
  required_version = ">= 1.3.0, < 2.0.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = ">= 3.1.0"
  }
}
`
	fsys := &mapFSAdapter{MapFS: fstest.MapFS{
		"main.tf": &fstest.MapFile{Data: []byte(content)},
	}}
	ext := New()
	inv, err := ext.Extract(context.Background(), &filesystem.ScanInput{
		FS:   fsys,
		Path: "main.tf",
	})
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(inv.Packages) != 3 {
		t.Fatalf("Extract() got %d packages, want 3", len(inv.Packages))
	}
	pkgs := map[string]*extractor.Package{}
	for _, pkg := range inv.Packages {
		pkgs[pkg.Name] = pkg
	}
	core := pkgs["terraform"]
	if core == nil {
		t.Fatalf("missing terraform core package")
	}
	if core.Version != ">= 1.3.0, < 2.0.0" {
		t.Errorf("core.Version = %q, want %q", core.Version, ">= 1.3.0, < 2.0.0")
	}
	if core.PURLType != purlx.TypeTerraform {
		t.Errorf("core.PURLType = %q, want %q", core.PURLType, purlx.TypeTerraform)
	}
	assertHasLocation(t, core, "main.tf")
	assertConstraintMetadata(t, core, "1.3.0", "2.0.0", true, false)

	aws := pkgs["hashicorp/aws"]
	if aws == nil {
		t.Fatalf("missing aws provider package")
	}
	if aws.PURLType != purlx.TypeTerraformProvider {
		t.Errorf("aws.PURLType = %q, want %q", aws.PURLType, purlx.TypeTerraformProvider)
	}
	meta, ok := aws.Metadata.(map[string]any)
	if !ok || meta["source"] != "hashicorp/aws" {
		t.Errorf("aws metadata source = %v, want %q", meta["source"], "hashicorp/aws")
	}
	assertConstraintMetadata(t, aws, "5.0.0", "6.0.0", true, false)

	random := pkgs["hashicorp/random"]
	if random == nil {
		t.Fatalf("missing random provider package")
	}
	if random.Version != ">= 3.1.0" {
		t.Errorf("random.Version = %q, want %q", random.Version, ">= 3.1.0")
	}
}

type mockFileAPI struct {
	path string
}

func (m *mockFileAPI) Path() string { return m.path }

func (m *mockFileAPI) Stat() (fs.FileInfo, error) {
	return &mockFileInfo{name: m.path}, nil
}

type mockFileInfo struct {
	name string
}

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() fs.FileMode  { return 0o644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() any           { return nil }

type mapFSAdapter struct {
	fstest.MapFS
}

func (m *mapFSAdapter) Open(name string) (fs.File, error) {
	return m.MapFS.Open(name)
}

func assertHasLocation(t *testing.T, pkg *extractor.Package, want string) {
	t.Helper()
	for _, loc := range pkg.Locations {
		if loc == want {
			return
		}
	}
	t.Fatalf("expected location %q in %v", want, pkg.Locations)
}

func assertConstraintMetadata(t *testing.T, pkg *extractor.Package, min, max string, minInc, maxInc bool) {
	t.Helper()
	meta, ok := pkg.Metadata.(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map on %s", pkg.Name)
	}
	if meta["min_version"] != min {
		t.Errorf("min_version = %v, want %v", meta["min_version"], min)
	}
	if meta["max_version"] != max {
		t.Errorf("max_version = %v, want %v", meta["max_version"], max)
	}
	if meta["min_inclusive"] != minInc {
		t.Errorf("min_inclusive = %v, want %v", meta["min_inclusive"], minInc)
	}
	if meta["max_inclusive"] != maxInc {
		t.Errorf("max_inclusive = %v, want %v", meta["max_inclusive"], maxInc)
	}
}
