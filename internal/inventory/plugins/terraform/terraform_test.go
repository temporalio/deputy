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
		{".terraform/lock.hcl", false},           // Internal cache directory
		{".terraform.lock.hcl", true},            // Lock file in root
		{"infra/.terraform.lock.hcl", true},      // Lock file in subdirectory
		{".terraform/providers/foo.tf", false},   // Internal cache
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

func TestExtractor_LockFile(t *testing.T) {
	lockContent := `# This file is maintained automatically by "terraform init".

provider "registry.terraform.io/hashicorp/aws" {
  version     = "5.31.0"
  constraints = "~> 5.0"
  hashes = [
    "h1:6y12cTFaxpFv4qyU3gkV9M15eSBBrgInoKY1iaHuhvg=",
    "zh:0573de96ba316d808be9f8d6fc8e8e68e0e6b614abcd",
  ]
}

provider "registry.terraform.io/hashicorp/random" {
  version = "3.6.0"
  hashes = [
    "h1:R5qdQjKzOU16TziCN1vR3Exr/B+8WGK80glLTT4ZCPk=",
  ]
}
`
	fsys := &mapFSAdapter{MapFS: fstest.MapFS{
		".terraform.lock.hcl": &fstest.MapFile{Data: []byte(lockContent)},
	}}
	ext := New()
	inv, err := ext.Extract(context.Background(), &filesystem.ScanInput{
		FS:   fsys,
		Path: ".terraform.lock.hcl",
	})
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}
	if len(inv.Packages) != 2 {
		t.Fatalf("Extract() got %d packages, want 2", len(inv.Packages))
	}
	pkgs := map[string]*extractor.Package{}
	for _, pkg := range inv.Packages {
		pkgs[pkg.Name] = pkg
	}

	aws := pkgs["hashicorp/aws"]
	if aws == nil {
		t.Fatalf("missing aws provider package")
	}
	if aws.Version != "5.31.0" {
		t.Errorf("aws.Version = %q, want %q", aws.Version, "5.31.0")
	}
	if aws.PURLType != purlx.TypeTerraformProvider {
		t.Errorf("aws.PURLType = %q, want %q", aws.PURLType, purlx.TypeTerraformProvider)
	}

	meta, ok := aws.Metadata.(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map on aws")
	}
	if meta["kind"] != "locked_provider" {
		t.Errorf("kind = %v, want %v", meta["kind"], "locked_provider")
	}
	if meta["resolved"] != true {
		t.Errorf("resolved = %v, want %v", meta["resolved"], true)
	}
	if meta["constraint"] != "~> 5.0" {
		t.Errorf("constraint = %v, want %v", meta["constraint"], "~> 5.0")
	}
	if meta["version_major"] != 5 {
		t.Errorf("version_major = %v, want %v", meta["version_major"], 5)
	}
	if meta["version_minor"] != 31 {
		t.Errorf("version_minor = %v, want %v", meta["version_minor"], 31)
	}
	hashes, ok := meta["hashes"].([]string)
	if !ok || len(hashes) != 2 {
		t.Errorf("hashes = %v, want 2 hashes", meta["hashes"])
	}

	random := pkgs["hashicorp/random"]
	if random == nil {
		t.Fatalf("missing random provider package")
	}
	if random.Version != "3.6.0" {
		t.Errorf("random.Version = %q, want %q", random.Version, "3.6.0")
	}
}

func TestExtractor_Modules(t *testing.T) {
	content := `module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.0"
}

module "eks" {
  source = "git::https://github.com/terraform-aws-modules/terraform-aws-eks.git?ref=v19.0.0"
}

module "networking" {
  source = "./modules/networking"
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

	vpc := pkgs["terraform-aws-modules/vpc/aws"]
	if vpc == nil {
		t.Fatalf("missing vpc module package")
	}
	if vpc.Version != "5.1.0" {
		t.Errorf("vpc.Version = %q, want %q", vpc.Version, "5.1.0")
	}
	if vpc.PURLType != purlx.TypeTerraformModule {
		t.Errorf("vpc.PURLType = %q, want %q", vpc.PURLType, purlx.TypeTerraformModule)
	}
	vpcMeta, ok := vpc.Metadata.(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map on vpc")
	}
	if vpcMeta["kind"] != "module" {
		t.Errorf("kind = %v, want %v", vpcMeta["kind"], "module")
	}
	if vpcMeta["module_type"] != "registry" {
		t.Errorf("module_type = %v, want %v", vpcMeta["module_type"], "registry")
	}

	eks := pkgs["git::https://github.com/terraform-aws-modules/terraform-aws-eks.git?ref=v19.0.0"]
	if eks == nil {
		t.Fatalf("missing eks module package")
	}
	eksMeta, ok := eks.Metadata.(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map on eks")
	}
	if eksMeta["module_type"] != "git" {
		t.Errorf("module_type = %v, want %v", eksMeta["module_type"], "git")
	}

	networking := pkgs["./modules/networking"]
	if networking == nil {
		t.Fatalf("missing networking module package")
	}
	netMeta, ok := networking.Metadata.(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map on networking")
	}
	if netMeta["module_type"] != "local" {
		t.Errorf("module_type = %v, want %v", netMeta["module_type"], "local")
	}
}

func TestClassifyModuleSource(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"terraform-aws-modules/vpc/aws", "registry"},
		{"./modules/networking", "local"},
		{"../shared/vpc", "local"},
		{"git::https://github.com/org/repo.git", "git"},
		{"github.com/hashicorp/example", "git"},
		{"bitbucket.org/hashicorp/terraform-consul-aws", "git"},
		{"https://example.com/module.zip", "http"},
		{"s3::https://s3-eu-west-1.amazonaws.com/bucket/module.zip", "s3"},
		{"gcs::https://www.googleapis.com/storage/v1/modules/module.zip", "gcs"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			got := classifyModuleSource(tt.source)
			if got != tt.want {
				t.Errorf("classifyModuleSource(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}
