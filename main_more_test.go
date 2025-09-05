package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func Test_normalizeGopkgInURL_and_extractCanonicalPackageName(t *testing.T) {
	cases := []struct {
		in    string
		norm  string
		canon string
	}{
		{"gopkg.in/go-jose/go-jose.v2", "github.com/go-jose/go-jose", "github.com/go-jose/go-jose"},
		{"gopkg.in/yaml.v3", "github.com/go-yaml/yaml", "github.com/go-yaml/yaml"},
		{"gopkg.in/user/repo/subpkg.v2", "github.com/user/repo/subpkg", "github.com/user/repo/subpkg"},
		{"modernc.org/cc/v3", "modernc.org/cc/v3", "modernc.org/cc"},
		{"github.com/example/pkg/v10", "github.com/example/pkg/v10", "github.com/example/pkg"},
		{"github.com/example/pkg/v1", "github.com/example/pkg/v1", "github.com/example/pkg/v1"},
	}

	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := normalizeGopkgInURL(c.in); got != c.norm {
				t.Fatalf("normalizeGopkgInURL(%q) = %q, want %q", c.in, got, c.norm)
			}
			if got := extractCanonicalPackageName(c.in); got != c.canon {
				t.Fatalf("extractCanonicalPackageName(%q) = %q, want %q", c.in, got, c.canon)
			}
		})
	}
}

// helper to write a minimal go.mod for testing direct deps
// helper to create a temp directory with a go.mod and return the dir path
func writeTempGoMod(t *testing.T, content string) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "deputy-test-")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	fpath := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(fpath, []byte(content), 0644); err != nil {
		os.RemoveAll(dir)
		t.Fatalf("failed to write go.mod: %v", err)
	}
	return dir
}

func removeTempGoMod(t *testing.T, dir string) {
	t.Helper()
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("failed to remove temp dir: %v", err)
	}
}

func Test_comparePackages_basic_changes(t *testing.T) {
	// Prepare a temporary go.mod marking github.com/example/pkg as a direct dep
	gm := `module test

go 1.20

require (
    github.com/example/pkg v1.2.3
)
`
	tmpDir := writeTempGoMod(t, gm)
	defer removeTempGoMod(t, tmpDir)
	// chdir into temp dir so getDirectDependencies reads the temporary go.mod
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmp dir: %v", err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	old := []*extractor.Package{
		{Name: "github.com/example/pkg/v2", Version: "2.1.0"},
		{Name: "modernc.org/cc/v3", Version: "3.41.0"},
	}

	new := []*extractor.Package{
		{Name: "github.com/example/pkg/v3", Version: "3.0.0"}, // major upgrade
		{Name: "modernc.org/cc/v3", Version: "3.42.0"},        // minor upgrade
		{Name: "github.com/new/pkg", Version: "1.0.0"},        // added
	}

	changes := comparePackages(old, new)

	if len(changes) == 0 {
		t.Fatalf("expected some changes, got none")
	}

	// Find changes by canonical name
	found := map[string]PackageChange{}
	for _, c := range changes {
		found[c.Name] = c
	}

	// Expect github.com/example/pkg upgrade (canonical github.com/example/pkg)
	var sawExample bool
	for _, c := range changes {
		if extractCanonicalPackageName(c.Name) == "github.com/example/pkg" || extractCanonicalPackageName(c.OldName) == "github.com/example/pkg" {
			sawExample = true
			if c.ChangeType != Updated {
				t.Fatalf("expected example pkg to be Updated, got %v", c.ChangeType)
			}
			break
		}
	}
	if !sawExample {
		t.Fatalf("did not see example package change in %v", changes)
	}

	// Expect new package to be present as Added
	var sawNew bool
	for _, c := range changes {
		if c.ChangeType == Added && extractCanonicalPackageName(c.Name) == "github.com/new/pkg" {
			sawNew = true
			break
		}
	}
	if !sawNew {
		t.Fatalf("expected new package to be added, changes=%v", changes)
	}
}
