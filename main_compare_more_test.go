package main

import (
	"os"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func Test_comparePackages_multi_new_majors(t *testing.T) {
	// use temp go.mod so direct deps don't touch repo
	gm := `module test

go 1.20
`
	tmpDir := writeTempGoMod(t, gm)
	defer removeTempGoMod(t, tmpDir)
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	old := []*extractor.Package{}
	new := []*extractor.Package{
		{Name: "github.com/example/pkg/v2", Version: "2.0.0"},
		{Name: "github.com/example/pkg/v3", Version: "3.0.0"},
	}

	changes := comparePackages(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected one summarized change, got %v", changes)
	}
	c := changes[0]
	if c.ChangeType != Updated {
		t.Fatalf("expected Updated, got %v", c.ChangeType)
	}
	if c.BaseVersion != "2.0.0" || c.TargetVersion != "3.0.0" {
		t.Fatalf("unexpected versions: %v", c)
	}
}

func Test_comparePackages_same_major_update(t *testing.T) {
	old := []*extractor.Package{{Name: "github.com/example/pkg/v3", Version: "3.1.0"}}
	new := []*extractor.Package{{Name: "github.com/example/pkg/v3", Version: "3.2.0"}}

	changes := comparePackages(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected one change, got %v", changes)
	}
	c := changes[0]
	if c.ChangeType != Updated {
		t.Fatalf("expected Updated, got %v", c.ChangeType)
	}
	// version compare should indicate upgrade
	if compareGoPackageVersions(c) != 1 {
		t.Fatalf("expected version upgrade, got %d", compareGoPackageVersions(c))
	}
}

func Test_normalizeGopkgInURL_singlepart_repo(t *testing.T) {
	in := "gopkg.in/repo.v2"
	want := "github.com/go-repo/repo"
	got := normalizeGopkgInURL(in)
	if got != want {
		t.Fatalf("normalizeGopkgInURL(%q) = %q, want %q", in, got, want)
	}

	// invalid should return original
	in2 := "gopkg.in/invalid"
	if normalizeGopkgInURL(in2) != in2 {
		t.Fatalf("expected unchanged for %q", in2)
	}
}
