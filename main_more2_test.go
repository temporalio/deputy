package main

import (
	"os"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func Test_comparePackages_major_upgrade_and_removal(t *testing.T) {
	// ensure any existing go.mod won't interfere
	// write a minimal go.mod for direct deps detection
	gm := `module test

go 1.20

require (
    github.com/example/pkg v1.2.3
)
`
	tmpDir := writeTempGoMod(t, gm)
	defer removeTempGoMod(t, tmpDir)
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to tmp dir: %v", err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	old := []*extractor.Package{{Name: "github.com/example/pkg/v2", Version: "2.1.0"}}
	new := []*extractor.Package{{Name: "github.com/example/pkg/v3", Version: "3.0.0"}}

	changes := comparePackages(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d: %v", len(changes), changes)
	}

	c := changes[0]
	if c.ChangeType != Updated {
		t.Fatalf("expected Updated change, got %v", c.ChangeType)
	}
	if c.BaseVersion != "2.1.0" || c.TargetVersion != "3.0.0" {
		t.Fatalf("unexpected versions: base=%q target=%q", c.BaseVersion, c.TargetVersion)
	}

	// Ensure compareGoPackageVersions identifies this as an upgrade
	if compareGoPackageVersions(c) != 1 {
		t.Fatalf("expected compareGoPackageVersions to return 1 for upgrade, got %d", compareGoPackageVersions(c))
	}

	// Now test removal: old has one, new has none
	changes2 := comparePackages(old, []*extractor.Package{})
	if len(changes2) != 1 {
		t.Fatalf("expected 1 removal change, got %d", len(changes2))
	}
	if changes2[0].ChangeType != Removed {
		t.Fatalf("expected Removed, got %v", changes2[0].ChangeType)
	}
}

func Test_comparePackages_gopkg_vanity_upgrade(t *testing.T) {
	// gopkg.in vanity URL upgraded to actual github path with major version bump
	old := []*extractor.Package{{Name: "gopkg.in/go-jose/go-jose.v2", Version: "2.6.3"}}
	new := []*extractor.Package{{Name: "github.com/go-jose/go-jose/v4", Version: "4.0.5"}}

	changes := comparePackages(old, new)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	c := changes[0]
	if c.ChangeType != Updated {
		t.Fatalf("expected Updated change, got %v", c.ChangeType)
	}
	// compareGoPackageVersions should see this as a major upgrade
	if compareGoPackageVersions(c) != 1 {
		t.Fatalf("expected major upgrade detected, got %d", compareGoPackageVersions(c))
	}
	// canonical names should match
	if extractCanonicalPackageName(old[0].Name) != extractCanonicalPackageName(new[0].Name) {
		t.Fatalf("expected canonical names to match: %q vs %q", extractCanonicalPackageName(old[0].Name), extractCanonicalPackageName(new[0].Name))
	}
}

func Test_getDirectDependencies_behaviour(t *testing.T) {
	// Remove any go.mod if present to test missing behavior
	// Back up existing go.mod if present
	const gmName = "go.mod"
	var backupName string
	if _, err := os.Stat(gmName); err == nil {
		backupName = gmName + ".bak"
		if err := os.Rename(gmName, backupName); err == nil {
			defer func() { os.Rename(backupName, gmName) }()
		}
	}

	// Ensure no go.mod exists
	_ = os.Remove(gmName)

	deps := getDirectDependencies()
	if !deps["stdlib"] {
		t.Fatalf("expected stdlib present when go.mod missing")
	}

	// Now create a go.mod with direct and indirect requires
	gm := `module test

go 1.20

require (
    github.com/direct/depd v1.0.0
    github.com/indirect/depd v1.2.3 // indirect
)
`
	tmpDir2 := writeTempGoMod(t, gm)
	defer removeTempGoMod(t, tmpDir2)
	oldwd2, _ := os.Getwd()
	if err := os.Chdir(tmpDir2); err != nil {
		t.Fatalf("failed to chdir to tmp dir: %v", err)
	}
	defer func() { _ = os.Chdir(oldwd2) }()

	deps2 := getDirectDependencies()
	if !deps2["github.com/direct/depd"] {
		t.Fatalf("expected direct dependency present in map")
	}
	if deps2["github.com/indirect/depd"] {
		t.Fatalf("did not expect indirect dependency to be marked as direct")
	}
}
