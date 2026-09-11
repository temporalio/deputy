package dependency

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory/location"
)

func TestPackagePaths(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want []string
	}{
		{name: "nil package"},
		{name: "no location", pkg: &extractor.Package{Name: "lodash"}},
		{
			name: "descriptor only",
			pkg:  &extractor.Package{Location: extractor.LocationFromPath("package-lock.json")},
			want: []string{"package-lock.json"},
		},
		{
			name: "descriptor first then related",
			pkg:  &extractor.Package{Location: NewPackageLocation("go.mod", "go.sum")},
			want: []string{"go.mod", "go.sum"},
		},
		{
			name: "blank and duplicate paths dropped",
			pkg:  &extractor.Package{Location: NewPackageLocation("go.mod", "", "go.mod", "go.sum")},
			want: []string{"go.mod", "go.sum"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := PackagePaths(tt.pkg); !slices.Equal(got, tt.want) {
				t.Errorf("PackagePaths() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSetPackagePathsPreservesDescriptorLine covers the case that motivated
// keeping the existing descriptor: upstream extractors record a line number on
// it, and filtering the path list must not throw that away.
func TestSetPackagePathsPreservesDescriptorLine(t *testing.T) {
	pkg := &extractor.Package{Location: extractor.LocationFromPathAndLine("Cargo.toml", 42)}
	SetPackagePaths(pkg, []string{"Cargo.toml", "Cargo.lock"})

	if got := pkg.Location.Descriptor.File.LineNumber; got != 42 {
		t.Errorf("descriptor line = %d, want 42 preserved", got)
	}
	if got := PackagePaths(pkg); !slices.Equal(got, []string{"Cargo.toml", "Cargo.lock"}) {
		t.Errorf("PackagePaths() = %v, want [Cargo.toml Cargo.lock]", got)
	}
}

// TestSetPackagePathsReplacesDroppedDescriptor pins the other branch: when the
// old descriptor is filtered out, the first remaining path becomes the
// descriptor rather than the package keeping a location it no longer has.
func TestSetPackagePathsReplacesDroppedDescriptor(t *testing.T) {
	pkg := &extractor.Package{Location: NewPackageLocation("cmd.test", "go.mod")}
	SetPackagePaths(pkg, []string{"go.mod"})

	if got := pkg.Location.PathOrEmpty(); got != "go.mod" {
		t.Errorf("descriptor = %q, want go.mod", got)
	}
	if got := pkg.Location.Related; len(got) != 0 {
		t.Errorf("related = %v, want empty", got)
	}
}

// TestSetPackagePathsClearsOnEmpty guards against an empty path list leaving a
// stale descriptor behind, which would report a package at a file it was filtered
// out of.
func TestSetPackagePathsClearsOnEmpty(t *testing.T) {
	pkg := &extractor.Package{Location: NewPackageLocation("go.mod")}
	SetPackagePaths(pkg, nil)

	if pkg.Location.Descriptor != nil || len(pkg.Location.Related) != 0 {
		t.Errorf("location = %+v, want zero value", pkg.Location)
	}
	if got := PackagePaths(pkg); got != nil {
		t.Errorf("PackagePaths() = %v, want nil", got)
	}
}

func TestNewPackageLocation(t *testing.T) {
	if got := NewPackageLocation(); got.Descriptor != nil || len(got.Related) != 0 {
		t.Errorf("NewPackageLocation() = %+v, want zero value", got)
	}
	got := NewPackageLocation("a", "b", "c")
	if got.Descriptor.PathOrEmpty() != "a" {
		t.Errorf("descriptor = %q, want a", got.Descriptor.PathOrEmpty())
	}
	want := []location.Location{location.FromPath("b"), location.FromPath("c")}
	if len(got.Related) != len(want) {
		t.Fatalf("related = %v, want %v", got.Related, want)
	}
	for i := range want {
		if got.Related[i].PathOrEmpty() != want[i].PathOrEmpty() {
			t.Errorf("related[%d] = %q, want %q", i, got.Related[i].PathOrEmpty(), want[i].PathOrEmpty())
		}
	}
}
