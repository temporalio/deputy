package dependency

import (
	"slices"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory/location"
)

// PackagePaths returns every file path OSV-SCALIBR recorded for a package: the
// descriptor it was extracted from (a manifest or lockfile) first, then any
// related files, with blanks and duplicates dropped.
//
// Upstream replaced the package's flat Locations slice with a structured
// PackageLocation, while Deputy's dependency records still carry a flat list of
// declaring paths. This is the single place that flattens one into the other, so
// callers stay agnostic about how upstream models locations.
func PackagePaths(pkg *extractor.Package) []string {
	if pkg == nil {
		return nil
	}
	paths := make([]string, 0, 1+len(pkg.Location.Related))
	appendPath := func(path string) {
		if path == "" {
			return
		}
		for _, existing := range paths {
			if existing == path {
				return
			}
		}
		paths = append(paths, path)
	}
	appendPath(pkg.Location.PathOrEmpty())
	for _, related := range pkg.Location.Related {
		appendPath(related.PathOrEmpty())
	}
	if len(paths) == 0 {
		return nil
	}
	return paths
}

// NewPackageLocation builds the location of a package declared in paths, taking
// the first as the descriptor and the rest as related locations. It is the
// counterpart of [PackagePaths] for callers that know a package's paths up front.
func NewPackageLocation(paths ...string) extractor.PackageLocation {
	if len(paths) == 0 {
		return extractor.PackageLocation{}
	}
	descriptor := location.FromPath(paths[0])
	return relateRemaining(&descriptor, paths)
}

// SetPackagePaths replaces a package's recorded locations with paths, the
// inverse of [PackagePaths]. The first path becomes the descriptor and the rest
// become related locations. When the existing descriptor is still in paths it is
// kept as-is so any line number upstream recorded survives the rewrite.
func SetPackagePaths(pkg *extractor.Package, paths []string) {
	if pkg == nil {
		return
	}
	if len(paths) == 0 {
		pkg.Location = extractor.PackageLocation{}
		return
	}
	descriptor := pkg.Location.Descriptor
	if descriptor == nil || !slices.Contains(paths, descriptor.PathOrEmpty()) {
		pkg.Location = NewPackageLocation(paths...)
		return
	}
	pkg.Location = relateRemaining(descriptor, paths)
}

// relateRemaining returns a location whose related entries are every path other
// than the descriptor's own, preserving the order paths were given in.
func relateRemaining(descriptor *location.Location, paths []string) extractor.PackageLocation {
	related := make([]location.Location, 0, len(paths))
	for _, path := range paths {
		if path == "" || path == descriptor.PathOrEmpty() {
			continue
		}
		related = append(related, location.FromPath(path))
	}
	return extractor.PackageLocation{Descriptor: descriptor, Related: related}
}
