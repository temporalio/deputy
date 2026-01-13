package plugin

import (
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
)

// NewPackage creates a new Package with the given name, version, and ecosystem.
// This is a convenience function for plugin authors.
//
// Example:
//
//	pkg := plugin.NewPackage("lodash", "4.17.21", "npm")
func NewPackage(name, version, ecosystem string) *Package {
	return &dependencyv1.Package{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
	}
}

// PackageBuilder provides a fluent interface for building Package instances.
//
// Example:
//
//	pkg := plugin.NewPackageBuilder("lodash", "4.17.21", "npm").
//	    WithPURL("pkg:npm/lodash@4.17.21").
//	    WithLicenses("MIT").
//	    WithDirect(true).
//	    Build()
type PackageBuilder struct {
	pkg *Package
}

// NewPackageBuilder creates a new PackageBuilder with required fields.
func NewPackageBuilder(name, version, ecosystem string) *PackageBuilder {
	return &PackageBuilder{
		pkg: &dependencyv1.Package{
			Name:      name,
			Version:   version,
			Ecosystem: ecosystem,
		},
	}
}

// WithPURL sets the Package URL (PURL).
func (b *PackageBuilder) WithPURL(purl string) *PackageBuilder {
	b.pkg.Purl = purl
	return b
}

// WithLicenses sets the SPDX license identifiers.
func (b *PackageBuilder) WithLicenses(licenses ...string) *PackageBuilder {
	b.pkg.Licenses = licenses
	return b
}

// WithDirect marks the package as a direct dependency.
func (b *PackageBuilder) WithDirect(direct bool) *PackageBuilder {
	b.pkg.Direct = direct
	return b
}

// WithLocations sets the file paths where this package was found.
func (b *PackageBuilder) WithLocations(locations ...string) *PackageBuilder {
	b.pkg.Locations = locations
	return b
}

// WithManifestRef adds a manifest reference describing where the dependency is declared.
func (b *PackageBuilder) WithManifestRef(path, manager string, groups ...string) *PackageBuilder {
	b.pkg.ManifestRefs = append(b.pkg.ManifestRefs, &dependencyv1.ManifestRef{
		Path:    path,
		Manager: manager,
		Groups:  groups,
	})
	return b
}

// Build returns the constructed Package.
func (b *PackageBuilder) Build() *Package {
	return b.pkg
}
