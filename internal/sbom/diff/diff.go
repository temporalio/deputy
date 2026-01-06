// Package diff provides SBOM comparison and change detection.
//
// This package enables comparing two SBOM documents to identify:
//   - Added packages (present in new, absent in old)
//   - Removed packages (present in old, absent in new)
//   - Changed packages (version or license changes)
//
// # Usage
//
//	old, _ := sbomx.ReadFile("old-sbom.json")
//	new, _ := sbomx.ReadFile("new-sbom.json")
//	diff, err := diff.Compare(old, new)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(diff.Summary())
//
// # Impact Analysis
//
// The diff can be enriched with vulnerability impact analysis to identify
// which vulnerabilities are introduced or resolved by the changes:
//
//	impact, _ := diff.AnalyzeImpact(ctx)
//	for _, vuln := range impact.NewVulns {
//	    fmt.Printf("New vulnerability: %s in %s\n", vuln.VulnID, vuln.Package.Name)
//	}
package diff

import (
	"fmt"
	"slices"
	"strings"

	"github.com/protobom/protobom/pkg/sbom"
	"golang.org/x/mod/semver"
)

// Diff represents the changes between two SBOM documents.
type Diff struct {
	// Old is the original SBOM document.
	Old *sbom.Document

	// New is the updated SBOM document.
	New *sbom.Document

	// Added contains packages present in New but not in Old.
	Added []Package

	// Removed contains packages present in Old but not in New.
	Removed []Package

	// Changed contains packages with version or license changes.
	Changed []Change
}

// Package represents a package extracted from an SBOM.
type Package struct {
	// PURL is the Package URL identifier.
	PURL string `json:"purl,omitempty"`

	// Name is the package name.
	Name string `json:"name"`

	// Version is the package version.
	Version string `json:"version"`

	// Ecosystem is the package ecosystem (derived from PURL type).
	Ecosystem string `json:"ecosystem,omitempty"`

	// Licenses contains SPDX license identifiers.
	Licenses []string `json:"licenses,omitempty"`
}

// String returns a human-readable representation of the package.
func (p Package) String() string {
	if p.Version != "" {
		return p.Name + "@" + p.Version
	}
	return p.Name
}

// Change represents a package that changed between SBOM versions.
type Change struct {
	// PURL is the Package URL identifier (from the new version).
	PURL string `json:"purl,omitempty"`

	// Name is the package name.
	Name string `json:"name"`

	// OldVersion is the version in the old SBOM.
	OldVersion string `json:"old_version"`

	// NewVersion is the version in the new SBOM.
	NewVersion string `json:"new_version"`

	// Kind indicates the type of version change.
	Kind ChangeKind `json:"kind"`

	// Licenses tracks license changes.
	Licenses LicenseChange `json:"licenses,omitempty"`
}

// String returns a human-readable representation of the change.
func (c Change) String() string {
	return fmt.Sprintf("%s: %s -> %s (%s)", c.Name, c.OldVersion, c.NewVersion, c.Kind)
}

// ChangeKind indicates the semantic versioning change type.
type ChangeKind string

const (
	// ChangeKindMajor indicates a major version change (breaking).
	ChangeKindMajor ChangeKind = "major"

	// ChangeKindMinor indicates a minor version change (feature).
	ChangeKindMinor ChangeKind = "minor"

	// ChangeKindPatch indicates a patch version change (fix).
	ChangeKindPatch ChangeKind = "patch"

	// ChangeKindDowngrade indicates a version downgrade.
	ChangeKindDowngrade ChangeKind = "downgrade"

	// ChangeKindUnknown indicates the change type couldn't be determined.
	ChangeKindUnknown ChangeKind = "unknown"
)

// LicenseChange tracks license modifications.
type LicenseChange struct {
	// Added contains licenses added in the new version.
	Added []string `json:"added,omitempty"`

	// Removed contains licenses removed in the new version.
	Removed []string `json:"removed,omitempty"`
}

// HasChange reports whether there are any license changes.
func (lc LicenseChange) HasChange() bool {
	return len(lc.Added) > 0 || len(lc.Removed) > 0
}

// Compare generates a diff between two SBOM documents.
// Returns an error if either document is nil.
func Compare(old, new *sbom.Document) (*Diff, error) {
	if old == nil {
		return nil, fmt.Errorf("old SBOM is nil")
	}
	if new == nil {
		return nil, fmt.Errorf("new SBOM is nil")
	}

	oldPkgs := extractPackages(old)
	newPkgs := extractPackages(new)

	// Index by name for comparison
	oldByName := indexByName(oldPkgs)
	newByName := indexByName(newPkgs)

	diff := &Diff{
		Old: old,
		New: new,
	}

	// Find added packages
	for name, pkg := range newByName {
		if _, exists := oldByName[name]; !exists {
			diff.Added = append(diff.Added, pkg)
		}
	}

	// Find removed packages
	for name, pkg := range oldByName {
		if _, exists := newByName[name]; !exists {
			diff.Removed = append(diff.Removed, pkg)
		}
	}

	// Find changed packages
	for name, newPkg := range newByName {
		if oldPkg, exists := oldByName[name]; exists {
			if oldPkg.Version != newPkg.Version || !slices.Equal(oldPkg.Licenses, newPkg.Licenses) {
				change := Change{
					PURL:       newPkg.PURL,
					Name:       name,
					OldVersion: oldPkg.Version,
					NewVersion: newPkg.Version,
					Kind:       classifyChange(oldPkg.Version, newPkg.Version),
					Licenses:   compareLicenses(oldPkg.Licenses, newPkg.Licenses),
				}
				diff.Changed = append(diff.Changed, change)
			}
		}
	}

	// Sort for deterministic output
	slices.SortFunc(diff.Added, func(a, b Package) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(diff.Removed, func(a, b Package) int { return strings.Compare(a.Name, b.Name) })
	slices.SortFunc(diff.Changed, func(a, b Change) int { return strings.Compare(a.Name, b.Name) })

	return diff, nil
}

// extractPackages converts an SBOM document to a slice of Package.
func extractPackages(doc *sbom.Document) []Package {
	if doc == nil || doc.NodeList == nil {
		return nil
	}

	var pkgs []Package
	for _, node := range doc.NodeList.Nodes {
		if node == nil {
			continue
		}

		pkg := Package{
			Name:     node.Name,
			Version:  node.Version,
			Licenses: node.Licenses,
		}

		// Extract PURL from identifiers
		if node.Identifiers != nil {
			if purl, ok := node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]; ok {
				pkg.PURL = purl
				pkg.Ecosystem = extractEcosystem(purl)
			}
		}

		pkgs = append(pkgs, pkg)
	}

	return pkgs
}

// extractEcosystem extracts the ecosystem from a PURL.
func extractEcosystem(purl string) string {
	// PURL format: pkg:type/namespace/name@version
	if !strings.HasPrefix(purl, "pkg:") {
		return ""
	}
	rest := strings.TrimPrefix(purl, "pkg:")
	if idx := strings.Index(rest, "/"); idx > 0 {
		return rest[:idx]
	}
	return ""
}

// indexByName creates a map from package name to package.
func indexByName(pkgs []Package) map[string]Package {
	m := make(map[string]Package)
	for _, pkg := range pkgs {
		m[pkg.Name] = pkg
	}
	return m
}

// classifyChange determines the type of version change.
func classifyChange(oldVer, newVer string) ChangeKind {
	// Normalize versions for semver comparison
	oldNorm := normalizeVersion(oldVer)
	newNorm := normalizeVersion(newVer)

	if !semver.IsValid(oldNorm) || !semver.IsValid(newNorm) {
		return ChangeKindUnknown
	}

	cmp := semver.Compare(oldNorm, newNorm)
	if cmp > 0 {
		return ChangeKindDowngrade
	}
	if cmp == 0 {
		return ChangeKindUnknown
	}

	// Determine if major, minor, or patch
	oldMajor := semver.Major(oldNorm)
	newMajor := semver.Major(newNorm)
	if oldMajor != newMajor {
		return ChangeKindMajor
	}

	// Extract minor versions
	oldMinor := extractMinor(oldNorm)
	newMinor := extractMinor(newNorm)
	if oldMinor != newMinor {
		return ChangeKindMinor
	}

	return ChangeKindPatch
}

// normalizeVersion ensures version has a 'v' prefix for semver.
func normalizeVersion(v string) string {
	if v == "" {
		return ""
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// extractMinor extracts the minor version component.
func extractMinor(v string) string {
	// v1.2.3 -> 1.2
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}

// compareLicenses identifies added and removed licenses.
func compareLicenses(old, new []string) LicenseChange {
	oldSet := make(map[string]bool)
	for _, l := range old {
		oldSet[l] = true
	}

	newSet := make(map[string]bool)
	for _, l := range new {
		newSet[l] = true
	}

	var change LicenseChange

	for l := range newSet {
		if !oldSet[l] {
			change.Added = append(change.Added, l)
		}
	}

	for l := range oldSet {
		if !newSet[l] {
			change.Removed = append(change.Removed, l)
		}
	}

	slices.Sort(change.Added)
	slices.Sort(change.Removed)

	return change
}

// Stats returns summary statistics about the diff.
func (d *Diff) Stats() Stats {
	stats := Stats{
		Added:   len(d.Added),
		Removed: len(d.Removed),
		Changed: len(d.Changed),
	}

	for _, c := range d.Changed {
		if c.Kind == ChangeKindMajor {
			stats.Breaking++
		}
		if c.Kind == ChangeKindDowngrade {
			stats.Downgrades++
		}
		if c.Licenses.HasChange() {
			stats.LicenseChanges++
		}
	}

	return stats
}

// Stats contains summary statistics about a diff.
type Stats struct {
	Added          int `json:"added"`
	Removed        int `json:"removed"`
	Changed        int `json:"changed"`
	Breaking       int `json:"breaking"`        // major version changes
	Downgrades     int `json:"downgrades"`      // version downgrades
	LicenseChanges int `json:"license_changes"` // packages with license changes
}

// Empty reports whether the diff contains no changes.
func (d *Diff) Empty() bool {
	return len(d.Added) == 0 && len(d.Removed) == 0 && len(d.Changed) == 0
}

// Summary generates a human-readable summary of the diff.
func (d *Diff) Summary() string {
	if d.Empty() {
		return "No changes detected"
	}

	var b strings.Builder
	stats := d.Stats()

	fmt.Fprintf(&b, "SBOM Diff Summary:\n")
	fmt.Fprintf(&b, "  Added:   %d packages\n", stats.Added)
	fmt.Fprintf(&b, "  Removed: %d packages\n", stats.Removed)
	fmt.Fprintf(&b, "  Changed: %d packages\n", stats.Changed)

	if stats.Breaking > 0 {
		fmt.Fprintf(&b, "  Breaking changes: %d\n", stats.Breaking)
	}
	if stats.Downgrades > 0 {
		fmt.Fprintf(&b, "  Downgrades: %d\n", stats.Downgrades)
	}
	if stats.LicenseChanges > 0 {
		fmt.Fprintf(&b, "  License changes: %d\n", stats.LicenseChanges)
	}

	return b.String()
}

// AddedNames returns the names of all added packages.
func (d *Diff) AddedNames() []string {
	names := make([]string, len(d.Added))
	for i, p := range d.Added {
		names[i] = p.Name
	}
	return names
}

// RemovedNames returns the names of all removed packages.
func (d *Diff) RemovedNames() []string {
	names := make([]string, len(d.Removed))
	for i, p := range d.Removed {
		names[i] = p.Name
	}
	return names
}

// ChangedNames returns the names of all changed packages.
func (d *Diff) ChangedNames() []string {
	names := make([]string, len(d.Changed))
	for i, c := range d.Changed {
		names[i] = c.Name
	}
	return names
}

// BreakingChanges returns only changes with major version bumps.
func (d *Diff) BreakingChanges() []Change {
	var breaking []Change
	for _, c := range d.Changed {
		if c.Kind == ChangeKindMajor {
			breaking = append(breaking, c)
		}
	}
	return breaking
}

// Downgrades returns only changes that are version downgrades.
func (d *Diff) Downgrades() []Change {
	var downgrades []Change
	for _, c := range d.Changed {
		if c.Kind == ChangeKindDowngrade {
			downgrades = append(downgrades, c)
		}
	}
	return downgrades
}

// LicenseOnlyChanges returns changes where only licenses changed (not version).
func (d *Diff) LicenseOnlyChanges() []Change {
	var licenseOnly []Change
	for _, c := range d.Changed {
		if c.OldVersion == c.NewVersion && c.Licenses.HasChange() {
			licenseOnly = append(licenseOnly, c)
		}
	}
	return licenseOnly
}
