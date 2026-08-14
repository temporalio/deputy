package inventory

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/temporalio/deputy/internal/dependency"
)

// TestPreferLockfileResolutions pins a live-spin regression: scalibr's
// rust/cargotoml extractor reports Cargo.toml requirement strings as versions
// (tokio = "1.26" while Cargo.lock resolves 1.52.3), so lock-resolved
// manifests must not contribute requirement-derived entries to the inventory.
func TestPreferLockfileResolutions(t *testing.T) {
	tests := []struct {
		name  string
		input []*extractor.Package
		want  []string // remaining name@version entries
	}{
		{
			name:  "empty input",
			input: nil,
			want:  []string{},
		},
		{
			name: "lock in same directory drops manifest entries",
			input: []*extractor.Package{
				{Name: "tokio", Version: "1.26", PURLType: "cargo", Location: extractor.LocationFromPath("bridge/Cargo.toml")},
				{Name: "tokio", Version: "1.52.3", PURLType: "cargo", Location: extractor.LocationFromPath("bridge/Cargo.lock")},
			},
			want: []string{"tokio@1.52.3"},
		},
		{
			name: "workspace root lock covers member crate manifests",
			input: []*extractor.Package{
				{Name: "anyhow", Version: "1.0", PURLType: "cargo", Location: extractor.LocationFromPath("crates/core/Cargo.toml")},
				{Name: "anyhow", Version: "1.0.103", PURLType: "cargo", Location: extractor.LocationFromPath("Cargo.lock")},
			},
			want: []string{"anyhow@1.0.103"},
		},
		{
			name: "manifest without a covering lock keeps requirement entries",
			input: []*extractor.Package{
				{Name: "serde", Version: "1.0", PURLType: "cargo", Location: extractor.LocationFromPath("tools/Cargo.toml")},
				{Name: "tokio", Version: "1.52.3", PURLType: "cargo", Location: extractor.LocationFromPath("bridge/Cargo.lock")},
			},
			want: []string{"serde@1.0", "tokio@1.52.3"},
		},
		{
			name: "sibling directory lock does not cover an unrelated manifest",
			input: []*extractor.Package{
				{Name: "serde", Version: "1.0", PURLType: "cargo", Location: extractor.LocationFromPath("a/Cargo.toml")},
				{Name: "tokio", Version: "1.52.3", PURLType: "cargo", Location: extractor.LocationFromPath("b/Cargo.lock")},
			},
			want: []string{"serde@1.0", "tokio@1.52.3"},
		},
		{
			name: "covered manifest location is trimmed from a mixed-source package",
			input: []*extractor.Package{
				{Name: "anyhow", Version: "1.0.103", PURLType: "cargo", Location: dependency.NewPackageLocation("Cargo.lock", "Cargo.toml")},
			},
			want: []string{"anyhow@1.0.103"},
		},
		{
			// A workspace root Cargo.lock only covers member crates. A nested
			// crate excluded from the workspace has no lock of its own, so its
			// packages were never resolved by the root lock; dropping the
			// manifest entry would erase them from the inventory entirely.
			name: "workspace-excluded nested crate keeps its manifest entry",
			input: []*extractor.Package{
				{Name: "rand", Version: "0.8", PURLType: "cargo", Location: extractor.LocationFromPath("tools/standalone/Cargo.toml")},
				{Name: "anyhow", Version: "1.0.103", PURLType: "cargo", Location: extractor.LocationFromPath("Cargo.lock")},
			},
			want: []string{"anyhow@1.0.103", "rand@0.8"},
		},
		{
			name: "vendored crate manifest survives an unrelated root lock",
			input: []*extractor.Package{
				{Name: "libc", Version: "0.2", PURLType: "cargo", Location: extractor.LocationFromPath("third_party/libc/Cargo.toml")},
				{Name: "anyhow", Version: "1.0.103", PURLType: "cargo", Location: extractor.LocationFromPath("Cargo.lock")},
			},
			want: []string{"anyhow@1.0.103", "libc@0.2"},
		},
		{
			// The safe condition for dropping: an ancestor lock that actually
			// contains the package resolved it, so the manifest entry yields
			// even for a crate the workspace excludes (the exact version in
			// the inventory beats a requirement string).
			name: "manifest yields when an ancestor lock contains the same package",
			input: []*extractor.Package{
				{Name: "tokio", Version: "1.26", PURLType: "cargo", Location: extractor.LocationFromPath("tools/standalone/Cargo.toml")},
				{Name: "tokio", Version: "1.52.3", PURLType: "cargo", Location: extractor.LocationFromPath("Cargo.lock")},
			},
			want: []string{"tokio@1.52.3"},
		},
		{
			// Lockfile containment is keyed on name and PURL type together:
			// a same-named package from another ecosystem must not count as
			// a resolution.
			name: "same-named package in another ecosystem does not resolve a manifest",
			input: []*extractor.Package{
				{Name: "shared-name", Version: "1.0", PURLType: "cargo", Location: extractor.LocationFromPath("Cargo.toml")},
				{Name: "shared-name", Version: "2.0.0", PURLType: "npm", Location: extractor.LocationFromPath("Cargo.lock")},
			},
			want: []string{"shared-name@1.0", "shared-name@2.0.0"},
		},
		{
			name: "non-cargo manifests are untouched",
			input: []*extractor.Package{
				{Name: "lodash", Version: "4.17.21", PURLType: "npm", Location: extractor.LocationFromPath("package.json")},
				{Name: "tokio", Version: "1.52.3", PURLType: "cargo", Location: extractor.LocationFromPath("Cargo.lock")},
			},
			want: []string{"lodash@4.17.21", "tokio@1.52.3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := preferLockfileResolutions(tt.input)
			entries := make([]string, 0, len(got))
			for _, pkg := range got {
				entries = append(entries, pkg.Name+"@"+pkg.Version)
			}
			slices.Sort(entries)
			if !slices.Equal(entries, tt.want) {
				t.Errorf("remaining packages = %v, want %v", entries, tt.want)
			}
		})
	}
}

// TestPreferLockfileResolutionsTrimsCoveredLocations verifies that a package
// discovered from both a manifest and its lockfile keeps only the lockfile
// location, so manifest refs downstream point at the resolution source.
func TestPreferLockfileResolutionsTrimsCoveredLocations(t *testing.T) {
	pkgs := preferLockfileResolutions([]*extractor.Package{
		{Name: "anyhow", Version: "1.0.103", PURLType: "cargo", Location: dependency.NewPackageLocation("Cargo.lock", "Cargo.toml")},
	})
	if len(pkgs) != 1 {
		t.Fatalf("packages = %d, want 1", len(pkgs))
	}
	if want := []string{"Cargo.lock"}; !slices.Equal(dependency.PackagePaths(pkgs[0]), want) {
		t.Errorf("locations = %v, want %v", dependency.PackagePaths(pkgs[0]), want)
	}
}
