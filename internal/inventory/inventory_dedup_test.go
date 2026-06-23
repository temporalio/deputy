package inventory

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestDeduplicatePackages(t *testing.T) {
	tests := []struct {
		name      string
		input     []*extractor.Package
		wantCount int
		wantLocs  map[string][]string // PURL -> expected locations
	}{
		{
			name:      "nil input",
			input:     nil,
			wantCount: 0,
		},
		{
			name:      "empty input",
			input:     []*extractor.Package{},
			wantCount: 0,
		},
		{
			name: "no duplicates",
			input: []*extractor.Package{
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.mod"}},
				{Name: "bar", Version: "2.0.0", PURLType: "golang", Locations: []string{"go.mod"}},
			},
			wantCount: 2,
		},
		{
			name: "duplicate packages merged",
			input: []*extractor.Package{
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.mod"}},
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.sum"}},
			},
			wantCount: 1,
			wantLocs: map[string][]string{
				"pkg:golang/foo@1.0.0": {"go.mod", "go.sum"},
			},
		},
		{
			name: "same name different version not merged",
			input: []*extractor.Package{
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.mod"}},
				{Name: "foo", Version: "2.0.0", PURLType: "golang", Locations: []string{"go.mod"}},
			},
			wantCount: 2,
		},
		{
			name: "merges licenses from duplicate",
			input: []*extractor.Package{
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.mod"}, Licenses: nil},
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.sum"}, Licenses: []string{"MIT"}},
			},
			wantCount: 1,
		},
		{
			name: "skips nil packages",
			input: []*extractor.Package{
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.mod"}},
				nil,
				{Name: "bar", Version: "1.0.0", PURLType: "golang", Locations: []string{"go.mod"}},
			},
			wantCount: 2,
		},
		{
			name: "multiple duplicates",
			input: []*extractor.Package{
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"a/go.mod"}},
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"b/go.mod"}},
				{Name: "foo", Version: "1.0.0", PURLType: "golang", Locations: []string{"c/go.mod"}},
			},
			wantCount: 1,
			wantLocs: map[string][]string{
				"pkg:golang/foo@1.0.0": {"a/go.mod", "b/go.mod", "c/go.mod"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicatePackages(tt.input)

			if len(got) != tt.wantCount {
				t.Errorf("deduplicatePackages() returned %d packages, want %d", len(got), tt.wantCount)
			}

			// Check location merging if specified
			if tt.wantLocs != nil {
				for _, pkg := range got {
					purl := pkg.PURL()
					if purl == nil {
						continue
					}
					key := purl.String()
					if expectedLocs, ok := tt.wantLocs[key]; ok {
						if len(pkg.Locations) != len(expectedLocs) {
							t.Errorf("package %s has %d locations, want %d: got %v, want %v",
								key, len(pkg.Locations), len(expectedLocs), pkg.Locations, expectedLocs)
						}
						// Check all expected locations are present
						locSet := make(map[string]bool)
						for _, loc := range pkg.Locations {
							locSet[loc] = true
						}
						for _, expectedLoc := range expectedLocs {
							if !locSet[expectedLoc] {
								t.Errorf("package %s missing location %q", key, expectedLoc)
							}
						}
					}
				}
			}
		})
	}
}

// TestDeduplicatePackagesDeterminism verifies that deduplicatePackages returns
// packages in a deterministic order regardless of input order or map iteration.
// This is a regression test for non-deterministic diff output.
func TestDeduplicatePackagesDeterminism(t *testing.T) {
	// Create packages that would appear in different orders with random map iteration
	pkgs := []*extractor.Package{
		{Name: "github.com/z/last", Version: "1.0.0", PURLType: "golang"},
		{Name: "github.com/a/first", Version: "1.0.0", PURLType: "golang"},
		{Name: "github.com/m/middle", Version: "1.0.0", PURLType: "golang"},
		{Name: "github.com/charmbracelet/lipgloss", Version: "1.0.0", PURLType: "golang"},
		{Name: "github.com/charmbracelet/lipgloss/v2", Version: "2.0.0", PURLType: "golang"},
	}

	// Run deduplication multiple times to verify determinism
	var firstResult []*extractor.Package
	for i := range 100 {
		// Shuffle input to simulate different iteration orders
		shuffled := make([]*extractor.Package, len(pkgs))
		copy(shuffled, pkgs)
		// Reverse every other iteration to vary input order
		if i%2 == 1 {
			slices.Reverse(shuffled)
		}

		result := deduplicatePackages(shuffled)

		if firstResult == nil {
			firstResult = result
			continue
		}

		// Verify same length
		if len(result) != len(firstResult) {
			t.Fatalf("iteration %d: got %d packages, want %d", i, len(result), len(firstResult))
		}

		// Verify exact same order
		for j := range result {
			if result[j].Name != firstResult[j].Name {
				t.Errorf("iteration %d, index %d: got name %q, want %q",
					i, j, result[j].Name, firstResult[j].Name)
			}
			if result[j].Version != firstResult[j].Version {
				t.Errorf("iteration %d, index %d: got version %q, want %q",
					i, j, result[j].Version, firstResult[j].Version)
			}
		}
	}

	// Verify the order is sorted by PURL
	for i := 1; i < len(firstResult); i++ {
		prevPURL := firstResult[i-1].PURL().String()
		currPURL := firstResult[i].PURL().String()
		if prevPURL >= currPURL {
			t.Errorf("packages not sorted: %q should come before %q", prevPURL, currPURL)
		}
	}
}

func TestMergeLocations(t *testing.T) {
	tests := []struct {
		name string
		a    []string
		b    []string
		want []string // expected sorted output
	}{
		{
			name: "empty both",
			a:    nil,
			b:    nil,
			want: nil,
		},
		{
			name: "empty a",
			a:    nil,
			b:    []string{"y", "x"},
			want: []string{"x", "y"}, // sorted
		},
		{
			name: "empty b",
			a:    []string{"y", "x"},
			b:    nil,
			want: []string{"x", "y"}, // sorted
		},
		{
			name: "no overlap",
			a:    []string{"b", "a"},
			b:    []string{"d", "c"},
			want: []string{"a", "b", "c", "d"}, // sorted
		},
		{
			name: "with overlap",
			a:    []string{"b", "a"},
			b:    []string{"c", "b"},
			want: []string{"a", "b", "c"}, // sorted, deduplicated
		},
		{
			name: "all overlap",
			a:    []string{"b", "a"},
			b:    []string{"a", "b"},
			want: []string{"a", "b"}, // sorted
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Make copies to avoid modifying test data
			aCopy := slices.Clone(tt.a)
			bCopy := slices.Clone(tt.b)
			got := mergeLocations(aCopy, bCopy)

			if len(got) != len(tt.want) {
				t.Errorf("mergeLocations() = %v, want %v", got, tt.want)
				return
			}

			// Verify exact order (result should be sorted)
			for i, w := range tt.want {
				if got[i] != w {
					t.Errorf("mergeLocations()[%d] = %q, want %q; full result: %v", i, got[i], w, got)
				}
			}
		})
	}
}

// TestMergeLocationsDeterminism verifies that mergeLocations returns sorted output.
func TestMergeLocationsDeterminism(t *testing.T) {
	a := []string{"z/go.mod", "a/go.mod", "m/go.mod"}
	b := []string{"y/go.sum", "b/go.sum"}

	result := mergeLocations(slices.Clone(a), slices.Clone(b))

	// Verify sorted
	if !slices.IsSorted(result) {
		t.Errorf("mergeLocations() result not sorted: %v", result)
	}

	// Verify all elements present
	expected := []string{"a/go.mod", "b/go.sum", "m/go.mod", "y/go.sum", "z/go.mod"}
	if !slices.Equal(result, expected) {
		t.Errorf("mergeLocations() = %v, want %v", result, expected)
	}
}
