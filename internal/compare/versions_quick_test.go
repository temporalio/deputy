package compare

import (
	"fmt"
	"testing"
	"testing/quick"
)

// TestVersionComparisonTransitivity verifies semantic version comparison is transitive.
// Property: If A > B and B > C, then A > C.
func TestVersionComparisonTransitivity(t *testing.T) {
	f := func(a, b, c uint8) bool {
		// Generate semantic version strings from uint8 values
		v1 := fmt.Sprintf("v1.%d.0", a)
		v2 := fmt.Sprintf("v1.%d.0", b)
		v3 := fmt.Sprintf("v1.%d.0", c)

		cmp12 := CompareGoPackageVersions(v2, v1)
		cmp23 := CompareGoPackageVersions(v3, v2)
		cmp13 := CompareGoPackageVersions(v3, v1)

		// Transitivity: if v1 > v2 and v2 > v3, then v1 > v3
		if cmp12 > 0 && cmp23 > 0 {
			return cmp13 > 0
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestVersionComparisonSymmetry verifies that comparison is antisymmetric.
// Property: If Compare(A, B) = x, then Compare(B, A) = -x
func TestVersionComparisonSymmetry(t *testing.T) {
	f := func(a, b uint8) bool {
		v1 := fmt.Sprintf("v1.%d.0", a)
		v2 := fmt.Sprintf("v1.%d.0", b)

		cmp12 := CompareGoPackageVersions(v2, v1)
		cmp21 := CompareGoPackageVersions(v1, v2)

		// Antisymmetry: cmp(v1, v2) = -cmp(v2, v1)
		return cmp12 == -cmp21
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestVersionComparisonReflexivity verifies that comparing a version with itself returns 0.
func TestVersionComparisonReflexivity(t *testing.T) {
	f := func(a uint8) bool {
		v := fmt.Sprintf("v1.%d.0", a)
		cmp := CompareGoPackageVersions(v, v)
		return cmp == 0
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestNormalizeGoVersionIdempotent verifies that normalizing twice is the same as once.
func TestNormalizeGoVersionIdempotent(t *testing.T) {
	f := func(major, minor, patch uint8) bool {
		// Create version with and without 'v' prefix
		version := fmt.Sprintf("%d.%d.%d", major, minor, patch)

		normalized1 := normalizeGoVersion(version)
		normalized2 := normalizeGoVersion(normalized1)

		// Normalizing twice should give the same result
		return normalized1 == normalized2
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
