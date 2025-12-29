package vuln

import (
	"testing"
	"testing/quick"
)

// TestSeverityOrdering verifies that severity ordering is transitive using property-based testing.
// If A > B and B > C, then A > C must hold.
func TestSeverityOrderingTransitivity(t *testing.T) {
	f := func(a, b, c uint8) bool {
		// Map uint8 to valid Severity values (0-4)
		sev1 := Severity(a % 5)
		sev2 := Severity(b % 5)
		sev3 := Severity(c % 5)

		// Check transitivity: if sev1 > sev2 and sev2 > sev3, then sev1 > sev3
		if sev1.IsHigherThan(sev2) && sev2.IsHigherThan(sev3) {
			return sev1.IsHigherThan(sev3)
		}
		return true // Property doesn't apply to this combination
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestSeveritySymmetry verifies that if A > B, then B is not > A.
func TestSeverityOrderingSymmetry(t *testing.T) {
	f := func(a, b uint8) bool {
		sev1 := Severity(a % 5)
		sev2 := Severity(b % 5)

		// If sev1 > sev2, then sev2 should not be > sev1
		if sev1.IsHigherThan(sev2) {
			return !sev2.IsHigherThan(sev1)
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestSeverityReflexivity verifies that a severity is never higher than itself.
func TestSeverityOrderingReflexivity(t *testing.T) {
	f := func(a uint8) bool {
		sev := Severity(a % 5)
		// A severity should never be higher than itself
		return !sev.IsHigherThan(sev)
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestParseSeverityRoundTrip verifies that parsing and stringifying a severity is idempotent.
func TestParseSeverityRoundTrip(t *testing.T) {
	f := func(a uint8) bool {
		sev := Severity(a % 5)
		str := sev.String()
		parsed := ParseSeverity(str)
		return parsed == sev
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestSeverityScoreMonotonicity verifies that score increases with severity.
func TestSeverityScoreMonotonicity(t *testing.T) {
	f := func(a, b uint8) bool {
		sev1 := Severity(a % 5)
		sev2 := Severity(b % 5)

		// If sev1 > sev2, then sev1.Score() should be > sev2.Score()
		if sev1.IsHigherThan(sev2) {
			return sev1.Score() > sev2.Score()
		}
		return true
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

// TestSeverityInfoValidationConsistency verifies IsValid is consistent.
func TestSeverityInfoValidationConsistency(t *testing.T) {
	f := func(a, b uint8) bool {
		sev := Severity(a % 5)
		sevType := SeverityType(b % 6)

		info := SeverityInfo{
			Level: sev,
			Type:  sevType,
		}

		// If both level and type are known (not zero/unknown), IsValid should be true
		expected := sev != SeverityUnknown && sevType != SeverityTypeUnknown
		return info.IsValid() == expected
	}

	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
