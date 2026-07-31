package osv

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// TestVulnerabilitiesFromProtoRoundTrip verifies the flatten direction is the
// inverse of VulnerabilitiesToFindings for the fields the proxy consumes, so
// results from any advisory source (built-in or plugin) flatten identically.
func TestVulnerabilitiesFromProtoRoundTrip(t *testing.T) {
	orig := Vulnerability{
		ID:            "GHSA-test",
		Aliases:       []string{"CVE-2024-1"},
		Summary:       "sum",
		Severity:      "HIGH",
		SeverityType:  "GHSA",
		Package:       "lodash",
		Version:       "4.17.20",
		IsDirect:      true,
		Ecosystem:     "npm",
		PURL:          "pkg:npm/lodash@4.17.20",
		FixedVersions: []string{"4.17.21"},
		Affected:      true,
	}
	findings := VulnerabilitiesToFindings([]Vulnerability{orig})
	if len(findings) != 1 {
		t.Fatalf("forward conversion produced %d findings, want 1", len(findings))
	}

	got := VulnerabilitiesFromProto(findings, nil)
	if len(got) != 1 {
		t.Fatalf("inverse conversion produced %d records, want 1", len(got))
	}
	v := got[0]
	if v.ID != orig.ID || v.Package != orig.Package || v.Version != orig.Version ||
		v.Ecosystem != orig.Ecosystem || v.PURL != orig.PURL ||
		v.Severity != orig.Severity || v.SeverityType != orig.SeverityType ||
		!v.IsDirect || !v.Affected {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", v, orig)
	}
	if len(v.FixedVersions) != 1 || v.FixedVersions[0] != "4.17.21" {
		t.Fatalf("FixedVersions = %v, want [4.17.21]", v.FixedVersions)
	}
}

// TestVulnerabilitiesFromProtoAdvisoryFallback verifies a finding without an
// inline advisory (as a plugin may return) resolves via the advisories map.
func TestVulnerabilitiesFromProtoAdvisoryFallback(t *testing.T) {
	findings := []*vulnerabilityv1.Finding{{
		AdvisoryId: "FEED-1",
		Package:    &dependencyv1.Package{Name: "x", Version: "1", Ecosystem: "npm"},
		Affected:   true,
	}}
	advisories := map[string]*vulnerabilityv1.Advisory{
		"FEED-1": {Id: "FEED-1", Summary: "from map", Severity: vulnerability.NewSeverity("CRITICAL", "GHSA")},
	}
	got := VulnerabilitiesFromProto(findings, advisories)
	if len(got) != 1 || got[0].Summary != "from map" || got[0].Severity != "CRITICAL" {
		t.Fatalf("advisory fallback not applied: %+v", got)
	}
}
