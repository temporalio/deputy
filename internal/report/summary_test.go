package report

import (
	"testing"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestBuildSummary_NoVulns(t *testing.T) {
	summary := BuildSummary(nil, vulnerabilityv1.Stats{})
	if summary.HasVulnerabilities {
		t.Fatalf("expected HasVulnerabilities=false")
	}
}

func TestBuildSummary_WithVulns(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{PrimaryID: "V1", Severity: "9.8", SeverityType: "CVSS_V3", FixedVersions: []string{"v1.2.0"}, Version: "v1.0.0"},
		{PrimaryID: "V2", Severity: "HIGH", SeverityType: "GHSA"},
	}
	summary := BuildSummary(cons, vulnerabilityv1.Stats{})
	if !summary.HasVulnerabilities {
		t.Fatalf("expected HasVulnerabilities=true")
	}
	if summary.CriticalHighCount == 0 {
		t.Fatalf("expected critical/high count > 0")
	}
	if summary.FixAvailableCount != 1 {
		t.Fatalf("expected FixAvailableCount=1, got %d", summary.FixAvailableCount)
	}
	if summary.CommandsHeader == "" {
		t.Fatalf("expected CommandsHeader")
	}
}

// A supply-chain finding (fix = a command, not a version upgrade) must be
// counted as command-fixable, not as "no fix available".
func TestBuildSummary_CommandRemediation(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			PrimaryID:    "DEPUTY-SC-UNPINNED-ACTION",
			Severity:     "MEDIUM",
			SeverityType: "CUSTOM",
			Version:      "v2",
			// Encoded as a fake fixed version upstream; not a semver upgrade.
			FixedVersions:    []string{"deputy pin"},
			DatabaseSpecific: map[string]string{"type": "supply-chain", "remediation": "deputy pin"},
		},
	}
	// stats.Unique=1, FixAvailable=0 (no semver fix).
	summary := BuildSummary(cons, vulnerabilityv1.Stats{Unique: 1})

	if summary.UnfixedCount != 0 {
		t.Errorf("supply-chain finding should not be 'unfixed', got UnfixedCount=%d", summary.UnfixedCount)
	}
	if summary.CommandFixableCount != 1 {
		t.Errorf("expected CommandFixableCount=1, got %d", summary.CommandFixableCount)
	}
	if len(summary.CommandRemediations) != 1 || summary.CommandRemediations[0] != "deputy pin" {
		t.Errorf("expected CommandRemediations=[deputy pin], got %v", summary.CommandRemediations)
	}
}

// When a semver upgrade exists, CommandRemediation must defer to it.
func TestConsolidated_CommandRemediation_PrefersSemver(t *testing.T) {
	v := vulnerability.Consolidated{
		Version:          "v1.0.0",
		FixedVersions:    []string{"v1.2.0"},
		DatabaseSpecific: map[string]string{"remediation": "deputy pin"},
	}
	if cmd := v.CommandRemediation(); cmd != "" {
		t.Errorf("expected empty (semver upgrade available), got %q", cmd)
	}
}
