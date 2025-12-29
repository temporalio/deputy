package report

import (
	"testing"

	"github.com/picatz/deputy/internal/vulnerability"
)

func TestBuildSummary_NoVulns(t *testing.T) {
	summary := BuildSummary(nil, vulnerability.Stats{})
	if summary.HasVulnerabilities {
		t.Fatalf("expected HasVulnerabilities=false")
	}
}

func TestBuildSummary_WithVulns(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{PrimaryID: "V1", Severity: "9.8", SeverityType: "CVSS_V3", FixedVersions: []string{"v1.2.0"}, Version: "v1.0.0"},
		{PrimaryID: "V2", Severity: "HIGH", SeverityType: "GHSA"},
	}
	summary := BuildSummary(cons, vulnerability.Stats{})
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
