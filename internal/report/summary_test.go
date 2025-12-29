package report

import (
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
)

func TestBuildSummary_NoVulns(t *testing.T) {
	summary := BuildSummary(nil)
	if summary.HasVulnerabilities {
		t.Fatalf("expected HasVulnerabilities=false")
	}
}

func TestBuildSummary_WithVulns(t *testing.T) {
	vulns := []analysis.Vulnerability{
		{ID: "V1", Severity: "9.8", SeverityType: "CVSS_V3", FixedVersions: []string{"v1.2.0"}, Version: "v1.0.0", Affected: true},
		{ID: "V2", Severity: "HIGH", SeverityType: "GHSA", Affected: true},
	}
	summary := BuildSummary(vulns)
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
