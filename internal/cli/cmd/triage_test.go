package cmd

import (
	"testing"

	analysis "github.com/picatz/deputy/internal/analysis"
)

func TestAggregatePackages(t *testing.T) {
	cons := []analysis.ConsolidatedVulnerability{
		{Package: "pkg/a", Version: "1.0.0", Severity: "HIGH", Summary: "bug", FixedVersions: []string{"1.1.0"}, PrimaryID: "CVE-1", IsDirect: true},
		{Package: "pkg/a", Version: "1.0.0", Severity: "MEDIUM", Summary: "other", PrimaryID: "CVE-2", IsDirect: true},
		{Package: "pkg/b", Version: "2.0.0", Severity: "CRITICAL", Summary: "serious", FixedVersions: []string{"2.1.0"}, PrimaryID: "CVE-3", IsDirect: false},
	}
	pkgs := aggregatePackages(cons)
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 package summaries, got %d", len(pkgs))
	}
	if pkgs[0].Package != "pkg/b" {
		t.Fatalf("expected pkg/b first, got %s", pkgs[0].Package)
	}
	if pkgs[0].FixVersion != "v2.1.0" {
		t.Fatalf("expected pkg/b fix v2.1.0, got %s", pkgs[0].FixVersion)
	}
	if len(pkgs[0].SampleIDs) != 1 {
		t.Fatalf("expected sample id for pkg/b")
	}
}
