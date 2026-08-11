package cmd

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/internal/report"
)

// TestConsolidateReportVulnerabilities_EmptyStatsNonNil guards the never-nil
// Stats invariant: an empty vuln set must still yield a usable Stats so the
// diff threshold checks (unchangedStats.Critical, …) don't nil-panic. This
// regressed when Stats became a pointer.
func TestConsolidateReportVulnerabilities_EmptyStatsNonNil(t *testing.T) {
	_, stats := consolidateReportVulnerabilities(nil)
	if stats == nil {
		t.Fatal("consolidateReportVulnerabilities(nil) returned nil Stats; callers dereference it")
	}
	if stats.Critical != 0 || stats.Unique != 0 {
		t.Errorf("empty stats should be zero-valued, got %+v", stats)
	}
}

func TestSplitVulnsByChange(t *testing.T) {
	vulns := []report.Vulnerability{
		{Package: "github.com/foo/bar", Version: "v1.0.0"},
		{Package: "github.com/baz/qux", Version: "v0.1.0"},
	}
	changes := []*diffv1.PackageChange{
		{Package: &dependencyv1.Package{Name: "github.com/foo/bar"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_UPDATED},
	}
	changed, unchanged := splitVulnsByChange(vulns, changes)
	if len(changed) != 1 || changed[0].Package != "github.com/foo/bar" {
		t.Fatalf("expected foo/bar in changed, got %#v", changed)
	}
	if len(unchanged) != 1 || unchanged[0].Package != "github.com/baz/qux" {
		t.Fatalf("expected baz/qux in unchanged, got %#v", unchanged)
	}
}

func TestSplitVulnsByChange_Downgrade(t *testing.T) {
	vulns := []report.Vulnerability{{Package: "github.com/example/down", Version: "v1.0.0"}}
	changes := []*diffv1.PackageChange{{Package: &dependencyv1.Package{Name: "github.com/example/down"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED}}
	changed, unchanged := splitVulnsByChange(vulns, changes)
	if len(changed) != 1 || changed[0].Package != "github.com/example/down" {
		t.Fatalf("downgraded package should be marked changed: changed=%#v", changed)
	}
	if len(unchanged) != 0 {
		t.Fatalf("expected no unchanged vulns, got %#v", unchanged)
	}
}

// Ensure splitVulnsByChange handles gopkg.in to GitHub path transitions.
func TestSplitVulnsByChange_GopkgInCanonical(t *testing.T) {
	vulns := []report.Vulnerability{{Package: "gopkg.in/go-jose/go-jose.v4", Version: "v4.0.5"}}
	changes := []*diffv1.PackageChange{{Package: &dependencyv1.Package{Name: "github.com/go-jose/go-jose/v4"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_UPDATED}}
	changed, unchanged := splitVulnsByChange(vulns, changes)
	if len(changed) != 1 || changed[0].Package != "gopkg.in/go-jose/go-jose.v4" {
		t.Fatalf("expected jose vuln classified as changed: %#v %#v", changed, unchanged)
	}
	if len(unchanged) != 0 {
		t.Fatalf("expected no unchanged vulns, got %#v", unchanged)
	}
}
