package cmd

import (
	"testing"

	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/report"
)

func TestSplitVulnsByChange(t *testing.T) {
	vulns := []report.Vulnerability{
		{Package: "github.com/foo/bar", Version: "v1.0.0"},
		{Package: "github.com/baz/qux", Version: "v0.1.0"},
	}
	changes := []compare.Change{
		{Name: "github.com/foo/bar", ChangeType: compare.Updated},
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
	changes := []compare.Change{{Name: "github.com/example/down", ChangeType: compare.Downgraded}}
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
	changes := []compare.Change{{Name: "github.com/go-jose/go-jose/v4", ChangeType: compare.Updated}}
	changed, unchanged := splitVulnsByChange(vulns, changes)
	if len(changed) != 1 || changed[0].Package != "gopkg.in/go-jose/go-jose.v4" {
		t.Fatalf("expected jose vuln classified as changed: %#v %#v", changed, unchanged)
	}
	if len(unchanged) != 0 {
		t.Fatalf("expected no unchanged vulns, got %#v", unchanged)
	}
}
