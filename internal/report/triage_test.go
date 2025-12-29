package report

import (
	"testing"

	"github.com/picatz/deputy/internal/vulnerability"
)

func TestBuildTriageReportAggregatesPackages(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{Package: "pkg/a", Version: "1.0.0", Severity: "HIGH", Summary: "bug", FixedVersions: []string{"1.1.0"}, PrimaryID: "CVE-1", IsDirect: true},
		{Package: "pkg/a", Version: "1.0.0", Severity: "MEDIUM", Summary: "other", PrimaryID: "CVE-2", IsDirect: true},
		{Package: "pkg/b", Version: "2.0.0", Severity: "CRITICAL", Summary: "serious", FixedVersions: []string{"2.1.0"}, PrimaryID: "CVE-3", IsDirect: false},
	}
	report := BuildTriageReport(Target{}, vulnerability.Stats{}, cons)
	if len(report.TopPackages) != 2 {
		t.Fatalf("expected 2 package summaries, got %d", len(report.TopPackages))
	}
	if report.TopPackages[0].Package != "pkg/b" {
		t.Fatalf("expected pkg/b first, got %s", report.TopPackages[0].Package)
	}
	if report.TopPackages[0].FixVersion != "v2.1.0" {
		t.Fatalf("expected pkg/b fix v2.1.0, got %s", report.TopPackages[0].FixVersion)
	}
	if len(report.TopPackages[0].SampleIDs) != 1 {
		t.Fatalf("expected sample id for pkg/b")
	}
}

func TestBuildTriageReportMergesImports(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			Package:         "pkg/a",
			Version:         "1.0.0",
			Severity:        "HIGH",
			AffectedImports: []vulnerability.AffectedImport{{Path: "net/http", Symbols: []string{"Serve"}}},
		},
		{
			Package:         "pkg/a",
			Version:         "1.0.0",
			Severity:        "LOW",
			AffectedImports: []vulnerability.AffectedImport{{Path: "crypto/tls"}, {Path: "net/http", Symbols: []string{"Serve"}}},
		},
	}
	report := BuildTriageReport(Target{}, vulnerability.Stats{}, cons)
	if len(report.TopPackages) != 1 {
		t.Fatalf("expected 1 package summary, got %d", len(report.TopPackages))
	}
	imports := report.TopPackages[0].AffectedImports
	if len(imports) != 2 {
		t.Fatalf("expected merged imports, got %d", len(imports))
	}
	if imports[0].Path != "crypto/tls" {
		t.Fatalf("expected crypto/tls first, got %s", imports[0].Path)
	}
	if len(imports[1].Symbols) != 1 || imports[1].Symbols[0] != "Serve" {
		t.Fatalf("expected deduped symbol Serve, got %v", imports[1].Symbols)
	}
}
