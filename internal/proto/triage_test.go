package proto

import (
	"testing"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
)

func TestBuildTriageResponseAggregatesPackages(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{Package: "pkg/a", Version: "1.0.0", Severity: "HIGH", Summary: "bug", FixedVersions: []string{"1.1.0"}, PrimaryID: "CVE-1", IsDirect: true},
		{Package: "pkg/a", Version: "1.0.0", Severity: "MEDIUM", Summary: "other", PrimaryID: "CVE-2", IsDirect: true},
		{Package: "pkg/b", Version: "2.0.0", Severity: "CRITICAL", Summary: "serious", FixedVersions: []string{"2.1.0"}, PrimaryID: "CVE-3", IsDirect: false},
	}
	resp := BuildTriageResponse("/repo", &vulnerabilityv1.Stats{}, cons, 10)
	if len(resp.TopPackages) != 2 {
		t.Fatalf("expected 2 package summaries, got %d", len(resp.TopPackages))
	}
	top := resp.TopPackages[0]
	if top.Package != "pkg/b" {
		t.Fatalf("expected pkg/b first, got %s", top.Package)
	}
	if top.FixVersion != "2.1.0" {
		t.Fatalf("expected pkg/b fix 2.1.0, got %s", top.FixVersion)
	}
	if len(top.SampleIds) != 1 {
		t.Fatalf("expected sample id for pkg/b")
	}
	// Priority comes from the canonical triage ladder: critical + fixable.
	if top.Priority != vulnerability.TriagePriorityCritical || top.PriorityReason == "" {
		t.Fatalf("pkg/b priority = %q (%q), want critical with a reason", top.Priority, top.PriorityReason)
	}
}

// TestBuildTriageResponsePicksHigherTriageRankOnSeverityTie guards the
// summary selection for a package with several findings of equal severity:
// fixability and directness change the triage priority, so the summary must
// take the finding with the more urgent triage rank, not whichever arrived
// first.
func TestBuildTriageResponsePicksHigherTriageRankOnSeverityTie(t *testing.T) {
	unfixableFirst := []vulnerability.Consolidated{
		{Package: "pkg/a", Version: "1.0.0", Severity: "CRITICAL", Summary: "unfixable", PrimaryID: "CVE-1", IsDirect: false},
		{Package: "pkg/a", Version: "1.0.0", Severity: "CRITICAL", Summary: "fixable direct", FixedVersions: []string{"1.1.0"}, PrimaryID: "CVE-2", IsDirect: true},
	}
	for name, cons := range map[string][]vulnerability.Consolidated{
		"unfixable first": unfixableFirst,
		"fixable first":   {unfixableFirst[1], unfixableFirst[0]},
	} {
		t.Run(name, func(t *testing.T) {
			resp := BuildTriageResponse("/repo", &vulnerabilityv1.Stats{}, cons, 10)
			if len(resp.TopPackages) != 1 {
				t.Fatalf("expected 1 package summary, got %d", len(resp.TopPackages))
			}
			top := resp.TopPackages[0]
			if top.Priority != vulnerability.TriagePriorityCritical {
				t.Fatalf("priority = %q, want critical: severity tie must resolve by triage rank", top.Priority)
			}
			if top.FixVersion != "1.1.0" {
				t.Fatalf("fixVersion = %q, want 1.1.0 from the ranking finding", top.FixVersion)
			}
		})
	}
}

func TestBuildTriageResponseMergesImports(t *testing.T) {
	cons := []vulnerability.Consolidated{
		{
			Package:         "pkg/a",
			Version:         "1.0.0",
			Severity:        "HIGH",
			AffectedImports: []vulnerabilityv1.AffectedImport{{Path: "net/http", Symbols: []string{"Serve"}}},
		},
		{
			Package:         "pkg/a",
			Version:         "1.0.0",
			Severity:        "LOW",
			AffectedImports: []vulnerabilityv1.AffectedImport{{Path: "crypto/tls"}, {Path: "net/http", Symbols: []string{"Serve"}}},
		},
	}
	resp := BuildTriageResponse("/repo", &vulnerabilityv1.Stats{}, cons, 10)
	if len(resp.TopPackages) != 1 {
		t.Fatalf("expected 1 package summary, got %d", len(resp.TopPackages))
	}
	imports := resp.TopPackages[0].AffectedImports
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
