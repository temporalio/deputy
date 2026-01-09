package scan

import (
	"testing"
	"time"

	"github.com/google/osv-scalibr/extractor"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestMergeResults(t *testing.T) {
	base := Result{
		GeneratedAt:     time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		PackagesScanned: 1,
		Inventory: Inventory{
			Packages: []*extractor.Package{{Name: "base", Version: "1.0.0"}},
			Direct:   map[string]bool{"pkg:npm/base@1.0.0": true},
		},
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "ADV-1",
				Dependency: dependency.ID{Name: "base", Ecosystem: "npm", PURL: "pkg:npm/base@1.0.0"},
				Version:    "1.0.0",
				Direct:     true,
				Affected:   true,
			},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"ADV-1": {Id: "ADV-1"},
		},
		Warnings: []string{"base warning"},
	}

	extra := Result{
		GeneratedAt:     time.Date(2025, 1, 2, 0, 0, 0, 0, time.UTC),
		PackagesScanned: 2,
		Inventory: Inventory{
			Packages: []*extractor.Package{{Name: "extra", Version: "2.0.0"}},
		},
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "ADV-2",
				Dependency: dependency.ID{Name: "extra", Ecosystem: "npm", PURL: "pkg:npm/extra@2.0.0"},
				Version:    "2.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"ADV-2": {Id: "ADV-2"},
		},
		Warnings: []string{"extra warning"},
	}

	merged := MergeResults(base, extra)
	if merged.PackagesScanned != 3 {
		t.Fatalf("expected packages scanned 3, got %d", merged.PackagesScanned)
	}
	if len(merged.Inventory.Packages) != 2 {
		t.Fatalf("expected 2 inventory packages, got %d", len(merged.Inventory.Packages))
	}
	if len(merged.Findings) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(merged.Findings))
	}
	if len(merged.Advisories) != 2 {
		t.Fatalf("expected 2 advisories, got %d", len(merged.Advisories))
	}
	if len(merged.Warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(merged.Warnings))
	}
	if merged.GeneratedAt != extra.GeneratedAt {
		t.Fatalf("expected latest GeneratedAt, got %s", merged.GeneratedAt)
	}
	if merged.Stats.Total != 2 {
		t.Fatalf("expected 2 consolidated vulns, got %d", merged.Stats.Total)
	}
}
