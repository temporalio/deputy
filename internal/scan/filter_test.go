package scan

import (
	"testing"

	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/ignore"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestFilterUnfixed_EmptyResult(t *testing.T) {
	t.Parallel()
	result := FilterUnfixed(Result{})
	if len(result.Findings) != 0 {
		t.Errorf("expected empty findings, got %d", len(result.Findings))
	}
}

func TestFilterUnfixed_NoFindings(t *testing.T) {
	t.Parallel()
	result := FilterUnfixed(Result{
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1234": {Id: "CVE-2024-1234", FixedVersions: []string{"1.0.1"}},
		},
	})
	if len(result.Findings) != 0 {
		t.Errorf("expected empty findings, got %d", len(result.Findings))
	}
}

func TestFilterUnfixed_KeepsFixable(t *testing.T) {
	t.Parallel()
	result := FilterUnfixed(Result{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2024-1234",
				Dependency: dependency.ID{Name: "pkg"},
				Version:    "1.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1234": {Id: "CVE-2024-1234", FixedVersions: []string{"1.0.1"}},
		},
	})
	if len(result.Findings) != 1 {
		t.Errorf("expected 1 finding (fixable), got %d", len(result.Findings))
	}
}

func TestFilterUnfixed_DropsUnfixable(t *testing.T) {
	t.Parallel()
	result := FilterUnfixed(Result{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2024-1234",
				Dependency: dependency.ID{Name: "pkg"},
				Version:    "1.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1234": {Id: "CVE-2024-1234"}, // No fixed versions
		},
	})
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings (unfixable), got %d", len(result.Findings))
	}
}

func TestFilterUnfixed_DropsNoUpgradePath(t *testing.T) {
	t.Parallel()
	result := FilterUnfixed(Result{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2024-1234",
				Dependency: dependency.ID{Name: "pkg"},
				Version:    "2.0.0", // Already newer than fix
				Affected:   true,
			},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1234": {Id: "CVE-2024-1234", FixedVersions: []string{"1.0.1"}},
		},
	})
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings (no upgrade path), got %d", len(result.Findings))
	}
}

func TestFilterUnfixed_MixedResults(t *testing.T) {
	t.Parallel()
	result := FilterUnfixed(Result{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2024-1111",
				Dependency: dependency.ID{Name: "pkg1"},
				Version:    "1.0.0",
				Affected:   true,
			},
			{
				AdvisoryID: "CVE-2024-2222",
				Dependency: dependency.ID{Name: "pkg2"},
				Version:    "1.0.0",
				Affected:   true,
			},
			{
				AdvisoryID: "CVE-2024-3333",
				Dependency: dependency.ID{Name: "pkg3"},
				Version:    "1.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1111": {Id: "CVE-2024-1111", FixedVersions: []string{"1.0.1"}},        // Fixable
			"CVE-2024-2222": {Id: "CVE-2024-2222"},                                           // No fix
			"CVE-2024-3333": {Id: "CVE-2024-3333", FixedVersions: []string{"0.5.0", "1.1.0"}}, // Has upgrades
		},
	})
	if len(result.Findings) != 2 {
		t.Errorf("expected 2 findings (fixable), got %d", len(result.Findings))
	}
	// Advisory map should only contain the kept advisories
	if len(result.Advisories) != 2 {
		t.Errorf("expected 2 advisories, got %d", len(result.Advisories))
	}
}

func TestFilterUnfixed_MissingAdvisory(t *testing.T) {
	t.Parallel()
	result := FilterUnfixed(Result{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2024-MISSING",
				Dependency: dependency.ID{Name: "pkg"},
				Version:    "1.0.0",
				Affected:   true,
			},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{},
	})
	if len(result.Findings) != 0 {
		t.Errorf("expected 0 findings (missing advisory), got %d", len(result.Findings))
	}
}

func TestFilterAdvisories_Empty(t *testing.T) {
	t.Parallel()
	result := filterAdvisories(nil, nil)
	if result == nil {
		t.Error("expected empty map, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected empty map, got %d items", len(result))
	}
}

func TestFilterAdvisories_KeepsReferencedOnly(t *testing.T) {
	t.Parallel()
	findings := []vulnerability.Finding{
		{AdvisoryID: "CVE-2024-1111"},
		{AdvisoryID: "CVE-2024-3333"},
	}
	advisories := map[string]vulnerabilityv1.Advisory{
		"CVE-2024-1111": {Id: "CVE-2024-1111"},
		"CVE-2024-2222": {Id: "CVE-2024-2222"}, // Not referenced
		"CVE-2024-3333": {Id: "CVE-2024-3333"},
	}

	result := filterAdvisories(findings, advisories)

	if len(result) != 2 {
		t.Errorf("expected 2 advisories, got %d", len(result))
	}
	if _, ok := result["CVE-2024-2222"]; ok {
		t.Error("unreferenced advisory should be filtered out")
	}
}

func TestFilterIgnored_NilRules(t *testing.T) {
	t.Parallel()
	result := Result{
		Findings: []vulnerability.Finding{
			{AdvisoryID: "CVE-2024-1234"},
		},
	}
	filtered, count := FilterIgnored(result, nil)
	if count != 0 {
		t.Errorf("expected 0 ignored, got %d", count)
	}
	if len(filtered.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(filtered.Findings))
	}
}

func TestFilterIgnored_EmptyFindings(t *testing.T) {
	t.Parallel()
	rules := ignore.NewRules()
	rules.Add(ignore.Rule{ID: "CVE-2024-1234"})

	result := Result{}
	filtered, count := FilterIgnored(result, rules)
	if count != 0 {
		t.Errorf("expected 0 ignored, got %d", count)
	}
	if len(filtered.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(filtered.Findings))
	}
}

func TestFilterIgnored_MatchesID(t *testing.T) {
	t.Parallel()
	rules := ignore.NewRules()
	rules.Add(ignore.Rule{ID: "CVE-2024-1234"})

	result := Result{
		Findings: []vulnerability.Finding{
			{AdvisoryID: "CVE-2024-1234", Dependency: dependency.ID{Name: "pkg1", Ecosystem: "go"}},
			{AdvisoryID: "CVE-2024-5678", Dependency: dependency.ID{Name: "pkg2", Ecosystem: "go"}},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1234": {Id: "CVE-2024-1234"},
			"CVE-2024-5678": {Id: "CVE-2024-5678"},
		},
	}

	filtered, count := FilterIgnored(result, rules)
	if count != 1 {
		t.Errorf("expected 1 ignored, got %d", count)
	}
	if len(filtered.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(filtered.Findings))
	}
	if filtered.Findings[0].AdvisoryID != "CVE-2024-5678" {
		t.Errorf("wrong finding kept")
	}
}

func TestFilterIgnored_MatchesPackage(t *testing.T) {
	t.Parallel()
	rules := ignore.NewRules()
	rules.Add(ignore.Rule{Package: "vulnerable-pkg"})

	result := Result{
		Findings: []vulnerability.Finding{
			{AdvisoryID: "CVE-2024-1111", Dependency: dependency.ID{Name: "vulnerable-pkg", Ecosystem: "npm"}},
			{AdvisoryID: "CVE-2024-2222", Dependency: dependency.ID{Name: "safe-pkg", Ecosystem: "npm"}},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1111": {Id: "CVE-2024-1111"},
			"CVE-2024-2222": {Id: "CVE-2024-2222"},
		},
	}

	filtered, count := FilterIgnored(result, rules)
	if count != 1 {
		t.Errorf("expected 1 ignored, got %d", count)
	}
	if len(filtered.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(filtered.Findings))
	}
}

func TestFilterIgnored_MatchesEcosystem(t *testing.T) {
	t.Parallel()
	rules := ignore.NewRules()
	rules.Add(ignore.Rule{Ecosystem: "npm"})

	result := Result{
		Findings: []vulnerability.Finding{
			{AdvisoryID: "CVE-2024-1111", Dependency: dependency.ID{Name: "pkg1", Ecosystem: "npm"}},
			{AdvisoryID: "CVE-2024-2222", Dependency: dependency.ID{Name: "pkg2", Ecosystem: "go"}},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1111": {Id: "CVE-2024-1111"},
			"CVE-2024-2222": {Id: "CVE-2024-2222"},
		},
	}

	filtered, count := FilterIgnored(result, rules)
	if count != 1 {
		t.Errorf("expected 1 ignored, got %d", count)
	}
	if len(filtered.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(filtered.Findings))
	}
	if filtered.Findings[0].Dependency.Ecosystem != "go" {
		t.Errorf("wrong finding kept")
	}
}

func TestFilterIgnored_NoMatches(t *testing.T) {
	t.Parallel()
	rules := ignore.NewRules()
	rules.Add(ignore.Rule{ID: "CVE-9999-9999"})

	result := Result{
		Findings: []vulnerability.Finding{
			{AdvisoryID: "CVE-2024-1234", Dependency: dependency.ID{Name: "pkg1", Ecosystem: "go"}},
		},
		Advisories: map[string]vulnerabilityv1.Advisory{
			"CVE-2024-1234": {Id: "CVE-2024-1234"},
		},
	}

	filtered, count := FilterIgnored(result, rules)
	if count != 0 {
		t.Errorf("expected 0 ignored, got %d", count)
	}
	if len(filtered.Findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(filtered.Findings))
	}
}
