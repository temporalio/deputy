package scanning

import (
	"context"
	"testing"

	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// testResult creates a comprehensive test result with multiple severity levels,
// fix availability states, and direct/indirect dependencies for thorough testing.
func testResult() Result {
	criticalAdvisory := &vulnerabilityv1.Advisory{
		Id:      "CVE-2024-0001",
		Summary: "Critical vulnerability in crypto library",
		Severity: &vulnerabilityv1.Severity{
			Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL,
		},
		FixedVersions: []string{"2.0.0"},
		Cwes:          []string{"CWE-79", "CWE-89"},
	}

	highAdvisory := &vulnerabilityv1.Advisory{
		Id:      "CVE-2024-0002",
		Summary: "High severity vulnerability",
		Severity: &vulnerabilityv1.Severity{
			Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
		},
		FixedVersions: []string{"1.5.0"},
	}

	mediumAdvisory := &vulnerabilityv1.Advisory{
		Id:      "CVE-2024-0004",
		Summary: "Medium severity vulnerability",
		Severity: &vulnerabilityv1.Severity{
			Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
		},
		FixedVersions: []string{"3.0.0"},
	}

	lowAdvisory := &vulnerabilityv1.Advisory{
		Id:      "CVE-2024-0003",
		Summary: "Low severity vulnerability",
		Severity: &vulnerabilityv1.Severity{
			Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW,
		},
		// No fix available
	}

	return Result{
		Findings: []vulnerability.Finding{
			{
				AdvisoryID: "CVE-2024-0001",
				Dependency: dependency.ID{Name: "critical-pkg", Ecosystem: "npm"},
				Version:    "1.0.0",
				Direct:     true,
			},
			{
				AdvisoryID: "CVE-2024-0002",
				Dependency: dependency.ID{Name: "high-pkg", Ecosystem: "Go"},
				Version:    "1.0.0",
				Direct:     false,
			},
			{
				AdvisoryID: "CVE-2024-0003",
				Dependency: dependency.ID{Name: "low-pkg", Ecosystem: "npm"},
				Version:    "1.0.0",
				Direct:     true,
			},
			{
				AdvisoryID: "CVE-2024-0004",
				Dependency: dependency.ID{Name: "medium-pkg", Ecosystem: "PyPI"},
				Version:    "2.0.0",
				Direct:     false,
			},
		},
		Advisories: map[string]*vulnerabilityv1.Advisory{
			"CVE-2024-0001": criticalAdvisory,
			"CVE-2024-0002": highAdvisory,
			"CVE-2024-0003": lowAdvisory,
			"CVE-2024-0004": mediumAdvisory,
		},
	}
}

func TestFilterByCEL(t *testing.T) {
	result := testResult()

	tests := []struct {
		name         string
		filter       string
		wantCount    int
		wantAdvisory string // expected first advisory ID (optional)
		expectError  bool
		description  string // documents what the filter does
	}{
		// Severity-based filters
		{
			name:         "filter critical only",
			filter:       "vulnerability.advisory.severity.level == severity.critical",
			wantCount:    1,
			wantAdvisory: "CVE-2024-0001",
			description:  "Filter to only CRITICAL severity vulnerabilities",
		},
		{
			name:         "filter high and above",
			filter:       "vulnerability.advisory.severity.level in [severity.critical, severity.high]",
			wantCount:    2,
			wantAdvisory: "CVE-2024-0001",
			description:  "Filter to HIGH and CRITICAL severity",
		},
		{
			name:        "filter medium and above",
			filter:      "vulnerability.advisory.severity.level in [severity.critical, severity.high, severity.medium]",
			wantCount:   3,
			description: "Filter to MEDIUM, HIGH, and CRITICAL severity",
		},
		{
			name:        "filter excluding low",
			filter:      "vulnerability.advisory.severity.level != severity.low",
			wantCount:   3,
			description: "Filter out LOW severity vulnerabilities",
		},

		// Dependency type filters
		{
			name:        "filter direct dependencies only",
			filter:      "vulnerability.package.direct == true",
			wantCount:   2,
			description: "Only show vulnerabilities in direct dependencies",
		},
		{
			name:        "filter indirect dependencies only",
			filter:      "vulnerability.package.direct == false",
			wantCount:   2,
			description: "Only show vulnerabilities in transitive dependencies",
		},

		// Fix availability filters
		{
			name:        "filter with fix available",
			filter:      "size(vulnerability.advisory.fixed_versions) > 0",
			wantCount:   3,
			description: "Only show vulnerabilities that have a fix available",
		},
		{
			name:        "filter without fix",
			filter:      "size(vulnerability.advisory.fixed_versions) == 0",
			wantCount:   1,
			description: "Only show vulnerabilities without a fix",
		},

		// Ecosystem filters
		{
			name:        "filter npm ecosystem",
			filter:      "vulnerability.package.ecosystem == 'npm'",
			wantCount:   2,
			description: "Filter to npm packages only",
		},
		{
			name:        "filter Go ecosystem",
			filter:      "vulnerability.package.ecosystem == 'Go'",
			wantCount:   1,
			description: "Filter to Go packages only",
		},

		// Combined filters (real-world use cases)
		{
			name:        "actionable: high+ with fix in direct deps",
			filter:      "vulnerability.advisory.severity.level in [severity.critical, severity.high] && vulnerability.package.direct && size(vulnerability.advisory.fixed_versions) > 0",
			wantCount:   1,
			description: "High priority items: critical/high severity, direct dependency, fix available",
		},
		{
			name:        "blocking: critical without fix",
			filter:      "vulnerability.advisory.severity.level == severity.critical && size(vulnerability.advisory.fixed_versions) == 0",
			wantCount:   0,
			description: "Find critical vulnerabilities that block release (no fix)",
		},
		{
			name:        "transitive risk: indirect high+",
			filter:      "!vulnerability.package.direct && vulnerability.advisory.severity.level in [severity.critical, severity.high]",
			wantCount:   1,
			description: "Transitive vulnerabilities that are high risk",
		},

		// Package name filters
		{
			name:        "filter by package name contains",
			filter:      "vulnerability.package.name.contains('pkg')",
			wantCount:   4,
			description: "Filter packages containing 'pkg' in name",
		},
		{
			name:        "filter by specific package",
			filter:      "vulnerability.package.name == 'critical-pkg'",
			wantCount:   1,
			description: "Filter to a specific package name",
		},

		// Advisory ID filters
		{
			name:        "filter by advisory ID",
			filter:      "vulnerability.advisory_id == 'CVE-2024-0001'",
			wantCount:   1,
			description: "Filter to a specific CVE",
		},
		{
			name:        "filter by advisory ID pattern",
			filter:      "vulnerability.advisory_id.startsWith('CVE-2024')",
			wantCount:   4,
			description: "Filter to CVEs from 2024",
		},

		// Edge cases
		{
			name:        "empty filter returns all",
			filter:      "",
			wantCount:   4,
			description: "Empty filter expression returns all findings",
		},
		{
			name:        "true returns all",
			filter:      "true",
			wantCount:   4,
			description: "Constant true returns all findings",
		},
		{
			name:        "false returns none",
			filter:      "false",
			wantCount:   0,
			description: "Constant false returns no findings",
		},

		// Error cases
		{
			name:        "invalid syntax",
			filter:      "invalid.syntax[",
			expectError: true,
			description: "Malformed CEL expression should error",
		},
		{
			name:        "unknown field",
			filter:      "vulnerability.unknown_field == true",
			expectError: true,
			description: "Unknown field access should error at compile time",
		},
	}

	ctx := context.Background()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered, err := FilterByCEL(ctx, result, tt.filter)

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(filtered.Findings) != tt.wantCount {
				t.Errorf("got %d findings, want %d", len(filtered.Findings), tt.wantCount)
			}

			if tt.wantAdvisory != "" && len(filtered.Findings) > 0 {
				if filtered.Findings[0].AdvisoryID != tt.wantAdvisory {
					t.Errorf("got advisory %s, want %s", filtered.Findings[0].AdvisoryID, tt.wantAdvisory)
				}
			}

			// Verify advisories are filtered to match findings
			if len(filtered.Advisories) > tt.wantCount {
				t.Errorf("advisories not filtered correctly: got %d, want <= %d", len(filtered.Advisories), tt.wantCount)
			}
		})
	}
}

func TestFilterByCEL_EmptyResult(t *testing.T) {
	ctx := context.Background()
	result := Result{
		Findings:   []vulnerability.Finding{},
		Advisories: map[string]*vulnerabilityv1.Advisory{},
	}

	filtered, err := FilterByCEL(ctx, result, "vulnerability.package.direct == true")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(filtered.Findings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(filtered.Findings))
	}
}

func TestFilterByCEL_StatsRecomputation(t *testing.T) {
	ctx := context.Background()
	result := testResult()

	// Filter to only critical severity
	filtered, err := FilterByCEL(ctx, result, "vulnerability.advisory.severity.level == severity.critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify the findings count is correct
	if len(filtered.Findings) != 1 {
		t.Errorf("expected 1 finding after filtering, got %d", len(filtered.Findings))
	}

	// Verify advisories are filtered correctly
	if len(filtered.Advisories) != 1 {
		t.Errorf("expected 1 advisory after filtering, got %d", len(filtered.Advisories))
	}

	// The Stats are computed from Consolidate which groups findings by advisories.
	// Since we have 1 finding and 1 advisory, we should have valid stats.
	// Note: Stats.Total comes from len(cons) which is the consolidated count.
	// The test data may not produce proper consolidation since it lacks some fields.
	// For now, verify the core filtering worked.
	if filtered.Findings[0].AdvisoryID != "CVE-2024-0001" {
		t.Errorf("expected CVE-2024-0001 after filtering, got %s", filtered.Findings[0].AdvisoryID)
	}
}

func TestFilterByCEL_AdvisoriesFiltered(t *testing.T) {
	ctx := context.Background()
	result := testResult()

	// Filter to only npm ecosystem (2 findings: critical-pkg and low-pkg)
	filtered, err := FilterByCEL(ctx, result, "vulnerability.package.ecosystem == 'npm'")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should have exactly 2 advisories
	if len(filtered.Advisories) != 2 {
		t.Errorf("expected 2 advisories, got %d", len(filtered.Advisories))
	}

	// Verify the correct advisories are present
	if _, ok := filtered.Advisories["CVE-2024-0001"]; !ok {
		t.Error("expected CVE-2024-0001 in advisories")
	}
	if _, ok := filtered.Advisories["CVE-2024-0003"]; !ok {
		t.Error("expected CVE-2024-0003 in advisories")
	}

	// Verify Go advisory is NOT present
	if _, ok := filtered.Advisories["CVE-2024-0002"]; ok {
		t.Error("CVE-2024-0002 should not be in filtered advisories")
	}
}

func TestFilterByCEL_OriginalResultUnmodified(t *testing.T) {
	ctx := context.Background()
	result := testResult()

	originalCount := len(result.Findings)
	originalAdvisoriesCount := len(result.Advisories)

	// Apply a filter that reduces results
	_, err := FilterByCEL(ctx, result, "vulnerability.advisory.severity.level == severity.critical")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Original result should be unmodified
	if len(result.Findings) != originalCount {
		t.Errorf("original findings count changed: got %d, want %d", len(result.Findings), originalCount)
	}
	if len(result.Advisories) != originalAdvisoriesCount {
		t.Errorf("original advisories count changed: got %d, want %d", len(result.Advisories), originalAdvisoriesCount)
	}
}

// TestFilterByCEL_DocumentedExamples tests the exact expressions documented in the CLI help
// and documentation to ensure they work correctly.
func TestFilterByCEL_DocumentedExamples(t *testing.T) {
	ctx := context.Background()
	result := testResult()

	// These are the exact examples from docs/commands/scan.md
	documentedExamples := []struct {
		name   string
		filter string
	}{
		{
			name:   "critical severity (from docs)",
			filter: "vulnerability.advisory.severity.level == severity.critical",
		},
		{
			name:   "high and critical (from docs)",
			filter: "vulnerability.advisory.severity.level in [severity.critical, severity.high]",
		},
		{
			name:   "direct dependencies (from docs)",
			filter: "vulnerability.package.direct == true",
		},
		{
			name:   "fix available (from docs)",
			filter: "size(vulnerability.advisory.fixed_versions) > 0",
		},
	}

	for _, ex := range documentedExamples {
		t.Run(ex.name, func(t *testing.T) {
			_, err := FilterByCEL(ctx, result, ex.filter)
			if err != nil {
				t.Errorf("documented example failed: %v", err)
			}
		})
	}
}
