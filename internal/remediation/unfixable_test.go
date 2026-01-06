package remediation

import (
	"strings"
	"testing"

	"github.com/picatz/deputy/internal/vulnerability"
)

func TestUnfixableCategory_String(t *testing.T) {
	tests := []struct {
		category UnfixableCategory
		want     string
	}{
		{CategoryNoFixAvailable, "No fix available"},
		{CategoryTransitiveDependency, "Transitive dependency"},
		{CategoryAbandonedPackage, "Abandoned package"},
		{CategoryIncompatibleFix, "Incompatible fix"},
		{CategoryDisputed, "Disputed vulnerability"},
		{UnfixableCategory(99), "Unknown"},
	}

	for _, tt := range tests {
		got := tt.category.String()
		if got != tt.want {
			t.Errorf("UnfixableCategory(%d).String() = %q, want %q", tt.category, got, tt.want)
		}
	}
}

func TestAnalyzeUnfixable_SkipsFixable(t *testing.T) {
	vulns := []vulnerability.Consolidated{
		{
			PrimaryID:     "CVE-2023-0001",
			Package:       "example-pkg",
			Version:       "1.0.0",
			FixedVersions: []string{"1.0.1"}, // Has a fix
		},
	}

	guidance := AnalyzeUnfixable(vulns)
	if len(guidance) != 0 {
		t.Errorf("AnalyzeUnfixable should skip fixable vulns, got %d results", len(guidance))
	}
}

func TestAnalyzeUnfixable_DirectDependency(t *testing.T) {
	vulns := []vulnerability.Consolidated{
		{
			PrimaryID: "CVE-2023-0001",
			Package:   "vulnerable-pkg",
			Version:   "1.0.0",
			Ecosystem: "npm",
			IsDirect:  true,
			Severity:  "HIGH",
			Summary:   "Remote code execution vulnerability",
		},
	}

	guidance := AnalyzeUnfixable(vulns)
	if len(guidance) != 1 {
		t.Fatalf("expected 1 guidance entry, got %d", len(guidance))
	}

	g := guidance[0]
	if g.Category != CategoryNoFixAvailable {
		t.Errorf("expected CategoryNoFixAvailable, got %v", g.Category)
	}
	if g.VulnerabilityID != "CVE-2023-0001" {
		t.Errorf("VulnerabilityID = %q, want CVE-2023-0001", g.VulnerabilityID)
	}
	if len(g.Recommendations) == 0 {
		t.Error("expected recommendations for unfixable vuln")
	}
	if len(g.RiskFactors) == 0 {
		t.Error("expected risk factors")
	}
}

func TestAnalyzeUnfixable_TransitiveDependency(t *testing.T) {
	vulns := []vulnerability.Consolidated{
		{
			PrimaryID: "GHSA-xxxx-yyyy",
			Package:   "transitive-pkg",
			Version:   "2.0.0",
			Ecosystem: "npm",
			IsDirect:  false, // Transitive
		},
	}

	guidance := AnalyzeUnfixable(vulns)
	if len(guidance) != 1 {
		t.Fatalf("expected 1 guidance entry, got %d", len(guidance))
	}

	g := guidance[0]
	if g.Category != CategoryTransitiveDependency {
		t.Errorf("expected CategoryTransitiveDependency, got %v", g.Category)
	}

	// Should have npm-specific override guidance
	hasOverrideAdvice := false
	for _, r := range g.Recommendations {
		if strings.Contains(r, "overrides") {
			hasOverrideAdvice = true
			break
		}
	}
	if !hasOverrideAdvice {
		t.Error("expected npm override guidance for transitive dependency")
	}
}

func TestAnalyzeUnfixable_DisputedVulnerability(t *testing.T) {
	vulns := []vulnerability.Consolidated{
		{
			PrimaryID: "CVE-2023-9999",
			Package:   "some-pkg",
			Version:   "1.0.0",
			IsDirect:  true,
			Summary:   "DISPUTED: This issue has been contested by the vendor",
		},
	}

	guidance := AnalyzeUnfixable(vulns)
	if len(guidance) != 1 {
		t.Fatalf("expected 1 guidance entry, got %d", len(guidance))
	}

	g := guidance[0]
	if g.Category != CategoryDisputed {
		t.Errorf("expected CategoryDisputed, got %v", g.Category)
	}
}

func TestIdentifyRiskFactors_Severity(t *testing.T) {
	tests := []struct {
		severity    string
		wantContain string
	}{
		{"CRITICAL", "Critical severity"},
		{"HIGH", "High severity"},
		{"MEDIUM", ""},
		{"LOW", ""},
	}

	for _, tt := range tests {
		v := vulnerability.Consolidated{Severity: tt.severity}
		factors := identifyRiskFactors(v)

		hasExpected := false
		for _, f := range factors {
			if strings.Contains(f, tt.wantContain) {
				hasExpected = true
				break
			}
		}

		if tt.wantContain != "" && !hasExpected {
			t.Errorf("severity %q: expected factor containing %q", tt.severity, tt.wantContain)
		}
	}
}

func TestIdentifyRiskFactors_ExploitIndicators(t *testing.T) {
	tests := []struct {
		summary     string
		wantContain string
	}{
		{"Remote code execution allows attackers to...", "remotely exploitable"},
		{"Denial of service via malformed input", "Denial of service"},
		{"Information disclosure through error messages", "Data exposure"},
		{"Buffer overflow in parsing code", ""}, // No specific indicator
	}

	for _, tt := range tests {
		v := vulnerability.Consolidated{Summary: tt.summary}
		factors := identifyRiskFactors(v)

		hasExpected := tt.wantContain == ""
		for _, f := range factors {
			if strings.Contains(strings.ToLower(f), strings.ToLower(tt.wantContain)) {
				hasExpected = true
				break
			}
		}

		if !hasExpected {
			t.Errorf("summary %q: expected factor containing %q, got %v", tt.summary, tt.wantContain, factors)
		}
	}
}

func TestCweRiskNote(t *testing.T) {
	tests := []struct {
		cwe  string
		want string
	}{
		{"CWE-79", "CWE-79: Cross-site scripting"},
		{"CWE-89", "CWE-89: SQL injection"},
		{"cwe-79", "CWE-79: Cross-site scripting"}, // Case is normalized
		{"CWE-9999", ""},
	}

	for _, tt := range tests {
		got := cweRiskNote(tt.cwe)
		if tt.want == "" {
			if got != "" {
				t.Errorf("cweRiskNote(%q) = %q, want empty", tt.cwe, got)
			}
		} else {
			if !strings.HasPrefix(got, tt.want) {
				t.Errorf("cweRiskNote(%q) = %q, want prefix %q", tt.cwe, got, tt.want)
			}
		}
	}
}

func TestSuggestAlternatives(t *testing.T) {
	tests := []struct {
		pkg     string
		wantAny bool
	}{
		{"moment", true},    // Has known alternatives
		{"lodash", true},    // Has known alternatives
		{"request", true},   // Has known alternatives
		{"@scope/moment", true}, // Should strip scope
		{"unknown-pkg", false},  // No known alternatives
	}

	for _, tt := range tests {
		v := vulnerability.Consolidated{Package: tt.pkg}
		alts := suggestAlternatives(v)

		if tt.wantAny && len(alts) == 0 {
			t.Errorf("suggestAlternatives(%q) = empty, want alternatives", tt.pkg)
		}
		if !tt.wantAny && len(alts) > 0 {
			t.Errorf("suggestAlternatives(%q) = %v, want empty", tt.pkg, alts)
		}
	}
}

func TestGatherReferences(t *testing.T) {
	tests := []struct {
		id       string
		contains []string
	}{
		{"CVE-2023-0001", []string{"nvd.nist.gov", "cve.mitre.org", "osv.dev"}},
		{"GHSA-xxxx-yyyy", []string{"github.com/advisories", "osv.dev"}},
		{"OSV-2023-1234", []string{"osv.dev"}},
	}

	for _, tt := range tests {
		v := vulnerability.Consolidated{PrimaryID: tt.id}
		refs := gatherReferences(v)

		for _, want := range tt.contains {
			found := false
			for _, ref := range refs {
				if strings.Contains(ref, want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("gatherReferences(%q) missing %q, got %v", tt.id, want, refs)
			}
		}
	}
}

func TestFormatGuidance(t *testing.T) {
	g := UnfixableGuidance{
		VulnerabilityID:     "CVE-2023-0001",
		Package:             "test-pkg",
		Version:             "1.0.0",
		Category:            CategoryNoFixAvailable,
		Recommendations:     []string{"Implement compensating controls"},
		RiskFactors:         []string{"Critical severity"},
		AlternativePackages: []string{"better-pkg"},
		References:          []string{"https://example.com"},
	}

	output := FormatGuidance(g)

	expectedParts := []string{
		"test-pkg@1.0.0",
		"CVE-2023-0001",
		"No fix available",
		"Implement compensating controls",
		"Critical severity",
		"better-pkg",
		"https://example.com",
	}

	for _, part := range expectedParts {
		if !strings.Contains(output, part) {
			t.Errorf("FormatGuidance missing %q\nOutput:\n%s", part, output)
		}
	}
}

func TestGenerateRecommendations_EcosystemSpecific(t *testing.T) {
	tests := []struct {
		ecosystem   string
		category    UnfixableCategory
		wantContain string
	}{
		{"npm", CategoryNoFixAvailable, "npm audit"},
		{"go", CategoryNoFixAvailable, "build tags"},
		{"npm", CategoryTransitiveDependency, "overrides"},
		{"go", CategoryTransitiveDependency, "replace"},
		{"maven", CategoryTransitiveDependency, "dependencyManagement"},
	}

	for _, tt := range tests {
		v := vulnerability.Consolidated{
			Ecosystem: tt.ecosystem,
			IsDirect:  tt.category != CategoryTransitiveDependency,
		}
		recs := generateRecommendations(v, tt.category)

		found := false
		for _, r := range recs {
			if strings.Contains(strings.ToLower(r), strings.ToLower(tt.wantContain)) {
				found = true
				break
			}
		}

		if !found {
			t.Errorf("%s/%v: expected recommendation containing %q, got %v",
				tt.ecosystem, tt.category, tt.wantContain, recs)
		}
	}
}
