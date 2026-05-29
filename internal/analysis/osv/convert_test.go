package osv

import (
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
)

func tTime(tstr string) time.Time { tm, _ := time.Parse(time.RFC3339, tstr); return tm }

// Test_ProcessOSVVulnerability_PackageFixes verifies that fixes for sibling
// modules (e.g., a Go major-version migration target) are captured in
// PackageFixes even though the queried module's own path has no fix. This is
// the data the fix resolver uses to recommend a migration.
func Test_ProcessOSVVulnerability_PackageFixes(t *testing.T) {
	vuln := osvschema.Vulnerability{
		ID: "GHSA-test",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "github.com/docker/docker", Ecosystem: "Go"},
				Ranges:  []osvschema.Range{{Events: []osvschema.Event{{Introduced: "0"}, {LastAffected: "28.5.2"}}}},
			},
			{
				Package: osvschema.Package{Name: "github.com/moby/moby/v2", Ecosystem: "Go"},
				Ranges:  []osvschema.Range{{Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "2.0.0-beta.8"}}}},
			},
		},
	}
	out := ProcessOSVVulnerability(vuln, PkgInput{QueryKey: QueryKey{Name: "github.com/docker/docker", Version: "v28.5.2+incompatible", Ecosystem: "Go"}})

	// The queried module has no fix event, so FixedVersions is empty.
	if len(out.FixedVersions) != 0 {
		t.Errorf("expected no in-place fixed versions, got %v", out.FixedVersions)
	}
	// The sibling module's fix must be captured in PackageFixes.
	var moby *struct {
		mod      string
		versions []string
	}
	for _, pf := range out.PackageFixes {
		if pf.Module == "github.com/moby/moby/v2" {
			moby = &struct {
				mod      string
				versions []string
			}{pf.Module, pf.FixedVersions}
		}
	}
	if moby == nil {
		t.Fatalf("expected PackageFixes to include github.com/moby/moby/v2, got %+v", out.PackageFixes)
	}
	if len(moby.versions) != 1 || moby.versions[0] != "2.0.0-beta.8" {
		t.Errorf("expected moby/v2 fix 2.0.0-beta.8, got %v", moby.versions)
	}
}

func Test_ProcessOSVVulnerability_basic_fields(t *testing.T) {
	vuln := osvschema.Vulnerability{
		ID:               "GHSA-xxxx",
		Summary:          "Test summary",
		Details:          "Detailed info",
		Published:        tTime("2020-01-02T15:04:05Z"),
		Modified:         tTime("2020-02-03T12:00:00Z"),
		Aliases:          []string{"CVE-2020-1", "GO-2020-1"},
		Severity:         []osvschema.Severity{{Type: "CVSS_V3", Score: "7.8"}},
		DatabaseSpecific: map[string]any{"severity": "HIGH"},
		References:       []osvschema.Reference{{URL: "https://example.com"}},
		Affected:         []osvschema.Affected{{Ranges: []osvschema.Range{{Events: []osvschema.Event{{Fixed: "v1.2.3"}}}}}},
	}
	out := ProcessOSVVulnerability(vuln, PkgInput{QueryKey: QueryKey{Name: "github.com/example/pkg", Version: "v1.0.0", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}})
	if out.ID != "GHSA-xxxx" {
		t.Fatalf("unexpected ID: %v", out.ID)
	}
	if out.CVE != "CVE-2020-1" {
		t.Fatalf("expected CVE extracted, got %q", out.CVE)
	}
	if out.Severity == "" {
		t.Fatalf("expected severity set")
	}
	if len(out.References) == 0 || out.References[0] != "https://example.com" {
		t.Fatalf("unexpected refs: %v", out.References)
	}
	if len(out.FixedVersions) == 0 || out.FixedVersions[0] != "v1.2.3" {
		t.Fatalf("unexpected fixes: %v", out.FixedVersions)
	}
	if out.Published == "" || out.Modified == "" {
		t.Fatalf("expected published/modified set")
	}
}

func Test_ProcessOSVVulnerability_no_aliases_severity(t *testing.T) {
	vuln := osvschema.Vulnerability{ID: "V-1"}
	out := ProcessOSVVulnerability(vuln, PkgInput{QueryKey: QueryKey{Name: "pkg"}})
	if out.CVE != "" {
		t.Fatalf("unexpected CVE: %q", out.CVE)
	}
}

func Test_resolveSeverity(t *testing.T) {
	tests := []struct {
		name      string
		vuln      osvschema.Vulnerability
		wantScore string
		wantType  string
	}{
		{
			name: "CVSS_V3 takes priority for non-GHSA",
			vuln: osvschema.Vulnerability{
				ID:               "CVE-2020-1234",
				Severity:         []osvschema.Severity{{Type: "CVSS_V3", Score: "9.8"}},
				DatabaseSpecific: map[string]any{"severity": "MEDIUM"},
			},
			wantScore: "9.8",
			wantType:  "CVSS_V3",
		},
		{
			name: "GHSA overrides CVSS for GHSA advisory with HIGH/CRITICAL",
			vuln: osvschema.Vulnerability{
				ID:               "GHSA-xxxx",
				Severity:         []osvschema.Severity{{Type: "CVSS_V3", Score: "9.8"}},
				DatabaseSpecific: map[string]any{"severity": "CRITICAL"},
			},
			wantScore: "CRITICAL",
			wantType:  "GHSA",
		},
		{
			name: "CVSS_V2 fallback",
			vuln: osvschema.Vulnerability{
				ID:       "CVE-2020-1234",
				Severity: []osvschema.Severity{{Type: "CVSS_V2", Score: "7.5"}},
			},
			wantScore: "7.5",
			wantType:  "CVSS_V2",
		},
		{
			name: "GHSA database_specific when no CVSS",
			vuln: osvschema.Vulnerability{
				ID:               "GHSA-xxxx",
				DatabaseSpecific: map[string]any{"severity": "HIGH"},
			},
			wantScore: "HIGH",
			wantType:  "GHSA",
		},
		{
			name: "non-GHSA database_specific high severity",
			vuln: osvschema.Vulnerability{
				ID:               "CVE-2020-1234",
				DatabaseSpecific: map[string]any{"severity": "CRITICAL"},
			},
			wantScore: "CRITICAL",
			wantType:  "GHSA",
		},
		{
			name: "non-GHSA database_specific low severity",
			vuln: osvschema.Vulnerability{
				ID:               "CVE-2020-1234",
				DatabaseSpecific: map[string]any{"severity": "LOW"},
			},
			wantScore: "LOW",
			wantType:  "database_specific",
		},
		{
			name:      "no severity info",
			vuln:      osvschema.Vulnerability{ID: "V-1"},
			wantScore: "",
			wantType:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			score, sevType := resolveSeverity(tt.vuln)
			if score != tt.wantScore {
				t.Errorf("resolveSeverity() score = %q, want %q", score, tt.wantScore)
			}
			if sevType != tt.wantType {
				t.Errorf("resolveSeverity() type = %q, want %q", sevType, tt.wantType)
			}
		})
	}
}

func Test_isHighOrCritical(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"CRITICAL", true},
		{"critical", true},
		{"HIGH", true},
		{"high", true},
		{"  HIGH  ", true},
		{"MEDIUM", false},
		{"LOW", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isHighOrCritical(tt.input); got != tt.want {
				t.Errorf("isHighOrCritical(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func Test_ProcessOSVVulnerability_LayerDetails(t *testing.T) {
	vuln := osvschema.Vulnerability{
		ID:      "CVE-2024-1234",
		Summary: "Test vulnerability with layer details",
	}
	input := PkgInput{
		QueryKey: QueryKey{
			Name:      "openssl",
			Version:   "1.1.1k-1ubuntu1",
			Ecosystem: "Debian:11",
		},
		PackageContext: PackageContext{
			IsDirect: false,
			LayerDetails: &containerv1.LayerDetails{
				Index:       2,
				DiffId:      "sha256:abc123",
				ChainId:     "sha256:def456",
				Command:     "RUN apt-get install -y openssl",
				InBaseImage: true,
			},
		},
	}

	out := ProcessOSVVulnerability(vuln, input)

	if out.LayerDetails == nil {
		t.Fatal("expected LayerDetails to be populated, got nil")
	}
	if out.LayerDetails.Index != 2 {
		t.Errorf("LayerDetails.Index = %d, want 2", out.LayerDetails.Index)
	}
	if out.LayerDetails.DiffId != "sha256:abc123" {
		t.Errorf("LayerDetails.DiffId = %q, want %q", out.LayerDetails.DiffId, "sha256:abc123")
	}
	if out.LayerDetails.ChainId != "sha256:def456" {
		t.Errorf("LayerDetails.ChainId = %q, want %q", out.LayerDetails.ChainId, "sha256:def456")
	}
	if out.LayerDetails.Command != "RUN apt-get install -y openssl" {
		t.Errorf("LayerDetails.Command = %q, want %q", out.LayerDetails.Command, "RUN apt-get install -y openssl")
	}
	if !out.LayerDetails.InBaseImage {
		t.Error("LayerDetails.InBaseImage = false, want true")
	}
}

func Test_ProcessOSVVulnerability_NilLayerDetails(t *testing.T) {
	vuln := osvschema.Vulnerability{
		ID:      "CVE-2024-5678",
		Summary: "Test vulnerability without layer details",
	}
	input := PkgInput{
		QueryKey: QueryKey{
			Name:      "lodash",
			Version:   "4.17.20",
			Ecosystem: "npm",
		},
		PackageContext: PackageContext{
			LayerDetails: nil, // Non-container scan
		},
	}

	out := ProcessOSVVulnerability(vuln, input)

	if out.LayerDetails != nil {
		t.Errorf("expected LayerDetails to be nil for non-container scan, got %+v", out.LayerDetails)
	}
}

func Test_ProcessOSVVulnerabilityDomain_ExtractsCWEs(t *testing.T) {
	tests := []struct {
		name     string
		vuln     osvschema.Vulnerability
		wantCWEs []string
	}{
		{
			name: "GHSA with CWEs",
			vuln: osvschema.Vulnerability{
				ID:      "GHSA-1234-5678-abcd",
				Summary: "XSS vulnerability",
				DatabaseSpecific: map[string]any{
					"cwe_ids":  []any{"CWE-79", "CWE-80"},
					"severity": "HIGH",
				},
			},
			wantCWEs: []string{"CWE-79", "CWE-80"},
		},
		{
			name: "no CWEs",
			vuln: osvschema.Vulnerability{
				ID:      "CVE-2024-1234",
				Summary: "Some vulnerability",
			},
			wantCWEs: nil,
		},
		{
			name: "empty CWE array",
			vuln: osvschema.Vulnerability{
				ID:               "GHSA-xxxx-yyyy-zzzz",
				DatabaseSpecific: map[string]any{"cwe_ids": []any{}},
			},
			wantCWEs: nil,
		},
		{
			name: "CWEs with invalid entries filtered",
			vuln: osvschema.Vulnerability{
				ID: "GHSA-abcd-1234-efgh",
				DatabaseSpecific: map[string]any{
					"cwe_ids": []any{"CWE-89", "invalid", "CWE-79"},
				},
			},
			wantCWEs: []string{"CWE-79", "CWE-89"}, // sorted by ID
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			advisory, _ := ProcessOSVVulnerabilityDomain(tt.vuln, PkgInput{QueryKey: QueryKey{Name: "test-pkg"}})

			if tt.wantCWEs == nil {
				if len(advisory.Cwes) != 0 {
					t.Errorf("expected no CWEs, got %v", advisory.Cwes)
				}
				return
			}

			if len(advisory.Cwes) != len(tt.wantCWEs) {
				t.Errorf("CWEs count = %d, want %d", len(advisory.Cwes), len(tt.wantCWEs))
				return
			}

			for i, want := range tt.wantCWEs {
				if string(advisory.Cwes[i]) != want {
					t.Errorf("CWEs[%d] = %q, want %q", i, advisory.Cwes[i], want)
				}
			}
		})
	}
}
