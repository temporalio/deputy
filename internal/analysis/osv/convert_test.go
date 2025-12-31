package osv

import (
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"testing"
	"time"
)

func tTime(tstr string) time.Time { tm, _ := time.Parse(time.RFC3339, tstr); return tm }

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
	out := ProcessOSVVulnerability(vuln, PkgInput{Name: "github.com/example/pkg", Version: "v1.0.0", Ecosystem: "Go", IsDirect: true})
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
	out := ProcessOSVVulnerability(vuln, PkgInput{Name: "pkg"})
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
