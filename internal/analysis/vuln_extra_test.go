package analysis

import (
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func Test_ProcessOSVVulnerability_identifierPreference(t *testing.T) {
	v := osvschema.Vulnerability{
		ID:      "GHSA-xxxx-yyyy",
		Summary: "s",
		Details: "d",
		Aliases: []string{"CVE-2024-1234", "GO-2024-0001"},
	}
	out := ProcessOSVVulnerability(v, PkgInput{Name: "github.com/example/mod", Version: "v1.2.3", Ecosystem: "Go", IsDirect: true})
	if out.CVE != "CVE-2024-1234" {
		t.Fatalf("preferred identifier mismatch: %q", out.CVE)
	}
}

func Test_ProcessOSVVulnerability_severityPreference(t *testing.T) {
	t.Run("ghsa_overrides_cvss", func(t *testing.T) {
		v := osvschema.Vulnerability{
			ID:               "GHSA-aaa-bbb",
			Summary:          "s",
			Details:          "d",
			Severity:         []osvschema.Severity{{Type: "CVSS_V3", Score: "7.5"}},
			DatabaseSpecific: map[string]any{"severity": "HIGH"},
		}
		out := ProcessOSVVulnerability(v, PkgInput{Name: "github.com/example/mod", Version: "v1.0.0"})
		if out.Severity != "HIGH" || out.SeverityType != "GHSA" {
			t.Fatalf("expected GHSA override, got %q (%s)", out.Severity, out.SeverityType)
		}
	})
	t.Run("cvss_retained_when_not_ghsa", func(t *testing.T) {
		v := osvschema.Vulnerability{
			ID:               "CVE-2024-9999",
			Summary:          "s",
			Details:          "d",
			Severity:         []osvschema.Severity{{Type: "CVSS_V3", Score: "9.8"}},
			DatabaseSpecific: map[string]any{"severity": "CRITICAL"},
		}
		out := ProcessOSVVulnerability(v, PkgInput{Name: "github.com/example/mod", Version: "v1.0.0"})
		if out.Severity != "9.8" || out.SeverityType != "CVSS_V3" {
			t.Fatalf("expected CVSS retained, got %q (%s)", out.Severity, out.SeverityType)
		}
	})
}
