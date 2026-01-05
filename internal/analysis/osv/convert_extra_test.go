package osv

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
	out := ProcessOSVVulnerability(v, PkgInput{QueryKey: QueryKey{Name: "github.com/example/mod", Version: "v1.2.3", Ecosystem: "Go"}, PackageContext: PackageContext{IsDirect: true}})
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
		out := ProcessOSVVulnerability(v, PkgInput{QueryKey: QueryKey{Name: "github.com/example/mod", Version: "v1.0.0"}})
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
		out := ProcessOSVVulnerability(v, PkgInput{QueryKey: QueryKey{Name: "github.com/example/mod", Version: "v1.0.0"}})
		if out.Severity != "9.8" || out.SeverityType != "CVSS_V3" {
			t.Fatalf("expected CVSS retained, got %q (%s)", out.Severity, out.SeverityType)
		}
	})
}

func Test_ProcessOSVVulnerability_extractsImports(t *testing.T) {
	v := osvschema.Vulnerability{
		ID: "GO-IMPORTS",
		Affected: []osvschema.Affected{
			{
				Package: osvschema.Package{Name: "github.com/example/mod", Ecosystem: "Go"},
				EcosystemSpecific: map[string]any{
					"imports": []any{
						map[string]any{"path": "net/http", "symbols": []any{"Serve", "ListenAndServe", "Serve"}},
						map[string]any{"path": "crypto/tls"},
					},
				},
			},
		},
	}
	out := ProcessOSVVulnerability(v, PkgInput{QueryKey: QueryKey{Name: "github.com/example/mod", Version: "v1.0.0", Ecosystem: "Go"}})
	if len(out.AffectedImports) != 2 {
		t.Fatalf("expected 2 import entries, got %d", len(out.AffectedImports))
	}
	if out.AffectedImports[0].Path != "crypto/tls" {
		t.Fatalf("expected crypto/tls first, got %s", out.AffectedImports[0].Path)
	}
	if out.AffectedImports[1].Path != "net/http" {
		t.Fatalf("expected net/http second, got %s", out.AffectedImports[1].Path)
	}
	if len(out.AffectedImports[1].Symbols) != 2 {
		t.Fatalf("expected deduped symbols, got %v", out.AffectedImports[1].Symbols)
	}
}

func Test_ProcessOSVVulnerability_databaseSpecific(t *testing.T) {
	v := osvschema.Vulnerability{
		ID:               "GO-DBSPEC",
		DatabaseSpecific: map[string]any{"url": "https://pkg.go.dev/vuln/GO-DBSPEC", "review_status": "REVIEWED", "count": 5},
	}
	out := ProcessOSVVulnerability(v, PkgInput{QueryKey: QueryKey{Name: "github.com/example/mod", Version: "v1.0.0", Ecosystem: "Go"}})
	if out.DatabaseSpecific["url"] != "https://pkg.go.dev/vuln/GO-DBSPEC" {
		t.Fatalf("expected url preserved, got %q", out.DatabaseSpecific["url"])
	}
	if out.DatabaseSpecific["review_status"] != "REVIEWED" {
		t.Fatalf("expected review_status preserved, got %q", out.DatabaseSpecific["review_status"])
	}
	if len(out.DatabaseSpecific) != 2 {
		t.Fatalf("expected only string entries kept, got %v", out.DatabaseSpecific)
	}
}
