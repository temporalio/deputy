package main

import (
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func makeTime(tstr string) time.Time {
	tm, _ := time.Parse(time.RFC3339, tstr)
	return tm
}

func Test_processOSVVulnerability_basic_fields(t *testing.T) {
	vuln := osvschema.Vulnerability{
		ID:        "GHSA-xxxx",
		Summary:   "Test summary",
		Details:   "Detailed info",
		Published: makeTime("2020-01-02T15:04:05Z"),
		Modified:  makeTime("2020-02-03T12:00:00Z"),
		Aliases:   []string{"CVE-2020-1", "GO-2020-1"},
		Severity: []osvschema.Severity{
			{Type: "CVSS_V3", Score: "7.8"},
		},
		DatabaseSpecific: map[string]interface{}{"severity": "HIGH"},
		References:       []osvschema.Reference{{URL: "https://example.com"}},
		Affected: []osvschema.Affected{
			{Ranges: []osvschema.Range{{Events: []osvschema.Event{{Fixed: "v1.2.3"}}}}},
		},
	}

	out := processOSVVulnerability(vuln, "github.com/example/pkg", "v1.0.0", true)

	if out.ID != "GHSA-xxxx" {
		t.Fatalf("unexpected ID: %v", out.ID)
	}
	if out.CVE != "CVE-2020-1" {
		t.Fatalf("expected CVE extracted, got %q", out.CVE)
	}
	if out.Severity == "" {
		t.Fatalf("expected severity to be set from CVSS or DB specific")
	}
	if len(out.References) == 0 || out.References[0] != "https://example.com" {
		t.Fatalf("unexpected references: %v", out.References)
	}
	if len(out.FixedVersions) == 0 || out.FixedVersions[0] != "v1.2.3" {
		t.Fatalf("unexpected fixed versions: %v", out.FixedVersions)
	}
	if out.Published == "" || out.Modified == "" {
		t.Fatalf("expected published and modified to be set")
	}
}

func Test_processOSVVulnerability_no_aliases_severity(t *testing.T) {
	vuln := osvschema.Vulnerability{
		ID: "V-1",
	}
	out := processOSVVulnerability(vuln, "pkg", "", false)
	if out.CVE != "" {
		t.Fatalf("unexpected CVE for aliasless vuln: %q", out.CVE)
	}
}
