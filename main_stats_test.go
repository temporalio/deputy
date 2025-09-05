package main

import (
	"testing"
)

func Test_categorizeVulnerabilities_counts(t *testing.T) {
	// Create multiple vulnerabilities with overlaps to test consolidation and stats
	v1 := Vulnerability{ID: "V1", Aliases: []string{"CVE-2020-1"}, Severity: "9.8", SeverityType: "CVSS_V3", IsDirect: true, FixedVersions: []string{"v1.2.0"}, Package: "pkgA"}
	v1dup := Vulnerability{ID: "V1b", Aliases: []string{"CVE-2020-1"}, Severity: "9.8", SeverityType: "CVSS_V3", IsDirect: true, FixedVersions: []string{"v1.2.0"}, Package: "pkgA"}
	v2 := Vulnerability{ID: "V2", Aliases: []string{"GHSA-1"}, Severity: "HIGH", SeverityType: "GHSA", IsDirect: false, FixedVersions: nil, Package: "pkgB"}
	v3 := Vulnerability{ID: "V3", Aliases: nil, Severity: "", SeverityType: "", IsDirect: false, FixedVersions: nil, Package: "pkgC"}

	input := []Vulnerability{v1, v1dup, v2, v3}

	stats := categorizeVulnerabilities(input)

	if stats.TotalVulns != 4 {
		t.Fatalf("TotalVulns expected 4, got %d", stats.TotalVulns)
	}

	if stats.UniqueVulns != 3 {
		t.Fatalf("UniqueVulns expected 3 after consolidation, got %d", stats.UniqueVulns)
	}

	if stats.DuplicatesFound != 1 {
		t.Fatalf("DuplicatesFound expected 1, got %d", stats.DuplicatesFound)
	}

	if stats.CVECount != 1 {
		t.Fatalf("CVECount expected 1, got %d", stats.CVECount)
	}

	if stats.CriticalSev != 1 {
		t.Fatalf("CriticalSev expected 1, got %d", stats.CriticalSev)
	}

	if stats.HighSeverity != 1 {
		t.Fatalf("HighSeverity expected 1, got %d", stats.HighSeverity)
	}

	if stats.UnknownSev == 0 {
		t.Fatalf("UnknownSev expected >0, got %d", stats.UnknownSev)
	}

	if stats.FixAvailable != 1 {
		t.Fatalf("FixAvailable expected 1, got %d", stats.FixAvailable)
	}

	if stats.DirectDeps != 1 {
		t.Fatalf("DirectDeps expected 1, got %d", stats.DirectDeps)
	}

	if stats.IndirectDeps != 2 {
		t.Fatalf("IndirectDeps expected 2, got %d", stats.IndirectDeps)
	}
}
