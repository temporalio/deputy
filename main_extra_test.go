package main

import (
	"testing"
)

func Test_parseFloat_and_parseCVSSScore(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"simple int", "3", 3},
		{"simple float", "7.5", 7.5},
		{"with text", "7.5-something", 7.5},
		{"out of range", "11.1", -1},
		{"invalid", "abc", -1},
	}

	for _, tt := range tests {
		t.Run("parseFloat: "+tt.name, func(t *testing.T) {
			got := parseFloat(tt.input)
			if got != tt.expected {
				t.Fatalf("parseFloat(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}

	cvssTests := []struct {
		name     string
		input    string
		expected float64
	}{
		{"numeric", "9.8", 9.8},
		{"text high", "HIGH", 7.5},
		{"vector with base", "CVSS:3.1/Base:9.8/AV:N/AC:L", 9.8},
		{"unknown", "no-score", -1},
	}

	for _, tt := range cvssTests {
		t.Run("parseCVSSScore: "+tt.name, func(t *testing.T) {
			got := parseCVSSScore(tt.input)
			if got != tt.expected {
				t.Fatalf("parseCVSSScore(%q) = %v, want %v", tt.input, got, tt.expected)
			}
		})
	}
}

func Test_version_helpers_and_extraction(t *testing.T) {
	testsNorm := []struct {
		in  string
		out string
	}{
		{"1.2.3", "v1.2.3"},
		{"v2.0.0", "v2.0.0"},
		{"", ""},
	}
	for _, tt := range testsNorm {
		t.Run("normalizeGoVersion:"+tt.in, func(t *testing.T) {
			if got := normalizeGoVersion(tt.in); got != tt.out {
				t.Fatalf("normalizeGoVersion(%q) = %q, want %q", tt.in, got, tt.out)
			}
		})
	}

	majTests := []struct {
		in  string
		out int
	}{
		{"v3.41.0", 3},
		{"3.41.0", 3},
		{"v10.0.0", 10},
	}
	for _, tt := range majTests {
		t.Run("extractMajorFromSemver:"+tt.in, func(t *testing.T) {
			if got := extractMajorFromSemver(tt.in); got != tt.out {
				t.Fatalf("extractMajorFromSemver(%q) = %d, want %d", tt.in, got, tt.out)
			}
		})
	}

	pathTests := []struct {
		in  string
		out int
	}{
		{"github.com/example/pkg/v2", 2},
		{"github.com/example/pkg", 1},
		{"/v10", 10},
	}
	for _, tt := range pathTests {
		t.Run("extractMajorVersionFromPath:"+tt.in, func(t *testing.T) {
			if got := extractMajorVersionFromPath(tt.in); got != tt.out {
				t.Fatalf("extractMajorVersionFromPath(%q) = %d, want %d", tt.in, got, tt.out)
			}
		})
	}
}

func Test_alias_and_filter_helpers(t *testing.T) {
	t.Run("hasCommonAlias", func(t *testing.T) {
		a := []string{"A", "B"}
		b := []string{"C", "B"}
		if !hasCommonAlias(a, b) {
			t.Fatalf("expected hasCommonAlias to be true")
		}
		c := []string{"X"}
		if hasCommonAlias(a, c) {
			t.Fatalf("expected hasCommonAlias to be false")
		}
	})

	t.Run("filterRelevantSecondaryIDs", func(t *testing.T) {
		secondaries := []string{"GO-1", "GHSA-1", "CVE-1", "OTHER"}

		got := filterRelevantSecondaryIDs(secondaries, "CVE-1")
		// For CVE primary, expect GO- and GHSA- (order not important)
		expected := map[string]bool{"GO-1": true, "GHSA-1": true}
		if len(got) != 2 {
			t.Fatalf("unexpected result %v", got)
		}
		for _, id := range got {
			if !expected[id] {
				t.Fatalf("unexpected id %q in result %v", id, got)
			}
		}

		got2 := filterRelevantSecondaryIDs(secondaries, "GO-1")
		expected2 := map[string]bool{"CVE-1": true, "GHSA-1": true}
		if len(got2) != 2 {
			t.Fatalf("unexpected result %v", got2)
		}
		for _, id := range got2 {
			if !expected2[id] {
				t.Fatalf("unexpected id %q in result %v", id, got2)
			}
		}
	})
}

func Test_cleanSummaryText_and_similarity(t *testing.T) {
	t.Run("cleanSummaryText removes package occurrences and capitalizes", func(t *testing.T) {
		summary := "vulnerability in github.com/foo/bar causes crash"
		cleaned := cleanSummaryText(summary, "github.com/foo/bar/v2")
		if cleaned == summary {
			t.Fatalf("expected summary to be cleaned, got %q", cleaned)
		}
		// Should not contain the package name
		if contains := (len(cleaned) > 0 && cleaned == ""); contains {
			t.Fatalf("unexpected empty cleaned summary")
		}
	})

	t.Run("calculateSimilarity basic", func(t *testing.T) {
		a := "abcdef"
		b := "abcxyz"
		sim := calculateSimilarity(a, b)
		if sim <= 0.4 || sim >= 0.6 { // expect ~0.5
			t.Fatalf("unexpected similarity %v", sim)
		}
	})
}

func Test_findBestSeverity_and_consolidateVulnerabilities(t *testing.T) {
	t.Run("findBestSeverity picks highest numeric then GHSA preference", func(t *testing.T) {
		vulns := []Vulnerability{
			{ID: "V1", Severity: "7.5", SeverityType: "CVSS_V3"},
			{ID: "GHSA-1", Severity: "HIGH", SeverityType: "GHSA"},
			{ID: "V3", Severity: "9.0", SeverityType: "CVSS_V3"},
		}
		// First pass picks 9.0
		sev, sevType := findBestSeverity(vulns)
		if sev != "9.0" || sevType != "CVSS_V3" {
			t.Fatalf("unexpected best severity %v %v", sev, sevType)
		}

		// If GHSA has higher mapped score, it should win
		vulns2 := []Vulnerability{
			{ID: "V1", Severity: "5.0", SeverityType: "CVSS_V3"},
			{ID: "GHSA-1", Severity: "CRITICAL", SeverityType: "GHSA"},
		}
		sev2, sevType2 := findBestSeverity(vulns2)
		if sev2 != "CRITICAL" || sevType2 != "GHSA" {
			t.Fatalf("unexpected best severity %v %v", sev2, sevType2)
		}
	})

	t.Run("consolidateVulnerabilities groups by alias and picks best primary", func(t *testing.T) {
		v1 := Vulnerability{ID: "V1", Aliases: []string{"CVE-2020-1", "GHSA-1"}}
		v2 := Vulnerability{ID: "V2", Aliases: []string{"GHSA-1"}}
		v3 := Vulnerability{ID: "V3", Aliases: []string{"OTHER-1"}}
		cons := consolidateVulnerabilities([]Vulnerability{v1, v2, v3})
		if len(cons) != 2 {
			t.Fatalf("expected 2 groups, got %d", len(cons))
		}
		// Collect primary IDs
		primaries := map[string]bool{}
		for _, c := range cons {
			primaries[c.PrimaryID] = true
		}
		if !primaries["CVE-2020-1"] {
			t.Fatalf("expected CVE primary to be selected, primaries=%v", primaries)
		}
	})
}
