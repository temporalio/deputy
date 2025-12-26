package ui

import (
	"regexp"
	"testing"
)

var ansiRegex = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")

func stripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

func TestSeverityLabel(t *testing.T) {
	tests := []struct {
		name         string
		severity     string
		severityType string
		wantContains string
	}{
		{"GHSA Critical", "CRITICAL", "GHSA", "CRITICAL"},
		{"GHSA High", "HIGH", "GHSA", "HIGH"},
		{"GHSA Moderate", "MODERATE", "GHSA", "MED"},
		{"GHSA Medium", "MEDIUM", "GHSA", "MED"},
		{"GHSA Low", "LOW", "GHSA", "LOW"},
		{"CVSS Critical", "9.8", "CVSS", "CRITICAL"},
		{"CVSS High", "7.5", "CVSS", "HIGH"},
		{"CVSS Medium", "5.0", "CVSS", "MED"},
		{"CVSS Low", "2.0", "CVSS", "LOW"},
		{"CVSS Vector v3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS", "CRITICAL"},
		{"CVSS Vector v3.1 No Prefix", "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "CVSS", "CRITICAL"},
		{"Unknown", "FOO", "BAR", "?"},
		{"Empty", "", "", "?"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SeverityLabel(tt.severity, tt.severityType)
			if !contains(got, tt.wantContains) {
				t.Errorf("SeverityLabel(%q, %q) = %q, want to contain %q", tt.severity, tt.severityType, got, tt.wantContains)
			}
		})
	}
}

func TestScoreLabel(t *testing.T) {
	tests := []struct {
		score        float64
		wantContains string
	}{
		{10.0, "CRITICAL"},
		{9.0, "CRITICAL"},
		{8.9, "HIGH"},
		{7.0, "HIGH"},
		{6.9, "MED"},
		{4.0, "MED"},
		{3.9, "LOW"},
		{0.0, "LOW"},
		{-1.0, "?"},
	}

	for _, tt := range tests {
		t.Run(tt.wantContains, func(t *testing.T) {
			got := ScoreLabel(tt.score)
			if !contains(got, tt.wantContains) {
				t.Errorf("ScoreLabel(%v) = %q, want to contain %q", tt.score, got, tt.wantContains)
			}
		})
	}
}

func contains(s, substr string) bool {
	stripped := stripANSI(s)
	return stripped == "["+substr+"]" || stripped == substr
}

// FuzzSeverityLabel tests that SeverityLabel does not panic on arbitrary input.
func FuzzSeverityLabel(f *testing.F) {
	f.Add("CRITICAL", "GHSA")
	f.Add("9.8", "CVSS")
	f.Add("", "")
	f.Add("HIGH", "")
	f.Add("random", "unknown")

	f.Fuzz(func(t *testing.T, severity, severityType string) {
		result := SeverityLabel(severity, severityType)
		if result == "" {
			t.Errorf("SeverityLabel(%q, %q) returned empty string", severity, severityType)
		}
	})
}
