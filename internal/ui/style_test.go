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

func TestParseCVSSScoreSimple(t *testing.T) {
	tests := []struct {
		input string
		want  float64
	}{
		{"9.8", 9.8},
		{"  7.5  ", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8", 9.8},
		{"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.5}, // Estimated
		{"invalid", -1},
		{"", -1},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := parseCVSSScoreSimple(tt.input)
			if got != tt.want {
				t.Errorf("parseCVSSScoreSimple(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseFloat(t *testing.T) {
	tests := []struct {
		input   string
		want    float64
		wantErr bool
	}{
		{"1.2", 1.2, false},
		{"0.5", 0.5, false},
		{"10", 10, false},
		{"0", 0, false},
		{"0.0", 0, false},
		{"abc", 0, true},
		{"", 0, true},
		{"  ", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			var got float64
			err := parseFloat(tt.input, &got)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseFloat(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseFloat(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestEstimateScoreFromVector(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"AV:N/AC:L/PR:N/C:H/I:H/A:H", 9.5},
		{"AV:L/AC:H/PR:H/C:N/I:N/A:N", 4.0},
		{"", 5.0},
	}

	for _, tt := range tests {
		t.Run(tt.vector, func(t *testing.T) {
			got := estimateScoreFromVector(tt.vector)
			if got != tt.want {
				t.Errorf("estimateScoreFromVector(%q) = %v, want %v", tt.vector, got, tt.want)
			}
		})
	}
}

func contains(s, substr string) bool {
	stripped := stripANSI(s)
	return stripped == "["+substr+"]" || stripped == substr
}

// FuzzParseFloat tests that parseFloat does not panic on arbitrary input.
func FuzzParseFloat(f *testing.F) {
	// Seed corpus with representative inputs
	f.Add("9.8")
	f.Add("0")
	f.Add("0.0")
	f.Add("")
	f.Add("   ")
	f.Add("abc")
	f.Add("10.0.0")
	f.Add("-5.5")
	f.Add("1e10")
	f.Add("NaN")
	f.Add("Inf")

	f.Fuzz(func(t *testing.T, input string) {
		var out float64
		_ = parseFloat(input, &out)
		// No panic is success
	})
}

// FuzzParseCVSSScoreSimple tests that parseCVSSScoreSimple does not panic
// and returns a score in the valid range [-1, 10].
func FuzzParseCVSSScoreSimple(f *testing.F) {
	f.Add("9.8")
	f.Add("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	f.Add("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H 9.8")
	f.Add("")
	f.Add("invalid")
	f.Add("CRITICAL")
	f.Add("7.5 some text")

	f.Fuzz(func(t *testing.T, input string) {
		score := parseCVSSScoreSimple(input)
		if score < -1 || score > 10 {
			t.Errorf("parseCVSSScoreSimple(%q) = %v, want in range [-1, 10]", input, score)
		}
	})
}

// FuzzEstimateScoreFromVector tests that estimateScoreFromVector does not panic
// and returns a score in the valid range [0, 10].
func FuzzEstimateScoreFromVector(f *testing.F) {
	f.Add("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
	f.Add("AV:L/AC:H/PR:H/C:N/I:N/A:N")
	f.Add("")
	f.Add("///")
	f.Add("AV:X/AC:Y/PR:Z")

	f.Fuzz(func(t *testing.T, vector string) {
		score := estimateScoreFromVector(vector)
		if score < 0 || score > 10 {
			t.Errorf("estimateScoreFromVector(%q) = %v, want in range [0, 10]", vector, score)
		}
	})
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
