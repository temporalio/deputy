package vuln

import (
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		severity Severity
		want     string
	}{
		{SeverityUnknown, "UNKNOWN"},
		{SeverityLow, "LOW"},
		{SeverityMedium, "MEDIUM"},
		{SeverityHigh, "HIGH"},
		{SeverityCritical, "CRITICAL"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.severity.String()
			if got != tt.want {
				t.Errorf("Severity.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  Severity
	}{
		{"LOW", SeverityLow},
		{"low", SeverityLow},
		{"  Low  ", SeverityLow},
		{"MEDIUM", SeverityMedium},
		{"MODERATE", SeverityMedium},
		{"MED", SeverityMedium},
		{"HIGH", SeverityHigh},
		{"high", SeverityHigh},
		{"CRITICAL", SeverityCritical},
		{"CRIT", SeverityCritical},
		{"critical", SeverityCritical},
		{"UNKNOWN", SeverityUnknown},
		{"invalid", SeverityUnknown},
		{"", SeverityUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseSeverity(tt.input)
			if got != tt.want {
				t.Errorf("ParseSeverity(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestSeverityScore(t *testing.T) {
	// Verify that severity scores are ordered correctly
	tests := []struct {
		name             string
		sev1             Severity
		sev2             Severity
		want1HigherThan2 bool
	}{
		{"critical > high", SeverityCritical, SeverityHigh, true},
		{"high > medium", SeverityHigh, SeverityMedium, true},
		{"medium > low", SeverityMedium, SeverityLow, true},
		{"low > unknown", SeverityLow, SeverityUnknown, true},
		{"low < high", SeverityLow, SeverityHigh, false},
		{"equal", SeverityMedium, SeverityMedium, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.sev1.IsHigherThan(tt.sev2)
			if got != tt.want1HigherThan2 {
				t.Errorf("%v.IsHigherThan(%v) = %v, want %v", tt.sev1, tt.sev2, got, tt.want1HigherThan2)
			}
		})
	}
}

func TestSeverityTypeString(t *testing.T) {
	tests := []struct {
		sevType SeverityType
		want    string
	}{
		{SeverityTypeUnknown, "UNKNOWN"},
		{SeverityTypeCVSSv2, "CVSS_V2"},
		{SeverityTypeCVSSv3, "CVSS_V3"},
		{SeverityTypeCVSSv4, "CVSS_V4"},
		{SeverityTypeGHSA, "GHSA"},
		{SeverityTypeCustom, "CUSTOM"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.sevType.String()
			if got != tt.want {
				t.Errorf("SeverityType.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSeverityType(t *testing.T) {
	tests := []struct {
		input string
		want  SeverityType
	}{
		{"CVSS_V2", SeverityTypeCVSSv2},
		{"CVSSV2", SeverityTypeCVSSv2},
		{"cvss_v2", SeverityTypeCVSSv2},
		{"CVSS_V3", SeverityTypeCVSSv3},
		{"CVSSV3", SeverityTypeCVSSv3},
		{"CVSS_V4", SeverityTypeCVSSv4},
		{"GHSA", SeverityTypeGHSA},
		{"ghsa", SeverityTypeGHSA},
		{"CUSTOM", SeverityTypeCustom},
		{"invalid", SeverityTypeUnknown},
		{"", SeverityTypeUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := ParseSeverityType(tt.input)
			if got != tt.want {
				t.Errorf("ParseSeverityType(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestNewSeverityInfo(t *testing.T) {
	tests := []struct {
		name        string
		severityStr string
		typeStr     string
		wantLevel   Severity
		wantType    SeverityType
	}{
		{
			name:        "CVSS v3 High",
			severityStr: "HIGH",
			typeStr:     "CVSS_V3",
			wantLevel:   SeverityHigh,
			wantType:    SeverityTypeCVSSv3,
		},
		{
			name:        "GHSA Critical",
			severityStr: "CRITICAL",
			typeStr:     "GHSA",
			wantLevel:   SeverityCritical,
			wantType:    SeverityTypeGHSA,
		},
		{
			name:        "Unknown severity",
			severityStr: "WEIRD",
			typeStr:     "UNKNOWN",
			wantLevel:   SeverityUnknown,
			wantType:    SeverityTypeUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewSeverityInfo(tt.severityStr, tt.typeStr)
			if got.Level != tt.wantLevel {
				t.Errorf("NewSeverityInfo().Level = %v, want %v", got.Level, tt.wantLevel)
			}
			if got.Type != tt.wantType {
				t.Errorf("NewSeverityInfo().Type = %v, want %v", got.Type, tt.wantType)
			}
			if got.RawScore != tt.severityStr {
				t.Errorf("NewSeverityInfo().RawScore = %q, want %q", got.RawScore, tt.severityStr)
			}
			if got.RawType != tt.typeStr {
				t.Errorf("NewSeverityInfo().RawType = %q, want %q", got.RawType, tt.typeStr)
			}
		})
	}
}

func TestSeverityInfoIsValid(t *testing.T) {
	tests := []struct {
		name string
		si   SeverityInfo
		want bool
	}{
		{
			name: "valid",
			si:   NewSeverityInfo("HIGH", "CVSS_V3"),
			want: true,
		},
		{
			name: "unknown level",
			si:   NewSeverityInfo("WEIRD", "CVSS_V3"),
			want: false,
		},
		{
			name: "unknown type",
			si:   NewSeverityInfo("HIGH", "WEIRD"),
			want: false,
		},
		{
			name: "both unknown",
			si:   NewSeverityInfo("", ""),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.si.IsValid()
			if got != tt.want {
				t.Errorf("SeverityInfo.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSeverityInfoString(t *testing.T) {
	tests := []struct {
		name string
		si   SeverityInfo
		want string
	}{
		{
			name: "with type",
			si:   NewSeverityInfo("HIGH", "CVSS_V3"),
			want: "HIGH (CVSS_V3)",
		},
		{
			name: "without type",
			si:   NewSeverityInfo("MEDIUM", ""),
			want: "MEDIUM",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.si.String()
			if got != tt.want {
				t.Errorf("SeverityInfo.String() = %q, want %q", got, tt.want)
			}
		})
	}
}
