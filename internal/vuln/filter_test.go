package vuln

import (
	"testing"
	"time"
)

func TestFilterVulnerabilities(t *testing.T) {
	t.Parallel()

	vulns := []Vulnerability{
		{ID: "V1", Severity: "CRITICAL", FixedVersions: []string{"2.0.0"}, Version: "1.0.0", IsDirect: true},
		{ID: "V2", Severity: "HIGH", FixedVersions: nil, IsDirect: false},
		{ID: "V3", Severity: "MEDIUM", FixedVersions: []string{"3.0.0"}, Version: "2.0.0", IsDirect: true},
		{ID: "V4", Severity: "LOW", IsDirect: false},
	}

	tests := []struct {
		name    string
		filters []VulnFilter
		wantIDs []string
	}{
		{
			name:    "no filters",
			filters: nil,
			wantIDs: []string{"V1", "V2", "V3", "V4"},
		},
		{
			name:    "has fix",
			filters: []VulnFilter{HasFix()},
			wantIDs: []string{"V1", "V3"},
		},
		{
			name:    "is direct",
			filters: []VulnFilter{IsDirect()},
			wantIDs: []string{"V1", "V3"},
		},
		{
			name:    "severity at least HIGH",
			filters: []VulnFilter{SeverityAtLeast("HIGH")},
			wantIDs: []string{"V1", "V2"},
		},
		{
			name:    "combined: direct with fix",
			filters: []VulnFilter{HasFix(), IsDirect()},
			wantIDs: []string{"V1", "V3"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterVulnerabilities(vulns, tt.filters...)
			if len(got) != len(tt.wantIDs) {
				t.Errorf("got %d vulns, want %d", len(got), len(tt.wantIDs))
				return
			}
			for i, v := range got {
				if v.ID != tt.wantIDs[i] {
					t.Errorf("got[%d].ID = %s, want %s", i, v.ID, tt.wantIDs[i])
				}
			}
		})
	}
}

func TestPublishedFilters(t *testing.T) {
	t.Parallel()

	ref := time.Date(2024, 6, 15, 0, 0, 0, 0, time.UTC)
	vulns := []Vulnerability{
		{ID: "V1", Published: "2024-01-01T00:00:00Z"},
		{ID: "V2", Published: "2024-06-15T00:00:00Z"},
		{ID: "V3", Published: "2024-12-31T00:00:00Z"},
		{ID: "V4", Published: ""}, // unknown
	}

	tests := []struct {
		name    string
		filter  VulnFilter
		wantIDs []string
	}{
		{
			name:    "published after",
			filter:  PublishedAfter(ref),
			wantIDs: []string{"V2", "V3"},
		},
		{
			name:    "published before",
			filter:  PublishedBefore(ref),
			wantIDs: []string{"V1", "V2", "V4"}, // V4 included conservatively
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterVulnerabilities(vulns, tt.filter)
			if len(got) != len(tt.wantIDs) {
				t.Errorf("got %d vulns, want %d", len(got), len(tt.wantIDs))
				return
			}
			for i, v := range got {
				if v.ID != tt.wantIDs[i] {
					t.Errorf("got[%d].ID = %s, want %s", i, v.ID, tt.wantIDs[i])
				}
			}
		})
	}
}

func TestParseSeverityScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		severity string
		wantRank int
	}{
		{"CRITICAL", 4},
		{"HIGH", 3},
		{"MEDIUM", 2},
		{"LOW", 1},
		{"UNKNOWN", 0},
		{"", 0},
	}

	for _, tt := range tests {
		if got := ParseSeverity(tt.severity).Score(); got != tt.wantRank {
			t.Errorf("ParseSeverity(%q).Score() = %d, want %d", tt.severity, got, tt.wantRank)
		}
	}
}
