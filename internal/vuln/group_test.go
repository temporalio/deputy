package vuln

import (
	"testing"

	"github.com/picatz/deputy/internal/collections"
)

func TestFilterTrustedAliases(t *testing.T) {
	aliases := []string{
		"GO-2024-0001",
		"ghsa-xxxx",
		"pysec-2024-1",
		"rubysec-2023-1",
		"rustsec-2021-0001",
		"msrc-2024-0001",
		"gsd-2024-1",
		"BIT-golang-2024-1",
	}
	preferred, hidden := filterTrustedAliases(aliases)
	if hidden != 1 {
		t.Fatalf("expected 1 hidden alias, got %d", hidden)
	}

	want := collections.NewSet(
		"GO-2024-0001",
		"ghsa-xxxx",
		"pysec-2024-1",
		"rubysec-2023-1",
		"rustsec-2021-0001",
		"msrc-2024-0001",
		"gsd-2024-1",
	)
	if len(preferred) != len(want) {
		t.Fatalf("expected %d preferred aliases, got %d", len(want), len(preferred))
	}
	for _, alias := range preferred {
		if !want.Has(alias) {
			t.Fatalf("unexpected alias kept: %s", alias)
		}
	}
}

func TestCreateConsolidatedVulnerabilityAliasFiltering(t *testing.T) {
	vulns := []Vulnerability{
		{
			ID: "CVE-2024-0001",
			Aliases: []string{
				"GO-2024-0001",
				"ghsa-xxxx",
				"PYSEC-2024-1",
				"RUBYSEC-2023-1",
				"RUSTSEC-2021-0001",
				"MSRC-2024-0001",
				"GSD-2024-1",
				"BIT-golang-2024-1",
			},
			Affected: true,
		},
	}

	cons := createConsolidatedVulnerability("CVE-2024-0001", vulns)

	wantSet := collections.NewSet(
		"GO-2024-0001",
		"ghsa-xxxx",
		"PYSEC-2024-1",
		"RUBYSEC-2023-1",
		"RUSTSEC-2021-0001",
		"MSRC-2024-0001",
		"GSD-2024-1",
	)
	if cons.HiddenAliasCount != 1 {
		t.Fatalf("expected hidden alias count 1, got %d", cons.HiddenAliasCount)
	}
	if len(cons.SecondaryIDs) != len(wantSet) {
		t.Fatalf("expected %d secondary aliases, got %d", len(wantSet), len(cons.SecondaryIDs))
	}
	for _, alias := range cons.SecondaryIDs {
		if !wantSet.Has(alias) {
			t.Fatalf("unexpected secondary alias %s", alias)
		}
	}
}

func TestCreateConsolidatedVulnerabilityAllAliasesHidden(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "VULN-1", Aliases: []string{"BIT-golang-2024-1", "UNTRUSTED-0001"}, Affected: true},
	}
	cons := createConsolidatedVulnerability("VULN-PRIMARY", vulns)
	if len(cons.SecondaryIDs) != 0 {
		t.Fatalf("expected no secondary aliases, got %d", len(cons.SecondaryIDs))
	}
	if cons.HiddenAliasCount != 3 {
		t.Fatalf("expected hidden alias count 3, got %d", cons.HiddenAliasCount)
	}
}

func TestCreateConsolidatedVulnerabilityDatabaseSpecificMerged(t *testing.T) {
	vulns := []Vulnerability{
		{ID: "A", Affected: true, DatabaseSpecific: map[string]string{"url": "https://pkg.go.dev/vuln/GO-A"}},
		{ID: "B", Affected: true, DatabaseSpecific: map[string]string{"review_status": "REVIEWED"}},
		{ID: "C", Affected: true, DatabaseSpecific: map[string]string{"url": "https://pkg.go.dev/vuln/GO-A"}},
	}
	cons := createConsolidatedVulnerability("A", vulns)
	if len(cons.DatabaseSpecific) != 2 {
		t.Fatalf("expected merged database_specific entries, got %v", cons.DatabaseSpecific)
	}
	if cons.DatabaseSpecific["url"] != "https://pkg.go.dev/vuln/GO-A" {
		t.Fatalf("unexpected url %q", cons.DatabaseSpecific["url"])
	}
	if cons.DatabaseSpecific["review_status"] != "REVIEWED" {
		t.Fatalf("unexpected review_status %q", cons.DatabaseSpecific["review_status"])
	}
}

func TestIDPriorityConstants(t *testing.T) {
	t.Parallel()

	// Verify constants have expected values and ordering
	tests := []struct {
		name     string
		constant int
		want     int
	}{
		{"IDPriorityCVE", IDPriorityCVE, 1},
		{"IDPriorityGO", IDPriorityGO, 2},
		{"IDPriorityGHSA", IDPriorityGHSA, 3},
		{"IDPriorityOther", IDPriorityOther, 4},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.want {
				t.Errorf("%s = %d, want %d", tt.name, tt.constant, tt.want)
			}
		})
	}

	// Verify priority ordering: CVE < GO < GHSA < Other
	if IDPriorityCVE >= IDPriorityGO {
		t.Error("CVE priority should be higher (lower number) than GO")
	}
	if IDPriorityGO >= IDPriorityGHSA {
		t.Error("GO priority should be higher (lower number) than GHSA")
	}
	if IDPriorityGHSA >= IDPriorityOther {
		t.Error("GHSA priority should be higher (lower number) than Other")
	}
}

func TestGetIDPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		id   string
		want int
	}{
		{"CVE-2024-0001", IDPriorityCVE},
		{"CVE-2023-12345", IDPriorityCVE},
		{"GO-2024-0001", IDPriorityGO},
		{"GO-2023-9999", IDPriorityGO},
		{"GHSA-xxxx-xxxx-xxxx", IDPriorityGHSA},
		{"GHSA-1234-5678-9abc", IDPriorityGHSA},
		{"PYSEC-2024-0001", IDPriorityOther},
		{"RUSTSEC-2024-0001", IDPriorityOther},
		{"BIT-golang-2024-1", IDPriorityOther},
		{"UNKNOWN-123", IDPriorityOther},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			got := getIDPriority(tt.id)
			if got != tt.want {
				t.Errorf("getIDPriority(%q) = %d, want %d", tt.id, got, tt.want)
			}
		})
	}
}
