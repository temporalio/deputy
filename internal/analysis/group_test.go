package analysis

import "testing"

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

	want := map[string]bool{
		"GO-2024-0001":      true,
		"ghsa-xxxx":         true,
		"pysec-2024-1":      true,
		"rubysec-2023-1":    true,
		"rustsec-2021-0001": true,
		"msrc-2024-0001":    true,
		"gsd-2024-1":        true,
	}
	if len(preferred) != len(want) {
		t.Fatalf("expected %d preferred aliases, got %d", len(want), len(preferred))
	}
	for _, alias := range preferred {
		if !want[alias] {
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

	wantSet := map[string]struct{}{
		"GO-2024-0001":      {},
		"ghsa-xxxx":         {},
		"PYSEC-2024-1":      {},
		"RUBYSEC-2023-1":    {},
		"RUSTSEC-2021-0001": {},
		"MSRC-2024-0001":    {},
		"GSD-2024-1":        {},
	}
	if cons.HiddenAliasCount != 1 {
		t.Fatalf("expected hidden alias count 1, got %d", cons.HiddenAliasCount)
	}
	if len(cons.SecondaryIDs) != len(wantSet) {
		t.Fatalf("expected %d secondary aliases, got %d", len(wantSet), len(cons.SecondaryIDs))
	}
	for _, alias := range cons.SecondaryIDs {
		if _, ok := wantSet[alias]; !ok {
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
