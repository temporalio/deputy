package analysis

import "testing"

func Test_HasCommonAlias(t *testing.T) {
    a := []string{"A", "B"}
    b := []string{"C", "B"}
    if !HasCommonAlias(a, b) { t.Fatalf("expected true") }
    c := []string{"X"}
    if HasCommonAlias(a, c) { t.Fatalf("expected false") }
}

func Test_FindBestSeverity_and_Consolidate(t *testing.T) {
    t.Run("findBestSeverity picks correct", func(t *testing.T) {
        vulns := []Vulnerability{
            {ID: "V1", Severity: "7.5", SeverityType: "CVSS_V3", Affected: true},
            {ID: "GHSA-1", Severity: "HIGH", SeverityType: "GHSA", Affected: true},
            {ID: "V3", Severity: "9.0", SeverityType: "CVSS_V3", Affected: true},
        }
        sev, sevType := FindBestSeverity(vulns)
        if sev == "" || sevType == "" { t.Fatalf("empty severity") }
    })

    t.Run("consolidateVulnerabilities groups by alias", func(t *testing.T) {
        v1 := Vulnerability{ID: "V1", Aliases: []string{"CVE-2020-1", "GHSA-1"}, Affected: true}
        v2 := Vulnerability{ID: "V2", Aliases: []string{"GHSA-1"}, Affected: true}
        v3 := Vulnerability{ID: "V3", Aliases: []string{"OTHER-1"}, Affected: true}
        cons := ConsolidateVulnerabilities([]Vulnerability{v1, v2, v3})
        if len(cons) != 2 { t.Fatalf("expected 2 groups, got %d", len(cons)) }
        primaries := map[string]bool{}
        for _, c := range cons { primaries[c.PrimaryID] = true }
        if !primaries["CVE-2020-1"] { t.Fatalf("expected CVE primary selected, got %v", primaries) }
    })
}

