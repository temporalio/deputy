package analysis

import "testing"

func Test_CategorizeVulnerabilities_counts(t *testing.T) {
    v1 := Vulnerability{ID: "V1", Aliases: []string{"CVE-2020-1"}, Severity: "9.8", SeverityType: "CVSS_V3", IsDirect: true, FixedVersions: []string{"v1.2.0"}, Package: "pkgA", Affected: true}
    v1dup := Vulnerability{ID: "V1b", Aliases: []string{"CVE-2020-1"}, Severity: "9.8", SeverityType: "CVSS_V3", IsDirect: true, FixedVersions: []string{"v1.2.0"}, Package: "pkgA", Affected: true}
    v2 := Vulnerability{ID: "V2", Aliases: []string{"GHSA-1"}, Severity: "HIGH", SeverityType: "GHSA", IsDirect: false, FixedVersions: nil, Package: "pkgB", Affected: true}
    v3 := Vulnerability{ID: "V3", Aliases: nil, Severity: "", SeverityType: "", IsDirect: false, FixedVersions: nil, Package: "pkgC", Affected: true}
    input := []Vulnerability{v1, v1dup, v2, v3}

    stats := CategorizeVulnerabilities(input)
    if stats.TotalVulns != 3 { t.Fatalf("TotalVulns= %d", stats.TotalVulns) }
    if stats.UniqueVulns != 3 { t.Fatalf("UniqueVulns= %d", stats.UniqueVulns) }
    if stats.DuplicatesFound != 1 { t.Fatalf("DuplicatesFound= %d", stats.DuplicatesFound) }
    if stats.CVECount != 1 { t.Fatalf("CVECount= %d", stats.CVECount) }
    if stats.CriticalSev != 1 { t.Fatalf("CriticalSev= %d", stats.CriticalSev) }
    if stats.HighSeverity != 1 { t.Fatalf("HighSeverity= %d", stats.HighSeverity) }
    if stats.UnknownSev == 0 { t.Fatalf("UnknownSev= %d", stats.UnknownSev) }
    if stats.FixAvailable != 1 { t.Fatalf("FixAvailable= %d", stats.FixAvailable) }
    if stats.DirectDeps != 1 { t.Fatalf("DirectDeps= %d", stats.DirectDeps) }
    if stats.IndirectDeps != 2 { t.Fatalf("IndirectDeps= %d", stats.IndirectDeps) }
}

