package analysis

// Vulnerability represents a vulnerability found in a package.
type Vulnerability struct {
    ID            string
    Aliases       []string
    Summary       string
    Details       string
    CVE           string
    Severity      string
    SeverityType  string
    Package       string
    Version       string
    IsDirect      bool
    Published     string
    Modified      string
    References    []string
    FixedVersions []string
}

// ConsolidatedVulnerability represents a deduplicated vulnerability with primary/secondary IDs.
type ConsolidatedVulnerability struct {
    PrimaryID     string
    SecondaryIDs  []string
    AllIDs        []string
    Summary       string
    Details       string
    Severity      string
    SeverityType  string
    Package       string
    Version       string
    IsDirect      bool
    Published     string
    Modified      string
    References    []string
    FixedVersions []string
    RelatedCount  int
}

// VulnerabilityStats tracks vulnerability statistics.
type VulnerabilityStats struct {
    TotalVulns      int
    UniqueVulns     int
    CVECount        int
    HighSeverity    int
    MedSeverity     int
    LowSeverity     int
    UnknownSev      int
    DirectDeps      int
    IndirectDeps    int
    CriticalSev     int
    FixAvailable    int
    DuplicatesFound int
}

