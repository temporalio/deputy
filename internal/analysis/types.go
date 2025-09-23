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
	Ecosystem     string
	PURL          string
	Published     string
	Modified      string
	References    []string
	FixedVersions []string
	Affected      bool
	Locations     []string
	ManifestRefs  []ManifestReference
}

// ConsolidatedVulnerability represents a deduplicated vulnerability with primary/secondary IDs.
type ConsolidatedVulnerability struct {
	PrimaryID        string
	SecondaryIDs     []string
	AllIDs           []string
	HiddenAliasCount int
	Summary          string
	Details          string
	Severity         string
	SeverityType     string
	Package          string
	Version          string
	IsDirect         bool
	Ecosystem        string
	PURL             string
	Published        string
	Modified         string
	References       []string
	FixedVersions    []string
	RelatedCount     int
	Locations        []string
	ManifestRefs     []ManifestReference
}

// ManifestReference describes the manifest/lockfile context for a dependency.
type ManifestReference struct {
	Path    string
	Manager string
	Groups  []string
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
