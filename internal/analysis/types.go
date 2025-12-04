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
	// AffectedImports carries ecosystem-specific import path and symbol hints (from OSV; currently populated for Go).
	AffectedImports []AffectedImport
	// DatabaseSpecific holds string metadata from OSV (e.g., review_status, url).
	DatabaseSpecific map[string]string
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
	// AffectedImports carries ecosystem-specific import path and symbol hints (from OSV; currently populated for Go).
	AffectedImports []AffectedImport
	// DatabaseSpecific holds string metadata from OSV (e.g., review_status, url).
	DatabaseSpecific map[string]string
}

// ManifestReference describes the manifest/lockfile context for a dependency.
type ManifestReference struct {
	Path    string
	Manager string
	Groups  []string
}

// AffectedImport captures ecosystem-specific import path and symbol data from OSV.
// These hints are useful for reachability/manual triage and are currently populated for Go.
type AffectedImport struct {
	// Path is the fully qualified import path reported by OSV.
	Path string `json:"path"`
	// Symbols lists vulnerable symbols (functions/methods/types) under the import path.
	Symbols []string `json:"symbols,omitempty"`
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
