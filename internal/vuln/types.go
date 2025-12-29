package vuln

// Vulnerability represents a security vulnerability found in a software package.
// It contains metadata from vulnerability databases (primarily OSV) including
// identifiers, severity information, affected version ranges, and fix availability.
type Vulnerability struct {
	// ID is the primary vulnerability identifier (e.g., "GHSA-xxxx-xxxx-xxxx", "CVE-2024-1234").
	ID string
	// Aliases contains alternate identifiers for the same vulnerability across databases.
	Aliases []string
	// Summary is a short description of the vulnerability.
	Summary string
	// Details provides the full vulnerability description including impact and context.
	Details string
	// CVE is the CVE identifier if assigned (may duplicate an alias).
	CVE string
	// Severity is the severity rating - either a textual value (CRITICAL/HIGH/MEDIUM/LOW)
	// or a CVSS vector string depending on SeverityType.
	Severity string
	// SeverityType indicates the format of Severity (e.g., "GHSA" for textual, "CVSS_V3" for vectors).
	SeverityType string
	// Package is the name of the affected package/module.
	Package string
	// Version is the installed version of the package being checked.
	Version string
	// IsDirect indicates whether this is a direct dependency (true) or transitive (false).
	IsDirect bool
	// Ecosystem identifies the package ecosystem (e.g., "Go", "npm", "PyPI").
	Ecosystem string
	// PURL is the Package URL uniquely identifying the package version.
	PURL string
	// Published is the ISO 8601 timestamp when the vulnerability was first published.
	Published string
	// Modified is the ISO 8601 timestamp when the vulnerability was last updated.
	Modified string
	// References contains URLs to advisories, patches, and related resources.
	References []string
	// FixedVersions lists versions where this vulnerability is resolved.
	FixedVersions []string
	// Affected indicates whether the installed version is within the vulnerable range.
	Affected bool
	// Locations lists file paths where the vulnerable dependency was detected.
	Locations []string
	// ManifestRefs describes the manifest/lockfile context for the dependency.
	ManifestRefs []ManifestReference
	// AffectedImports carries ecosystem-specific import path and symbol hints
	// (from OSV; currently populated for Go).
	AffectedImports []AffectedImport
	// DatabaseSpecific holds string metadata from OSV (e.g., review_status, url).
	DatabaseSpecific map[string]string
}

// ConsolidatedVulnerability represents a deduplicated vulnerability record formed by
// merging multiple vulnerability reports that share common aliases (CVE IDs, etc.).
// This provides a cleaner view for reporting by eliminating duplicate entries from
// different vulnerability databases that describe the same underlying issue.
type ConsolidatedVulnerability struct {
	// PrimaryID is the preferred identifier chosen from all aliases (CVE > GO > GHSA > others).
	PrimaryID string
	// SecondaryIDs contains trusted aliases (CVE, GHSA, etc.) excluding the primary.
	SecondaryIDs []string
	// AllIDs contains every identifier including untrusted/internal database IDs.
	AllIDs []string
	// HiddenAliasCount is the number of aliases filtered from SecondaryIDs (untrusted sources).
	HiddenAliasCount int
	// Summary is a short description of the vulnerability.
	Summary string
	// Details provides the full vulnerability description.
	Details string
	// Severity is the highest severity rating found across merged records.
	Severity string
	// SeverityType indicates the format of Severity.
	SeverityType string
	// Package is the name of the affected package/module.
	Package string
	// Version is the installed version of the package.
	Version string
	// IsDirect indicates whether this is a direct dependency.
	IsDirect bool
	// Ecosystem identifies the package ecosystem.
	Ecosystem string
	// PURL is the Package URL uniquely identifying the package version.
	PURL string
	// Published is the earliest publication timestamp among merged records.
	Published string
	// Modified is the latest modification timestamp among merged records.
	Modified string
	// References contains deduplicated URLs from all merged records.
	References []string
	// FixedVersions lists all known fix versions across merged records.
	FixedVersions []string
	// RelatedCount is the number of original vulnerability records that were merged.
	RelatedCount int
	// Locations lists file paths where the vulnerable dependency was detected.
	Locations []string
	// ManifestRefs describes the manifest/lockfile context for the dependency.
	ManifestRefs []ManifestReference
	// AffectedImports carries ecosystem-specific import path and symbol hints
	// (from OSV; currently populated for Go).
	AffectedImports []AffectedImport
	// DatabaseSpecific holds string metadata from OSV (e.g., review_status, url).
	DatabaseSpecific map[string]string
}

// ManifestReference describes the manifest/lockfile context for a dependency,
// identifying where the dependency is declared and how it's categorized.
type ManifestReference struct {
	// Path is the file path to the manifest or lockfile (e.g., "go.mod", "package.json").
	Path string
	// Manager identifies the package manager (e.g., "go", "npm", "pip").
	Manager string
	// Groups categorizes the dependency (e.g., "dev", "optional", "peer" for npm).
	Groups []string
}

// AffectedImport captures ecosystem-specific import path and symbol data from OSV.
// These hints are useful for reachability analysis and manual triage.
// Currently populated for Go vulnerabilities.
type AffectedImport struct {
	// Path is the fully qualified import path reported by OSV.
	Path string `json:"path"`
	// Symbols lists vulnerable symbols (functions/methods/types) under the import path.
	Symbols []string `json:"symbols,omitempty"`
}

// VulnerabilityStats provides aggregate statistics for a set of vulnerabilities,
// useful for dashboards and summary reports.
type VulnerabilityStats struct {
	// TotalVulns is the total count of consolidated vulnerabilities.
	TotalVulns int
	// UniqueVulns is the count after deduplication (same as TotalVulns post-consolidation).
	UniqueVulns int
	// CVECount is the number of vulnerabilities with assigned CVE identifiers.
	CVECount int
	// HighSeverity counts vulnerabilities rated HIGH (CVSS 7.0-8.9).
	HighSeverity int
	// MedSeverity counts vulnerabilities rated MEDIUM (CVSS 4.0-6.9).
	MedSeverity int
	// LowSeverity counts vulnerabilities rated LOW (CVSS 0.1-3.9).
	LowSeverity int
	// UnknownSev counts vulnerabilities without severity information.
	UnknownSev int
	// DirectDeps counts vulnerabilities in direct dependencies.
	DirectDeps int
	// IndirectDeps counts vulnerabilities in transitive dependencies.
	IndirectDeps int
	// CriticalSev counts vulnerabilities rated CRITICAL (CVSS 9.0-10.0).
	CriticalSev int
	// FixAvailable counts vulnerabilities with at least one known fix version.
	FixAvailable int
	// DuplicatesFound is the number of records merged during consolidation.
	DuplicatesFound int
}
