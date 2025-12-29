package analysis

import (
	"time"

	"github.com/picatz/deputy/internal/vuln"
)

// Domain type aliases for compatibility with existing analysis callers.
type (
	Vulnerability             = vuln.Vulnerability
	ConsolidatedVulnerability = vuln.ConsolidatedVulnerability
	ManifestReference         = vuln.ManifestReference
	AffectedImport            = vuln.AffectedImport
	VulnerabilityStats        = vuln.VulnerabilityStats
	VulnFilter                = vuln.VulnFilter

	Severity     = vuln.Severity
	SeverityType = vuln.SeverityType
	SeverityInfo = vuln.SeverityInfo
)

const (
	SeverityUnknown  = vuln.SeverityUnknown
	SeverityLow      = vuln.SeverityLow
	SeverityMedium   = vuln.SeverityMedium
	SeverityHigh     = vuln.SeverityHigh
	SeverityCritical = vuln.SeverityCritical

	SeverityTypeUnknown = vuln.SeverityTypeUnknown
	SeverityTypeCVSSv2  = vuln.SeverityTypeCVSSv2
	SeverityTypeCVSSv3  = vuln.SeverityTypeCVSSv3
	SeverityTypeCVSSv4  = vuln.SeverityTypeCVSSv4
	SeverityTypeGHSA    = vuln.SeverityTypeGHSA
	SeverityTypeCustom  = vuln.SeverityTypeCustom

	CVSSScoreCritical = vuln.CVSSScoreCritical
	CVSSScoreHigh     = vuln.CVSSScoreHigh
	CVSSScoreMedium   = vuln.CVSSScoreMedium
	CVSSScoreLow      = vuln.CVSSScoreLow
)

const (
	IDPriorityCVE   = vuln.IDPriorityCVE
	IDPriorityGO    = vuln.IDPriorityGO
	IDPriorityGHSA  = vuln.IDPriorityGHSA
	IDPriorityOther = vuln.IDPriorityOther
)

// ParseCVSSScore interprets common CVSS representations and returns the base score or -1.
func ParseCVSSScore(severity string) float64 {
	return vuln.ParseCVSSScore(severity)
}

// ParseSeverity converts a string severity level to the Severity enum.
func ParseSeverity(s string) Severity {
	return vuln.ParseSeverity(s)
}

// SeverityFromCVSS converts a CVSS score to a Severity level.
func SeverityFromCVSS(score float64) Severity {
	return vuln.SeverityFromCVSS(score)
}

// ParseSeverityType converts a string to the SeverityType enum.
func ParseSeverityType(s string) SeverityType {
	return vuln.ParseSeverityType(s)
}

// NewSeverityInfo creates a SeverityInfo from raw string values.
func NewSeverityInfo(severityStr, typeStr string) SeverityInfo {
	return vuln.NewSeverityInfo(severityStr, typeStr)
}

// HasCommonAlias reports if two alias sets intersect.
func HasCommonAlias(a1, a2 []string) bool {
	return vuln.HasCommonAlias(a1, a2)
}

// FindBestSeverity chooses the best severity across related vulns.
func FindBestSeverity(vulns []Vulnerability) (string, string) {
	return vuln.FindBestSeverity(vulns)
}

// ConsolidateVulnerabilities groups related vulnerabilities using aliases.
func ConsolidateVulnerabilities(vulns []Vulnerability) []ConsolidatedVulnerability {
	return vuln.ConsolidateVulnerabilities(vulns)
}

// CategorizeVulnerabilities computes stats after consolidating by alias.
func CategorizeVulnerabilities(vs []Vulnerability) VulnerabilityStats {
	return vuln.CategorizeVulnerabilities(vs)
}

// FindBestFixedVersion selects the smallest applicable fix >= current.
func FindBestFixedVersion(fixed []string, current string) string {
	return vuln.FindBestFixedVersion(fixed, current)
}

// FilterVulnerabilities applies a list of filters to vulnerabilities.
func FilterVulnerabilities(vulns []Vulnerability, filters ...VulnFilter) []Vulnerability {
	return vuln.FilterVulnerabilities(vulns, filters...)
}

// HasFix returns a filter that includes only vulnerabilities with applicable fixes.
func HasFix() VulnFilter {
	return vuln.HasFix()
}

// PublishedAfter returns a filter that includes vulnerabilities published on or after the given time.
func PublishedAfter(t time.Time) VulnFilter {
	return vuln.PublishedAfter(t)
}

// PublishedBefore returns a filter that includes vulnerabilities published on or before the given time.
func PublishedBefore(t time.Time) VulnFilter {
	return vuln.PublishedBefore(t)
}

// SeverityAtLeast returns a filter that includes only vulnerabilities at or above the given severity.
func SeverityAtLeast(minSeverity string) VulnFilter {
	return vuln.SeverityAtLeast(minSeverity)
}

// IsDirect returns a filter that includes only direct dependencies.
func IsDirect() VulnFilter {
	return vuln.IsDirect()
}

// ParseFlexibleDate parses common date forms for CLI filtering.
func ParseFlexibleDate(s, intent string) (time.Time, error) {
	return vuln.ParseFlexibleDate(s, intent)
}

// FilterVulnerabilitiesByPublished filters vulnerabilities based on published timestamp.
func FilterVulnerabilitiesByPublished(vs []Vulnerability, after, before time.Time) []Vulnerability {
	return vuln.FilterVulnerabilitiesByPublished(vs, after, before)
}

// MergeManifestReference adds a manifest reference to the list, merging groups if it already exists.
func MergeManifestReference(existing []ManifestReference, ref ManifestReference) []ManifestReference {
	return vuln.MergeManifestReference(existing, ref)
}

// SortAndUniqueManifestRefs deduplicates and sorts manifest references.
func SortAndUniqueManifestRefs(refs []ManifestReference) []ManifestReference {
	return vuln.SortAndUniqueManifestRefs(refs)
}

// MergeAffectedImports deduplicates import paths and symbols while keeping output stable.
func MergeAffectedImports(importSets ...[]AffectedImport) []AffectedImport {
	return vuln.MergeAffectedImports(importSets...)
}
