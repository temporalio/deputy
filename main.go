package main

import (
	"bufio"
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"time"

	pb "deps.dev/api/v3"
	"github.com/charmbracelet/fang"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	pl "github.com/google/osv-scalibr/plugin/list"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/spf13/cobra"
	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"osv.dev/bindings/go/osvdev"
)

func init() {
	log.SetLogger(&scalibrNullLogger{})
}

// ANSI color codes
const (
	colorReset = "\033[0m"
	colorBold  = "\033[1m"
	colorDim   = "\033[2m"

	// Semantic colors - thoughtful and meaningful
	colorAdded      = "\033[1;32m" // Bold Green - positive, something new
	colorRemoved    = "\033[1;31m" // Bold Red - negative, something lost
	colorUpgraded   = "\033[1;36m" // Bold Cyan - neutral positive, forward movement
	colorDowngraded = "\033[1;33m" // Bold Yellow - caution, potential concern
	colorNeutral    = "\033[1;37m" // Bold White - neutral change

	// UI elements - subtle and supportive
	colorPackageName = "\033[0m"    // Default color for package names
	colorVersion     = "\033[90m"   // Gray for version numbers (less important)
	colorLicense     = "\033[2;90m" // Dim gray for license info (least important)
	colorArrow       = "\033[2;36m" // Dim cyan for arrows - subtle but visible
	colorHeader      = "\033[1;94m" // Bold bright blue for headers
	colorSymbol      = "\033[1m"    // Bold for symbols
)

// PackageChangeType represents the type of change for a package
type PackageChangeType int

const (
	Added PackageChangeType = iota
	Removed
	Updated
)

// PackageChange represents a change to a package between references
type PackageChange struct {
	Name          string
	OldName       string // Original package name (for major version path changes)
	TargetVersion string // Version in the target reference
	BaseVersion   string // Version in the base reference
	ChangeType    PackageChangeType
	Ecosystem     string // The package ecosystem (go, npm, pip, etc.)
	IsDirect      bool   // Whether this is a direct dependency
}

// Vulnerability represents a vulnerability found in a package
type Vulnerability struct {
	ID            string
	Aliases       []string
	Summary       string
	Details       string
	CVE           string   // Primary CVE if available
	Severity      string   // CVSS score or severity level
	SeverityType  string   // Type of severity (CVSS_V3, CVSS_V2, etc.)
	Package       string   // Package name
	Version       string   // Affected version
	IsDirect      bool     // Whether this is a direct dependency
	Published     string   // When the vulnerability was published
	Modified      string   // When the vulnerability was last modified
	References    []string // URLs to references
	FixedVersions []string // Versions where this is fixed
}

// ConsolidatedVulnerability represents a deduplicated vulnerability with primary and secondary IDs
type ConsolidatedVulnerability struct {
	PrimaryID     string   // CVE if available, otherwise most recognizable ID
	SecondaryIDs  []string // Other related IDs (GHSA, GO, etc.)
	AllIDs        []string // All original IDs for this vulnerability
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
	RelatedCount  int // Number of original vulnerabilities this represents
}

// VulnerabilityStats tracks vulnerability statistics
type VulnerabilityStats struct {
	TotalVulns      int
	UniqueVulns     int // After deduplication
	CVECount        int
	HighSeverity    int
	MedSeverity     int
	LowSeverity     int
	UnknownSev      int
	DirectDeps      int // Vulnerabilities in direct dependencies
	IndirectDeps    int // Vulnerabilities in indirect dependencies
	CriticalSev     int // Critical severity (9.0-10.0)
	FixAvailable    int // Vulnerabilities with fixes available
	DuplicatesFound int // Number of duplicate/related vulnerabilities found
}

// EcosystemType represents different package management ecosystems
type EcosystemType string

const (
	EcosystemGo       EcosystemType = "go"
	EcosystemNpm      EcosystemType = "npm"
	EcosystemPip      EcosystemType = "pip"
	EcosystemMaven    EcosystemType = "maven"
	EcosystemNuGet    EcosystemType = "nuget"
	EcosystemCargo    EcosystemType = "cargo"
	EcosystemComposer EcosystemType = "composer"
)

// PackageEcosystem defines the interface for different package management ecosystems
type PackageEcosystem interface {
	// GetName returns the ecosystem name (e.g., "go", "npm", "pip")
	GetName() EcosystemType

	// GetManifestFiles returns the list of manifest files that indicate this ecosystem
	GetManifestFiles() []string

	// CompareVersions compares two version strings and returns:
	// 1 for upgrade, -1 for downgrade, 0 for unclear/equal
	CompareVersions(oldVersion, newVersion string) int

	// NormalizeVersion normalizes a version string for comparison
	NormalizeVersion(version string) string

	// IsPseudoVersion checks if a version is a pseudo-version (if applicable)
	IsPseudoVersion(version string) bool

	// GetVersionInfo extracts detailed information from a version string
	GetVersionInfo(version string) VersionInfo

	// GetApiSystem returns the system identifier for deps.dev API
	GetApiSystem() pb.System
}

// VersionInfo contains detailed information about a version
type VersionInfo struct {
	Original  string            // Original version string
	Canonical string            // Normalized canonical version
	IsPseudo  bool              // Whether this is a pseudo-version
	Base      string            // Base version for pseudo-versions
	Timestamp string            // Timestamp for pseudo-versions
	Hash      string            // Hash for pseudo-versions
	Metadata  map[string]string // Additional ecosystem-specific metadata
}

type scalibrNullLogger struct{}

func (*scalibrNullLogger) Debug(args ...any)                 {}
func (*scalibrNullLogger) Debugf(format string, args ...any) {}
func (*scalibrNullLogger) Error(args ...any)                 {}
func (*scalibrNullLogger) Errorf(format string, args ...any) {}
func (*scalibrNullLogger) Info(args ...any)                  {}
func (*scalibrNullLogger) Infof(format string, args ...any)  {}
func (*scalibrNullLogger) Warn(args ...any)                  {}
func (*scalibrNullLogger) Warnf(format string, args ...any)  {}

// queryOSVBatch performs a batch vulnerability query to the OSV API using the official client
func queryOSVBatch(ctx context.Context, packages []PackageChange) ([]Vulnerability, error) {
	if len(packages) == 0 {
		return nil, nil
	}

	// Create OSV client
	client := osvdev.DefaultClient()

	// Prepare batch queries
	queries := make([]*osvdev.Query, 0, len(packages))
	packageMeta := make([]PackageChange, 0, len(packages)) // Track metadata for each query

	for _, pkg := range packages {
		// Only query for packages that exist in the target (added or updated)
		version := pkg.TargetVersion
		if pkg.ChangeType == Removed || version == "" {
			continue
		}

		// Normalize version for OSV API
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}

		queries = append(queries, &osvdev.Query{
			Package: osvdev.Package{
				Name:      pkg.Name,
				Ecosystem: "Go", // OSV uses "Go" not "go"
			},
			Version: version,
		})
		packageMeta = append(packageMeta, pkg)
	}

	if len(queries) == 0 {
		return nil, nil
	}

	// Make batch request using the official client
	batchResp, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}

	// Process results and extract vulnerabilities
	var vulnerabilities []Vulnerability
	for i, result := range batchResp.Results {
		if i >= len(queries) || i >= len(packageMeta) {
			break // Safety check
		}

		packageName := queries[i].Package.Name
		version := queries[i].Version
		isDirect := packageMeta[i].IsDirect

		// For each minimal vulnerability, get the full details
		for _, minVuln := range result.Vulns {
			// Get full vulnerability details by ID
			fullVuln, err := client.GetVulnByID(ctx, minVuln.ID)
			if err != nil {
				// Log the error but continue with other vulnerabilities
				fmt.Printf("Warning: failed to get details for vulnerability %s: %v\n", minVuln.ID, err)
				continue
			}

			vulnerability := processOSVVulnerability(*fullVuln, packageName, version, isDirect)
			vulnerabilities = append(vulnerabilities, vulnerability)
		}
	}

	return vulnerabilities, nil
}

// processOSVVulnerability processes an OSV vulnerability and extracts relevant information
func processOSVVulnerability(vuln osvschema.Vulnerability, packageName, version string, isDirect bool) Vulnerability {
	v := Vulnerability{
		ID:       vuln.ID,
		Summary:  vuln.Summary,
		Details:  vuln.Details,
		Package:  packageName,
		Version:  version,
		IsDirect: isDirect,
	}

	// Convert time.Time to string
	if !vuln.Published.IsZero() {
		v.Published = vuln.Published.Format(time.RFC3339)
	}
	if !vuln.Modified.IsZero() {
		v.Modified = vuln.Modified.Format(time.RFC3339)
	}

	// Copy aliases
	if vuln.Aliases != nil {
		v.Aliases = make([]string, len(vuln.Aliases))
		copy(v.Aliases, vuln.Aliases)
	}

	// Extract CVE from aliases, prioritizing CVE over other identifiers
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			v.CVE = alias
			break
		}
	}

	// If no CVE found, use GO- or GHSA- identifiers
	if v.CVE == "" {
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "GO-") || strings.HasPrefix(alias, "GHSA-") {
				v.CVE = alias
				break
			}
		}
	}

	// Extract severity information - prioritize CVSS scores but also check database_specific
	if vuln.Severity != nil {
		for _, severity := range vuln.Severity {
			if severity.Type == "CVSS_V3" || severity.Type == "CVSS_V2" {
				v.Severity = severity.Score
				v.SeverityType = string(severity.Type)
				break
			}
		}
	}

	// Also check database_specific field for GitHub/GHSA severity information
	if vuln.DatabaseSpecific != nil {
		// Try to extract severity from database_specific (common in GHSA entries)
		if severityVal, exists := vuln.DatabaseSpecific["severity"]; exists {
			if severityStr, ok := severityVal.(string); ok && severityStr != "" {
				// If we don't have a CVSS score yet, or if this is a GHSA entry, use this severity
				isGHSA := strings.HasPrefix(vuln.ID, "GHSA-")
				if v.Severity == "" || isGHSA {
					v.Severity = severityStr
					v.SeverityType = "GHSA"
				}
			}
		}
	}

	// Extract references
	if vuln.References != nil {
		for _, ref := range vuln.References {
			if ref.URL != "" {
				v.References = append(v.References, ref.URL)
			}
		}
	}

	// Extract fixed versions from affected ranges
	if vuln.Affected != nil {
		for _, affected := range vuln.Affected {
			if affected.Ranges != nil {
				for _, r := range affected.Ranges {
					if r.Events != nil {
						for _, event := range r.Events {
							if event.Fixed != "" {
								v.FixedVersions = append(v.FixedVersions, event.Fixed)
							}
						}
					}
				}
			}
		}
	}

	return v
}

// consolidateVulnerabilities groups related vulnerabilities using alias information
func consolidateVulnerabilities(vulns []Vulnerability) []ConsolidatedVulnerability {
	if len(vulns) == 0 {
		return nil
	}

	// Create a union-find like structure to group related vulnerabilities
	processed := make(map[string]bool)
	var groups [][]Vulnerability

	for _, vuln := range vulns {
		if processed[vuln.ID] {
			continue
		}

		// Start a new group with this vulnerability
		group := []Vulnerability{vuln}
		processed[vuln.ID] = true

		// Get all aliases for this vulnerability (including the ID itself)
		vulnAliases := append([]string{vuln.ID}, vuln.Aliases...)

		// Look for other unprocessed vulnerabilities that share any alias
		for _, otherVuln := range vulns {
			if processed[otherVuln.ID] {
				continue
			}

			// Get all aliases for the other vulnerability
			otherAliases := append([]string{otherVuln.ID}, otherVuln.Aliases...)

			// Check if there's any overlap in aliases
			if hasCommonAlias(vulnAliases, otherAliases) {
				group = append(group, otherVuln)
				processed[otherVuln.ID] = true

				// Add the new vulnerability's aliases to our search set for potential transitive matches
				vulnAliases = append(vulnAliases, otherAliases...)
			}
		}

		groups = append(groups, group)
	}

	// Convert groups to consolidated vulnerabilities
	var consolidated []ConsolidatedVulnerability
	for _, group := range groups {
		// Find the best primary ID from all vulnerabilities in the group
		primaryID := findBestPrimaryIDFromGroup(group)
		consolidated = append(consolidated, createConsolidatedVulnerability(primaryID, group))
	}

	return consolidated
}

// findBestPrimaryIDFromGroup finds the best primary ID from a group of related vulnerabilities
func findBestPrimaryIDFromGroup(vulns []Vulnerability) string {
	var allIDs []string

	// Collect all IDs and aliases from all vulnerabilities in the group
	for _, vuln := range vulns {
		allIDs = append(allIDs, vuln.ID)
		allIDs = append(allIDs, vuln.Aliases...)
	}

	// Remove duplicates
	idSet := make(map[string]bool)
	var uniqueIDs []string
	for _, id := range allIDs {
		if !idSet[id] {
			idSet[id] = true
			uniqueIDs = append(uniqueIDs, id)
		}
	}

	// Find the best ID according to our priority: CVE > GO- > GHSA- > others
	var bestID string
	priority := 999

	for _, id := range uniqueIDs {
		currentPriority := getIDPriority(id)
		if currentPriority < priority {
			priority = currentPriority
			bestID = id
		}
	}

	// Fallback to first vulnerability's ID if no good match
	if bestID == "" && len(vulns) > 0 {
		bestID = vulns[0].ID
	}

	return bestID
}

// getIDPriority returns the priority of an ID type (lower is better)
func getIDPriority(id string) int {
	if strings.HasPrefix(id, "CVE-") {
		return 1 // Highest priority
	}
	if strings.HasPrefix(id, "GO-") {
		return 2
	}
	if strings.HasPrefix(id, "GHSA-") {
		return 3
	}
	return 4 // Lowest priority for other types
}

// hasCommonAlias checks if two sets of aliases have any common elements
func hasCommonAlias(aliases1, aliases2 []string) bool {
	aliasSet := make(map[string]bool)
	for _, alias := range aliases1 {
		aliasSet[alias] = true
	}

	for _, alias := range aliases2 {
		if aliasSet[alias] {
			return true
		}
	}

	return false
}

// findBestSeverity finds the most reliable severity information from a group of vulnerabilities
// Priority: GHSA with database_specific severity > CVSS scores > other sources
func findBestSeverity(vulns []Vulnerability) (string, string) {
	if len(vulns) == 0 {
		return "", ""
	}

	var bestSeverity, bestSeverityType string
	bestScore := -1.0

	// First pass: look for the highest numeric CVSS score
	for _, vuln := range vulns {
		if vuln.Severity != "" {
			score := parseCVSSScore(vuln.Severity)
			if score > bestScore {
				bestScore = score
				bestSeverity = vuln.Severity
				bestSeverityType = vuln.SeverityType
			}
		}
	}

	// Second pass: check for GHSA database_specific severity which is often more accurate
	// This is typically stored in the severity field for GHSA entries
	for _, vuln := range vulns {
		// If this vulnerability has a GHSA ID and severity info, it might be better
		hasGHSA := false
		if strings.HasPrefix(vuln.ID, "GHSA-") {
			hasGHSA = true
		} else {
			for _, alias := range vuln.Aliases {
				if strings.HasPrefix(alias, "GHSA-") {
					hasGHSA = true
					break
				}
			}
		}

		if hasGHSA && vuln.Severity != "" {
			// Check if this is a textual severity (HIGH, MEDIUM, LOW, CRITICAL)
			severityUpper := strings.ToUpper(vuln.Severity)
			if severityUpper == "CRITICAL" || severityUpper == "HIGH" ||
				severityUpper == "MEDIUM" || severityUpper == "LOW" {
				// Convert to numeric for comparison
				var ghsaScore float64
				switch severityUpper {
				case "CRITICAL":
					ghsaScore = 9.5
				case "HIGH":
					ghsaScore = 7.5
				case "MEDIUM":
					ghsaScore = 5.5
				case "LOW":
					ghsaScore = 2.5
				}

				// Use GHSA severity if it's higher or if we don't have a good numeric score
				if ghsaScore > bestScore || bestScore < 0 {
					bestSeverity = vuln.Severity
					bestSeverityType = vuln.SeverityType
					bestScore = ghsaScore
				}
			}
		}
	}

	return bestSeverity, bestSeverityType
}

// findBestSummary finds the most informative summary from a group of vulnerabilities
func findBestSummary(vulns []Vulnerability) string {
	if len(vulns) == 0 {
		return ""
	}

	var bestSummary string
	maxLength := 0

	// Pick the longest non-empty summary as it's likely most informative
	for _, vuln := range vulns {
		if vuln.Summary != "" && len(vuln.Summary) > maxLength {
			maxLength = len(vuln.Summary)
			bestSummary = vuln.Summary
		}
	}

	// If no summary found, return the first one
	if bestSummary == "" && len(vulns) > 0 {
		bestSummary = vulns[0].Summary
	}

	return bestSummary
}

// createConsolidatedVulnerability creates a consolidated vulnerability from a group
func createConsolidatedVulnerability(primaryID string, vulns []Vulnerability) ConsolidatedVulnerability {
	if len(vulns) == 0 {
		return ConsolidatedVulnerability{}
	}

	// Use the first vulnerability as the base, but with the primary ID
	base := vulns[0]

	// Collect all unique IDs and aliases
	allIDsMap := make(map[string]bool)

	for _, vuln := range vulns {
		allIDsMap[vuln.ID] = true
		for _, alias := range vuln.Aliases {
			allIDsMap[alias] = true
		}
	}

	// Build lists
	var allIDs, secondaryIDs []string
	for id := range allIDsMap {
		allIDs = append(allIDs, id)
		if id != primaryID {
			secondaryIDs = append(secondaryIDs, id)
		}
	}

	// Merge fixed versions
	fixedVersionsMap := make(map[string]bool)
	for _, vuln := range vulns {
		for _, fix := range vuln.FixedVersions {
			fixedVersionsMap[fix] = true
		}
	}
	var fixedVersions []string
	for fix := range fixedVersionsMap {
		fixedVersions = append(fixedVersions, fix)
	}

	// Merge references
	referencesMap := make(map[string]bool)
	for _, vuln := range vulns {
		for _, ref := range vuln.References {
			referencesMap[ref] = true
		}
	}
	var references []string
	for ref := range referencesMap {
		references = append(references, ref)
	}

	// Find the best severity and summary information from all vulnerabilities
	bestSeverity, bestSeverityType := findBestSeverity(vulns)
	bestSummary := findBestSummary(vulns)

	return ConsolidatedVulnerability{
		PrimaryID:     primaryID,
		SecondaryIDs:  secondaryIDs,
		AllIDs:        allIDs,
		Summary:       bestSummary,
		Details:       base.Details,
		Severity:      bestSeverity,
		SeverityType:  bestSeverityType,
		Package:       base.Package,
		Version:       base.Version,
		IsDirect:      base.IsDirect,
		Published:     base.Published,
		Modified:      base.Modified,
		References:    references,
		FixedVersions: fixedVersions,
		RelatedCount:  len(vulns),
	}
}

// categorizeVulnerabilities categorizes vulnerabilities by severity
func categorizeVulnerabilities(vulns []Vulnerability) VulnerabilityStats {
	// First consolidate to remove duplicates
	consolidated := consolidateVulnerabilities(vulns)

	stats := VulnerabilityStats{
		TotalVulns:      len(vulns),
		UniqueVulns:     len(consolidated),
		DuplicatesFound: len(vulns) - len(consolidated),
	}

	for _, vuln := range consolidated {
		// Count CVEs
		if strings.HasPrefix(vuln.PrimaryID, "CVE-") {
			stats.CVECount++
		}

		// Count direct vs indirect dependencies
		if vuln.IsDirect {
			stats.DirectDeps++
		} else {
			stats.IndirectDeps++
		}

		// Count vulnerabilities with fixes available
		if len(vuln.FixedVersions) > 0 {
			stats.FixAvailable++
		}

		// Categorize by severity - handle both GHSA textual and numeric CVSS scores
		if vuln.Severity != "" {
			// Handle GHSA textual severity specially (same logic as display)
			if vuln.SeverityType == "GHSA" {
				severityUpper := strings.ToUpper(vuln.Severity)
				switch severityUpper {
				case "CRITICAL":
					stats.CriticalSev++
				case "HIGH":
					stats.HighSeverity++
				case "MEDIUM", "MODERATE":
					stats.MedSeverity++
				case "LOW":
					stats.LowSeverity++
				default:
					// Fall back to numeric parsing for unknown GHSA values
					score := parseCVSSScore(vuln.Severity)
					if score >= 9.0 {
						stats.CriticalSev++
					} else if score >= 7.0 {
						stats.HighSeverity++
					} else if score >= 4.0 {
						stats.MedSeverity++
					} else if score >= 0.0 {
						stats.LowSeverity++
					} else {
						stats.UnknownSev++
					}
				}
			} else {
				// Handle numeric CVSS scores
				score := parseCVSSScore(vuln.Severity)
				if score >= 9.0 {
					stats.CriticalSev++
				} else if score >= 7.0 {
					stats.HighSeverity++
				} else if score >= 4.0 {
					stats.MedSeverity++
				} else if score >= 0.0 {
					stats.LowSeverity++
				} else {
					stats.UnknownSev++
				}
			}
		} else {
			stats.UnknownSev++
		}
	}

	return stats
}

// parseCVSSScore extracts numeric CVSS score from severity string
func parseCVSSScore(severity string) float64 {
	// Try to extract a numeric score from the severity string
	// Handle formats like "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" with base score
	// or simple numeric scores like "7.5"

	// Look for base score in CVSS vector
	if strings.Contains(severity, "/") {
		parts := strings.Split(severity, "/")
		for _, part := range parts {
			if strings.HasPrefix(part, "Base:") || strings.HasPrefix(part, "base:") {
				scoreStr := strings.TrimPrefix(strings.TrimPrefix(part, "Base:"), "base:")
				if score := parseFloat(scoreStr); score >= 0 {
					return score
				}
			}
		}
	}

	// Try to parse as direct numeric value
	if score := parseFloat(severity); score >= 0 {
		return score
	}

	// Handle common severity levels
	switch strings.ToLower(severity) {
	case "critical":
		return 9.5
	case "high":
		return 7.5
	case "medium", "moderate":
		return 5.5
	case "low":
		return 2.5
	default:
		return -1.0 // Unknown
	}
}

// parseFloat safely parses a string to float64, returns -1 on error
func parseFloat(s string) float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return -1
	}

	// Simple float parsing for CVSS scores (0.0-10.0)
	var result float64
	var decimal float64 = 1
	var foundDot bool

	for _, r := range s {
		if r >= '0' && r <= '9' {
			digit := float64(r - '0')
			if foundDot {
				decimal *= 0.1
				result += digit * decimal
			} else {
				result = result*10 + digit
			}
		} else if r == '.' && !foundDot {
			foundDot = true
		} else {
			break // Stop at first non-numeric character
		}
	}

	// Validate CVSS range
	if result >= 0.0 && result <= 10.0 {
		return result
	}

	return -1
}

// findBestFixedVersion finds the most appropriate fixed version for the current package version
// It prioritizes versions within the same major version, then the lowest suitable version
func findBestFixedVersion(fixedVersions []string, currentVersion string) string {
	if len(fixedVersions) == 0 {
		return ""
	}

	// Normalize current version for comparison
	currentVersion = normalizeGoVersion(currentVersion)

	// Extract major version from current version using semver
	currentMajor := extractMajorFromSemver(currentVersion)

	var sameMajorVersions []string
	var otherVersions []string

	for _, fix := range fixedVersions {
		normalizedFix := normalizeGoVersion(fix)
		fixMajor := extractMajorFromSemver(normalizedFix)

		if fixMajor == currentMajor {
			// This is a fix within the same major version
			sameMajorVersions = append(sameMajorVersions, fix)
		} else {
			otherVersions = append(otherVersions, fix)
		}
	}

	// Prefer same major version fixes
	if len(sameMajorVersions) > 0 {
		// Sort and return the earliest available fix in the same major version
		// For simplicity, return the first one for now
		return sameMajorVersions[0]
	}

	// If no same-major version fix, return the first available fix
	return fixedVersions[0]
}

// extractMajorFromSemver extracts major version from a semantic version string
func extractMajorFromSemver(version string) int {
	version = normalizeGoVersion(version)
	if !strings.HasPrefix(version, "v") {
		return 1
	}

	versionPart := strings.TrimPrefix(version, "v")
	dotIndex := strings.Index(versionPart, ".")
	if dotIndex == -1 {
		// No dot found, try to parse the whole thing as major version
		if major := parseIntSafe(versionPart); major > 0 {
			return major
		}
		return 1
	}

	majorStr := versionPart[:dotIndex]
	if major := parseIntSafe(majorStr); major > 0 {
		return major
	}

	return 1
}

// parseIntSafe safely parses a string to int, returns 0 on error
func parseIntSafe(s string) int {
	result := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			result = result*10 + int(r-'0')
		} else {
			return 0 // Invalid character
		}
	}
	return result
}

// displayVulnerabilities shows vulnerability information in a user-friendly format
func displayVulnerabilities(vulns []Vulnerability) {
	if len(vulns) == 0 {
		fmt.Printf("\n%s✓ No vulnerabilities found%s\n", colorAdded, colorReset)
		return
	}

	// Consolidate vulnerabilities to remove duplicates
	consolidated := consolidateVulnerabilities(vulns)
	stats := categorizeVulnerabilities(vulns)

	fmt.Printf("\n%s⚠%s %sVulnerabilities Found:%s\n", colorDowngraded, colorReset, colorHeader, colorReset)

	// Group consolidated vulnerabilities by package for cleaner display
	vulnsByPackage := make(map[string][]ConsolidatedVulnerability)
	for _, vuln := range consolidated {
		vulnsByPackage[vuln.Package] = append(vulnsByPackage[vuln.Package], vuln)
	}

	for packageName, packageVulns := range vulnsByPackage {
		// Determine if this package has any direct dependencies
		hasDirectDep := false
		for _, vuln := range packageVulns {
			if vuln.IsDirect {
				hasDirectDep = true
				break
			}
		}

		depType := ""
		if hasDirectDep {
			depType = fmt.Sprintf(" %s[direct]%s", colorBold+colorUpgraded, colorReset)
		} else {
			depType = fmt.Sprintf(" %s[indirect]%s", colorDim, colorReset)
		}

		fmt.Printf("\n%s%s%s %s@%s%s%s:\n",
			colorBold, packageName, colorReset,
			colorDim, packageVulns[0].Version, colorReset,
			depType)

		for _, vuln := range packageVulns {
			// Determine color and display based on severity
			var sevColor, severityDisplay string

			// Handle GHSA textual severity specially
			if vuln.SeverityType == "GHSA" {
				severityUpper := strings.ToUpper(vuln.Severity)
				switch severityUpper {
				case "CRITICAL":
					sevColor = "\033[1;35m" // Magenta for critical
					severityDisplay = fmt.Sprintf(" %s[CRITICAL]%s", sevColor, colorReset)
				case "HIGH":
					sevColor = colorRemoved // Red for high severity
					severityDisplay = fmt.Sprintf(" %s[HIGH]%s", sevColor, colorReset)
				case "MEDIUM", "MODERATE":
					sevColor = colorDowngraded // Yellow for medium severity
					severityDisplay = fmt.Sprintf(" %s[MED]%s", sevColor, colorReset)
				case "LOW":
					sevColor = colorDim // Dim for low severity
					severityDisplay = fmt.Sprintf(" %s[LOW]%s", sevColor, colorReset)
				default:
					// Fall back to numeric parsing
					score := parseCVSSScore(vuln.Severity)
					if score >= 9.0 {
						sevColor = "\033[1;35m"
						severityDisplay = fmt.Sprintf(" %s[CRITICAL %.1f]%s", sevColor, score, colorReset)
					} else if score >= 7.0 {
						sevColor = colorRemoved
						severityDisplay = fmt.Sprintf(" %s[HIGH %.1f]%s", sevColor, score, colorReset)
					} else if score >= 4.0 {
						sevColor = colorDowngraded
						severityDisplay = fmt.Sprintf(" %s[MED %.1f]%s", sevColor, score, colorReset)
					} else if score >= 0.0 {
						sevColor = colorDim
						severityDisplay = fmt.Sprintf(" %s[LOW %.1f]%s", sevColor, score, colorReset)
					} else {
						sevColor = colorDim
						severityDisplay = ""
					}
				}
			} else {
				// Handle numeric CVSS scores
				score := parseCVSSScore(vuln.Severity)
				if score >= 9.0 {
					sevColor = "\033[1;35m" // Magenta for critical
					severityDisplay = fmt.Sprintf(" %s[CRITICAL %.1f]%s", sevColor, score, colorReset)
				} else if score >= 7.0 {
					sevColor = colorRemoved // Red for high severity
					severityDisplay = fmt.Sprintf(" %s[HIGH %.1f]%s", sevColor, score, colorReset)
				} else if score >= 4.0 {
					sevColor = colorDowngraded // Yellow for medium severity
					severityDisplay = fmt.Sprintf(" %s[MED %.1f]%s", sevColor, score, colorReset)
				} else if score >= 0.0 {
					sevColor = colorDim // Dim for low severity
					severityDisplay = fmt.Sprintf(" %s[LOW %.1f]%s", sevColor, score, colorReset)
				} else {
					sevColor = colorDim // Dim for unknown
					severityDisplay = ""
				}
			}

			// Fix availability - most important info
			fixInfo := ""
			if len(vuln.FixedVersions) > 0 {
				bestFix := findBestFixedVersion(vuln.FixedVersions, vuln.Version)
				fixInfo = fmt.Sprintf(" %s(↑ %s)%s", colorUpgraded, bestFix, colorReset)
			}

			// Show consolidation info if multiple IDs were found
			consolidationInfo := ""
			if vuln.RelatedCount > 1 {
				consolidationInfo = fmt.Sprintf(" %s[%d related]%s", colorDim, vuln.RelatedCount, colorReset)
			}

			fmt.Printf("  %s•%s %s%s%s%s%s%s\n",
				colorDim, colorReset,
				colorBold, vuln.PrimaryID, colorReset,
				severityDisplay, fixInfo, consolidationInfo)

			// Show summary if available and not too long
			if vuln.Summary != "" && len(vuln.Summary) < 120 {
				// Clean up summary by removing redundant package references
				cleanSummary := cleanSummaryText(vuln.Summary, packageName)
				fmt.Printf("    %s%s%s\n", colorBold, cleanSummary, colorReset)
			}

			// Show related IDs if there are any significant ones (limited to most important)
			if len(vuln.SecondaryIDs) > 0 {
				relevantSecondary := filterRelevantSecondaryIDs(vuln.SecondaryIDs, vuln.PrimaryID)
				if len(relevantSecondary) > 0 {
					fmt.Printf("    %sAliases: %s%s\n", colorDim, strings.Join(relevantSecondary, ", "), colorReset)
				}
			}

			// Show publication date if recent (within last year)
			if vuln.Published != "" && len(vuln.Published) >= 10 {
				fmt.Printf("    %sPublished: %s%s\n", colorDim, vuln.Published[:10], colorReset)
			}
		}
	}

	// Display enhanced vulnerability statistics with consolidation info
	fmt.Printf("\n%sVulnerability Summary:%s\n", colorHeader, colorReset)

	// Lead with the most important info - what needs action
	highPriority := stats.CriticalSev + stats.HighSeverity
	if highPriority > 0 {
		fmt.Printf("  %s!%s %s%d%s require immediate attention %s(critical/high severity)%s\n",
			colorSymbol+colorRemoved, colorReset, colorBold, highPriority, colorReset,
			colorRemoved, colorReset)
	}

	// Show actionable fix information prominently
	if stats.FixAvailable > 0 {
		fmt.Printf("  %s↑%s %s%d%s can be fixed by upgrading\n",
			colorSymbol+colorUpgraded, colorReset, colorBold, stats.FixAvailable, colorReset)
	}

	unfixed := stats.UniqueVulns - stats.FixAvailable
	if unfixed > 0 {
		fmt.Printf("  %s-%s %s%d%s have no fix available yet\n",
			colorSymbol+colorRemoved, colorReset, colorBold, unfixed, colorReset)
	}

	// Total with deduplication context (less prominent)
	fmt.Println() // Separator
	if stats.DuplicatesFound > 0 {
		fmt.Printf("  %s%d%s total vulnerabilities\n",
			colorBold, stats.UniqueVulns, colorReset)
	} else {
		fmt.Printf("  %s%d%s total vulnerabilities\n",
			colorBold, stats.UniqueVulns, colorReset)
	}

	// Severity breakdown - only show significant ones
	severityParts := []string{}
	if stats.CriticalSev > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%s%d critical%s", colorRemoved, stats.CriticalSev, colorReset))
	}
	if stats.HighSeverity > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%s%d high%s", colorRemoved, stats.HighSeverity, colorReset))
	}
	if stats.MedSeverity > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%s%d medium%s", colorDowngraded, stats.MedSeverity, colorReset))
	}
	if stats.LowSeverity > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%s%d low%s", colorDim, stats.LowSeverity, colorReset))
	}

	unknownSev := stats.UniqueVulns - (stats.CriticalSev + stats.HighSeverity + stats.MedSeverity + stats.LowSeverity)
	if unknownSev > 0 {
		severityParts = append(severityParts, fmt.Sprintf("%s%d unscored%s", colorDim, unknownSev, colorReset))
	}

	if len(severityParts) > 0 {
		fmt.Printf("  Severity: %s\n", strings.Join(severityParts, ", "))
	}

	// Dependency context - only if there's a mix
	if stats.DirectDeps > 0 && stats.IndirectDeps > 0 {
		fmt.Printf("  Dependencies: %s%d direct%s, %s%d indirect%s\n",
			colorBold, stats.DirectDeps, colorReset,
			colorDim, stats.IndirectDeps, colorReset)
	} else if stats.DirectDeps > 0 {
		fmt.Printf("  All in %sdirect%s dependencies (can upgrade directly)\n",
			colorBold, colorReset)
	} else if stats.IndirectDeps > 0 {
		fmt.Printf("  All in %sindirect%s dependencies (check dependency tree)\n",
			colorDim, colorReset)
	}

	// Action-oriented next steps
	fmt.Printf("\n%sRecommended Actions:%s\n", colorHeader, colorReset)

	if stats.FixAvailable > 0 {
		if highPriority > 0 {
			fmt.Printf("  %s1.%s %sUpgrade packages immediately%s - critical/high severity fixes available\n",
				colorSymbol+colorRemoved, colorReset, colorBold, colorReset)
		} else {
			fmt.Printf("  %s1.%s %sUpgrade packages%s with available fixes\n",
				colorSymbol+colorAdded, colorReset, colorBold, colorReset)
		}
		fmt.Printf("      %sgo get -u%s\n", colorVersion, colorReset)
	}

	if unfixed > 0 {
		actionNum := 1
		if stats.FixAvailable > 0 {
			actionNum = 2
		}
		fmt.Printf("  %s%d.%s %sInvestigate unfixed vulnerabilities%s - review manually or consider alternatives\n",
			colorSymbol+colorNeutral, actionNum, colorReset, colorBold, colorReset)
	}
}

// filterRelevantSecondaryIDs filters secondary IDs to show only the most relevant ones
func filterRelevantSecondaryIDs(secondaryIDs []string, primaryID string) []string {
	var relevant []string

	// If primary is CVE, show GO- and GHSA- equivalents
	if strings.HasPrefix(primaryID, "CVE-") {
		for _, id := range secondaryIDs {
			if strings.HasPrefix(id, "GO-") || strings.HasPrefix(id, "GHSA-") {
				relevant = append(relevant, id)
			}
		}
	} else if strings.HasPrefix(primaryID, "GO-") {
		// If primary is GO-, show CVE and GHSA- equivalents
		for _, id := range secondaryIDs {
			if strings.HasPrefix(id, "CVE-") || strings.HasPrefix(id, "GHSA-") {
				relevant = append(relevant, id)
			}
		}
	} else if strings.HasPrefix(primaryID, "GHSA-") {
		// If primary is GHSA-, show CVE and GO- equivalents
		for _, id := range secondaryIDs {
			if strings.HasPrefix(id, "CVE-") || strings.HasPrefix(id, "GO-") {
				relevant = append(relevant, id)
			}
		}
	}

	// Limit to 3 most relevant secondary IDs to avoid clutter
	if len(relevant) > 3 {
		relevant = relevant[:3]
	}

	return relevant
}

// cleanSummaryText removes redundant package references from vulnerability summaries
func cleanSummaryText(summary, packageName string) string {
	if summary == "" {
		return summary
	}

	// Extract the base package name without version suffixes for better matching
	basePackageName := packageName
	if idx := strings.LastIndex(basePackageName, "/v"); idx != -1 {
		basePackageName = basePackageName[:idx]
	}

	// List of patterns to clean up (case insensitive)
	patterns := []string{
		" in " + packageName,
		" in " + basePackageName,
		" for " + packageName,
		" for " + basePackageName,
		" of " + packageName,
		" of " + basePackageName,
		packageName + " ",
		basePackageName + " ",
	}

	cleanedSummary := summary
	lowerSummary := strings.ToLower(summary)

	for _, pattern := range patterns {
		lowerPattern := strings.ToLower(pattern)
		if strings.Contains(lowerSummary, lowerPattern) {
			// Find the actual case in the original string and replace it
			idx := strings.Index(lowerSummary, lowerPattern)
			if idx != -1 {
				// Replace the actual text, preserving case where it doesn't match the pattern
				originalPattern := cleanedSummary[idx : idx+len(pattern)]

				// If the pattern starts/ends with space, preserve those spaces
				replacement := ""
				if strings.HasPrefix(pattern, " ") && strings.HasSuffix(pattern, " ") {
					replacement = " "
				} else if strings.HasPrefix(pattern, " ") {
					replacement = " "
				} else if strings.HasSuffix(pattern, " ") {
					replacement = " "
				}

				cleanedSummary = cleanedSummary[:idx] + replacement + cleanedSummary[idx+len(originalPattern):]
				lowerSummary = strings.ToLower(cleanedSummary) // Update for next iteration
			}
		}
	}

	// Clean up any double spaces and trim
	cleanedSummary = strings.ReplaceAll(cleanedSummary, "  ", " ")
	cleanedSummary = strings.TrimSpace(cleanedSummary)

	// Capitalize first letter if it got lowercased
	if len(cleanedSummary) > 0 && cleanedSummary[0] >= 'a' && cleanedSummary[0] <= 'z' {
		cleanedSummary = strings.ToUpper(string(cleanedSummary[0])) + cleanedSummary[1:]
	}

	return cleanedSummary
}

func checkFilesChanged(repoPath string, baseRef string, prRef string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("error opening repository: %w", err)
	}

	baseHash, err := repo.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		return nil, fmt.Errorf("error resolving base reference '%s': %w", baseRef, err)
	}

	prHash, err := repo.ResolveRevision(plumbing.Revision(prRef))
	if err != nil {
		return nil, fmt.Errorf("error resolving PR reference '%s': %w", prRef, err)
	}

	baseCommit, err := repo.CommitObject(*baseHash)
	if err != nil {
		return nil, fmt.Errorf("error getting base commit: %w", err)
	}

	prCommit, err := repo.CommitObject(*prHash)
	if err != nil {
		return nil, fmt.Errorf("error getting PR commit: %w", err)
	}

	changes, err := baseCommit.Patch(prCommit)
	if err != nil {
		return nil, fmt.Errorf("error getting patch: %w", err)
	}

	fileNames := make([]string, 0)
	for _, change := range changes.FilePatches() {
		from, to := change.Files()
		var fileName string
		if from != nil {
			fileName = from.Path()
		} else if to != nil {
			fileName = to.Path()
		} else {
			// This shouldn't happen, but let's be safe
			continue
		}
		fileNames = append(fileNames, fileName)
	}

	return fileNames, nil
}

// GitState represents the current state of a git repository
type GitState struct {
	CurrentHash   plumbing.Hash
	CurrentBranch string
	IsDetached    bool
	HasChanges    bool
}

// saveGitState captures the current git repository state
func saveGitState(repo *git.Repository, worktree *git.Worktree) (*GitState, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("error getting current HEAD: %w", err)
	}

	state := &GitState{
		CurrentHash: head.Hash(),
		IsDetached:  false,
		HasChanges:  false,
	}

	// Check if we're on a branch or in detached HEAD state
	if head.Name().IsBranch() {
		state.CurrentBranch = head.Name().Short()
	} else {
		state.IsDetached = true
	}

	// Check if there are uncommitted changes
	status, err := worktree.Status()
	if err != nil {
		return nil, fmt.Errorf("error checking worktree status: %w", err)
	}
	state.HasChanges = !status.IsClean()

	return state, nil
}

// restoreGitState restores the git repository to its previous state
func restoreGitState(worktree *git.Worktree, state *GitState) error {
	var checkoutErr error

	if state.IsDetached {
		// If we were in detached HEAD state, restore to the exact commit
		checkoutErr = worktree.Checkout(&git.CheckoutOptions{
			Hash:  state.CurrentHash,
			Force: true,
		})
	} else {
		// If we were on a branch, restore to that branch
		checkoutErr = worktree.Checkout(&git.CheckoutOptions{
			Branch: plumbing.ReferenceName("refs/heads/" + state.CurrentBranch),
			Force:  true,
		})
	}

	if checkoutErr != nil {
		return fmt.Errorf("error restoring git checkout: %w", checkoutErr)
	}

	// Note: We don't try to restore uncommitted changes as they would be complex to handle
	// and could conflict with the forced checkout. Users should stash changes before running.
	if state.HasChanges {
		fmt.Println("Note: Your working directory had uncommitted changes before running deputy. These were not restored.")
	}

	return nil
}

func scanPackages(ctx context.Context, repoPath string, commitHash plumbing.Hash) ([]*extractor.Package, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("error opening repository: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("error getting worktree: %w", err)
	}

	// Save current git state for restoration
	originalState, err := saveGitState(repo, worktree)
	if err != nil {
		return nil, fmt.Errorf("error saving git state: %w", err)
	}

	// Ensure we restore the original state, even on error
	defer func() {
		if restoreErr := restoreGitState(worktree, originalState); restoreErr != nil {
			fmt.Printf("Warning: failed to restore git state: %v\n", restoreErr)
		}
	}()

	err = worktree.Checkout(&git.CheckoutOptions{
		Hash:  commitHash,
		Force: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error checking out commit: %w", err)
	}

	plugins, err := pl.FromNames([]string{"go"})
	if err != nil {
		return nil, fmt.Errorf("error creating plugins: %w", err)
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots: scalibrfs.RealFSScanRoots(repoPath),
		Plugins:   plugins,
	}

	results := scalibr.New().Scan(ctx, cfg)

	return results.Inventory.Packages, nil
}

// normalizeGopkgInURL converts gopkg.in URLs to their canonical GitHub repository names
// For example: "gopkg.in/go-jose/go-jose.v2" -> "github.com/go-jose/go-jose"
func normalizeGopkgInURL(packageName string) string {
	if !strings.HasPrefix(packageName, "gopkg.in/") {
		return packageName
	}

	// Remove the "gopkg.in/" prefix
	remainder := strings.TrimPrefix(packageName, "gopkg.in/")
	parts := strings.Split(remainder, "/")

	if len(parts) == 0 {
		return packageName
	}

	// gopkg.in URLs can have different formats:
	// 1. gopkg.in/user/repo.vN -> github.com/user/repo
	// 2. gopkg.in/repo.vN -> github.com/go-pkg/repo (for go-pkg namespace)

	if len(parts) == 1 {
		// Format: gopkg.in/repo.vN
		repoWithVersion := parts[0]
		// Find the last dot followed by 'v' and a number
		for i := len(repoWithVersion) - 1; i >= 0; i-- {
			if repoWithVersion[i] == '.' && i+1 < len(repoWithVersion) && repoWithVersion[i+1] == 'v' {
				// Check if what follows 'v' is numeric
				versionPart := repoWithVersion[i+2:]
				isNumeric := len(versionPart) > 0
				for _, r := range versionPart {
					if r < '0' || r > '9' {
						isNumeric = false
						break
					}
				}
				if isNumeric {
					repo := repoWithVersion[:i]
					return "github.com/go-" + repo + "/" + repo
				}
			}
		}
	} else if len(parts) >= 2 {
		// Format: gopkg.in/user/repo.vN or gopkg.in/user/repo/subpkg.vN
		user := parts[0]

		// Find which part has the version suffix
		var repoWithVersion string
		var repoIndex int
		var hasVersionSuffix bool

		// Check each part for a version suffix (.vN)
		for i := 1; i < len(parts); i++ {
			part := parts[i]
			for j := len(part) - 1; j >= 0; j-- {
				if part[j] == '.' && j+1 < len(part) && part[j+1] == 'v' {
					// Check if what follows 'v' is numeric
					versionPart := part[j+2:]
					isNumeric := len(versionPart) > 0
					for _, r := range versionPart {
						if r < '0' || r > '9' {
							isNumeric = false
							break
						}
					}
					if isNumeric {
						repoWithVersion = part
						repoIndex = i
						hasVersionSuffix = true
						break
					}
				}
			}
			if hasVersionSuffix {
				break
			}
		}

		if hasVersionSuffix {
			// Find the version suffix in the identified part
			for i := len(repoWithVersion) - 1; i >= 0; i-- {
				if repoWithVersion[i] == '.' && i+1 < len(repoWithVersion) && repoWithVersion[i+1] == 'v' {
					// Check if what follows 'v' is numeric
					versionPart := repoWithVersion[i+2:]
					isNumeric := len(versionPart) > 0
					for _, r := range versionPart {
						if r < '0' || r > '9' {
							isNumeric = false
							break
						}
					}
					if isNumeric {
						partWithoutVersion := repoWithVersion[:i]

						// Build the GitHub URL
						result := "github.com/" + user

						// Add the repo name (if repoIndex == 1, it's the repo part)
						if repoIndex == 1 {
							result += "/" + partWithoutVersion
						} else {
							// It's a subpackage with version, keep the repo part as-is
							result += "/" + parts[1]
						}

						// Add any path components before the versioned part
						for j := 2; j < repoIndex; j++ {
							result += "/" + parts[j]
						}

						// Add the versioned part without the version
						if repoIndex > 1 {
							result += "/" + partWithoutVersion
						}

						// Add any remaining path components
						if repoIndex+1 < len(parts) {
							result += "/" + strings.Join(parts[repoIndex+1:], "/")
						}

						return result
					}
				}
			}
		}
	}

	// If we couldn't parse the version, return the original
	return packageName
}

// extractCanonicalPackageName extracts the base package name without major version suffix
// For example: "modernc.org/cc/v3" -> "modernc.org/cc"
// Also normalizes gopkg.in URLs: "gopkg.in/go-jose/go-jose.v2" -> "github.com/go-jose/go-jose"
func extractCanonicalPackageName(packageName string) string {
	// First, normalize gopkg.in URLs
	normalized := normalizeGopkgInURL(packageName)

	// Then check if the package has a major version suffix (/v2, /v3, etc.)
	// This pattern matches Go module major version suffixes
	parts := strings.Split(normalized, "/")
	if len(parts) == 0 {
		return normalized
	}

	lastPart := parts[len(parts)-1]

	// Check if the last part is a major version (v2, v3, v4, etc.)
	// Note: v0 and v1 don't typically use suffixes in Go modules
	if len(lastPart) >= 2 && lastPart[0] == 'v' && len(lastPart) > 1 {
		// Check if the rest is a number >= 2
		versionPart := lastPart[1:]
		if len(versionPart) > 0 {
			// Simple check for numeric version (could be more sophisticated)
			isNumeric := true
			for _, r := range versionPart {
				if r < '0' || r > '9' {
					isNumeric = false
					break
				}
			}

			if isNumeric && versionPart != "0" && versionPart != "1" {
				// This looks like a major version suffix, remove it
				return strings.Join(parts[:len(parts)-1], "/")
			}
		}
	}

	return normalized
}

// GoPackageInfo represents information about a Go package including version metadata
type GoPackageInfo struct {
	OriginalName  string // Original package name as it appears in go.mod (e.g., "gopkg.in/go-jose/go-jose.v2")
	FullName      string // Normalized full package name with version suffix (e.g., "github.com/go-jose/go-jose")
	CanonicalName string // Package name without version suffix (e.g., "github.com/go-jose/go-jose")
	Version       string // Actual version (e.g., "3.41.0")
	MajorVersion  int    // Major version from path suffix (e.g., 3 from /v3)
}

// parseGoPackage extracts Go-specific package information
func parseGoPackage(pkg *extractor.Package) GoPackageInfo {
	// Normalize gopkg.in URLs for canonical comparison
	normalizedName := normalizeGopkgInURL(pkg.Name)

	info := GoPackageInfo{
		OriginalName:  pkg.Name,                              // Keep original for display
		FullName:      normalizedName,                        // Normalized for comparison
		CanonicalName: extractCanonicalPackageName(pkg.Name), // This will handle gopkg.in normalization internally
		Version:       pkg.Version,
		MajorVersion:  1, // Default to v1 if no suffix
	}

	// Extract major version from path suffix (try normalized name first)
	if info.FullName != info.CanonicalName {
		// Package has a version suffix
		parts := strings.Split(info.FullName, "/")
		lastPart := parts[len(parts)-1]
		if len(lastPart) > 1 && lastPart[0] == 'v' {
			versionStr := lastPart[1:]
			// Simple integer parsing (could use strconv.Atoi for robustness)
			majorVer := 0
			for _, r := range versionStr {
				if r >= '0' && r <= '9' {
					majorVer = majorVer*10 + int(r-'0')
				} else {
					break
				}
			}
			if majorVer > 0 {
				info.MajorVersion = majorVer
			}
		}
	} else if strings.HasPrefix(pkg.Name, "gopkg.in/") {
		// For gopkg.in URLs, extract major version from the original URL
		// Example: gopkg.in/go-jose/go-jose.v2 -> major version 2
		for i := len(pkg.Name) - 1; i >= 0; i-- {
			if pkg.Name[i] == '.' && i+1 < len(pkg.Name) && pkg.Name[i+1] == 'v' {
				versionPart := pkg.Name[i+2:]
				isNumeric := len(versionPart) > 0
				for _, r := range versionPart {
					if r < '0' || r > '9' {
						isNumeric = false
						break
					}
				}
				if isNumeric {
					majorVer := 0
					for _, r := range versionPart {
						if r >= '0' && r <= '9' {
							majorVer = majorVer*10 + int(r-'0')
						} else {
							break
						}
					}
					if majorVer > 0 {
						info.MajorVersion = majorVer
					}
				}
				break
			}
		}
	}

	return info
}

func comparePackages(oldPkgs, newPkgs []*extractor.Package) []PackageChange {
	var changes []PackageChange

	// Parse package information for old and new packages
	oldPackageInfos := make(map[string][]GoPackageInfo) // canonical name -> package infos
	newPackageInfos := make(map[string][]GoPackageInfo)

	for _, pkg := range oldPkgs {
		info := parseGoPackage(pkg)
		oldPackageInfos[info.CanonicalName] = append(oldPackageInfos[info.CanonicalName], info)
	}

	for _, pkg := range newPkgs {
		info := parseGoPackage(pkg)
		newPackageInfos[info.CanonicalName] = append(newPackageInfos[info.CanonicalName], info)
	}

	// Get direct dependencies from go.mod (if it exists in current working directory)
	directDeps := getDirectDependencies()

	// Get all canonical package names
	allCanonicalNames := make(map[string]bool)
	for name := range oldPackageInfos {
		allCanonicalNames[name] = true
	}
	for name := range newPackageInfos {
		allCanonicalNames[name] = true
	}

	// Compare packages by canonical name
	for canonicalName := range allCanonicalNames {
		oldInfos := oldPackageInfos[canonicalName]
		newInfos := newPackageInfos[canonicalName]

		if len(oldInfos) == 0 {
			// Package was added - but check if we have multiple major versions
			if len(newInfos) > 1 {
				// Multiple new major versions - show as upgrade to the highest version
				newBest := findBestPackageInfo(newInfos)

				// Find the lowest version as the "base" for a more meaningful display
				newLowest := newInfos[0]
				for _, info := range newInfos[1:] {
					if info.MajorVersion < newLowest.MajorVersion {
						newLowest = info
					}
				}

				// If we have a version progression (e.g., v2 and v3), show as upgrade
				if newBest.MajorVersion > newLowest.MajorVersion {
					changes = append(changes, PackageChange{
						Name:          newBest.OriginalName,
						OldName:       newLowest.OriginalName,
						BaseVersion:   newLowest.Version,
						TargetVersion: newBest.Version,
						ChangeType:    Updated, // Treat as upgrade, not addition
						Ecosystem:     "go",
						IsDirect:      directDeps[newBest.OriginalName] || directDeps[newLowest.OriginalName] || directDeps[canonicalName],
					})
				} else {
					// No clear progression, show the best one as added
					changes = append(changes, PackageChange{
						Name:          newBest.OriginalName,
						OldName:       "",
						BaseVersion:   "",
						TargetVersion: newBest.Version,
						ChangeType:    Added,
						Ecosystem:     "go",
						IsDirect:      directDeps[newBest.OriginalName] || directDeps[canonicalName],
					})
				}
			} else {
				// Single new package - straightforward addition
				newInfo := newInfos[0]
				changes = append(changes, PackageChange{
					Name:          newInfo.OriginalName,
					OldName:       "", // No old name for added packages
					BaseVersion:   "",
					TargetVersion: newInfo.Version,
					ChangeType:    Added,
					Ecosystem:     "go",
					IsDirect:      directDeps[newInfo.OriginalName] || directDeps[canonicalName],
				})
			}
		} else if len(newInfos) == 0 {
			// Package was removed
			for _, oldInfo := range oldInfos {
				changes = append(changes, PackageChange{
					Name:          oldInfo.OriginalName,
					OldName:       "", // OldName same as Name for removed packages
					BaseVersion:   oldInfo.Version,
					TargetVersion: "",
					ChangeType:    Removed,
					Ecosystem:     "go",
					IsDirect:      directDeps[oldInfo.OriginalName] || directDeps[canonicalName],
				})
			}
		} else {
			// Package exists in both, check for changes
			// Find the best old and new representatives
			oldBest := findBestPackageInfo(oldInfos)
			newBest := findBestPackageInfo(newInfos)

			// Check if there's a meaningful change
			if oldBest.FullName != newBest.FullName || oldBest.Version != newBest.Version {
				// Determine if this is an upgrade or update
				changeType := Updated
				displayName := newBest.OriginalName
				oldDisplayName := oldBest.OriginalName

				// If the major version changed in the path, prefer showing the newer path
				if oldBest.MajorVersion != newBest.MajorVersion {
					// Major version upgrade - this is what we want to detect!
					displayName = newBest.OriginalName
				}

				changes = append(changes, PackageChange{
					Name:          displayName,
					OldName:       oldDisplayName, // Track the original name for display
					BaseVersion:   oldBest.Version,
					TargetVersion: newBest.Version,
					ChangeType:    changeType,
					Ecosystem:     "go",
					IsDirect:      directDeps[oldBest.OriginalName] || directDeps[newBest.OriginalName] || directDeps[canonicalName],
				})
			}
		}
	}

	// Sort changes by name
	slices.SortFunc(changes, func(a, b PackageChange) int {
		return strings.Compare(a.Name, b.Name)
	})

	return changes
}

// findBestPackageInfo selects the best representative from multiple package infos
// Prioritizes higher major versions
func findBestPackageInfo(infos []GoPackageInfo) GoPackageInfo {
	if len(infos) == 0 {
		return GoPackageInfo{}
	}

	best := infos[0]
	for _, info := range infos[1:] {
		// Prefer higher major version
		if info.MajorVersion > best.MajorVersion {
			best = info
		} else if info.MajorVersion == best.MajorVersion {
			// Same major version, prefer lexicographically later version (rough heuristic)
			if semver.Compare(normalizeGoVersion(info.Version), normalizeGoVersion(best.Version)) > 0 {
				best = info
			}
		}
	}

	return best
}

// getDirectDependencies reads go.mod file and returns a map of direct dependencies
func getDirectDependencies() map[string]bool {
	directDeps := make(map[string]bool)

	// Standard library packages are always direct
	directDeps["stdlib"] = true

	// Try to read go.mod from current directory
	file, err := os.Open("go.mod")
	if err != nil {
		return directDeps // Return map with stdlib if go.mod doesn't exist
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	inRequireBlock := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Start of require block
		if strings.HasPrefix(line, "require (") {
			inRequireBlock = true
			continue
		}

		// End of require block
		if inRequireBlock && line == ")" {
			inRequireBlock = false
			continue
		}

		// Single line require
		if strings.HasPrefix(line, "require ") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				pkgName := parts[1]
				// Check if it's not marked as indirect
				isIndirect := false
				for _, part := range parts[3:] {
					if strings.Contains(part, "indirect") {
						isIndirect = true
						break
					}
				}
				if !isIndirect {
					directDeps[pkgName] = true
				}
			}
			continue
		}

		// Inside require block
		if inRequireBlock && line != "" && !strings.HasPrefix(line, "//") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				pkgName := parts[0]
				// Check if it's not marked as indirect
				isIndirect := false
				for _, part := range parts[2:] {
					if strings.Contains(part, "indirect") {
						isIndirect = true
						break
					}
				}
				if !isIndirect {
					directDeps[pkgName] = true
				}
			}
		}
	}

	return directDeps
}

// compareGoPackageVersions compares two package changes considering major version changes
// This is used when we have additional context about package names
func compareGoPackageVersions(pkg PackageChange) int {
	// If old and new names are different, extract major version info
	if pkg.OldName != "" && pkg.OldName != pkg.Name {
		oldInfo := GoPackageInfo{
			FullName:      pkg.OldName,
			CanonicalName: extractCanonicalPackageName(pkg.OldName),
			Version:       pkg.BaseVersion,
		}
		oldInfo.MajorVersion = extractMajorVersionFromPath(pkg.OldName)

		newInfo := GoPackageInfo{
			FullName:      pkg.Name,
			CanonicalName: extractCanonicalPackageName(pkg.Name),
			Version:       pkg.TargetVersion,
		}
		newInfo.MajorVersion = extractMajorVersionFromPath(pkg.Name)

		return compareGoPackageChanges(oldInfo, newInfo)
	}

	// Fallback to regular version comparison
	return compareGoVersions(pkg.BaseVersion, pkg.TargetVersion)
}

// extractMajorVersionFromPath extracts the major version number from a package path
func extractMajorVersionFromPath(packagePath string) int {
	parts := strings.Split(packagePath, "/")
	if len(parts) == 0 {
		return 1 // Default to v1
	}

	lastPart := parts[len(parts)-1]
	if len(lastPart) >= 2 && lastPart[0] == 'v' {
		versionStr := lastPart[1:]
		majorVer := 0
		for _, r := range versionStr {
			if r >= '0' && r <= '9' {
				majorVer = majorVer*10 + int(r-'0')
			} else {
				break
			}
		}
		if majorVer > 0 {
			return majorVer
		}
	}

	return 1 // Default to v1 if no version suffix
}

// compareGoVersions attempts to determine if a version change is an upgrade or downgrade using Go module semantics
// Returns: 1 for upgrade, -1 for downgrade, 0 for unclear/equal
func compareGoVersions(oldVersion, newVersion string) int {
	// Handle empty versions
	if oldVersion == "" || newVersion == "" {
		return 0
	}

	// Normalize versions to ensure they have 'v' prefix for Go module comparison
	oldNormalized := normalizeGoVersion(oldVersion)
	newNormalized := normalizeGoVersion(newVersion)

	// Use Go's semver package for proper semantic version comparison
	// This handles pseudo-versions, pre-releases, and standard semantic versions correctly
	result := semver.Compare(oldNormalized, newNormalized)

	// semver.Compare returns:
	//   -1 if oldVersion < newVersion (upgrade) -> we want to return 1
	//    0 if oldVersion = newVersion (no change) -> we want to return 0
	//    1 if oldVersion > newVersion (downgrade) -> we want to return -1
	return -result
}

// compareGoPackageChanges compares package changes considering major version path changes
// This is specifically for Go modules where major versions can appear in import paths
func compareGoPackageChanges(oldPkg, newPkg GoPackageInfo) int {
	// If major versions are different, this is definitely an upgrade/downgrade
	if oldPkg.MajorVersion != newPkg.MajorVersion {
		if newPkg.MajorVersion > oldPkg.MajorVersion {
			return 1 // Major version upgrade
		} else {
			return -1 // Major version downgrade
		}
	}

	// Same major version, compare the actual version strings
	return compareGoVersions(oldPkg.Version, newPkg.Version)
}

// normalizeGoVersion ensures a version string is in the format expected by Go's semver package
func normalizeGoVersion(version string) string {
	if version == "" {
		return version
	}

	// If it already starts with 'v', return as-is
	if strings.HasPrefix(version, "v") {
		return version
	}

	// Add 'v' prefix
	return "v" + version
}

// validateReference checks if a Git reference is valid and provides helpful error messages
func validateReference(repo *git.Repository, ref string) error {
	// Try to resolve the reference
	_, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err == nil {
		return nil // Reference is valid
	}

	// If resolution failed, provide helpful suggestions
	suggestions := getReferenceSuggestions(repo, ref)
	if len(suggestions) > 0 {
		return fmt.Errorf("%w\nDid you mean one of these?\n  %s",
			err, strings.Join(suggestions, "\n  "))
	}

	// Provide general help about valid reference types
	return fmt.Errorf("%w\nValid references include:\n"+
		"  • Branch names: main, develop, feature-branch\n"+
		"  • Tags: v1.0.0, release-2023\n"+
		"  • Commit SHAs: 1a2b3c4, 1a2b3c4d5e6f7890abcdef\n"+
		"  • Remote refs: origin/main, upstream/develop\n"+
		"  • Git expressions: HEAD~3, main^, HEAD@{yesterday}\n"+
		"Use 'git branch -a' and 'git tag' to see available references", err)
}

// getReferenceSuggestions provides helpful suggestions for similar reference names
func getReferenceSuggestions(repo *git.Repository, invalidRef string) []string {
	var suggestions []string

	// Check local branches
	if branches, err := repo.Branches(); err == nil {
		branches.ForEach(func(ref *plumbing.Reference) error {
			branchName := ref.Name().Short()
			if similarity := calculateSimilarity(invalidRef, branchName); similarity > 0.6 {
				suggestions = append(suggestions, branchName)
			}
			return nil
		})
	}

	// Check tags
	if tags, err := repo.Tags(); err == nil {
		tags.ForEach(func(ref *plumbing.Reference) error {
			tagName := ref.Name().Short()
			if similarity := calculateSimilarity(invalidRef, tagName); similarity > 0.6 {
				suggestions = append(suggestions, tagName)
			}
			return nil
		})
	}

	// Check remotes
	if remotes, err := repo.Remotes(); err == nil {
		for _, remote := range remotes {
			remoteName := remote.Config().Name
			candidate := fmt.Sprintf("%s/%s", remoteName, invalidRef)
			if _, err := repo.ResolveRevision(plumbing.Revision(candidate)); err == nil {
				suggestions = append(suggestions, candidate)
			}
		}
	}

	// Limit suggestions to avoid overwhelming output
	if len(suggestions) > 5 {
		suggestions = suggestions[:5]
	}

	return suggestions
}

// calculateSimilarity returns a simple similarity score between two strings
func calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	// Simple similarity: ratio of common characters
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
	if maxLen == 0 {
		return 0
	}

	common := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			common++
		}
	}

	return float64(common) / float64(maxLen)
}

// parseReferences intelligently parses command line arguments to determine base and target references
// It supports all Git reference types: branches, tags, commits, remote refs, and Git revision expressions
func parseReferences(repoPath string, args []string) (baseRef, targetRef string, err error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", "", fmt.Errorf("error opening Git repository at %s: %w", repoPath, err)
	}

	// Find the default branch (main, master, or current HEAD)
	defaultBranch, err := getDefaultBranch(repo)
	if err != nil {
		return "", "", fmt.Errorf("error determining default branch: %w", err)
	}

	switch len(args) {
	case 0:
		// No arguments: compare current HEAD with default branch
		// This is useful for checking what changed in your current work vs the main branch
		return defaultBranch, "HEAD", nil
	case 1:
		// One argument: compare default branch with provided reference
		// Validate the provided reference
		if err := validateReference(repo, args[0]); err != nil {
			return "", "", fmt.Errorf("invalid target reference %q: %w", args[0], err)
		}
		return defaultBranch, args[0], nil
	case 2:
		// Two arguments: first is base, second is target
		// Validate both references
		if err := validateReference(repo, args[0]); err != nil {
			return "", "", fmt.Errorf("invalid base reference %q: %w", args[0], err)
		}
		if err := validateReference(repo, args[1]); err != nil {
			return "", "", fmt.Errorf("invalid target reference %q: %w", args[1], err)
		}
		return args[0], args[1], nil
	default:
		return "", "", fmt.Errorf("too many arguments provided (maximum 2)")
	}
}

// getDefaultBranch attempts to find the repository's default branch using multiple strategies
func getDefaultBranch(repo *git.Repository) (string, error) {
	// Strategy 1: Try to get the remote HEAD symref (most reliable for GitHub/GitLab)
	if defaultBranch := getRemoteDefaultBranch(repo); defaultBranch != "" {
		return defaultBranch, nil
	}

	// Strategy 2: Check if we're currently on a reasonable default branch
	if head, err := repo.Head(); err == nil && head.Name().IsBranch() {
		currentBranch := head.Name().Short()
		if isLikelyDefaultBranch(currentBranch) {
			return currentBranch, nil
		}
	}

	// Strategy 3: Look for common default branch names in local branches
	if defaultBranch := findLocalDefaultBranch(repo); defaultBranch != "" {
		return defaultBranch, nil
	}

	// Strategy 4: Try to find any branch that looks like a default
	if branches, err := repo.Branches(); err == nil {
		var firstBranch string
		err = branches.ForEach(func(ref *plumbing.Reference) error {
			branchName := ref.Name().Short()
			if firstBranch == "" {
				firstBranch = branchName
			}
			if isLikelyDefaultBranch(branchName) {
				return fmt.Errorf("found:%s", branchName) // Use error to break early
			}
			return nil
		})

		if err != nil && strings.HasPrefix(err.Error(), "found:") {
			return strings.TrimPrefix(err.Error(), "found:"), nil
		}

		// If we found at least one branch, use it
		if firstBranch != "" {
			return firstBranch, nil
		}
	}

	// Ultimate fallback: use HEAD
	return "HEAD", nil
}

// getRemoteDefaultBranch tries to determine the default branch from remote HEAD symref
func getRemoteDefaultBranch(repo *git.Repository) string {
	remotes, err := repo.Remotes()
	if err != nil || len(remotes) == 0 {
		return ""
	}

	// Prioritize 'origin' remote, then 'upstream', then any remote
	remoteOrder := []string{"origin", "upstream"}

	for _, remoteName := range remoteOrder {
		for _, remote := range remotes {
			if remote.Config().Name == remoteName {
				if branch := getRemoteHeadBranch(remote); branch != "" {
					return branch
				}
			}
		}
	}

	// Try any remaining remote
	for _, remote := range remotes {
		if branch := getRemoteHeadBranch(remote); branch != "" {
			return branch
		}
	}

	return ""
}

// getRemoteHeadBranch extracts the default branch from a remote's HEAD symref
func getRemoteHeadBranch(remote *git.Remote) string {
	refs, err := remote.List(&git.ListOptions{})
	if err != nil {
		return ""
	}

	var headSymref *plumbing.Reference
	for _, ref := range refs {
		if ref.Name().String() == fmt.Sprintf("refs/remotes/%s/HEAD", remote.Config().Name) {
			headSymref = ref
			break
		}
	}

	if headSymref != nil && headSymref.Type() == plumbing.SymbolicReference {
		// Extract branch name from symref target
		target := headSymref.Target().String()
		if strings.HasPrefix(target, fmt.Sprintf("refs/remotes/%s/", remote.Config().Name)) {
			return strings.TrimPrefix(target, fmt.Sprintf("refs/remotes/%s/", remote.Config().Name))
		}
	}

	return ""
}

// findLocalDefaultBranch looks for common default branch names in local branches
func findLocalDefaultBranch(repo *git.Repository) string {
	branches, err := repo.Branches()
	if err != nil {
		return ""
	}

	// Check for common default branch names in order of preference
	defaultCandidates := []string{"main", "master", "develop", "development", "trunk"}

	for _, candidate := range defaultCandidates {
		var found bool
		branches.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().Short() == candidate {
				found = true
				return fmt.Errorf("stop") // break early
			}
			return nil
		})
		if found {
			return candidate
		}
	}

	return ""
}

// isLikelyDefaultBranch checks if a branch name looks like a default branch
func isLikelyDefaultBranch(branchName string) bool {
	defaultPatterns := []string{"main", "master", "develop", "development", "trunk", "default"}
	for _, pattern := range defaultPatterns {
		if branchName == pattern {
			return true
		}
	}
	return false
}

// listAvailableReferences displays all available Git references in a user-friendly format
func listAvailableReferences(repoPath string) error {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("error opening Git repository at %s: %w", repoPath, err)
	}

	fmt.Printf("Available Git references in %s:\n\n", repoPath)

	// Show default branch
	defaultBranch, err := getDefaultBranch(repo)
	if err == nil {
		fmt.Printf("%sDefault branch:%s %s\n\n", colorHeader, colorReset, defaultBranch)
	}

	// List local branches
	fmt.Printf("%sLocal branches:%s\n", colorHeader, colorReset)
	branches, err := repo.Branches()
	if err != nil {
		fmt.Printf("  Error listing branches: %v\n", err)
	} else {
		var branchCount int
		branches.ForEach(func(ref *plumbing.Reference) error {
			branchName := ref.Name().Short()
			if branchName == defaultBranch {
				fmt.Printf("  %s (default)\n", branchName)
			} else {
				fmt.Printf("  %s\n", branchName)
			}
			branchCount++
			return nil
		})
		if branchCount == 0 {
			fmt.Println("  No local branches found")
		}
	}

	// List tags
	fmt.Printf("\n%sTags:%s\n", colorHeader, colorReset)
	tags, err := repo.Tags()
	if err != nil {
		fmt.Printf("  Error listing tags: %v\n", err)
	} else {
		var tagCount int
		tags.ForEach(func(ref *plumbing.Reference) error {
			fmt.Printf("  %s\n", ref.Name().Short())
			tagCount++
			return nil
		})
		if tagCount == 0 {
			fmt.Println("  No tags found")
		}
	}

	// List remotes and their branches
	fmt.Printf("\n%sRemote branches:%s\n", colorHeader, colorReset)
	remotes, err := repo.Remotes()
	if err != nil {
		fmt.Printf("  Error listing remotes: %v\n", err)
	} else if len(remotes) == 0 {
		fmt.Println("  No remotes configured")
	} else {
		for _, remote := range remotes {
			fmt.Printf("  %s:\n", remote.Config().Name)
			refs, err := remote.List(&git.ListOptions{})
			if err != nil {
				fmt.Printf("    Error listing remote refs: %v\n", err)
				continue
			}

			var remoteBranches []string
			for _, ref := range refs {
				if ref.Name().IsBranch() {
					// Extract branch name from refs/heads/branch-name
					branchName := strings.TrimPrefix(ref.Name().String(), "refs/heads/")
					remoteBranches = append(remoteBranches, fmt.Sprintf("%s/%s", remote.Config().Name, branchName))
				}
			}

			if len(remoteBranches) == 0 {
				fmt.Println("    No remote branches found")
			} else {
				for _, branch := range remoteBranches {
					fmt.Printf("    %s\n", branch)
				}
			}
		}
	}

	// Show usage examples
	fmt.Printf("\n%sUsage examples:%s\n", colorHeader, colorReset)
	fmt.Println("  deputy                    # Compare HEAD with default branch")
	fmt.Println("  deputy feature-branch     # Compare default branch with feature-branch")
	if defaultBranch != "" {
		fmt.Printf("  deputy %s HEAD           # Compare %s with current HEAD\n", defaultBranch, defaultBranch)
	}
	fmt.Println("  deputy HEAD~3 HEAD        # Compare 3 commits ago with HEAD")
	if len(remotes) > 0 {
		remoteName := remotes[0].Config().Name
		fmt.Printf("  deputy %s/main main       # Compare remote with local branch\n", remoteName)
	}

	return nil
}

func main() {
	var repoPath string
	var listRefs bool
	var skipVulnScan bool

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	rootCmd := &cobra.Command{
		Use:   "deputy [base] [target]",
		Short: "Analyze dependency changes between Git references",
		Long: `deputy analyzes dependency changes between Git references with comprehensive support for all Git reference types.

SUPPORTED REFERENCE TYPES:
• Branch names: main, develop, feature-branch, bugfix/issue-123
• Tags: v1.0.0, release-2023, latest
• Commit SHAs: 1a2b3c4, 1a2b3c4d5e6f7890abcdef123456789
• Remote references: origin/main, upstream/develop, fork/feature
• Git revision expressions: HEAD~3, main^, HEAD@{yesterday}, @{upstream}
• Relative references: HEAD~1, main~5, tag^{tree}

USAGE PATTERNS:
• No arguments: Compare current HEAD with default branch (auto-detected)
• One argument: Compare default branch with the specified reference  
• Two arguments: Compare first reference (base) with second reference (target)

The tool automatically detects the repository's default branch by checking:
1. Remote HEAD symref (most reliable for GitHub/GitLab repos)
2. Current branch if it's a likely default (main, master, develop)
3. Common default branch names in local branches
4. Falls back to any available branch or HEAD

DEPENDENCY DETECTION:
Only analyzes changes when go.mod or go.sum files are modified between references.
Provides license information for changed packages via the deps.dev API.
Includes vulnerability scanning using the OSV (Open Source Vulnerabilities) database.

VULNERABILITY SCANNING:
Automatically scans added and updated packages for known vulnerabilities.
Reports CVE identifiers when available, otherwise shows GO- or GHSA- identifiers.
Uses batch queries to the OSV API for efficient scanning.
Can be disabled with --skip-vuln-scan for faster execution.`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle list-refs flag
			if listRefs {
				return listAvailableReferences(repoPath)
			}

			baseRef, targetRef, err := parseReferences(repoPath, args)
			if err != nil {
				return err
			}
			return runDepDelta(repoPath, baseRef, targetRef, !skipVulnScan)
		},
	}

	// Add flags
	rootCmd.Flags().StringVarP(&repoPath, "repo", "r", cwd, "Path to the repository")
	rootCmd.Flags().BoolVarP(&listRefs, "list-refs", "l", false, "List all available Git references (branches, tags, remotes)")
	rootCmd.Flags().BoolVarP(&skipVulnScan, "skip-vuln-scan", "s", false, "Skip vulnerability scanning (faster execution)")

	// Add comprehensive examples for all user types
	rootCmd.Example = `BASIC USAGE:
  # Compare current work with default branch (beginner-friendly)
  deputy

  # Compare default branch with a feature branch
  deputy feature-branch
  deputy my-awesome-feature

BRANCH COMPARISONS:
  # Compare two specific branches
  deputy main develop
  deputy master feature/new-auth
  deputy develop release/v2.0

TAG AND RELEASE COMPARISONS:
  # Compare releases or versions
  deputy v1.0.0 v2.0.0
  deputy release-2023 release-2024
  deputy latest HEAD

COMMIT COMPARISONS:
  # Compare specific commits
  deputy 1a2b3c4 main
  deputy abc123def main
  deputy HEAD~5 HEAD

REMOTE BRANCH COMPARISONS:
  # Compare with remote branches (useful for forks)
  deputy origin/main feature-branch
  deputy upstream/main origin/main
  deputy main origin/develop

ADVANCED GIT EXPRESSIONS:
  # Compare relative to HEAD
  deputy HEAD~3 HEAD
  deputy HEAD^ HEAD
  deputy main~1 main

  # Time-based comparisons
  deputy "HEAD@{yesterday}" HEAD
  deputy "main@{1.week.ago}" main

  # Compare with upstream
  deputy @{upstream} HEAD
  deputy main @{upstream}

WORKFLOW EXAMPLES:
  # Before merging a PR
  deputy main feature/user-auth

  # Check what changed in last 3 commits
  deputy HEAD~3 HEAD

  # Compare your fork with upstream
  deputy upstream/main main

  # Check dependency changes between releases
  deputy v1.2.0 v1.3.0

ERROR HANDLING:
If you specify an invalid reference, deputy will suggest similar valid references
and provide guidance on supported reference types.`

	// Use Fang to execute the command with enhanced error handling and styling
	ctx := context.Background()
	fang.Execute(ctx, rootCmd)
}

func runDepDelta(repoPath, baseRef, targetRef string, enableVulnScan bool) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Display what we're comparing for better UX
	fmt.Printf("Comparing dependencies: %s → %s\n", baseRef, targetRef)

	changesFiles, err := checkFilesChanged(repoPath, baseRef, targetRef)
	if err != nil {
		return fmt.Errorf("error checking files changed: %w", err)
	}

	containsDepChanges := slices.ContainsFunc(changesFiles, func(fileName string) bool {
		switch filepath.Base(fileName) {
		case "go.mod", "go.sum":
			return true
		}
		return false
	})

	if !containsDepChanges {
		fmt.Println("No dependency changes detected.")
		return nil
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("error opening Git repository at %s: %w\nMake sure you're running this from within a valid Git repository", repoPath, err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("error getting worktree: %w", err)
	}

	// Save the current git state for proper restoration
	originalState, err := saveGitState(repo, worktree)
	if err != nil {
		return fmt.Errorf("error saving git state: %w", err)
	}

	// Ensure we restore the original state, even on error or interruption
	defer func() {
		if restoreErr := restoreGitState(worktree, originalState); restoreErr != nil {
			if originalState.IsDetached {
				fmt.Printf("Warning: failed to restore git state to detached HEAD %s: %v\n",
					originalState.CurrentHash.String()[:8], restoreErr)
			} else {
				fmt.Printf("Warning: failed to restore git state to branch %s: %v\n",
					originalState.CurrentBranch, restoreErr)
			}
		}
	}()

	baseHash, err := repo.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		// Provide helpful error message with suggestions
		suggestions := getReferenceSuggestions(repo, baseRef)
		if len(suggestions) > 0 {
			return fmt.Errorf("error resolving base reference %q: %v\nDid you mean one of these?\n  %s",
				baseRef, err, strings.Join(suggestions, "\n  "))
		}
		return fmt.Errorf("error resolving base reference %q: %v\nUse 'git branch -a' to see available branches or 'git tag' to see available tags",
			baseRef, err)
	}

	targetHash, err := repo.ResolveRevision(plumbing.Revision(targetRef))
	if err != nil {
		// Provide helpful error message with suggestions
		suggestions := getReferenceSuggestions(repo, targetRef)
		if len(suggestions) > 0 {
			return fmt.Errorf("error resolving target reference %q: %v\nDid you mean one of these?\n  %s",
				targetRef, err, strings.Join(suggestions, "\n  "))
		}
		return fmt.Errorf("error resolving target reference %q: %v\nUse 'git branch -a' to see available branches or 'git tag' to see available tags",
			targetRef, err)
	}

	fmt.Println("Scanning packages in base reference", baseHash.String()[:8], "...")
	basePackages, err := scanPackages(ctx, repoPath, *baseHash)
	if err != nil {
		return fmt.Errorf("error scanning base reference packages: %w", err)
	}

	fmt.Println("Scanning packages in target reference", targetHash.String()[:8], "...")
	targetPackages, err := scanPackages(ctx, repoPath, *targetHash)
	if err != nil {
		return fmt.Errorf("error scanning target reference packages: %w", err)
	}

	// Call comparePackages with correct parameter order: base is old, target is new
	changedPackages := comparePackages(basePackages, targetPackages)

	slices.SortFunc(changedPackages, func(a, b PackageChange) int {
		return strings.Compare(a.Name, b.Name)
	})

	changedPackages = slices.CompactFunc(changedPackages, func(a, b PackageChange) bool {
		return a.Name == b.Name && a.ChangeType == b.ChangeType
	})

	if len(changedPackages) == 0 {
		fmt.Println("No package changes detected.")
		return nil
	}

	// Create and configure a client for the gRPC API.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	conn, err := grpc.NewClient("api.deps.dev:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	client := pb.NewInsightsClient(conn)

	fmt.Printf("\n%sDependency Changes:%s\n", colorHeader, colorReset)

	var added, removed, updated, upgraded, downgraded int

	for _, pkg := range changedPackages {
		licenses := []string{"?"}
		versionInfo, err := client.GetVersion(ctx, &pb.GetVersionRequest{
			VersionKey: &pb.VersionKey{
				System:  pb.System_GO,
				Name:    pkg.Name,
				Version: "v" + pkg.TargetVersion,
			},
		})
		if err == nil {
			licenses = versionInfo.GetLicenses()
		}

		// Format license info with subtle styling
		licenseStr := ""
		if len(licenses) > 0 && licenses[0] != "?" {
			licenseStr = fmt.Sprintf(" %s[%s]%s", colorLicense, strings.Join(licenses, ", "), colorReset)
		}

		switch pkg.ChangeType {
		case Added:
			fmt.Printf("  %s+ %s%s%s @%s%s%s%s\n",
				colorSymbol+colorAdded,
				colorBold, pkg.Name, colorReset,
				colorVersion, pkg.TargetVersion, colorReset,
				licenseStr)
			added++
		case Removed:
			fmt.Printf("  %s- %s%s%s @%s%s%s\n",
				colorSymbol+colorRemoved,
				colorBold+colorDim, pkg.Name, colorReset,
				colorVersion, pkg.BaseVersion, colorReset)
			removed++
		case Updated:
			// Determine if this is an upgrade or downgrade using Go-aware comparison
			versionChange := compareGoPackageVersions(pkg)
			var symbol, symbolColor string

			switch versionChange {
			case 1: // Upgrade
				symbol = "↑"
				symbolColor = colorSymbol + colorUpgraded
				upgraded++
			case -1: // Downgrade
				symbol = "↓"
				symbolColor = colorSymbol + colorDowngraded
				downgraded++
			default: // Unclear or lateral change
				symbol = "~"
				symbolColor = colorSymbol + colorNeutral
			}

			// Make package name bold for updates, and target version bold for upgrades
			packageDisplay := fmt.Sprintf("%s%s%s", colorBold, pkg.Name, colorReset)
			targetVersionDisplay := pkg.TargetVersion
			if versionChange == 1 { // Upgrade - make target version bold
				targetVersionDisplay = fmt.Sprintf("%s%s%s", colorBold, pkg.TargetVersion, colorReset)
			}

			// Show old package name if it's different (major version upgrade case)
			oldPackageDisplay := ""
			if pkg.OldName != "" && pkg.OldName != pkg.Name {
				oldPackageDisplay = fmt.Sprintf("%s%s%s %s→%s ",
					colorDim, pkg.OldName, colorReset, colorArrow, colorReset)
			}

			fmt.Printf("  %s%s%s %s%s @%s%s%s %s→%s %s%s%s%s\n",
				symbolColor, symbol, colorReset,
				oldPackageDisplay,
				packageDisplay,
				colorVersion, pkg.BaseVersion, colorReset,
				colorArrow, colorReset,
				colorVersion, targetVersionDisplay, colorReset,
				licenseStr)
			updated++
		}
	}

	// Clean summary without visual noise
	fmt.Printf("\n%sSummary:%s\n", colorHeader, colorReset)

	if added > 0 {
		fmt.Printf("  %s+ %s%d%s package%s added\n",
			colorSymbol+colorAdded, colorBold, added, colorReset,
			func() string {
				if added == 1 {
					return ""
				} else {
					return "s"
				}
			}())
	}

	if removed > 0 {
		fmt.Printf("  %s- %s%d%s package%s removed\n",
			colorSymbol+colorRemoved, colorBold, removed, colorReset,
			func() string {
				if removed == 1 {
					return ""
				} else {
					return "s"
				}
			}())
	}

	if updated > 0 {
		if upgraded > 0 {
			fmt.Printf("  %s↑ %s%d%s package%s upgraded\n",
				colorSymbol+colorUpgraded, colorBold, upgraded, colorReset,
				func() string {
					if upgraded == 1 {
						return ""
					} else {
						return "s"
					}
				}())
		}
		if downgraded > 0 {
			fmt.Printf("  %s↓ %s%d%s package%s downgraded\n",
				colorSymbol+colorDowngraded, colorBold, downgraded, colorReset,
				func() string {
					if downgraded == 1 {
						return ""
					} else {
						return "s"
					}
				}())
		}
		otherChanges := updated - (upgraded + downgraded)
		if otherChanges > 0 {
			fmt.Printf("  %s~ %s%d%s package%s changed\n",
				colorSymbol+colorNeutral, colorBold, otherChanges, colorReset,
				func() string {
					if otherChanges == 1 {
						return ""
					} else {
						return "s"
					}
				}())
		}
	}

	// Perform vulnerability scanning on changed packages if enabled
	if enableVulnScan {
		fmt.Printf("\nScanning for vulnerabilities...\n")
		vulnerabilities, err := queryOSVBatch(ctx, changedPackages)
		if err != nil {
			fmt.Printf("Warning: Vulnerability scanning failed: %v\n", err)
		} else {
			displayVulnerabilities(vulnerabilities)
		}
	}

	return nil
}
