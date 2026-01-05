package osv

import (
	"strings"

	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/picatz/deputy/internal/vulnerability/severity/cvss"
)

// Vulnerability represents a security vulnerability found in a software package.
// This is the flattened output format used by the OSV query layer for backward
// compatibility. For new code, prefer using vulnerability.Advisory and vulnerability.Finding.
type Vulnerability struct {
	ID               string
	Aliases          []string
	Summary          string
	Details          string
	CVE              string
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
	Affected         bool
	Locations        []string
	ManifestRefs     []ManifestReference
	AffectedImports  []AffectedImport
	DatabaseSpecific map[string]string
	LayerDetails     *vulnerability.LayerDetails
}

// ManifestReference describes the manifest/lockfile context for a dependency.
// Type alias for dependency.ManifestRef, providing a domain-appropriate name within the osv package.
type ManifestReference = dependency.ManifestRef

// AffectedImport captures ecosystem-specific import path and symbol data.
// Type alias for vulnerability.AffectedImport, providing a domain-appropriate name within the osv package.
type AffectedImport = vulnerability.AffectedImport

// FindBestSeverity chooses the most meaningful severity across related vulns.
// Prefers GHSA textual severities when HIGH/CRITICAL, otherwise the highest CVSS score.
func FindBestSeverity(vulns []Vulnerability) (string, string) {
	if len(vulns) == 0 {
		return "", ""
	}
	var bestScore float64 = -1
	var bestSev, bestType string

	// GHSA textual severities (HIGH/CRITICAL) take precedence.
	for _, v := range vulns {
		if v.SeverityType == "GHSA" {
			up := strings.ToUpper(v.Severity)
			if up == "CRITICAL" {
				return v.Severity, v.SeverityType
			}
			if up == "HIGH" && bestSev == "" {
				bestSev, bestType = v.Severity, v.SeverityType
			}
		}
	}

	// Otherwise pick the highest CVSS score.
	for _, v := range vulns {
		score := cvss.ParseScore(v.Severity)
		if score > bestScore {
			bestScore = score
			bestSev = v.Severity
			bestType = v.SeverityType
		}
	}
	return bestSev, bestType
}
