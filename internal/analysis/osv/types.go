package osv

import (
	"strings"

	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/picatz/deputy/internal/vulnerability/severity/cvss"
)

// NOTE: This package previously defined type aliases (ManifestReference, AffectedImport, LayerDetails)
// that pointed to canonical types in the dependency and vulnerability packages.
// These aliases have been removed. Import the canonical types directly:
//   - dependency.ManifestRef for manifest file references
//   - vulnerability.AffectedImport for ecosystem-specific import/symbol data
//   - dependency.LayerDetails for container image layer information

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
	ManifestRefs     []dependency.ManifestRef
	AffectedImports  []vulnerability.AffectedImport
	DatabaseSpecific map[string]string
	LayerDetails     *dependency.LayerDetails
}

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
