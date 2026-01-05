package osv

import (
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/picatz/deputy/internal/vulnerability/severity"
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
	values := make([]severity.Value, 0, len(vulns))
	for _, v := range vulns {
		values = append(values, severity.FromRaw(v.Severity, v.SeverityType))
	}
	return severity.SelectBest(values).Strings()
}
