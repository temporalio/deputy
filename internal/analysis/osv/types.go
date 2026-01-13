package osv

import (
	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/vulnerability/severity"
)

// NOTE: This package previously defined type aliases (ManifestReference, AffectedImport, LayerDetails)
// that pointed to canonical types in the dependency and vulnerability packages.
// These aliases have been removed. Import the proto types directly:
//   - dependencyv1.ManifestRef for manifest file references
//   - vulnerabilityv1.AffectedImport for ecosystem-specific import/symbol data
//   - containerv1.LayerDetails for container image layer information

// Vulnerability represents a security vulnerability found in a software package.
// This is the flattened output format used by the OSV query layer for backward
// compatibility. For new code, prefer using vulnerabilityv1.Advisory and vulnerability.Finding.
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
	ManifestRefs     []dependencyv1.ManifestRef
	AffectedImports  []vulnerabilityv1.AffectedImport
	DatabaseSpecific map[string]string
	LayerDetails     *containerv1.LayerDetails
}

// FindBestSeverity chooses the most meaningful severity across related vulns.
// Prefers GHSA textual severities when HIGH/CRITICAL, otherwise the highest CVSS score.
func FindBestSeverity(vulns []Vulnerability) (string, string) {
	if len(vulns) == 0 {
		return "", ""
	}
	values := make([]*vulnerabilityv1.Severity, 0, len(vulns))
	for _, v := range vulns {
		values = append(values, severity.FromRaw(v.Severity, v.SeverityType))
	}
	return severity.SelectBestStrings(values)
}
