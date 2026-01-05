package scan

import (
	"maps"
	"slices"
	"time"

	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
)

// filterVulnerabilitiesByPublished filters vulnerabilities based on published timestamp.
func filterVulnerabilitiesByPublished(vulns []osv.Vulnerability, after, before time.Time) []osv.Vulnerability {
	if after.IsZero() && before.IsZero() {
		return vulns
	}
	out := make([]osv.Vulnerability, 0, len(vulns))
	for _, v := range vulns {
		if v.Published == "" {
			if !after.IsZero() {
				continue // can't satisfy 'after' constraint
			}
			out = append(out, v)
			continue
		}
		pt := vulnerability.ParseTimeRFC3339(v.Published)
		if pt.IsZero() {
			if !after.IsZero() {
				continue
			}
			out = append(out, v)
			continue
		}
		if !after.IsZero() && pt.Before(after) {
			continue
		}
		if !before.IsZero() && pt.After(before) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func splitLegacyVulnerabilities(vulns []osv.Vulnerability) ([]vulnerability.Finding, map[string]vulnerability.Advisory) {
	if len(vulns) == 0 {
		return nil, map[string]vulnerability.Advisory{}
	}
	advisories := make(map[string]vulnerability.Advisory)
	findings := make([]vulnerability.Finding, 0, len(vulns))
	for _, v := range vulns {
		advisory, finding := splitLegacyVulnerability(v)
		if advisory.ID != "" {
			if existing, ok := advisories[advisory.ID]; ok {
				advisories[advisory.ID] = vulnerability.MergeAdvisory(existing, advisory)
			} else {
				advisories[advisory.ID] = advisory
			}
		}
		findings = append(findings, finding)
	}
	return findings, advisories
}

func splitLegacyVulnerability(v osv.Vulnerability) (vulnerability.Advisory, vulnerability.Finding) {
	advisory := vulnerability.Advisory{
		ID:      v.ID,
		Aliases: slices.Clone(v.Aliases),
		Summary: v.Summary,
		Details: v.Details,
		CVE:     v.CVE,
		Severity: vulnerability.NewSeverity(
			v.Severity,
			v.SeverityType,
		),
		References:       slices.Clone(v.References),
		FixedVersions:    slices.Clone(v.FixedVersions),
		DatabaseSpecific: maps.Clone(v.DatabaseSpecific),
	}
	if t := vulnerability.ParseTimeRFC3339(v.Published); !t.IsZero() {
		advisory.Published = t
	}
	if t := vulnerability.ParseTimeRFC3339(v.Modified); !t.IsZero() {
		advisory.Modified = t
	}

	finding := vulnerability.Finding{
		AdvisoryID: v.ID,
		Dependency: dependency.ID{
			Name:      v.Package,
			Ecosystem: v.Ecosystem,
			PURL:      v.PURL,
		},
		Version:         v.Version,
		Direct:          v.IsDirect,
		Locations:       slices.Clone(v.Locations),
		ManifestRefs:    cloneManifestRefs(v.ManifestRefs),
		AffectedImports: cloneAffectedImports(v.AffectedImports),
		Affected:        v.Affected,
		LayerDetails:    dependency.CloneLayerDetails(v.LayerDetails),
	}
	return advisory, finding
}


// cloneManifestRefs deep clones a slice of ManifestReference.
// Since osv.ManifestReference is a type alias for dependency.ManifestRef,
// this creates a new slice with cloned Groups fields.
func cloneManifestRefs(refs []osv.ManifestReference) []dependency.ManifestRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]dependency.ManifestRef, len(refs))
	for i, ref := range refs {
		out[i] = dependency.ManifestRef{
			Path:    ref.Path,
			Manager: ref.Manager,
			Groups:  slices.Clone(ref.Groups),
		}
	}
	return out
}

// cloneAffectedImports deep clones a slice of AffectedImport.
// Since osv.AffectedImport is a type alias for vulnerability.AffectedImport,
// this creates a new slice with cloned Symbols fields.
func cloneAffectedImports(imports []osv.AffectedImport) []vulnerability.AffectedImport {
	if len(imports) == 0 {
		return nil
	}
	out := make([]vulnerability.AffectedImport, len(imports))
	for i, imp := range imports {
		out[i] = vulnerability.AffectedImport{
			Path:    imp.Path,
			Symbols: slices.Clone(imp.Symbols),
		}
	}
	return out
}
