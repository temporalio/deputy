package scan

import (
	"slices"
	"strings"
	"time"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vulnerability"
)

func splitLegacyVulnerabilities(vulns []analysis.Vulnerability) ([]vulnerability.Finding, map[string]vulnerability.Advisory) {
	if len(vulns) == 0 {
		return nil, map[string]vulnerability.Advisory{}
	}
	advisories := make(map[string]vulnerability.Advisory)
	findings := make([]vulnerability.Finding, 0, len(vulns))
	for _, v := range vulns {
		advisory, finding := splitLegacyVulnerability(v)
		if advisory.ID != "" {
			if existing, ok := advisories[advisory.ID]; ok {
				advisories[advisory.ID] = mergeAdvisory(existing, advisory)
			} else {
				advisories[advisory.ID] = advisory
			}
		}
		findings = append(findings, finding)
	}
	return findings, advisories
}

func splitLegacyVulnerability(v analysis.Vulnerability) (vulnerability.Advisory, vulnerability.Finding) {
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
		DatabaseSpecific: cloneStringMap(v.DatabaseSpecific),
	}
	if t := parseTimeRFC3339(v.Published); !t.IsZero() {
		advisory.Published = t
	}
	if t := parseTimeRFC3339(v.Modified); !t.IsZero() {
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
		ManifestRefs:    toDomainManifestRefs(v.ManifestRefs),
		AffectedImports: toDomainAffectedImports(v.AffectedImports),
		Affected:        v.Affected,
	}
	return advisory, finding
}

func mergeAdvisory(base, extra vulnerability.Advisory) vulnerability.Advisory {
	if base.ID == "" {
		base.ID = extra.ID
	}
	if base.Summary == "" {
		base.Summary = extra.Summary
	}
	if base.Details == "" {
		base.Details = extra.Details
	}
	if base.CVE == "" {
		base.CVE = extra.CVE
	}
	base.Aliases = mergeUniqueStrings(base.Aliases, extra.Aliases)
	base.References = mergeUniqueStrings(base.References, extra.References)
	base.FixedVersions = mergeUniqueStrings(base.FixedVersions, extra.FixedVersions)
	base.DatabaseSpecific = mergeStringMap(base.DatabaseSpecific, extra.DatabaseSpecific)

	if base.Published.IsZero() {
		base.Published = extra.Published
	} else if !extra.Published.IsZero() && extra.Published.Before(base.Published) {
		base.Published = extra.Published
	}
	if base.Modified.IsZero() {
		base.Modified = extra.Modified
	} else if !extra.Modified.IsZero() && extra.Modified.After(base.Modified) {
		base.Modified = extra.Modified
	}

	base.Severity = mergeSeverity(base.Severity, extra.Severity)
	return base
}

func mergeSeverity(base, extra vulnerability.Severity) vulnerability.Severity {
	if base.Level == vulnerability.SeverityUnknown {
		return extra
	}
	if extra.Level > base.Level {
		return extra
	}
	if base.Raw == "" && extra.Raw != "" {
		base.Raw = extra.Raw
	}
	if base.RawType == "" && extra.RawType != "" {
		base.RawType = extra.RawType
	}
	if base.Type == vulnerability.SeverityTypeUnknown {
		base.Type = extra.Type
	}
	return base
}

func mergeUniqueStrings(base, extra []string) []string {
	if len(extra) == 0 {
		return base
	}
	out := slices.Clone(base)
	for _, v := range extra {
		if v == "" || slices.Contains(out, v) {
			continue
		}
		out = append(out, v)
	}
	return out
}

func mergeStringMap(base map[string]string, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = map[string]string{}
	}
	for k, v := range extra {
		if k == "" || v == "" {
			continue
		}
		if _, ok := base[k]; ok {
			continue
		}
		base[k] = v
	}
	return base
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func parseTimeRFC3339(raw string) time.Time {
	if strings.TrimSpace(raw) == "" {
		return time.Time{}
	}
	if t, err := time.Parse(time.RFC3339, raw); err == nil {
		return t
	}
	if len(raw) >= 10 {
		if t, err := time.Parse("2006-01-02", raw[:10]); err == nil {
			return t
		}
	}
	return time.Time{}
}

func toDomainManifestRefs(refs []analysis.ManifestReference) []dependency.ManifestRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]dependency.ManifestRef, 0, len(refs))
	for _, ref := range refs {
		out = append(out, dependency.ManifestRef{
			Path:    ref.Path,
			Manager: ref.Manager,
			Groups:  slices.Clone(ref.Groups),
		})
	}
	return out
}

func toDomainAffectedImports(imports []analysis.AffectedImport) []vulnerability.AffectedImport {
	if len(imports) == 0 {
		return nil
	}
	out := make([]vulnerability.AffectedImport, 0, len(imports))
	for _, imp := range imports {
		out = append(out, vulnerability.AffectedImport{
			Path:    imp.Path,
			Symbols: slices.Clone(imp.Symbols),
		})
	}
	return out
}
