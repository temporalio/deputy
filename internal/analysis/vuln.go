package analysis

import (
	"strings"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// ProcessOSVVulnerability converts a raw OSV schema vulnerability into the
// internal Vulnerability representation scoped to a specific package@version.
// It selects a stable preferred identifier (CVE where present, else GO-/GHSA-),
// normalizes timestamp formatting, extracts reference URLs, severity score/type
// preference (favoring CVSS metrics unless GHSA severity is authoritative),
// and aggregates fixed version markers relevant to the matched package.
func ProcessOSVVulnerability(vuln osvschema.Vulnerability, packageName, version string, isDirect bool) Vulnerability {
	v := Vulnerability{
		ID:       vuln.ID,
		Summary:  vuln.Summary,
		Details:  vuln.Details,
		Package:  packageName,
		Version:  version,
		IsDirect: isDirect,
	}
	if !vuln.Published.IsZero() {
		v.Published = vuln.Published.Format(time.RFC3339)
	}
	if !vuln.Modified.IsZero() {
		v.Modified = vuln.Modified.Format(time.RFC3339)
	}
	if vuln.Aliases != nil {
		v.Aliases = append([]string{}, vuln.Aliases...)
	}

	// Prefer CVE alias; fallback to GO- or GHSA-
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			v.CVE = alias
			break
		}
	}
	if v.CVE == "" {
		for _, alias := range v.Aliases {
			if strings.HasPrefix(alias, "GO-") || strings.HasPrefix(alias, "GHSA-") {
				v.CVE = alias
				break
			}
		}
	}

	// Severity: prefer CVSS, then GHSA textual in database_specific
	if vuln.Severity != nil {
		for _, s := range vuln.Severity {
			if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
				v.Severity = s.Score
				v.SeverityType = string(s.Type)
				break
			}
		}
	}
	if vuln.DatabaseSpecific != nil {
		if sevVal, ok := vuln.DatabaseSpecific["severity"]; ok {
			if sevStr, ok := sevVal.(string); ok && sevStr != "" {
				isGHSA := strings.HasPrefix(vuln.ID, "GHSA-")
				if v.Severity == "" || isGHSA {
					v.Severity = sevStr
					v.SeverityType = "GHSA"
				}
			}
		}
	}

	// References
	if vuln.References != nil {
		for _, ref := range vuln.References {
			if ref.URL != "" {
				v.References = append(v.References, ref.URL)
			}
		}
	}

	// Fixed versions applicable to this package
	if vuln.Affected != nil {
		for _, a := range vuln.Affected {
			if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, packageName) {
				continue
			}
			for _, r := range a.Ranges {
				for _, e := range r.Events {
					if e.Fixed != "" {
						v.FixedVersions = append(v.FixedVersions, e.Fixed)
					}
				}
			}
		}
	}
	return v
}
