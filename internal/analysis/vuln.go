package analysis

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/collections"
)

// ProcessOSVVulnerability converts a raw OSV schema vulnerability into the
// internal Vulnerability representation scoped to a specific package@version.
// It selects a stable preferred identifier (CVE where present, else GO-/GHSA-),
// normalizes timestamp formatting, extracts reference URLs, severity score/type
// preference (favoring CVSS metrics unless GHSA severity is authoritative),
// and aggregates fixed version markers relevant to the matched package.
func ProcessOSVVulnerability(vuln osvschema.Vulnerability, input PkgInput) Vulnerability {
	v := Vulnerability{
		ID:           vuln.ID,
		Summary:      vuln.Summary,
		Details:      vuln.Details,
		Package:      input.Name,
		Version:      input.Version,
		IsDirect:     input.IsDirect,
		Ecosystem:    input.Ecosystem,
		PURL:         input.PURL,
		Locations:    slices.Clone(input.Locations),
		ManifestRefs: slices.Clone(input.ManifestRefs),
	}
	if !vuln.Published.IsZero() {
		v.Published = vuln.Published.Format(time.RFC3339)
	}
	if !vuln.Modified.IsZero() {
		v.Modified = vuln.Modified.Format(time.RFC3339)
	}
	if vuln.Aliases != nil {
		v.Aliases = slices.Clone(vuln.Aliases)
	}

	// Prefer CVE alias; fallback to GO- or GHSA-
	v.CVE = cmp.Or(
		findAliasPrefix(v.Aliases, "CVE-"),
		findAliasPrefix(v.Aliases, "GO-"),
		findAliasPrefix(v.Aliases, "GHSA-"),
	)

	// Resolve severity using priority order
	v.Severity, v.SeverityType = resolveSeverity(vuln)

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
			if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, input.Name) {
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
	if imports := extractGoImports(vuln.Affected, input); len(imports) > 0 {
		v.AffectedImports = imports
	}
	if ds := extractDatabaseSpecificStrings(vuln.DatabaseSpecific); len(ds) > 0 {
		v.DatabaseSpecific = ds
	}
	return v
}

func findAliasPrefix(aliases []string, prefix string) string {
	for _, alias := range aliases {
		if strings.HasPrefix(alias, prefix) {
			return alias
		}
	}
	return ""
}

// resolveSeverity applies a priority-ordered severity resolution strategy:
//  1. For GHSA advisories: GHSA severity (HIGH/CRITICAL) is authoritative and overrides CVSS
//  2. CVSS_V3 score (highest priority for non-GHSA or when GHSA severity is not HIGH/CRITICAL)
//  3. CVSS_V2 score (fallback CVSS)
//  4. Any database_specific severity as final fallback
//
// Returns the severity score/label and its type indicator.
func resolveSeverity(vuln osvschema.Vulnerability) (score, severityType string) {
	isGHSA := strings.HasPrefix(vuln.ID, "GHSA-")
	ghsaSev := extractDatabaseSeverity(vuln.DatabaseSpecific)

	// For GHSA advisories with HIGH/CRITICAL severity, GHSA is authoritative
	if isGHSA && ghsaSev != "" && isHighOrCritical(ghsaSev) {
		return ghsaSev, "GHSA"
	}

	// For non-GHSA advisories or low-severity GHSA, prefer CVSS scores
	if cvss := findCVSSSeverity(vuln.Severity); cvss != nil {
		return cvss.Score, string(cvss.Type)
	}

	// Fallback to database_specific severity
	if ghsaSev != "" {
		if isGHSA || isHighOrCritical(ghsaSev) {
			return ghsaSev, "GHSA"
		}
		return ghsaSev, "database_specific"
	}

	return "", ""
}

// findCVSSSeverity returns the first CVSS severity entry (preferring V3 over V2).
func findCVSSSeverity(severities []osvschema.Severity) *osvschema.Severity {
	for i := range severities {
		s := &severities[i]
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			return s
		}
	}
	return nil
}

// extractDatabaseSeverity extracts the severity string from database_specific metadata.
func extractDatabaseSeverity(dbSpecific map[string]any) string {
	if dbSpecific == nil {
		return ""
	}
	sevVal, ok := dbSpecific["severity"]
	if !ok {
		return ""
	}
	sevStr, ok := sevVal.(string)
	if !ok || sevStr == "" {
		return ""
	}
	return sevStr
}

// isHighOrCritical returns true if the severity string indicates HIGH or CRITICAL level.
func isHighOrCritical(severity string) bool {
	upper := strings.ToUpper(strings.TrimSpace(severity))
	return upper == "CRITICAL" || upper == "HIGH"
}

// extractGoImports pulls Go ecosystem-specific import/symbol metadata from OSV records.
func extractGoImports(affected []osvschema.Affected, input PkgInput) []AffectedImport {
	var imports []AffectedImport
	for _, a := range affected {
		if !matchesPackage(a.Package, input) {
			continue
		}
		raw, ok := a.EcosystemSpecific["imports"]
		if !ok {
			continue
		}
		imports = append(imports, parseImports(raw)...)
	}
	return MergeAffectedImports(imports)
}

func parseImports(raw any) []AffectedImport {
	switch val := raw.(type) {
	case []any:
		return parseImportArray(val)
	case []map[string]any:
		tmp := make([]any, 0, len(val))
		for _, v := range val {
			tmp = append(tmp, v)
		}
		return parseImportArray(tmp)
	default:
		return nil
	}
}

func parseImportArray(items []any) []AffectedImport {
	var imports []AffectedImport
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		pathVal, ok := m["path"].(string)
		if !ok || strings.TrimSpace(pathVal) == "" {
			continue
		}
		pathVal = strings.TrimSpace(pathVal)
		var syms []string
		switch rawSyms := m["symbols"].(type) {
		case []any:
			for _, s := range rawSyms {
				if str, ok := s.(string); ok {
					if trimmed := strings.TrimSpace(str); trimmed != "" {
						syms = append(syms, trimmed)
					}
				}
			}
		case []string:
			for _, s := range rawSyms {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					syms = append(syms, trimmed)
				}
			}
		}
		imports = append(imports, AffectedImport{Path: pathVal, Symbols: syms})
	}
	return imports
}

// MergeAffectedImports deduplicates import paths and symbols while keeping output stable.
// Callers can pass multiple slices (e.g., from aliases) and receive a merged, sorted result.
func MergeAffectedImports(importSets ...[]AffectedImport) []AffectedImport {
	pathMap := make(map[string]collections.Set[string])
	for _, imports := range importSets {
		for _, imp := range imports {
			path := strings.TrimSpace(imp.Path)
			if path == "" {
				continue
			}
			if _, ok := pathMap[path]; !ok {
				pathMap[path] = collections.NewSet[string]()
			}
			if len(imp.Symbols) == 0 {
				continue
			}
			for _, sym := range imp.Symbols {
				s := strings.TrimSpace(sym)
				if s == "" {
					continue
				}
				pathMap[path].Add(s)
			}
		}
	}
	if len(pathMap) == 0 {
		return nil
	}
	paths := slices.Sorted(maps.Keys(pathMap))
	out := make([]AffectedImport, 0, len(paths))
	for _, p := range paths {
		symSet := pathMap[p]
		syms := symSet.Slice()
		slices.Sort(syms)
		out = append(out, AffectedImport{Path: p, Symbols: syms})
	}
	return out
}

// extractDatabaseSpecificStrings normalizes database_specific entries that are plain strings.
// Non-string values are ignored.
func extractDatabaseSpecificStrings(raw map[string]any) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range raw {
		str, ok := v.(string)
		if !ok {
			continue
		}
		str = strings.TrimSpace(str)
		if str == "" {
			continue
		}
		out[k] = str
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
