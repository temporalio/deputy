package osv

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/vuln"
	"github.com/picatz/deputy/internal/vulnerability"
)

// ProcessOSVVulnerability converts a raw OSV schema vulnerability into the
// internal Vulnerability representation scoped to a specific package@version.
// It selects a stable preferred identifier (CVE where present, else GO-/GHSA-),
// normalizes timestamp formatting, extracts reference URLs, severity score/type
// preference (favoring CVSS metrics unless GHSA severity is authoritative),
// and aggregates fixed version markers relevant to the matched package.
func ProcessOSVVulnerability(vuln osvschema.Vulnerability, input PkgInput) Vulnerability {
	advisory, finding := ProcessOSVVulnerabilityDomain(vuln, input)
	return flattenAdvisoryFinding(advisory, finding)
}

// ProcessOSVVulnerabilityDomain converts a raw OSV vulnerability into the
// domain Advisory + Finding pair, keeping the advisory metadata separate from
// scan-time occurrence details.
func ProcessOSVVulnerabilityDomain(vuln osvschema.Vulnerability, input PkgInput) (vulnerability.Advisory, vulnerability.Finding) {
	advisory := vulnerability.Advisory{
		ID:      vuln.ID,
		Summary: vuln.Summary,
		Details: vuln.Details,
	}
	finding := vulnerability.Finding{
		AdvisoryID: vuln.ID,
		Dependency: dependency.ID{
			Name:      input.Name,
			Ecosystem: input.Ecosystem,
			PURL:      input.PURL,
		},
		Version:      input.Version,
		Direct:       input.IsDirect,
		Locations:    slices.Clone(input.Locations),
		ManifestRefs: toDomainManifestRefs(input.ManifestRefs),
		LayerDetails: toDomainLayerDetails(input.LayerDetails),
	}

	if !vuln.Published.IsZero() {
		advisory.Published = vuln.Published
	}
	if !vuln.Modified.IsZero() {
		advisory.Modified = vuln.Modified
	}
	if vuln.Aliases != nil {
		advisory.Aliases = slices.Clone(vuln.Aliases)
	}

	// Prefer CVE alias; fallback to GO- or GHSA-
	advisory.CVE = cmp.Or(
		findAliasPrefix(advisory.Aliases, "CVE-"),
		findAliasPrefix(advisory.Aliases, "GO-"),
		findAliasPrefix(advisory.Aliases, "GHSA-"),
	)

	// Resolve severity using priority order
	sev, sevType := resolveSeverity(vuln)
	advisory.Severity = vulnerability.NewSeverity(sev, sevType)

	// References
	if vuln.References != nil {
		for _, ref := range vuln.References {
			if ref.URL != "" {
				advisory.References = append(advisory.References, ref.URL)
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
						advisory.FixedVersions = append(advisory.FixedVersions, e.Fixed)
					}
				}
			}
		}
	}
	if imports := extractGoImports(vuln.Affected, input); len(imports) > 0 {
		finding.AffectedImports = toDomainAffectedImports(imports)
	}
	if ds := extractDatabaseSpecificStrings(vuln.DatabaseSpecific); len(ds) > 0 {
		advisory.DatabaseSpecific = ds
	}
	return advisory, finding
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
	return vuln.MergeAffectedImports(imports)
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

func flattenAdvisoryFinding(advisory vulnerability.Advisory, finding vulnerability.Finding) Vulnerability {
	sev := advisory.Severity.Raw
	if sev == "" && advisory.Severity.Level != vulnerability.SeverityUnknown {
		sev = advisory.Severity.Level.String()
	}
	sevType := advisory.Severity.RawType
	if sevType == "" && advisory.Severity.Type != vulnerability.SeverityTypeUnknown {
		sevType = advisory.Severity.Type.String()
	}

	var published string
	if !advisory.Published.IsZero() {
		published = advisory.Published.Format(time.RFC3339)
	}
	var modified string
	if !advisory.Modified.IsZero() {
		modified = advisory.Modified.Format(time.RFC3339)
	}

	return Vulnerability{
		ID:              advisory.ID,
		Aliases:         slices.Clone(advisory.Aliases),
		Summary:         advisory.Summary,
		Details:         advisory.Details,
		CVE:             advisory.CVE,
		Severity:        sev,
		SeverityType:    sevType,
		Package:         finding.Dependency.Name,
		Version:         finding.Version,
		IsDirect:        finding.Direct,
		Ecosystem:       finding.Dependency.Ecosystem,
		PURL:            finding.Dependency.PURL,
		Published:       published,
		Modified:        modified,
		References:      slices.Clone(advisory.References),
		FixedVersions:   slices.Clone(advisory.FixedVersions),
		Affected:        finding.Affected,
		Locations:       slices.Clone(finding.Locations),
		ManifestRefs:    toLegacyManifestRefs(finding.ManifestRefs),
		AffectedImports: toLegacyAffectedImports(finding.AffectedImports),
		DatabaseSpecific: func() map[string]string {
			if len(advisory.DatabaseSpecific) == 0 {
				return nil
			}
			return maps.Clone(advisory.DatabaseSpecific)
		}(),
		LayerDetails: toVulnLayerDetails(finding.LayerDetails),
	}
}

func toDomainManifestRefs(refs []ManifestReference) []dependency.ManifestRef {
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

func toDomainAffectedImports(imports []AffectedImport) []vulnerability.AffectedImport {
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

func toLegacyManifestRefs(refs []dependency.ManifestRef) []ManifestReference {
	if len(refs) == 0 {
		return nil
	}
	out := make([]ManifestReference, 0, len(refs))
	for _, ref := range refs {
		out = append(out, ManifestReference{
			Path:    ref.Path,
			Manager: ref.Manager,
			Groups:  slices.Clone(ref.Groups),
		})
	}
	return out
}

func toLegacyAffectedImports(imports []vulnerability.AffectedImport) []AffectedImport {
	if len(imports) == 0 {
		return nil
	}
	out := make([]AffectedImport, 0, len(imports))
	for _, imp := range imports {
		out = append(out, AffectedImport{
			Path:    imp.Path,
			Symbols: slices.Clone(imp.Symbols),
		})
	}
	return out
}

// toDomainLayerDetails converts OSV package LayerDetails to the vulnerability domain type.
func toDomainLayerDetails(ld *LayerDetails) *vulnerability.LayerDetails {
	if ld == nil {
		return nil
	}
	return &vulnerability.LayerDetails{
		Index:       ld.Index,
		DiffID:      ld.DiffID,
		ChainID:     ld.ChainID,
		Command:     ld.Command,
		InBaseImage: ld.InBaseImage,
	}
}

// toLegacyLayerDetails converts domain LayerDetails to the legacy OSV type.
func toLegacyLayerDetails(ld *vulnerability.LayerDetails) *LayerDetails {
	if ld == nil {
		return nil
	}
	return &LayerDetails{
		Index:       ld.Index,
		DiffID:      ld.DiffID,
		ChainID:     ld.ChainID,
		Command:     ld.Command,
		InBaseImage: ld.InBaseImage,
	}
}

// toVulnLayerDetails converts domain LayerDetails to vuln.LayerDetails for the Vulnerability struct.
func toVulnLayerDetails(ld *vulnerability.LayerDetails) *vuln.LayerDetails {
	if ld == nil {
		return nil
	}
	return &vuln.LayerDetails{
		Index:       ld.Index,
		DiffID:      ld.DiffID,
		ChainID:     ld.ChainID,
		Command:     ld.Command,
		InBaseImage: ld.InBaseImage,
	}
}
