package osv

import (
	"cmp"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/vulnerability"
	"github.com/temporalio/deputy/internal/vulnerability/severity"
	"github.com/temporalio/deputy/internal/vulnerability/weakness/cwe"
	"google.golang.org/protobuf/types/known/structpb"
)

// ProcessOSVVulnerability converts a raw OSV schema vulnerability into the
// internal Vulnerability representation scoped to a specific package@version.
// It selects a stable preferred identifier (CVE where present, else GO-/GHSA-),
// normalizes timestamp formatting, extracts reference URLs, severity score/type
// preference (favoring CVSS metrics unless GHSA severity is authoritative),
// and aggregates fixed version markers relevant to the matched package.
func ProcessOSVVulnerability(vuln *osvschema.Vulnerability, input PkgInput) Vulnerability {
	advisory, finding := ProcessOSVVulnerabilityDomain(vuln, input)
	return flattenAdvisoryFinding(advisory, finding)
}

// VulnerabilitiesFromProto flattens proto findings (plus their advisory
// records) back into the flat records the proxy layer consumes, the inverse of
// VulnerabilitiesToFindings. Each finding's inline advisory is preferred,
// falling back to the advisories map by ID, so results from any advisory
// source (built-in or plugin) flatten identically.
func VulnerabilitiesFromProto(findings []*vulnerabilityv1.Finding, advisories map[string]*vulnerabilityv1.Advisory) []Vulnerability {
	out := make([]Vulnerability, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		adv := f.GetAdvisory()
		if adv == nil {
			adv = advisories[f.GetAdvisoryId()]
		}
		if adv == nil {
			adv = &vulnerabilityv1.Advisory{Id: f.GetAdvisoryId()}
		}
		out = append(out, flattenAdvisoryFinding(adv, vulnerability.FindingFromProto(f)))
	}
	return out
}

// ProcessOSVVulnerabilityDomain converts a raw OSV vulnerability into the
// domain Advisory + Finding pair, keeping the advisory metadata separate from
// scan-time occurrence details.
func ProcessOSVVulnerabilityDomain(vuln *osvschema.Vulnerability, input PkgInput) (*vulnerabilityv1.Advisory, vulnerability.Finding) {
	advisory := &vulnerabilityv1.Advisory{
		Id:      vuln.GetId(),
		Summary: vuln.GetSummary(),
		Details: vuln.GetDetails(),
	}
	finding := vulnerability.Finding{
		AdvisoryID: vuln.GetId(),
		Dependency: dependency.ID{
			Name:      input.Name,
			Ecosystem: input.Ecosystem,
			PURL:      input.PURL,
		},
		Version:      input.Version,
		Direct:       input.IsDirect,
		Locations:    slices.Clone(input.Locations),
		ManifestRefs: dependency.CloneManifestRefs(input.ManifestRefs),
		LayerDetails: dependency.CloneLayerDetails(input.LayerDetails),
	}

	vulnerability.SetAdvisoryPublished(advisory, vulnerability.OSVTime(vuln.GetPublished()))
	vulnerability.SetAdvisoryModified(advisory, vulnerability.OSVTime(vuln.GetModified()))
	if vuln.GetAliases() != nil {
		advisory.Aliases = slices.Clone(vuln.GetAliases())
	}

	// Prefer CVE alias; fallback to GO- or GHSA-
	advisory.Cve = cmp.Or(
		findAliasPrefix(advisory.Aliases, "CVE-"),
		findAliasPrefix(advisory.Aliases, "GO-"),
		findAliasPrefix(advisory.Aliases, "GHSA-"),
	)

	// Resolve severity using priority order
	sev, sevType := resolveSeverity(vuln)
	advisory.Severity = vulnerability.NewSeverity(sev, sevType)

	// References
	for _, ref := range vuln.GetReferences() {
		if ref.GetUrl() != "" {
			advisory.References = append(advisory.References, ref.GetUrl())
		}
	}

	// Fixed versions applicable to this package, plus per-module fixes for every
	// affected package. The latter preserves fixes that live on a sibling module
	// (e.g., a Go major-version migration github.com/foo -> github.com/foo/v2)
	// so remediation can recommend a migration instead of an impossible in-place
	// upgrade. See [vulnerability.Consolidated.PackageFixes].
	byModule := map[string]*vulnerabilityv1.PackageFix{}
	var moduleOrder []string
	for _, a := range vuln.GetAffected() {
		var fixes []string
		for _, r := range a.GetRanges() {
			for _, e := range r.GetEvents() {
				if e.GetFixed() != "" {
					fixes = append(fixes, e.GetFixed())
				}
			}
		}
		if len(fixes) == 0 {
			continue
		}
		name := a.GetPackage().GetName()
		// Fixes on this dependency's own module path drive in-place upgrades.
		if name == "" || strings.EqualFold(name, input.Name) {
			advisory.FixedVersions = append(advisory.FixedVersions, fixes...)
		}
		// Record fixes per module path (including sibling modules) so the
		// resolver can discover migration targets.
		if name == "" {
			continue
		}
		pf, ok := byModule[name]
		if !ok {
			pf = &vulnerabilityv1.PackageFix{Module: name, Ecosystem: a.GetPackage().GetEcosystem()}
			byModule[name] = pf
			moduleOrder = append(moduleOrder, name)
		}
		pf.FixedVersions = append(pf.FixedVersions, fixes...)
	}
	for _, m := range moduleOrder {
		advisory.PackageFixes = append(advisory.PackageFixes, byModule[m])
	}
	if imports := extractGoImports(vuln.GetAffected(), input); len(imports) > 0 {
		finding.AffectedImports = vulnerability.CloneAffectedImports(imports)
	}
	if ds := extractDatabaseSpecificStrings(vuln.GetDatabaseSpecific()); len(ds) > 0 {
		advisory.DatabaseSpecific = ds
	}
	// Extract CWEs from database_specific.cwe_ids (GHSA records)
	if cwes := cwe.ExtractFromDatabaseSpecific(vuln.GetDatabaseSpecific().AsMap()); len(cwes) > 0 {
		vulnerability.SetAdvisoryCWEs(advisory, cwes)
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
func resolveSeverity(vuln *osvschema.Vulnerability) (score, severityType string) {
	isGHSA := strings.HasPrefix(vuln.GetId(), "GHSA-")
	ghsaSev := extractDatabaseSeverity(vuln.GetDatabaseSpecific())

	// For GHSA advisories with HIGH/CRITICAL severity, GHSA is authoritative
	if isGHSA && ghsaSev != "" && isHighOrCritical(ghsaSev) {
		return ghsaSev, "GHSA"
	}

	// For non-GHSA advisories or low-severity GHSA, prefer CVSS scores
	if cvss := findCVSSSeverity(vuln.GetSeverity()); cvss != nil {
		return cvss.GetScore(), cvss.GetType().String()
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
func findCVSSSeverity(severities []*osvschema.Severity) *osvschema.Severity {
	for _, s := range severities {
		if s.GetType() == osvschema.Severity_CVSS_V3 || s.GetType() == osvschema.Severity_CVSS_V2 {
			return s
		}
	}
	return nil
}

// extractDatabaseSeverity extracts the severity string from database_specific metadata.
// Non-string severity values are ignored, matching the schema's expectation.
func extractDatabaseSeverity(dbSpecific *structpb.Struct) string {
	return dbSpecific.GetFields()["severity"].GetStringValue()
}

// isHighOrCritical returns true if the severity string indicates HIGH or CRITICAL level.
func isHighOrCritical(severity string) bool {
	upper := strings.ToUpper(strings.TrimSpace(severity))
	return upper == "CRITICAL" || upper == "HIGH"
}

// extractGoImports pulls Go ecosystem-specific import/symbol metadata from OSV records.
func extractGoImports(affected []*osvschema.Affected, input PkgInput) []vulnerabilityv1.AffectedImport {
	var imports []vulnerabilityv1.AffectedImport
	for _, a := range affected {
		if !matchesPackage(a.GetPackage(), input) {
			continue
		}
		raw, ok := a.GetEcosystemSpecific().AsMap()["imports"]
		if !ok {
			continue
		}
		imports = append(imports, parseImports(raw)...)
	}
	return vulnerability.MergeAffectedImports(imports)
}

func parseImports(raw any) []vulnerabilityv1.AffectedImport {
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

func parseImportArray(items []any) []vulnerabilityv1.AffectedImport {
	var imports []vulnerabilityv1.AffectedImport
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
		imports = append(imports, vulnerabilityv1.AffectedImport{Path: pathVal, Symbols: syms})
	}
	return imports
}

// extractDatabaseSpecificStrings normalizes database_specific entries that are plain strings.
// Non-string values are ignored.
func extractDatabaseSpecificStrings(raw *structpb.Struct) map[string]string {
	fields := raw.GetFields()
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range fields {
		if _, ok := v.GetKind().(*structpb.Value_StringValue); !ok {
			continue
		}
		str := strings.TrimSpace(v.GetStringValue())
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

func flattenAdvisoryFinding(advisory *vulnerabilityv1.Advisory, finding vulnerability.Finding) Vulnerability {
	var sev, sevType string
	if advisory.Severity != nil {
		sev = advisory.Severity.Raw
		if sev == "" && advisory.Severity.Level != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED {
			sev = severity.LevelString(advisory.Severity.Level)
		}
		sevType = advisory.Severity.RawType
		if sevType == "" && advisory.Severity.Type != vulnerabilityv1.SeverityType_SEVERITY_TYPE_UNSPECIFIED {
			sevType = advisory.Severity.Type.String()
		}
	}

	var published string
	if pub := vulnerability.AdvisoryPublished(advisory); !pub.IsZero() {
		published = pub.Format(time.RFC3339)
	}
	var modified string
	if mod := vulnerability.AdvisoryModified(advisory); !mod.IsZero() {
		modified = mod.Format(time.RFC3339)
	}

	return Vulnerability{
		ID:              advisory.Id,
		Aliases:         slices.Clone(advisory.Aliases),
		Summary:         advisory.Summary,
		Details:         advisory.Details,
		CVE:             advisory.Cve,
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
		PackageFixes:    vulnerability.ClonePackageFixes(advisory.PackageFixes),
		Affected:        finding.Affected,
		Locations:       slices.Clone(finding.Locations),
		ManifestRefs:    dependency.CloneManifestRefs(finding.ManifestRefs),
		AffectedImports: vulnerability.CloneAffectedImports(finding.AffectedImports),
		DatabaseSpecific: func() map[string]string {
			if len(advisory.DatabaseSpecific) == 0 {
				return nil
			}
			return maps.Clone(advisory.DatabaseSpecific)
		}(),
		LayerDetails: dependency.CloneLayerDetails(finding.LayerDetails),
	}
}
