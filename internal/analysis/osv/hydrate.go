package osv

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// HydrateSparseVulnerabilityAliases fills sparse OSV records from richer alias
// records when available. OSV CVE records can omit package and fixed-version
// data that ecosystem-native aliases, such as GO advisories, contain.
func HydrateSparseVulnerabilityAliases(ctx context.Context, client Client, vuln *osvschema.Vulnerability) *osvschema.Vulnerability {
	if vuln == nil || client == nil || !NeedsVulnerabilityAliasHydration(vuln) {
		return vuln
	}

	out := cloneOSVVulnerability(vuln)
	baseID := out.ID
	seen := map[string]struct{}{strings.ToUpper(strings.TrimSpace(baseID)): {}}
	for _, alias := range vuln.Aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		key := strings.ToUpper(alias)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}

		aliasVuln, err := client.GetVulnByID(ctx, alias)
		if err != nil || aliasVuln == nil {
			continue
		}
		mergeOSVVulnerability(out, aliasVuln)
	}

	out.ID = baseID
	out.Aliases = removeEqualFold(out.Aliases, baseID)
	return out
}

// NeedsVulnerabilityAliasHydration reports whether an OSV record is missing
// fields that commonly exist in alias records: a summary, affected packages,
// or a severity rating (ecosystem databases like the Go vulnerability
// database publish unrated records whose GHSA aliases carry the rating).
// Single-advisory lookups hydrate on any of these so their answer is the full
// picture across the alias set.
func NeedsVulnerabilityAliasHydration(vuln *osvschema.Vulnerability) bool {
	return vuln != nil && (strings.TrimSpace(vuln.Summary) == "" || len(vuln.Affected) == 0 || !hasSeverityRating(vuln))
}

func cloneOSVVulnerability(vuln *osvschema.Vulnerability) *osvschema.Vulnerability {
	if vuln == nil {
		return nil
	}
	out := *vuln
	out.Aliases = slices.Clone(vuln.Aliases)
	out.Related = slices.Clone(vuln.Related)
	out.Upstream = slices.Clone(vuln.Upstream)
	out.Severity = slices.Clone(vuln.Severity)
	out.Affected = slices.Clone(vuln.Affected)
	out.References = slices.Clone(vuln.References)
	out.Credits = slices.Clone(vuln.Credits)
	out.DatabaseSpecific = maps.Clone(vuln.DatabaseSpecific)
	return &out
}

func mergeOSVVulnerability(base *osvschema.Vulnerability, extra *osvschema.Vulnerability) {
	if base == nil || extra == nil {
		return
	}
	if base.SchemaVersion == "" {
		base.SchemaVersion = extra.SchemaVersion
	}
	if strings.TrimSpace(base.Summary) == "" {
		base.Summary = extra.Summary
	}
	if strings.TrimSpace(base.Details) == "" {
		base.Details = extra.Details
	}
	if !extra.Published.IsZero() && (base.Published.IsZero() || extra.Published.Before(base.Published)) {
		base.Published = extra.Published
	}
	if !extra.Modified.IsZero() && (base.Modified.IsZero() || extra.Modified.After(base.Modified)) {
		base.Modified = extra.Modified
	}
	// Withdrawn deliberately never fills from an alias: withdrawal is a
	// per-record statement, not a property of the alias set. GHSAs are often
	// withdrawn as duplicates while the CVE they alias stays active; copying
	// the alias's timestamp would mark a live advisory withdrawn and let
	// downstream filters suppress a real vulnerability.

	base.Aliases = mergeUniqueEqualFold(base.Aliases, []string{extra.ID})
	base.Aliases = mergeUniqueEqualFold(base.Aliases, extra.Aliases)
	base.Related = mergeUniqueEqualFold(base.Related, extra.Related)
	base.Upstream = mergeUniqueEqualFold(base.Upstream, extra.Upstream)
	base.Severity = mergeOSVSeverity(base.Severity, extra.Severity)
	base.Affected = mergeOSVAffected(base.Affected, extra.Affected)
	base.References = mergeOSVReferences(base.References, extra.References)
	base.Credits = mergeOSVCredits(base.Credits, extra.Credits)
	base.DatabaseSpecific = mergeStringAnyMap(base.DatabaseSpecific, extra.DatabaseSpecific)
}

func mergeUniqueEqualFold(base []string, extra []string) []string {
	out := slices.Clone(base)
	for _, value := range extra {
		value = strings.TrimSpace(value)
		if value == "" || slices.ContainsFunc(out, func(existing string) bool {
			return strings.EqualFold(existing, value)
		}) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func removeEqualFold(values []string, target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return values
	}
	out := values[:0]
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), target) {
			continue
		}
		out = append(out, value)
	}
	return out
}

func mergeOSVSeverity(base []osvschema.Severity, extra []osvschema.Severity) []osvschema.Severity {
	return mergeUniqueByKey(base, extra, func(severity osvschema.Severity) string {
		return string(severity.Type) + "\x00" + severity.Score
	})
}

func mergeOSVAffected(base []osvschema.Affected, extra []osvschema.Affected) []osvschema.Affected {
	return mergeUniqueByKey(base, extra, affectedKey)
}

func mergeOSVReferences(base []osvschema.Reference, extra []osvschema.Reference) []osvschema.Reference {
	return mergeUniqueByKey(base, extra, func(ref osvschema.Reference) string {
		if strings.TrimSpace(ref.URL) != "" {
			return ref.URL
		}
		return string(ref.Type)
	})
}

func mergeOSVCredits(base []osvschema.Credit, extra []osvschema.Credit) []osvschema.Credit {
	return mergeUniqueByKey(base, extra, func(credit osvschema.Credit) string {
		data, err := json.Marshal(credit)
		if err != nil {
			return fmt.Sprintf("%#v", credit)
		}
		return string(data)
	})
}

func mergeUniqueByKey[T any](base []T, extra []T, keyFunc func(T) string) []T {
	if len(extra) == 0 {
		return base
	}
	out := slices.Clone(base)
	seen := make(map[string]struct{}, len(base)+len(extra))
	for _, value := range out {
		seen[keyFunc(value)] = struct{}{}
	}
	for _, value := range extra {
		key := keyFunc(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func affectedKey(affected osvschema.Affected) string {
	data, err := json.Marshal(affected)
	if err != nil {
		return fmt.Sprintf("%#v", affected)
	}
	return string(data)
}

func mergeStringAnyMap(base map[string]any, extra map[string]any) map[string]any {
	if len(extra) == 0 {
		return base
	}
	out := maps.Clone(base)
	if out == nil {
		out = make(map[string]any, len(extra))
	}
	for key, value := range extra {
		if key == "" {
			continue
		}
		if _, ok := out[key]; ok {
			continue
		}
		out[key] = value
	}
	return out
}

// hasSeverityRating reports whether the record itself carries any severity
// signal: a CVSS entry or a database_specific severity label.
func hasSeverityRating(vuln *osvschema.Vulnerability) bool {
	if vuln == nil {
		return false
	}
	return len(vuln.Severity) > 0 || extractDatabaseSeverity(vuln.DatabaseSpecific) != ""
}

// SeverityAliasOrder returns the advisory's aliases in the order severity
// resolution should consult them: GHSA aliases first (GitHub reviews and
// rates advisories), then CVE, then everything else, alphabetical within each
// class so resolution is deterministic.
func SeverityAliasOrder(aliases []string) []string {
	out := make([]string, 0, len(aliases))
	seen := map[string]struct{}{}
	for _, alias := range aliases {
		alias = strings.TrimSpace(alias)
		if alias == "" {
			continue
		}
		key := strings.ToUpper(alias)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, alias)
	}
	class := func(id string) int {
		upper := strings.ToUpper(id)
		switch {
		case strings.HasPrefix(upper, "GHSA-"):
			return 0
		case strings.HasPrefix(upper, "CVE-"):
			return 1
		default:
			return 2
		}
	}
	slices.SortFunc(out, func(a, b string) int {
		if c := class(a) - class(b); c != 0 {
			return c
		}
		return strings.Compare(a, b)
	})
	return out
}

// ResolveSeverityFromAliases returns the first severity rating found among
// the given alias records, consulted in SeverityAliasOrder. It returns the
// raw severity value and its type descriptor in the same shape the matched
// record's own rating would have, so callers normalize both identically.
// Empty results mean no alias record carries a rating. This lookup is always
// opt-in: Deputy never substitutes an alias rating silently.
func ResolveSeverityFromAliases(ctx context.Context, client Client, aliases []string) (raw, rawType string) {
	if client == nil {
		return "", ""
	}
	for _, alias := range SeverityAliasOrder(aliases) {
		if err := ctx.Err(); err != nil {
			return "", ""
		}
		vuln, err := client.GetVulnByID(ctx, alias)
		if err != nil || vuln == nil {
			continue
		}
		if raw, rawType = resolveSeverity(*vuln); raw != "" {
			return raw, rawType
		}
	}
	return "", ""
}
