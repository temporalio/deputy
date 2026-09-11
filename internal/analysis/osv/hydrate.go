package osv

import (
	"context"
	"maps"
	"slices"
	"strings"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/temporalio/deputy/internal/vulnerability"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
)

// HydrateSparseVulnerabilityAliases fills sparse OSV records from richer alias
// records when available. OSV CVE records can omit package and fixed-version
// data that ecosystem-native aliases, such as GO advisories, contain.
func HydrateSparseVulnerabilityAliases(ctx context.Context, client Client, vuln *osvschema.Vulnerability) *osvschema.Vulnerability {
	if vuln == nil || client == nil || !NeedsVulnerabilityAliasHydration(vuln) {
		return vuln
	}

	out := proto.CloneOf(vuln)
	baseID := out.GetId()
	seen := map[string]struct{}{strings.ToUpper(strings.TrimSpace(baseID)): {}}
	for _, alias := range vuln.GetAliases() {
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

	out.Id = baseID
	out.Aliases = removeEqualFold(out.GetAliases(), baseID)
	return out
}

// NeedsVulnerabilityAliasHydration reports whether an OSV record is missing
// fields that commonly exist in alias records: a summary, affected packages,
// or a severity rating (ecosystem databases like the Go vulnerability
// database publish unrated records whose GHSA aliases carry the rating).
// Single-advisory lookups hydrate on any of these so their answer is the full
// picture across the alias set.
func NeedsVulnerabilityAliasHydration(vuln *osvschema.Vulnerability) bool {
	return vuln != nil && (strings.TrimSpace(vuln.GetSummary()) == "" || len(vuln.GetAffected()) == 0 || !hasSeverityRating(vuln))
}

func mergeOSVVulnerability(base *osvschema.Vulnerability, extra *osvschema.Vulnerability) {
	if base == nil || extra == nil {
		return
	}
	// Clone the donor so the merged record owns every message it keeps: alias
	// records come from a shared cache, and appending their pointers would let a
	// later mutation of one advisory show up in another.
	extra = proto.CloneOf(extra)
	if base.GetSchemaVersion() == "" {
		base.SchemaVersion = extra.GetSchemaVersion()
	}
	if strings.TrimSpace(base.GetSummary()) == "" {
		base.Summary = extra.GetSummary()
	}
	if strings.TrimSpace(base.GetDetails()) == "" {
		base.Details = extra.GetDetails()
	}
	// An absent timestamp is nil, not a zero value, so both "is the donor dated
	// at all" and "is the base undated" go through OSVTime rather than reading
	// the fields, which would score a missing date as the Unix epoch and let it
	// win the earliest-published comparison.
	if extraPub := vulnerability.OSVTime(extra.GetPublished()); !extraPub.IsZero() {
		basePub := vulnerability.OSVTime(base.GetPublished())
		if basePub.IsZero() || extraPub.Before(basePub) {
			base.Published = extra.GetPublished()
		}
	}
	if extraMod := vulnerability.OSVTime(extra.GetModified()); !extraMod.IsZero() {
		baseMod := vulnerability.OSVTime(base.GetModified())
		if baseMod.IsZero() || extraMod.After(baseMod) {
			base.Modified = extra.GetModified()
		}
	}
	// Withdrawn deliberately never fills from an alias: withdrawal is a
	// per-record statement, not a property of the alias set. GHSAs are often
	// withdrawn as duplicates while the CVE they alias stays active; copying
	// the alias's timestamp would mark a live advisory withdrawn and let
	// downstream filters suppress a real vulnerability.

	base.Aliases = mergeUniqueEqualFold(base.GetAliases(), []string{extra.GetId()})
	base.Aliases = mergeUniqueEqualFold(base.GetAliases(), extra.GetAliases())
	base.Related = mergeUniqueEqualFold(base.GetRelated(), extra.GetRelated())
	base.Upstream = mergeUniqueEqualFold(base.GetUpstream(), extra.GetUpstream())
	base.Severity = mergeOSVSeverity(base.GetSeverity(), extra.GetSeverity())
	base.Affected = mergeOSVAffected(base.GetAffected(), extra.GetAffected())
	base.References = mergeOSVReferences(base.GetReferences(), extra.GetReferences())
	base.Credits = mergeOSVCredits(base.GetCredits(), extra.GetCredits())
	base.DatabaseSpecific = mergeStructFields(base.GetDatabaseSpecific(), extra.GetDatabaseSpecific())
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

func mergeOSVSeverity(base []*osvschema.Severity, extra []*osvschema.Severity) []*osvschema.Severity {
	return mergeUniqueByKey(base, extra, func(severity *osvschema.Severity) string {
		return severity.GetType().String() + "\x00" + severity.GetScore()
	})
}

func mergeOSVAffected(base []*osvschema.Affected, extra []*osvschema.Affected) []*osvschema.Affected {
	return mergeUniqueByKey(base, extra, protoKey)
}

func mergeOSVReferences(base []*osvschema.Reference, extra []*osvschema.Reference) []*osvschema.Reference {
	return mergeUniqueByKey(base, extra, func(ref *osvschema.Reference) string {
		if strings.TrimSpace(ref.GetUrl()) != "" {
			return ref.GetUrl()
		}
		return ref.GetType().String()
	})
}

func mergeOSVCredits(base []*osvschema.Credit, extra []*osvschema.Credit) []*osvschema.Credit {
	return mergeUniqueByKey(base, extra, protoKey)
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

// protoKey derives a stable identity string for a message so structurally equal
// records dedupe. Marshaling deterministically sorts map keys, which
// [proto.Marshal] does not guarantee on its own.
func protoKey[M proto.Message](msg M) string {
	data, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return prototext.Format(msg)
	}
	return string(data)
}

func mergeStructFields(base *structpb.Struct, extra *structpb.Struct) *structpb.Struct {
	if len(extra.GetFields()) == 0 {
		return base
	}
	fields := maps.Clone(base.GetFields())
	if fields == nil {
		fields = make(map[string]*structpb.Value, len(extra.GetFields()))
	}
	for key, value := range extra.GetFields() {
		if key == "" {
			continue
		}
		if _, ok := fields[key]; ok {
			continue
		}
		fields[key] = value
	}
	return &structpb.Struct{Fields: fields}
}

// hasSeverityRating reports whether the record itself carries any severity
// signal: a CVSS entry or a database_specific severity label.
func hasSeverityRating(vuln *osvschema.Vulnerability) bool {
	if vuln == nil {
		return false
	}
	return len(vuln.GetSeverity()) > 0 || extractDatabaseSeverity(vuln.GetDatabaseSpecific()) != ""
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
		if raw, rawType = resolveSeverity(vuln); raw != "" {
			return raw, rawType
		}
	}
	return "", ""
}
