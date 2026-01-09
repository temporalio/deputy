package scanning

import (
	"github.com/google/osv-scalibr/extractor"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/ignore"
	"github.com/picatz/deputy/internal/vulnerability"
)

// FilterUnfixed drops findings without applicable fixes and recomputes stats.
func FilterUnfixed(result Result) Result {
	if len(result.Findings) == 0 {
		return result
	}
	filtered := make([]vulnerability.Finding, 0, len(result.Findings))
	for _, f := range result.Findings {
		adv, ok := result.Advisories[f.AdvisoryID]
		if !ok {
			continue
		}
		if len(adv.FixedVersions) == 0 {
			continue
		}
		if vulnerability.FindBestFixedVersion(adv.FixedVersions, f.Version) == "" {
			continue
		}
		filtered = append(filtered, f)
	}
	result.Findings = filtered
	result.Advisories = filterAdvisories(filtered, result.Advisories)
	result.Stats = vulnerability.ConsolidateAll(result.Findings, result.Advisories).Stats
	return result
}

func filterAdvisories(findings []vulnerability.Finding, advisories map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
	if len(findings) == 0 {
		return map[string]*vulnerabilityv1.Advisory{}
	}
	out := make(map[string]*vulnerabilityv1.Advisory, len(advisories))
	for _, f := range findings {
		if adv, ok := advisories[f.AdvisoryID]; ok {
			out[f.AdvisoryID] = adv
		}
	}
	return out
}

// FilterIgnored drops findings matching ignore rules and recomputes stats.
// Returns the filtered result and count of ignored findings.
func FilterIgnored(result Result, rules *ignore.Rules) (Result, int) {
	if rules == nil || len(result.Findings) == 0 {
		return result, 0
	}
	filtered := make([]vulnerability.Finding, 0, len(result.Findings))
	ignoredCount := 0
	for _, f := range result.Findings {
		if rules.ShouldIgnore(f.AdvisoryID, f.Dependency.Name, f.Dependency.Ecosystem) {
			ignoredCount++
			continue
		}
		filtered = append(filtered, f)
	}
	if ignoredCount == 0 {
		return result, 0
	}
	result.Findings = filtered
	result.Advisories = filterAdvisories(filtered, result.Advisories)
	result.Stats = vulnerability.ConsolidateAll(result.Findings, result.Advisories).Stats
	return result, ignoredCount
}

// MergeResults combines two scan results into one aggregate result.
// The base target is preserved; packages, findings, advisories, and warnings
// are merged, and stats are recomputed from the consolidated findings.
func MergeResults(base, extra Result) Result {
	merged := base

	if extra.GeneratedAt.After(merged.GeneratedAt) {
		merged.GeneratedAt = extra.GeneratedAt
	}

	merged.Packages = append(append([]*extractor.Package{}, base.Packages...), extra.Packages...)
	merged.Direct = mergeDirect(base.Direct, extra.Direct)
	merged.Findings = append(append([]vulnerability.Finding{}, base.Findings...), extra.Findings...)
	merged.Advisories = mergeAdvisories(base.Advisories, extra.Advisories)
	merged.Warnings = append(append([]string{}, base.Warnings...), extra.Warnings...)

	merged.Stats = vulnerability.ConsolidateAll(merged.Findings, merged.Advisories).Stats

	return merged
}

func mergeDirect(base, extra map[string]bool) map[string]bool {
	if len(base) == 0 && len(extra) == 0 {
		return nil
	}
	out := make(map[string]bool, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		if v {
			out[k] = v
		}
	}
	return out
}

func mergeAdvisories(base, extra map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
	if len(base) == 0 && len(extra) == 0 {
		return map[string]*vulnerabilityv1.Advisory{}
	}
	out := make(map[string]*vulnerabilityv1.Advisory, len(base)+len(extra))
	for id, adv := range base {
		out[id] = adv
	}
	for id, adv := range extra {
		if existing, ok := out[id]; ok {
			out[id] = vulnerability.MergeAdvisory(existing, adv)
			continue
		}
		out[id] = adv
	}
	return out
}
