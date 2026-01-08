package scan

import (
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

func filterAdvisories(findings []vulnerability.Finding, advisories map[string]vulnerabilityv1.Advisory) map[string]vulnerabilityv1.Advisory {
	if len(findings) == 0 {
		return map[string]vulnerabilityv1.Advisory{}
	}
	out := make(map[string]vulnerabilityv1.Advisory, len(advisories))
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
