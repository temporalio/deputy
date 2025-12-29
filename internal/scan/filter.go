package scan

import (
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
	cons := vulnerability.Consolidate(result.Findings, result.Advisories)
	result.Stats = vulnerability.StatsFromConsolidated(cons, len(result.Findings))
	return result
}

func filterAdvisories(findings []vulnerability.Finding, advisories map[string]vulnerability.Advisory) map[string]vulnerability.Advisory {
	if len(findings) == 0 {
		return map[string]vulnerability.Advisory{}
	}
	out := make(map[string]vulnerability.Advisory, len(advisories))
	for _, f := range findings {
		if adv, ok := advisories[f.AdvisoryID]; ok {
			out[f.AdvisoryID] = adv
		}
	}
	return out
}
