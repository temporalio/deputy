package scan

import (
	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/vulnerability"
)

// MergeResults combines two scan results into one aggregate result.
// The base target is preserved; inventories, findings, advisories, and warnings
// are merged, and stats are recomputed from the consolidated findings.
func MergeResults(base, extra Result) Result {
	merged := base

	if extra.GeneratedAt.After(merged.GeneratedAt) {
		merged.GeneratedAt = extra.GeneratedAt
	}

	merged.PackagesScanned = base.PackagesScanned + extra.PackagesScanned
	merged.Inventory = mergeInventory(base.Inventory, extra.Inventory)
	merged.Findings = append(append([]vulnerability.Finding{}, base.Findings...), extra.Findings...)
	merged.Advisories = mergeAdvisories(base.Advisories, extra.Advisories)
	merged.Warnings = append(append([]string{}, base.Warnings...), extra.Warnings...)
	merged.PolicyActions = append(append([]policy.Action{}, base.PolicyActions...), extra.PolicyActions...)

	cons := vulnerability.Consolidate(merged.Findings, merged.Advisories)
	merged.Stats = vulnerability.StatsFromConsolidated(cons, len(merged.Findings))

	return merged
}

func mergeInventory(base, extra Inventory) Inventory {
	out := Inventory{
		Packages: append(append([]*extractor.Package{}, base.Packages...), extra.Packages...),
		Direct:   nil,
	}
	if len(base.Direct) > 0 || len(extra.Direct) > 0 {
		out.Direct = make(map[string]bool, len(base.Direct)+len(extra.Direct))
		for k, v := range base.Direct {
			out.Direct[k] = v
		}
		for k, v := range extra.Direct {
			if v {
				out.Direct[k] = v
			}
		}
	}
	return out
}

func mergeAdvisories(base, extra map[string]vulnerability.Advisory) map[string]vulnerability.Advisory {
	if len(base) == 0 && len(extra) == 0 {
		return map[string]vulnerability.Advisory{}
	}
	out := make(map[string]vulnerability.Advisory, len(base)+len(extra))
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
