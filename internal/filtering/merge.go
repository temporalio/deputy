package filtering

import (
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Merge combines two scan responses into one aggregate response.
// The base target is preserved; packages, findings, advisories, and warnings
// are merged, and stats are recomputed from the consolidated findings.
func Merge(base, extra *scanv1.ScanResponse) *scanv1.ScanResponse {
	if base == nil {
		return extra
	}
	if extra == nil {
		return base
	}

	// Use later timestamp
	generatedAt := base.GeneratedAt
	if extra.GeneratedAt != nil && (generatedAt == nil || extra.GeneratedAt.AsTime().After(generatedAt.AsTime())) {
		generatedAt = extra.GeneratedAt
	}

	// Merge packages
	packages := append(base.Packages[:len(base.Packages):len(base.Packages)], extra.Packages...)

	// Merge findings
	findings := append(base.Findings[:len(base.Findings):len(base.Findings)], extra.Findings...)

	// Merge advisories
	advisories := mergeAdvisoriesProto(base.Advisories, extra.Advisories)

	// Merge warnings
	warnings := append(base.Warnings[:len(base.Warnings):len(base.Warnings)], extra.Warnings...)

	// Merge policy actions
	policyActions := append(base.PolicyActions[:len(base.PolicyActions):len(base.PolicyActions)], extra.PolicyActions...)

	// Recompute stats from merged findings
	stats := computeStatsProto(findings, advisories)

	return &scanv1.ScanResponse{
		Target:          base.Target,
		GeneratedAt:     generatedAt,
		PackagesScanned: base.PackagesScanned + extra.PackagesScanned,
		Packages:        packages,
		Findings:        findings,
		Advisories:      advisories,
		Stats:           stats,
		PolicyActions:   policyActions,
		Warnings:        warnings,
		ImageInfo:       base.ImageInfo,
		SecretFindings:  base.SecretFindings,
		SecretStats:     base.SecretStats,
		Graph:           base.Graph,
		DockerfileInfo:  base.DockerfileInfo,
	}
}

// mergeAdvisoriesProto merges two advisory maps.
// When both maps contain the same ID, the advisories are merged.
func mergeAdvisoriesProto(base, extra map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
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
