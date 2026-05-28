package cmd

import (
	"context"
	"io"

	"github.com/temporalio/deputy/internal/report"
	"github.com/temporalio/deputy/internal/vulnerability/intel"
)

// enrichVulnerabilities enriches vulnerabilities with EPSS scores and KEV status.
// This function modifies the vulnerabilities in-place.
// It only enriches vulnerabilities that have a CVE identifier.
func enrichVulnerabilities(ctx context.Context, vulns []report.Vulnerability, errW io.Writer) {
	if len(vulns) == 0 {
		return
	}

	// Collect CVE IDs for batch lookup
	cveIDs := make([]string, 0, len(vulns))
	cveToIndex := make(map[string][]int) // CVE -> vulnerability indices

	for i, v := range vulns {
		cveID := v.CVE
		if cveID == "" {
			// Try to find CVE in ID or aliases
			if len(v.ID) >= 4 && v.ID[:4] == "CVE-" {
				cveID = v.ID
			} else {
				for _, alias := range v.Aliases {
					if len(alias) >= 4 && alias[:4] == "CVE-" {
						cveID = alias
						break
					}
				}
			}
		}
		if cveID != "" {
			if _, seen := cveToIndex[cveID]; !seen {
				cveIDs = append(cveIDs, cveID)
			}
			cveToIndex[cveID] = append(cveToIndex[cveID], i)
		}
	}

	if len(cveIDs) == 0 {
		return
	}

	// Batch enrichment with disk caching enabled for CLI
	enricher := intel.NewEnricher(&intel.EnricherConfig{DiskCache: true})
	results := enricher.EnrichBatch(ctx, cveIDs)

	// Apply enrichment results to vulnerabilities
	for cveID, indices := range cveToIndex {
		enrichment, ok := results[cveID]
		if !ok {
			continue
		}

		for _, idx := range indices {
			if enrichment.EPSS != nil {
				vulns[idx].EPSS = enrichment.EPSS
			}
			if enrichment.EPSSPercentile != nil {
				vulns[idx].EPSSPercentile = enrichment.EPSSPercentile
			}
			if enrichment.InKEV != nil {
				vulns[idx].InKEV = enrichment.InKEV
			}
			if enrichment.KEV != nil {
				vulns[idx].KEVDateAdded = enrichment.KEV.DateAdded
				vulns[idx].KEVDueDate = enrichment.KEV.DueDate
				vulns[idx].KEVRequiredAction = enrichment.KEV.RequiredAction
				vulns[idx].KEVKnownRansomwareCampaignUse = enrichment.KEV.KnownRansomwareCampaignUse
			}
		}
	}
}
