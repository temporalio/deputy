package filtering

import (
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/ignore"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// FilterUnfixed returns a new response with only findings that have available fixes.
// A finding is considered fixable if its advisory has fixed versions and at least
// one of those versions is >= the current package version.
//
// Stats are recomputed from the filtered findings.
func FilterUnfixed(resp *scanv1.ScanResponse) *scanv1.ScanResponse {
	if resp == nil || len(resp.Findings) == 0 {
		return resp
	}

	filtered := make([]*vulnerabilityv1.Finding, 0, len(resp.Findings))
	for _, f := range resp.Findings {
		if f == nil {
			continue
		}

		// Get advisory - either inline or from map
		adv := f.Advisory
		if adv == nil && resp.Advisories != nil {
			adv = resp.Advisories[f.AdvisoryId]
		}
		if adv == nil {
			continue
		}

		// Skip if no fixed versions
		if len(adv.FixedVersions) == 0 {
			continue
		}

		// Skip if no applicable fix for current version
		version := ""
		if f.Package != nil {
			version = f.Package.Version
		}
		if vulnerability.FindBestFixedVersion(adv.FixedVersions, version) == "" {
			continue
		}

		filtered = append(filtered, f)
	}

	return buildFilteredResponse(resp, filtered)
}

// FilterIgnored returns a new response with findings matching ignore rules removed.
// Returns the filtered response and the count of ignored findings.
//
// Stats are recomputed from the filtered findings.
func FilterIgnored(resp *scanv1.ScanResponse, rules *ignore.Rules) (*scanv1.ScanResponse, int) {
	if resp == nil || rules == nil || len(resp.Findings) == 0 {
		return resp, 0
	}

	filtered := make([]*vulnerabilityv1.Finding, 0, len(resp.Findings))
	ignoredCount := 0

	for _, f := range resp.Findings {
		if f == nil {
			continue
		}

		// Extract package info for matching
		var pkgName, ecosystem string
		if f.Package != nil {
			pkgName = f.Package.Name
			ecosystem = f.Package.Ecosystem
		}

		if rules.ShouldIgnore(f.AdvisoryId, pkgName, ecosystem) {
			ignoredCount++
			continue
		}

		filtered = append(filtered, f)
	}

	if ignoredCount == 0 {
		return resp, 0
	}

	return buildFilteredResponse(resp, filtered), ignoredCount
}

// buildFilteredResponse creates a new response with filtered findings and recomputed stats.
func buildFilteredResponse(original *scanv1.ScanResponse, filtered []*vulnerabilityv1.Finding) *scanv1.ScanResponse {
	// Build new advisories map with only referenced advisories
	newAdvisories := filterAdvisoriesProto(filtered, original.Advisories)

	// Recompute stats
	stats := computeStatsProto(filtered, newAdvisories)

	// Create new response preserving all other fields
	return &scanv1.ScanResponse{
		Target:          original.Target,
		GeneratedAt:     original.GeneratedAt,
		PackagesScanned: original.PackagesScanned,
		Packages:        original.Packages,
		Findings:        filtered,
		Advisories:      newAdvisories,
		Stats:           stats,
		PolicyActions:   original.PolicyActions,
		Warnings:        original.Warnings,
		ImageInfo:       original.ImageInfo,
		SecretFindings:  original.SecretFindings,
		SecretStats:     original.SecretStats,
		Graph:           original.Graph,
		DockerfileInfo:  original.DockerfileInfo,
	}
}

// filterAdvisoriesProto returns a new map containing only advisories referenced by findings.
func filterAdvisoriesProto(findings []*vulnerabilityv1.Finding, advisories map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
	if len(findings) == 0 {
		return map[string]*vulnerabilityv1.Advisory{}
	}

	out := make(map[string]*vulnerabilityv1.Advisory, len(advisories))
	for _, f := range findings {
		if f == nil {
			continue
		}
		if adv, ok := advisories[f.AdvisoryId]; ok {
			out[f.AdvisoryId] = adv
		}
	}
	return out
}

// computeStatsProto recomputes vulnerability stats from proto findings.
func computeStatsProto(findings []*vulnerabilityv1.Finding, advisories map[string]*vulnerabilityv1.Advisory) *vulnerabilityv1.Stats {
	// Convert to internal Finding type for stats computation
	// This reuses the existing, well-tested stats logic
	internalFindings := make([]vulnerability.Finding, 0, len(findings))
	for _, f := range findings {
		if f == nil {
			continue
		}
		internalFindings = append(internalFindings, internalproto.FindingFromProto(f))
	}

	consolidated := vulnerability.ConsolidateAll(internalFindings, advisories)
	return consolidated.Stats
}
