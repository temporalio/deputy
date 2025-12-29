package vuln

import (
	"cmp"
	"slices"
	"strings"

	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/ecosystem"
	"golang.org/x/mod/semver"
)

var trustedAliasPrefixes = []string{
	"CVE-",
	"GO-",
	"GHSA-",
	"PYSEC-",
	"RUBYSEC-",
	"RUSTSEC-",
	"MSRC-",
	"GSD-",
}

// ID priority constants for sorting vulnerability IDs.
// Lower numbers indicate higher priority when selecting the primary ID.
const (
	// IDPriorityCVE is the highest priority for CVE identifiers.
	IDPriorityCVE = 1
	// IDPriorityGO is the priority for Go vulnerability database identifiers.
	IDPriorityGO = 2
	// IDPriorityGHSA is the priority for GitHub Security Advisory identifiers.
	IDPriorityGHSA = 3
	// IDPriorityOther is the default priority for other identifier types.
	IDPriorityOther = 4
)

// HasCommonAlias reports if two alias sets intersect.
func HasCommonAlias(a1, a2 []string) bool {
	set := collections.NewSet[string]()
	for _, a := range a1 {
		set.Add(a)
	}
	for _, a := range a2 {
		if set.Has(a) {
			return true
		}
	}
	return false
}

// getIDPriority assigns a numeric priority to vulnerability IDs for sorting.
// Lower numbers indicate higher priority (CVE > GO > GHSA > others).
func getIDPriority(id string) int {
	if strings.HasPrefix(id, "CVE-") {
		return IDPriorityCVE
	}
	if strings.HasPrefix(id, "GO-") {
		return IDPriorityGO
	}
	if strings.HasPrefix(id, "GHSA-") {
		return IDPriorityGHSA
	}
	return IDPriorityOther
}

// isTrustedAlias checks if a vulnerability ID belongs to a known, trusted
// numbering authority (e.g., CVE, GHSA, GO).
func isTrustedAlias(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" {
		return false
	}
	upper := strings.ToUpper(id)
	for _, prefix := range trustedAliasPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// filterTrustedAliases separates trusted aliases from others and counts hidden ones.
func filterTrustedAliases(ids []string) (preferred []string, hidden int) {
	if len(ids) == 0 {
		return nil, 0
	}
	preferred = make([]string, 0, len(ids))
	for _, id := range ids {
		if isTrustedAlias(id) {
			preferred = append(preferred, id)
			continue
		}
		hidden++
	}
	return preferred, hidden
}

// findBestPrimaryIDFromGroup selects the best primary ID for a group of vulnerabilities.
func findBestPrimaryIDFromGroup(vs []Vulnerability) string {
	// Estimate capacity: each vuln has 1 ID + average ~2 aliases
	estimatedCap := len(vs) * 3
	all := make([]string, 0, estimatedCap)
	for _, v := range vs {
		all = append(all, v.ID)
		all = append(all, v.Aliases...)
	}
	seen := collections.NewSetWithCapacity[string](len(all))
	uniq := make([]string, 0, len(all))
	for _, id := range all {
		if seen.Add(id) {
			uniq = append(uniq, id)
		}
	}
	best := ""
	prio := 999
	for _, id := range uniq {
		p := getIDPriority(id)
		if p < prio {
			prio = p
			best = id
		}
	}
	if best == "" && len(vs) > 0 {
		best = vs[0].ID
	}
	return best
}

// collectUniqueIDs gathers all IDs from vulnerabilities, deduplicates them, and returns
// unique IDs, secondary IDs (excluding primary), and hidden alias count.
func collectUniqueIDs(primaryID string, vulns []Vulnerability) (uniqAll, secondaries []string, hiddenAliases int) {
	// Estimate capacity: 1 primary + each vuln has 1 ID + ~2 aliases on average
	estimatedCap := 1 + len(vulns)*3
	allIDs := make([]string, 0, estimatedCap)
	allIDs = append(allIDs, primaryID)
	for _, v := range vulns {
		allIDs = append(allIDs, v.ID)
		allIDs = append(allIDs, v.Aliases...)
	}

	seen := collections.NewSetWithCapacity[string](len(allIDs))
	uniqAll = make([]string, 0, len(allIDs))
	for _, id := range allIDs {
		if seen.Add(id) {
			uniqAll = append(uniqAll, id)
		}
	}

	secondaries = make([]string, 0, len(uniqAll)-1)
	for _, id := range uniqAll {
		if id != primaryID {
			secondaries = append(secondaries, id)
		}
	}

	var preferredSecondaries []string
	preferredSecondaries, hiddenAliases = filterTrustedAliases(secondaries)
	return uniqAll, preferredSecondaries, hiddenAliases
}

// mergeStringSlices combines string slices from vulnerabilities using a field extractor.
func mergeStringSlices(vulns []Vulnerability, extract func(Vulnerability) []string) []string {
	seen := collections.NewSet[string]()
	var result []string
	for _, v := range vulns {
		for _, s := range extract(v) {
			if seen.Add(s) {
				result = append(result, s)
			}
		}
	}
	return result
}

// mergeManifestRefs combines manifest references from vulnerabilities, deduplicating by manager|path.
func mergeManifestRefs(vulns []Vulnerability) []ManifestReference {
	manifestMap := map[string]ManifestReference{}
	for _, v := range vulns {
		for _, ref := range v.ManifestRefs {
			key := ref.Manager + "|" + ref.Path
			existing, ok := manifestMap[key]
			if !ok {
				existing = ManifestReference{Path: ref.Path, Manager: ref.Manager}
			}
			groupSet := collections.NewSet[string]()
			for _, g := range existing.Groups {
				groupSet.Add(g)
			}
			for _, g := range ref.Groups {
				if groupSet.Add(g) {
					existing.Groups = append(existing.Groups, g)
				}
			}
			manifestMap[key] = existing
		}
	}

	refs := make([]ManifestReference, 0, len(manifestMap))
	for _, ref := range manifestMap {
		refs = append(refs, ref)
	}
	slices.SortFunc(refs, func(a, b ManifestReference) int {
		if c := cmp.Compare(a.Manager, b.Manager); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
	})
	return refs
}

// mergeDatabaseSpecific combines database-specific fields from vulnerabilities.
func mergeDatabaseSpecific(vulns []Vulnerability) map[string]string {
	result := map[string]string{}
	for _, v := range vulns {
		for k, val := range v.DatabaseSpecific {
			k = strings.TrimSpace(k)
			if k == "" || val == "" {
				continue
			}
			if _, ok := result[k]; !ok {
				result[k] = val
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// createConsolidatedVulnerability merges a group of vulnerabilities into a single consolidated record.
func createConsolidatedVulnerability(primaryID string, vulns []Vulnerability) ConsolidatedVulnerability {
	if len(vulns) == 0 {
		return ConsolidatedVulnerability{}
	}
	base := vulns[0]

	uniqAll, secondaries, hiddenAliases := collectUniqueIDs(primaryID, vulns)

	fixed := mergeStringSlices(vulns, func(v Vulnerability) []string { return v.FixedVersions })
	refs := mergeStringSlices(vulns, func(v Vulnerability) []string { return v.References })
	locations := mergeStringSlices(vulns, func(v Vulnerability) []string { return v.Locations })
	slices.Sort(locations)

	manifestRefs := mergeManifestRefs(vulns)

	var importSets [][]AffectedImport
	for _, v := range vulns {
		if len(v.AffectedImports) > 0 {
			importSets = append(importSets, v.AffectedImports)
		}
	}

	bestSev, bestSevType := FindBestSeverity(vulns)

	return ConsolidatedVulnerability{
		PrimaryID:        primaryID,
		SecondaryIDs:     secondaries,
		AllIDs:           uniqAll,
		HiddenAliasCount: hiddenAliases,
		Summary:          base.Summary,
		Details:          base.Details,
		Severity:         bestSev,
		SeverityType:     bestSevType,
		Package:          base.Package,
		Version:          base.Version,
		IsDirect:         base.IsDirect,
		Ecosystem:        base.Ecosystem,
		PURL:             base.PURL,
		Published:        base.Published,
		Modified:         base.Modified,
		References:       refs,
		FixedVersions:    fixed,
		RelatedCount:     len(vulns),
		Locations:        locations,
		ManifestRefs:     manifestRefs,
		AffectedImports:  MergeAffectedImports(importSets...),
		DatabaseSpecific: mergeDatabaseSpecific(vulns),
	}
}

// ConsolidateVulnerabilities groups related vulnerabilities using aliases.
// Vulnerabilities sharing any common alias (including their own ID) are merged.
// Uses union-find for O(n × α(n)) ≈ O(n) complexity instead of O(n²).
func ConsolidateVulnerabilities(vulns []Vulnerability) []ConsolidatedVulnerability {
	if len(vulns) == 0 {
		return nil
	}

	// Union-find parent array: parent[i] is the parent of vulnerability i.
	// Initially each vulnerability is its own parent.
	parent := make([]int, len(vulns))
	for i := range parent {
		parent[i] = i
	}

	// find returns the root of the set containing x, with path compression.
	var find func(x int) int
	find = func(x int) int {
		if parent[x] != x {
			parent[x] = find(parent[x])
		}
		return parent[x]
	}

	// union merges the sets containing x and y.
	union := func(x, y int) {
		px, py := find(x), find(y)
		if px != py {
			parent[px] = py
		}
	}

	// Build alias → first vulnerability index map.
	// When we see the same alias again, union those vulnerabilities.
	aliasToIdx := make(map[string]int)
	for i, v := range vulns {
		// Include the vulnerability's own ID as an alias for grouping.
		allAliases := append([]string{v.ID}, v.Aliases...)
		for _, alias := range allAliases {
			if prev, ok := aliasToIdx[alias]; ok {
				union(prev, i)
			} else {
				aliasToIdx[alias] = i
			}
		}
	}

	// Collect vulnerabilities into groups by their root.
	rootToGroup := make(map[int][]Vulnerability)
	for i, v := range vulns {
		root := find(i)
		rootToGroup[root] = append(rootToGroup[root], v)
	}

	// Convert groups to consolidated vulnerabilities.
	out := make([]ConsolidatedVulnerability, 0, len(rootToGroup))
	for _, g := range rootToGroup {
		allAffected := true
		for _, v := range g {
			if !v.Affected {
				allAffected = false
				break
			}
		}
		if !allAffected {
			continue
		}
		pid := findBestPrimaryIDFromGroup(g)
		out = append(out, createConsolidatedVulnerability(pid, g))
	}
	return out
}

// incrementSeverityStats updates the stats counters based on severity string and type.
func incrementSeverityStats(stats *VulnerabilityStats, severity, severityType string) {
	if severity == "" {
		stats.UnknownSev++
		return
	}

	// For GHSA, try textual severity first using ParseSeverity
	if severityType == "GHSA" {
		if sev := ParseSeverity(severity); sev != SeverityUnknown {
			incrementStatsBySeverity(stats, sev)
			return
		}
	}

	// Fall back to CVSS score parsing
	sev := SeverityFromCVSS(ParseCVSSScore(severity))
	incrementStatsBySeverity(stats, sev)
}

// incrementStatsBySeverity updates the appropriate stats counter for the given severity level.
func incrementStatsBySeverity(stats *VulnerabilityStats, sev Severity) {
	switch sev {
	case SeverityCritical:
		stats.CriticalSev++
	case SeverityHigh:
		stats.HighSeverity++
	case SeverityMedium:
		stats.MedSeverity++
	case SeverityLow:
		stats.LowSeverity++
	default:
		stats.UnknownSev++
	}
}

// CategorizeVulnerabilities computes stats after consolidating by alias.
func CategorizeVulnerabilities(vs []Vulnerability) VulnerabilityStats {
	cons := ConsolidateVulnerabilities(vs)
	stats := VulnerabilityStats{TotalVulns: len(cons), UniqueVulns: len(cons), DuplicatesFound: len(vs) - len(cons)}
	for _, v := range cons {
		if strings.HasPrefix(v.PrimaryID, "CVE-") {
			stats.CVECount++
		}
		if v.IsDirect {
			stats.DirectDeps++
		} else {
			stats.IndirectDeps++
		}
		if len(v.FixedVersions) > 0 {
			if FindBestFixedVersion(v.FixedVersions, v.Version) != "" {
				stats.FixAvailable++
			}
		}
		incrementSeverityStats(&stats, v.Severity, v.SeverityType)
	}
	return stats
}

// FindBestFixedVersion selects the smallest applicable fix >= current.
func FindBestFixedVersion(fixed []string, current string) string {
	if len(fixed) == 0 {
		return ""
	}
	cur := normalizeGoVersion(current)
	cands := make([]string, 0, len(fixed))
	for _, f := range fixed {
		nf := normalizeGoVersion(f)
		if semver.Compare(nf, cur) >= 0 {
			cands = append(cands, nf)
		}
	}
	if len(cands) == 0 {
		return ""
	}
	// Sort candidates ascending and return the smallest (first) one
	slices.SortFunc(cands, semver.Compare)
	return cands[0]
}

// normalizeGoVersion ensures the Go version string starts with "v".
// Delegates to the canonical implementation in the ecosystem package.
func normalizeGoVersion(v string) string {
	return ecosystem.Go.NormalizeVersion(v)
}
