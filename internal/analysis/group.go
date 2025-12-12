package analysis

import (
	"sort"
	"strings"

	"github.com/picatz/deputy/internal/collections"
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
		return 1
	}
	if strings.HasPrefix(id, "GO-") {
		return 2
	}
	if strings.HasPrefix(id, "GHSA-") {
		return 3
	}
	return 4
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
	var all []string
	for _, v := range vs {
		all = append(all, v.ID)
		all = append(all, v.Aliases...)
	}
	seen := collections.NewSet[string]()
	var uniq []string
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

// createConsolidatedVulnerability merges a group of vulnerabilities into a single consolidated record.
func createConsolidatedVulnerability(primaryID string, vulns []Vulnerability) ConsolidatedVulnerability {
	if len(vulns) == 0 {
		return ConsolidatedVulnerability{}
	}
	base := vulns[0]

	// Secondary and all IDs
	seen := collections.NewSet[string](primaryID)
	var secondaries []string
	// Collect all IDs
	allIDs := []string{primaryID}
	for _, v := range vulns {
		allIDs = append(allIDs, v.ID)
		allIDs = append(allIDs, v.Aliases...)
	}
	uniqAll := make([]string, 0, len(allIDs))
	tmp := collections.NewSet[string]()
	for _, id := range allIDs {
		if tmp.Add(id) {
			uniqAll = append(uniqAll, id)
		}
	}
	for _, id := range uniqAll {
		if id == primaryID {
			continue
		}
		if seen.Add(id) {
			secondaries = append(secondaries, id)
		}
	}

	preferredSecondaries, hiddenAliases := filterTrustedAliases(secondaries)

	// Merge fixed versions
	fixSet := collections.NewSet[string]()
	var fixed []string
	for _, v := range vulns {
		for _, f := range v.FixedVersions {
			if fixSet.Add(f) {
				fixed = append(fixed, f)
			}
		}
	}

	// Merge references
	refSet := collections.NewSet[string]()
	var refs []string
	for _, v := range vulns {
		for _, r := range v.References {
			if refSet.Add(r) {
				refs = append(refs, r)
			}
		}
	}

	bestSev, bestSevType := FindBestSeverity(vulns)

	locSet := collections.NewSet[string]()
	var locations []string
	for _, v := range vulns {
		for _, loc := range v.Locations {
			if !locSet.Add(loc) {
				continue
			}
			locations = append(locations, loc)
		}
	}

	sort.Strings(locations)

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
				if !groupSet.Add(g) {
					continue
				}
				existing.Groups = append(existing.Groups, g)
			}
			manifestMap[key] = existing
		}
	}
	manifestRefs := make([]ManifestReference, 0, len(manifestMap))
	for _, ref := range manifestMap {
		manifestRefs = append(manifestRefs, ref)
	}
	sort.Slice(manifestRefs, func(i, j int) bool {
		if manifestRefs[i].Manager == manifestRefs[j].Manager {
			return manifestRefs[i].Path < manifestRefs[j].Path
		}
		return manifestRefs[i].Manager < manifestRefs[j].Manager
	})

	var importSets [][]AffectedImport
	for _, v := range vulns {
		if len(v.AffectedImports) > 0 {
			importSets = append(importSets, v.AffectedImports)
		}
	}
	mergedImports := MergeAffectedImports(importSets...)

	dbSpecific := map[string]string{}
	for _, v := range vulns {
		for k, val := range v.DatabaseSpecific {
			k = strings.TrimSpace(k)
			if k == "" {
				continue
			}
			if val == "" {
				continue
			}
			if _, ok := dbSpecific[k]; ok {
				continue
			}
			dbSpecific[k] = val
		}
	}
	if len(dbSpecific) == 0 {
		dbSpecific = nil
	}

	return ConsolidatedVulnerability{
		PrimaryID:        primaryID,
		SecondaryIDs:     preferredSecondaries,
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
		AffectedImports:  mergedImports,
		DatabaseSpecific: dbSpecific,
	}
}

// ConsolidateVulnerabilities groups related vulnerabilities using aliases.
func ConsolidateVulnerabilities(vulns []Vulnerability) []ConsolidatedVulnerability {
	if len(vulns) == 0 {
		return nil
	}
	processed := make(map[string]bool)
	var groups [][]Vulnerability
	for _, v := range vulns {
		if processed[v.ID] {
			continue
		}
		group := []Vulnerability{v}
		processed[v.ID] = true
		aliases := append([]string{v.ID}, v.Aliases...)
		for _, ov := range vulns {
			if processed[ov.ID] {
				continue
			}
			oAliases := append([]string{ov.ID}, ov.Aliases...)
			if HasCommonAlias(aliases, oAliases) {
				group = append(group, ov)
				processed[ov.ID] = true
				aliases = append(aliases, oAliases...)
			}
		}
		groups = append(groups, group)
	}
	out := make([]ConsolidatedVulnerability, 0, len(groups))
	for _, g := range groups {
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

// FindBestSeverity chooses the best severity across related vulns.
func FindBestSeverity(vulns []Vulnerability) (string, string) {
	if len(vulns) == 0 {
		return "", ""
	}
	// Prefer GHSA textual \"CRITICAL\" etc. if present; otherwise highest CVSS score.
	var bestScore float64 = -1
	var bestSev, bestType string
	// First, GHSA textual wins if present and equals CRITICAL/HIGH.
	for _, v := range vulns {
		if v.SeverityType == "GHSA" {
			up := strings.ToUpper(v.Severity)
			if up == "CRITICAL" {
				return v.Severity, v.SeverityType
			}
			if up == "HIGH" && bestSev == "" {
				bestSev, bestType = v.Severity, v.SeverityType
			}
		}
	}
	for _, v := range vulns {
		score := ParseCVSSScore(v.Severity)
		if score > bestScore {
			bestScore = score
			bestSev = v.Severity
			bestType = v.SeverityType
		}
	}
	return bestSev, bestType
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
		if v.Severity != "" {
			if v.SeverityType == "GHSA" {
				up := strings.ToUpper(v.Severity)
				switch up {
				case "CRITICAL":
					stats.CriticalSev++
				case "HIGH":
					stats.HighSeverity++
				case "MEDIUM", "MODERATE":
					stats.MedSeverity++
				case "LOW":
					stats.LowSeverity++
				default:
					score := ParseCVSSScore(v.Severity)
					switch {
					case score >= 9.0:
						stats.CriticalSev++
					case score >= 7.0:
						stats.HighSeverity++
					case score >= 4.0:
						stats.MedSeverity++
					case score >= 0.0:
						stats.LowSeverity++
					default:
						stats.UnknownSev++
					}
				}
			} else {
				score := ParseCVSSScore(v.Severity)
				switch {
				case score >= 9.0:
					stats.CriticalSev++
				case score >= 7.0:
					stats.HighSeverity++
				case score >= 4.0:
					stats.MedSeverity++
				case score >= 0.0:
					stats.LowSeverity++
				default:
					stats.UnknownSev++
				}
			}
		} else {
			stats.UnknownSev++
		}
	}
	return stats
}

// FindBestFixedVersion selects the smallest applicable fix >= current.
func FindBestFixedVersion(fixed []string, current string) string {
	if len(fixed) == 0 {
		return ""
	}
	cur := normalizeGoVersion(current)
	var cands []string
	for _, f := range fixed {
		nf := normalizeGoVersion(f)
		if semver.Compare(nf, cur) >= 0 {
			cands = append(cands, nf)
		}
	}
	if len(cands) == 0 {
		return ""
	}
	// Choose smallest applicable
	for i := 0; i < len(cands); i++ {
		for j := i + 1; j < len(cands); j++ {
			if semver.Compare(cands[j], cands[i]) < 0 {
				cands[i], cands[j] = cands[j], cands[i]
			}
		}
	}
	return cands[0]
}

// normalizeGoVersion ensures the Go version string starts with "v".
func normalizeGoVersion(v string) string {
	if v == "" {
		return v
	}
	if strings.HasPrefix(v, "v") {
		return v
	}
	return "v" + v
}
