package proto

import (
	"cmp"
	"slices"
	"strings"

	triagev1 "github.com/temporalio/deputy/gen/deputy/triage/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/vulnerability"
	"github.com/temporalio/deputy/internal/vulnerability/severity/cvss"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// BuildTriageResponse constructs a TriageResponse from consolidated vulnerabilities.
func BuildTriageResponse(
	displayPath string,
	stats *vulnerabilityv1.Stats,
	cons []vulnerability.Consolidated,
	maxPackages int,
) *triagev1.TriageResponse {
	if maxPackages <= 0 {
		maxPackages = 10
	}

	resp := &triagev1.TriageResponse{
		Stats:       stats,
		GeneratedAt: timestamppb.Now(),
	}

	// Aggregate by package
	agg := aggregatePackages(cons)
	resp.PackagesWithVulns = int32(len(agg))

	// Limit to top N
	if len(agg) > maxPackages {
		agg = agg[:maxPackages]
	}
	resp.TopPackages = agg

	return resp
}

// aggregatePackages aggregates consolidated vulnerabilities into package summaries.
func aggregatePackages(cons []vulnerability.Consolidated) []*triagev1.PackageSummary {
	type aggInfo struct {
		pkg        string
		version    string
		severity   string
		severityT  string
		priority   int
		fix        string
		summary    string
		ids        []string
		isDirect   bool
		imports    []*vulnerabilityv1.AffectedImport
		dbSpecific map[string]string
		counts     map[string]int32
		total      int32
	}

	pkgMap := map[string]*aggInfo{}
	for _, v := range cons {
		key := v.Package
		if key == "" {
			continue
		}
		priority := severityPriority(v.Severity, v.SeverityType)
		info, ok := pkgMap[key]
		if !ok {
			info = &aggInfo{
				pkg:       v.Package,
				version:   v.Version,
				severity:  v.Severity,
				severityT: v.SeverityType,
				priority:  priority,
				fix:       bestFix(v),
				summary:   v.Summary,
				isDirect:  v.IsDirect,
			}
			pkgMap[key] = info
		}
		if len(v.AffectedImports) > 0 {
			info.imports = mergeAffectedImports(info.imports, v.AffectedImports)
		}
		if len(v.DatabaseSpecific) > 0 {
			info.dbSpecific = mergeStringMap(info.dbSpecific, v.DatabaseSpecific)
		}
		if info.counts == nil {
			info.counts = map[string]int32{}
		}
		sevKey := severityBucket(v.Severity, v.SeverityType)
		info.counts[sevKey]++
		info.total++
		if priority > info.priority {
			info.priority = priority
			info.severity = v.Severity
			info.severityT = v.SeverityType
			info.fix = bestFix(v)
			if v.Summary != "" {
				info.summary = v.Summary
			}
			info.version = v.Version
			info.isDirect = v.IsDirect
		}
		if v.PrimaryID != "" {
			info.ids = append(info.ids, v.PrimaryID)
		}
	}

	list := make([]*triagev1.PackageSummary, 0, len(pkgMap))
	for _, info := range pkgMap {
		list = append(list, &triagev1.PackageSummary{
			Package:            info.pkg,
			Version:            info.version,
			Severity:           info.severity,
			SeverityType:       info.severityT,
			FixVersion:         info.fix,
			IsDirect:           info.isDirect,
			Summary:            info.summary,
			SampleIds:          info.ids,
			AffectedImports:    info.imports,
			DatabaseSpecific:   info.dbSpecific,
			VulnerabilityCount: info.total,
			SeverityCounts:     info.counts,
		})
	}

	slices.SortFunc(list, func(a, b *triagev1.PackageSummary) int {
		pa := severityRank(a.Severity)
		pb := severityRank(b.Severity)
		if pa != pb {
			// higher severity first
			if pa > pb {
				return -1
			}
			return 1
		}
		if a.IsDirect != b.IsDirect {
			// direct first
			if a.IsDirect {
				return -1
			}
			return 1
		}
		if c := cmp.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		return cmp.Compare(a.Version, b.Version)
	})

	return list
}

// severityBucket normalizes severities into coarse buckets for counting.
func severityBucket(sev, sevType string) string {
	up := strings.ToUpper(strings.TrimSpace(sev))
	if sevType == "GHSA" {
		switch up {
		case "CRITICAL":
			return "CRITICAL"
		case "HIGH":
			return "HIGH"
		case "MEDIUM", "MODERATE":
			return "MED"
		case "LOW":
			return "LOW"
		}
	}
	switch up {
	case "CRITICAL":
		return "CRITICAL"
	case "HIGH":
		return "HIGH"
	case "MEDIUM", "MODERATE":
		return "MED"
	case "LOW":
		return "LOW"
	}
	score := cvss.ParseScore(sev)
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MED"
	case score >= 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

// severityRank returns a numeric rank for a severity string.
func severityRank(sev string) int {
	up := strings.ToUpper(strings.TrimSpace(sev))
	switch up {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM", "MODERATE":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

// severityPriority returns priority based on severity and type.
func severityPriority(sev, sevType string) int {
	rank := severityRank(sev)
	// Boost CVSS-based scores slightly
	if sevType == "CVSS_V3" || sevType == "CVSS_V2" {
		return rank*10 + 1
	}
	return rank * 10
}

// bestFix returns the best available fix version for a vulnerability.
func bestFix(v vulnerability.Consolidated) string {
	if len(v.FixedVersions) == 0 {
		return ""
	}
	if fix := vulnerability.FindBestFixedVersion(v.FixedVersions, v.Version); fix != "" {
		return fix
	}
	return strings.Join(v.FixedVersions, ",")
}

// mergeAffectedImports merges affected imports lists.
func mergeAffectedImports(base []*vulnerabilityv1.AffectedImport, extra []vulnerabilityv1.AffectedImport) []*vulnerabilityv1.AffectedImport {
	if len(extra) == 0 {
		return base
	}
	pathMap := make(map[string]map[string]struct{})
	for _, imp := range base {
		path := strings.TrimSpace(imp.Path)
		if path == "" {
			continue
		}
		if pathMap[path] == nil {
			pathMap[path] = make(map[string]struct{})
		}
		for _, sym := range imp.Symbols {
			if s := strings.TrimSpace(sym); s != "" {
				pathMap[path][s] = struct{}{}
			}
		}
	}
	for i := range extra {
		imp := &extra[i]
		path := strings.TrimSpace(imp.Path)
		if path == "" {
			continue
		}
		if pathMap[path] == nil {
			pathMap[path] = make(map[string]struct{})
		}
		for _, sym := range imp.Symbols {
			if s := strings.TrimSpace(sym); s != "" {
				pathMap[path][s] = struct{}{}
			}
		}
	}
	if len(pathMap) == 0 {
		return nil
	}
	var paths []string
	for p := range pathMap {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	out := make([]*vulnerabilityv1.AffectedImport, 0, len(paths))
	for _, p := range paths {
		var syms []string
		for s := range pathMap[p] {
			syms = append(syms, s)
		}
		slices.Sort(syms)
		out = append(out, &vulnerabilityv1.AffectedImport{Path: p, Symbols: syms})
	}
	return out
}

// mergeStringMap merges two string maps.
func mergeStringMap(base, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = make(map[string]string)
	}
	for k, v := range extra {
		if _, ok := base[k]; !ok {
			base[k] = v
		}
	}
	return base
}
