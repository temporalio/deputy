package report

import (
	"cmp"
	"maps"
	"slices"
	"strings"

	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/vulnerability"
	"github.com/picatz/deputy/internal/vulnerability/severity/cvss"
)

// TriageReport represents the summary of a triage analysis.
type TriageReport struct {
	Target            Target                `json:"target"`
	Stats             vulnerabilityv1.Stats `json:"stats"`
	TopPackages       []TriagePackageSummary       `json:"topPackages"`
	PackagesWithVulns int                          `json:"packagesWithVulns"`
}

// TriagePackageSummary represents a summary of a single package's vulnerabilities.
type TriagePackageSummary struct {
	Package            string                    `json:"package"`
	Version            string                    `json:"version"`
	Severity           string                    `json:"severity"`
	SeverityType       string                    `json:"severityType"`
	FixVersion         string                    `json:"fixVersion,omitempty"`
	IsDirect           bool                      `json:"isDirect"`
	Summary            string                    `json:"summary,omitempty"`
	SampleIDs          []string                  `json:"sampleIDs,omitempty"`
	AffectedImports    []vulnerabilityv1.AffectedImport `json:"affectedImports,omitempty"`
	DatabaseSpecific   map[string]string         `json:"databaseSpecific,omitempty"`
	VulnerabilityCount int                       `json:"vulnerabilityCount"`
	SeverityCounts     map[string]int            `json:"severityCounts,omitempty"`
}

// BuildTriageReport constructs a TriageReport from the target, stats, and consolidated vulnerabilities.
func BuildTriageReport(target Target, stats vulnerabilityv1.Stats, cons []vulnerability.Consolidated) TriageReport {
	report := TriageReport{Target: target, Stats: stats}
	agg := aggregatePackages(cons)
	report.PackagesWithVulns = len(agg)
	report.TopPackages = agg
	if len(report.TopPackages) > 10 {
		report.TopPackages = report.TopPackages[:10]
	}
	return report
}

// aggregatePackages aggregates consolidated vulnerabilities into package summaries.
func aggregatePackages(cons []vulnerability.Consolidated) []TriagePackageSummary {
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
		imports    []vulnerabilityv1.AffectedImport
		dbSpecific map[string]string
		counts     map[string]int
		total      int
	}
	pkgMap := map[string]*aggInfo{}
	for _, v := range cons {
		key := v.Package
		if key == "" {
			continue
		}
		priority, _ := ConsolidatedSeverityPriority(v)
		info, ok := pkgMap[key]
		if !ok {
			info = &aggInfo{pkg: v.Package, version: v.Version, severity: v.Severity, severityT: v.SeverityType, priority: priority, fix: bestFix(v), summary: v.Summary, isDirect: v.IsDirect}
			pkgMap[key] = info
		}
		if len(v.AffectedImports) > 0 {
			info.imports = mergeAffectedImports(info.imports, v.AffectedImports)
		}
		if len(v.DatabaseSpecific) > 0 {
			info.dbSpecific = vulnerability.MergeStringMap(info.dbSpecific, v.DatabaseSpecific)
		}
		if info.counts == nil {
			info.counts = map[string]int{}
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
	list := make([]TriagePackageSummary, 0, len(pkgMap))
	for _, info := range pkgMap {
		list = append(list, TriagePackageSummary{
			Package:            info.pkg,
			Version:            info.version,
			Severity:           info.severity,
			SeverityType:       info.severityT,
			FixVersion:         info.fix,
			IsDirect:           info.isDirect,
			Summary:            info.summary,
			SampleIDs:          info.ids,
			AffectedImports:    info.imports,
			DatabaseSpecific:   info.dbSpecific,
			VulnerabilityCount: info.total,
			SeverityCounts:     info.counts,
		})
	}
	slices.SortFunc(list, func(a, b TriagePackageSummary) int {
		pa, _ := severityRank(a.Severity)
		pb, _ := severityRank(b.Severity)
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
func severityRank(sev string) (int, string) {
	up := strings.ToUpper(strings.TrimSpace(sev))
	switch up {
	case "CRITICAL":
		return 4, up
	case "HIGH":
		return 3, up
	case "MEDIUM", "MODERATE":
		return 2, up
	case "LOW":
		return 1, up
	default:
		return 0, up
	}
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

func mergeAffectedImports(base []vulnerabilityv1.AffectedImport, extra []vulnerabilityv1.AffectedImport) []vulnerabilityv1.AffectedImport {
	if len(extra) == 0 {
		return base
	}
	pathMap := make(map[string]collections.Set[string])
	for _, imp := range base {
		path := strings.TrimSpace(imp.Path)
		if path == "" {
			continue
		}
		set := pathMap[path]
		if set == nil {
			set = collections.NewSet[string]()
			pathMap[path] = set
		}
		for _, sym := range imp.Symbols {
			if s := strings.TrimSpace(sym); s != "" {
				set.Add(s)
			}
		}
	}
	for _, imp := range extra {
		path := strings.TrimSpace(imp.Path)
		if path == "" {
			continue
		}
		set := pathMap[path]
		if set == nil {
			set = collections.NewSet[string]()
			pathMap[path] = set
		}
		for _, sym := range imp.Symbols {
			if s := strings.TrimSpace(sym); s != "" {
				set.Add(s)
			}
		}
	}
	if len(pathMap) == 0 {
		return nil
	}
	paths := slices.Sorted(maps.Keys(pathMap))
	out := make([]vulnerabilityv1.AffectedImport, 0, len(paths))
	for _, p := range paths {
		syms := pathMap[p].Slice()
		slices.Sort(syms)
		out = append(out, vulnerabilityv1.AffectedImport{Path: p, Symbols: syms})
	}
	return out
}
