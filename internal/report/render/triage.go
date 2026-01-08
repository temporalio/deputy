package render

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/report"
	ui "github.com/picatz/deputy/internal/ui"
)

// TriageSummary prints a human-readable summary of the triage report.
func TriageSummary(w io.Writer, triageReport report.TriageReport, showDBInfo bool) {
	doc := TriageSummaryDoc(TargetSummary{
		Repo:   triageReport.Target.Repo,
		Ref:    triageReport.Target.Ref,
		Commit: triageReport.Target.Commit,
	}, triageReport.Stats, triageReport.PackagesWithVulns)
	if len(triageReport.TopPackages) == 0 {
		doc.AddBlank()
		doc.AddLine(output.Span{Text: "No fixable vulnerabilities after filtering.", Style: output.StyleAdded})
		_ = doc.Render(w, output.UIStyles())
		return
	}
	doc.AddBlank()
	title := TopImpactedTitle(triageReport.PackagesWithVulns, len(triageReport.TopPackages))
	doc.AddLine(output.Span{Text: title})
	doc.AddLine(output.Span{Text: "  Severity shown per package = highest vuln severity in that package.", Style: output.StyleMeta})
	_ = doc.Render(w, output.UIStyles())

	for idx, pkg := range triageReport.TopPackages {
		marker := fmt.Sprintf("%d.", idx+1)
		sev := ui.SeverityLabel(pkg.Severity, pkg.SeverityType)
		sevInline := formatSeverityCounts(pkg.SeverityCounts)
		countInline := ""
		if pkg.VulnerabilityCount > 0 {
			if sevInline != "" {
				countInline = ui.StyleMeta.Render(fmt.Sprintf("— %d vulns (%s)", pkg.VulnerabilityCount, sevInline))
			} else {
				countInline = ui.StyleMeta.Render(fmt.Sprintf("— %d vulns", pkg.VulnerabilityCount))
			}
		}
		fix := ""
		if pkg.FixVersion != "" {
			fix = ui.StyleUpgraded.Render("↑ " + pkg.FixVersion)
		}
		fmt.Fprintf(w, "  %s %s %s %s %s\n", marker, ui.StylePackageName.Render(pkg.Package), ui.StyleVersion.Render(pkg.Version), sev, countInline)
		if pkg.Summary != "" {
			fmt.Fprintln(w, "     ", ui.StyleDim.Render(pkg.Summary))
		}
		if fix != "" {
			fmt.Fprintln(w, "     ", fix)
		}
		if len(pkg.AffectedImports) > 0 {
			lines := FormatImportSummaries(pkg.AffectedImports, 2, 3)
			if len(lines) > 0 {
				fmt.Fprintln(w, "     ", ui.StyleMeta.Render("Symbol hints (Go/OSV):"))
				for _, line := range lines {
					fmt.Fprintln(w, "       ", ui.StylePath.Render(line))
				}
			}
		}
		if showDBInfo {
			if dbLines := FormatDatabaseSpecificInfo(pkg.DatabaseSpecific, 2); len(dbLines) > 0 {
				fmt.Fprintln(w, "     ", ui.StyleMeta.Render("Database info:"))
				for _, line := range dbLines {
					fmt.Fprintln(w, "       ", ui.StyleMeta.Render(line))
				}
			}
		}
	}
}

// FormatImportSummaries prepares a compact set of import/symbol hints for display.
func FormatImportSummaries(imps []vulnerabilityv1.AffectedImport, maxPaths, maxSymbols int) []string {
	if len(imps) == 0 {
		return nil
	}
	lines := make([]string, 0, len(imps))
	for i, imp := range imps {
		if maxPaths > 0 && i >= maxPaths {
			lines = append(lines, fmt.Sprintf("... %d more import paths", len(imps)-maxPaths))
			break
		}
		path := strings.TrimSpace(imp.Path)
		if path == "" {
			continue
		}
		if len(imp.Symbols) == 0 {
			lines = append(lines, path)
			continue
		}
		syms := imp.Symbols
		truncated := false
		if maxSymbols > 0 && len(syms) > maxSymbols {
			syms = syms[:maxSymbols]
			truncated = true
		}
		symStr := strings.Join(syms, ", ")
		if truncated {
			symStr += ", ..."
		}
		lines = append(lines, fmt.Sprintf("%s (%s)", path, symStr))
	}
	return lines
}

// formatSeverityCounts renders a short severity breakdown like "2 HIGH, 1 MED".
func formatSeverityCounts(counts map[string]int) string {
	if len(counts) == 0 {
		return ""
	}
	order := []string{"CRITICAL", "HIGH", "MED", "LOW", "UNKNOWN"}
	labels := map[string]string{
		"CRITICAL": "CRIT",
		"HIGH":     "HIGH",
		"MED":      "MED",
		"LOW":      "LOW",
		"UNKNOWN":  "?",
	}
	var parts []string
	for _, key := range order {
		if n := counts[key]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, labels[key]))
		}
	}
	return strings.Join(parts, ", ")
}

// FormatDatabaseSpecificInfo flattens database_specific metadata into displayable lines.
// It truncates after maxEntries with a summary entry when provided.
func FormatDatabaseSpecificInfo(db map[string]string, maxEntries int) []string {
	if len(db) == 0 {
		return nil
	}
	keys := slices.Sorted(maps.Keys(db))
	lines := make([]string, 0, len(keys))
	for idx, k := range keys {
		if maxEntries > 0 && idx >= maxEntries {
			lines = append(lines, fmt.Sprintf("... %d more entries", len(keys)-maxEntries))
			break
		}
		lines = append(lines, fmt.Sprintf("%s: %s", k, db[k]))
	}
	return lines
}
