package render

import (
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	triagev1 "github.com/temporalio/deputy/gen/deputy/triage/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/output"
	"github.com/temporalio/deputy/internal/ui"
)

// TriageSummary prints a human-readable summary of a triage response. It
// renders the deputy.triage.v1 proto directly — the same message the JSON
// output marshals and the API returns — so text and machine output can never
// disagree about what the triage found.
func TriageSummary(w io.Writer, resp *triagev1.TriageResponse, showDBInfo bool) {
	if resp == nil {
		return
	}
	target := resp.GetTarget()
	doc := TriageSummaryDoc(TargetSummary{
		Repo:   target.GetDisplayPath(),
		Ref:    target.GetRef(),
		Commit: target.GetCommitHash(),
	}, resp.GetStats(), int(resp.GetPackagesWithVulns()))
	if len(resp.GetTopPackages()) == 0 {
		doc.AddBlank()
		doc.AddLine(output.Span{Text: "No fixable vulnerabilities after filtering.", Style: output.StyleAdded})
		_ = doc.Render(w, output.UIStyles())
		return
	}
	doc.AddBlank()
	title := TopImpactedTitle(int(resp.GetPackagesWithVulns()), len(resp.GetTopPackages()))
	doc.AddLine(output.Span{Text: title})
	doc.AddLine(output.Span{Text: "  Severity shown per package = highest vuln severity in that package.", Style: output.StyleMeta})
	_ = doc.Render(w, output.UIStyles())

	for idx, pkg := range resp.GetTopPackages() {
		if pkg == nil {
			continue
		}
		marker := fmt.Sprintf("%d.", idx+1)
		sev := ui.SeverityLabel(pkg.GetSeverity(), pkg.GetSeverityType())
		sevInline := formatSeverityCounts(pkg.GetSeverityCounts())
		countInline := ""
		if pkg.GetVulnerabilityCount() > 0 {
			if sevInline != "" {
				countInline = ui.StyleMeta.Render(fmt.Sprintf("— %d vulns (%s)", pkg.GetVulnerabilityCount(), sevInline))
			} else {
				countInline = ui.StyleMeta.Render(fmt.Sprintf("— %d vulns", pkg.GetVulnerabilityCount()))
			}
		}
		fix := ""
		if pkg.GetFixVersion() != "" {
			fix = ui.StyleUpgraded.Render("↑ " + pkg.GetFixVersion())
		}
		fmt.Fprintf(w, "  %s %s %s %s %s\n", marker, ui.StylePackageName.Render(pkg.GetPackage()), ui.StyleVersion.Render(pkg.GetVersion()), sev, countInline)
		if pkg.GetSummary() != "" {
			fmt.Fprintln(w, "     ", ui.StyleDim.Render(pkg.GetSummary()))
		}
		if fix != "" {
			fmt.Fprintln(w, "     ", fix)
		}
		if imports := affectedImportValues(pkg.GetAffectedImports()); len(imports) > 0 {
			lines := FormatImportSummaries(imports, 2, 3)
			if len(lines) > 0 {
				fmt.Fprintln(w, "     ", ui.StyleMeta.Render("Symbol hints (Go/OSV):"))
				for _, line := range lines {
					fmt.Fprintln(w, "       ", ui.StylePath.Render(line))
				}
			}
		}
		if showDBInfo {
			if dbLines := FormatDatabaseSpecificInfo(pkg.GetDatabaseSpecific(), 2); len(dbLines) > 0 {
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
	for i := range imps {
		imp := &imps[i]
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
func formatSeverityCounts(counts map[string]int32) string {
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

// affectedImportValues adapts proto import pointers to the value slice the
// shared import formatter consumes.
func affectedImportValues(imports []*vulnerabilityv1.AffectedImport) []vulnerabilityv1.AffectedImport {
	if len(imports) == 0 {
		return nil
	}
	out := make([]vulnerabilityv1.AffectedImport, 0, len(imports))
	for _, imp := range imports {
		if imp != nil {
			out = append(out, vulnerabilityv1.AffectedImport{Path: imp.Path, Symbols: imp.Symbols})
		}
	}
	return out
}
