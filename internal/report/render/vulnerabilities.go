package render

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	pathpkg "path"

	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/vulnerability"
)

// VulnerabilityDisplayOptions controls optional verbosity in vulnerability output.
type VulnerabilityDisplayOptions struct {
	ShowSymbols      bool
	ShowDatabaseInfo bool
}

func resolveVulnerabilityDisplayOptions(opts []VulnerabilityDisplayOptions) VulnerabilityDisplayOptions {
	if len(opts) > 0 {
		return opts[0]
	}
	return VulnerabilityDisplayOptions{}
}

// DisplayVulnerabilities writes a styled vulnerability report to w with the default heading.
func DisplayVulnerabilities(w io.Writer, result scan.Result, opts ...VulnerabilityDisplayOptions) {
	DisplayVulnerabilitiesWithHeader(w, result, "Vulnerabilities Found:", opts...)
}

// DisplayVulnerabilitiesWithHeader writes a styled vulnerability report to w using the provided heading.
func DisplayVulnerabilitiesWithHeader(w io.Writer, result scan.Result, heading string, opts ...VulnerabilityDisplayOptions) {
	displayOpts := resolveVulnerabilityDisplayOptions(opts)
	cons := vulnerability.Consolidate(result.Findings, result.Advisories)
	if len(cons) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleAdded.Render("✓ No vulnerabilities found"))
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleDowngraded.Render("∴ ")+ui.StyleHeader.Render(heading))

	VulnerabilityList(w, cons, displayOpts)

	VulnerabilitySummaryAndActions(w, cons, result.Stats)
}

// VulnerabilityList writes per-package vulnerability details to w without headings or summary.
// Used by diff to compose combined views.
func VulnerabilityList(w io.Writer, cons []vulnerability.Consolidated, opts VulnerabilityDisplayOptions) {
	if len(cons) == 0 {
		return
	}

	byPkg := map[string][]vulnerability.Consolidated{}
	for _, v := range cons {
		byPkg[v.Package] = append(byPkg[v.Package], v)
	}

	pkgNames := slices.Sorted(maps.Keys(byPkg))

	for _, pkg := range pkgNames {
		list := byPkg[pkg]
		if len(list) == 0 {
			continue
		}
		slices.SortStableFunc(list, func(a, b vulnerability.Consolidated) int {
			pa, sa := report.ConsolidatedSeverityPriority(a)
			pb, sb := report.ConsolidatedSeverityPriority(b)
			if pa != pb {
				return cmp.Compare(pb, pa) // descending
			}
			if sa != sb {
				return cmp.Compare(sb, sa) // descending
			}
			return cmp.Compare(a.PrimaryID, b.PrimaryID)
		})

		hasDirect := slices.ContainsFunc(list, func(v vulnerability.Consolidated) bool {
			return v.IsDirect
		})
		depType := "[indirect]"
		depStyle := output.StyleVersion
		if hasDirect {
			depType = "[direct]"
			depStyle = output.StyleUpgraded
		}
		{
			var doc output.Doc
			doc.AddBlank()
			doc.AddLine(
				output.Span{Text: pkg, Style: output.StylePackageName},
				output.Span{Text: " "},
				output.Span{Text: list[0].Version, Style: output.StyleVersion},
				output.Span{Text: " "},
				output.Span{Text: depType, Style: depStyle},
				output.Span{Text: ":"},
			)
			_ = doc.Render(w, output.UIStyles())
		}

		for _, v := range list {
			sevDisp := ui.SeverityLabel(v.Severity, v.SeverityType)
			parts := []string{ui.StyleSymbol.Render(v.PrimaryID), sevDisp}
			if len(v.FixedVersions) > 0 {
				if best := vulnerability.FindBestFixedVersion(v.FixedVersions, v.Version); best != "" {
					parts = append(parts, ui.StyleUpgraded.Render(fmt.Sprintf("(↑ %s)", best)))
				}
			}
			if v.RelatedCount > 1 {
				parts = append(parts, ui.StyleVersion.Render(fmt.Sprintf("[%d related]", v.RelatedCount)))
			}
			// Add layer context for container image scans
			if v.LayerDetails != nil {
				layerTag := formatLayerTag(v.LayerDetails)
				if layerTag != "" {
					parts = append(parts, ui.StyleMeta.Render(layerTag))
				}
			}
			fmt.Fprintln(w, "  "+ui.StyleVersion.Render("• ")+strings.Join(parts, " "))

			if v.Summary != "" && len(v.Summary) < 120 {
				fmt.Fprintln(w, "    "+ui.StyleSymbol.Render(strings.TrimSpace(v.Summary)))
			}
			if opts.ShowSymbols && len(v.AffectedImports) > 0 {
				lines := FormatImportSummaries(v.AffectedImports, 3, 4)
				if len(lines) > 0 {
					fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Symbol hints (Go/OSV):"))
					for _, line := range lines {
						fmt.Fprintln(w, "      "+ui.StylePath.Render(line))
					}
				}
			}
			if opts.ShowDatabaseInfo {
				if dbLines := FormatDatabaseSpecificInfo(v.DatabaseSpecific, 3); len(dbLines) > 0 {
					fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Database info:"))
					for _, line := range dbLines {
						fmt.Fprintln(w, "      "+ui.StyleMeta.Render(line))
					}
				}
			}
			switch {
			case len(v.SecondaryIDs) > 0:
				aliases := slices.Clone(v.SecondaryIDs)
				slices.Sort(aliases)
				aliasBlocks := make([]string, 0, len(aliases))
				for _, a := range aliases {
					st := ui.StyleAliasOther
					if strings.HasPrefix(a, "CVE-") {
						st = ui.StyleAlias
					}
					aliasBlocks = append(aliasBlocks, st.Render(a))
				}
				if v.HiddenAliasCount > 0 {
					aliasBlocks = append(aliasBlocks, ui.StyleMeta.Render(fmt.Sprintf("(+%d more)", v.HiddenAliasCount)))
				}
				aliasRow := lipgloss.JoinHorizontal(lipgloss.Top, ui.StyleMeta.Render("Aliases:"), lipgloss.NewStyle().MarginLeft(1).Render(strings.Join(aliasBlocks, ", ")))
				fmt.Fprintln(w, "    "+aliasRow)
			case v.HiddenAliasCount > 0:
				aliasRow := lipgloss.JoinHorizontal(
					lipgloss.Top,
					ui.StyleMeta.Render("Aliases:"),
					lipgloss.NewStyle().MarginLeft(1).Render(ui.StyleMeta.Render(fmt.Sprintf("(+%d more)", v.HiddenAliasCount))),
				)
				fmt.Fprintln(w, "    "+aliasRow)
			}
			if v.Published != "" && len(v.Published) >= 10 {
				metaBlock := lipgloss.JoinHorizontal(lipgloss.Top, ui.StyleMeta.Render("Published:"), lipgloss.NewStyle().MarginLeft(1).Faint(true).Render(v.Published[:10]))
				fmt.Fprintln(w, "    "+metaBlock)
			}
		}

		renderManifestContext(w, list)
	}
}

// VulnerabilitySummaryAndActions writes the summary and recommended
// actions for a set of vulnerabilities without reprinting the list header.
func VulnerabilitySummaryAndActions(w io.Writer, cons []vulnerability.Consolidated, stats vulnerability.Stats) {
	summary := report.BuildSummary(cons, stats)
	if !summary.HasVulnerabilities {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleAdded.Render("✓ No vulnerabilities found"))
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Vulnerability Summary:"))
	if summary.CriticalHighCount > 0 {
		fmt.Fprintln(w, "  "+ui.StyleSymbol.Render(ui.StyleRemoved.Render("!"))+" "+ui.StyleSymbol.Render(fmt.Sprintf("%d require immediate attention ", summary.CriticalHighCount))+ui.StyleRemoved.Render("(critical/high severity)"))
	}
	if summary.FixAvailableCount > 0 {
		fmt.Fprintln(w, "  "+ui.StyleSymbol.Render(ui.StyleUpgraded.Render("↑"))+" "+ui.StyleSymbol.Render(fmt.Sprintf("%d can be fixed by upgrading", summary.FixAvailableCount)))
	}
	if summary.UnfixedCount > 0 {
		fmt.Fprintln(w, "  "+ui.StyleSymbol.Render(ui.StyleRemoved.Render("-"))+" "+ui.StyleSymbol.Render(fmt.Sprintf("%d have no fix available yet", summary.UnfixedCount)))
	}

	if len(summary.Commands) > 0 || summary.StdlibRecommendation != "" || summary.UnfixedCount > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleHeader.Render("Recommended Actions:"))
		step := 1
		if summary.StdlibRecommendation != "" {
			fmt.Fprintf(w, "  %d. %s %s %s\n", step, ui.StyleBold.Render("Upgrade Go toolchain to"), ui.StyleUpgraded.Render(summary.StdlibRecommendation), ui.StyleVersion.Render("(update 'go' directive in go.mod)"))
			step++
		}
		if len(summary.Commands) > 0 {
			fmt.Fprintf(w, "  %d. %s\n", step, ui.StyleBold.Render(summary.CommandsHeader))
			RemediationCommands(w, summary.Commands, "       ", "         ")
			step++
		}
		if summary.UnfixedCount > 0 {
			fmt.Fprintf(w, "  %d. %s %s\n", step, ui.StyleBold.Render("Investigate remaining unfixed vulnerabilities"), ui.StyleVersion.Render("(monitor upstream / consider alternatives)"))
		}
	}
}

// renderManifestContext writes the context (sources and artifacts) for a list of vulnerabilities.
func renderManifestContext(w io.Writer, list []vulnerability.Consolidated) {
	ctx := report.BuildManifestContext(list)
	if len(ctx.Sources) == 0 && len(ctx.Artifacts) == 0 {
		return
	}
	fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Context:"))
	sourceEntryCount := 0
	for _, grp := range ctx.Sources {
		sourceEntryCount += len(grp.Entries)
	}
	if sourceEntryCount > 0 {
		fmt.Fprintln(w, "      "+ui.StyleMeta.Render("Sources:"))
		for _, grp := range ctx.Sources {
			if len(grp.Entries) == 0 {
				continue
			}
			manager := strings.TrimSpace(grp.Manager)
			for _, entry := range grp.Entries {
				lineParts := []string{}
				if entry.Path != "" {
					lineParts = append(lineParts, ui.StylePath.Render(entry.Path))
				}
				metaParts := []string{}
				basename := pathpkg.Base(entry.Path)
				if manager != "" && basename != "go.mod" {
					metaParts = append(metaParts, ui.StyleManager.Render("("+manager+")"))
				}
				if len(entry.Groups) > 0 {
					metaParts = append(metaParts, ui.StyleVersion.Render("["+strings.Join(entry.Groups, ",")+"]"))
				}
				if len(metaParts) > 0 {
					lineParts = append(lineParts, strings.Join(metaParts, " "))
				}
				if len(lineParts) == 0 {
					lineParts = append(lineParts, ui.StyleMeta.Render("(manifest)"))
				}
				fmt.Fprintln(w, "        "+ui.StyleSymbol.Render("• ")+strings.Join(lineParts, " "))
			}
		}
	}
	if len(ctx.Artifacts) > 0 {
		fmt.Fprintln(w, "      "+ui.StyleMeta.Render("Artifacts:"))
		for _, grp := range ctx.Artifacts {
			if len(grp.Entries) == 0 {
				continue
			}
			manager := strings.TrimSpace(grp.Manager)
			for _, art := range grp.Entries {
				lineParts := []string{ui.StylePath.Render(art)}
				if manager != "" {
					lineParts = append(lineParts, ui.StyleManager.Render("("+manager+")"))
				}
				fmt.Fprintln(w, "        "+ui.StyleSymbol.Render("• ")+strings.Join(lineParts, " "))
			}
		}
	}
}

// formatLayerTag returns a concise layer context tag for container vulnerability display.
// Examples: "[BASE layer 0]", "[layer 5]", "[APP layer 12]"
func formatLayerTag(ld *vulnerability.LayerDetails) string {
	if ld == nil {
		return ""
	}
	var parts []string
	if ld.InBaseImage {
		parts = append(parts, "BASE")
	}
	parts = append(parts, fmt.Sprintf("layer %d", ld.Index))
	return "[" + strings.Join(parts, " ") + "]"
}
