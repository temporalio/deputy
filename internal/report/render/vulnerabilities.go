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
	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/dependency/graph"
	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/remediation"
	"github.com/picatz/deputy/internal/report"
	"github.com/picatz/deputy/internal/scanning"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/vulnerability"
)

// VulnerabilityDisplayOptions controls optional verbosity in vulnerability output.
type VulnerabilityDisplayOptions struct {
	ShowSymbols           bool
	ShowDatabaseInfo      bool
	ShowUnfixableGuidance bool
	// Graph is the dependency graph for showing paths to vulnerable packages.
	// When non-nil, transitive vulnerabilities will show their dependency path.
	Graph *graph.Graph
	// ShowDirectIndirect indicates whether to show [direct]/[indirect] labels.
	// This should be false for target types where direct/indirect doesn't apply
	// (container images, binaries, VM images, etc.). Default is true for backwards
	// compatibility with repository scans.
	ShowDirectIndirect bool
}

func resolveVulnerabilityDisplayOptions(opts []VulnerabilityDisplayOptions) VulnerabilityDisplayOptions {
	if len(opts) > 0 {
		return opts[0]
	}
	return VulnerabilityDisplayOptions{}
}

// DisplayVulnerabilities writes a styled vulnerability report to w with the default heading.
func DisplayVulnerabilities(w io.Writer, result scanning.Result, opts ...VulnerabilityDisplayOptions) {
	DisplayVulnerabilitiesWithHeader(w, result, "Vulnerabilities Found:", opts...)
}

// DisplayVulnerabilitiesWithHeader writes a styled vulnerability report to w using the provided heading.
func DisplayVulnerabilitiesWithHeader(w io.Writer, result scanning.Result, heading string, opts ...VulnerabilityDisplayOptions) {
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

	VulnerabilitySummaryAndActions(w, cons, result.Stats, displayOpts)
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

		// Build the package header line
		var headerSpans []output.Span
		headerSpans = append(headerSpans,
			output.Span{Text: pkg, Style: output.StylePackageName},
			output.Span{Text: " "},
			output.Span{Text: list[0].Version, Style: output.StyleVersion},
		)

		// Only show [direct]/[indirect] labels for target types where it applies
		// (repositories, directories). For container images, binaries, etc., omit the label.
		if opts.ShowDirectIndirect {
			hasDirect := slices.ContainsFunc(list, func(v vulnerability.Consolidated) bool {
				return v.IsDirect
			})
			depType := "[indirect]"
			depStyle := output.StyleIndirect
			if hasDirect {
				depType = "[direct]"
				depStyle = output.StyleDirect
			}
			headerSpans = append(headerSpans,
				output.Span{Text: " "},
				output.Span{Text: depType, Style: depStyle},
			)
		}
		headerSpans = append(headerSpans, output.Span{Text: ":"})

		{
			var doc output.Doc
			doc.AddBlank()
			doc.AddLine(headerSpans...)
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
			// Show dependency path for indirect vulnerabilities when graph is available
			if !v.IsDirect && opts.Graph != nil {
				renderDependencyPath(w, v, opts.Graph)
			}
		}

		renderManifestContext(w, list)
	}
}

// VulnerabilitySummaryAndActions writes the summary and recommended
// actions for a set of vulnerabilities without reprinting the list header.
func VulnerabilitySummaryAndActions(w io.Writer, cons []vulnerability.Consolidated, stats vulnerabilityv1.Stats, opts ...VulnerabilityDisplayOptions) {
	displayOpts := resolveVulnerabilityDisplayOptions(opts)
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

	// Show detailed guidance for unfixable vulnerabilities when enabled
	if displayOpts.ShowUnfixableGuidance && summary.UnfixedCount > 0 {
		UnfixableGuidance(w, cons)
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
func formatLayerTag(ld *containerv1.LayerDetails) string {
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

// UnfixableGuidance renders detailed actionable guidance for vulnerabilities
// that have no direct fix available. This helps security engineers make
// informed decisions about risk acceptance or alternative mitigations.
func UnfixableGuidance(w io.Writer, cons []vulnerability.Consolidated) {
	guidance := remediation.AnalyzeUnfixable(cons)
	if len(guidance) == 0 {
		return
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Unfixable Vulnerability Guidance:"))

	for _, g := range guidance {
		fmt.Fprintln(w)
		// Header line: package@version - vulnerability ID
		fmt.Fprintf(w, "  %s %s\n",
			ui.StylePackageName.Render(fmt.Sprintf("%s@%s", g.Package, g.Version)),
			ui.StyleSymbol.Render(g.VulnerabilityID))
		fmt.Fprintf(w, "    %s %s\n",
			ui.StyleMeta.Render("Status:"),
			ui.StyleVersion.Render(g.Category.String()))

		// Risk factors (concise, max 3)
		if len(g.RiskFactors) > 0 {
			fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Risk factors:"))
			for i, f := range g.RiskFactors {
				if i >= 3 {
					fmt.Fprintf(w, "      %s\n", ui.StyleMeta.Render(fmt.Sprintf("(+%d more)", len(g.RiskFactors)-3)))
					break
				}
				fmt.Fprintf(w, "      %s %s\n", ui.StyleVersion.Render("-"), ui.StyleSymbol.Render(f))
			}
		}

		// Recommendations (concise, max 3)
		if len(g.Recommendations) > 0 {
			fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Recommendations:"))
			for i, r := range g.Recommendations {
				if i >= 3 {
					fmt.Fprintf(w, "      %s\n", ui.StyleMeta.Render(fmt.Sprintf("(+%d more)", len(g.Recommendations)-3)))
					break
				}
				fmt.Fprintf(w, "      %s %s\n", ui.StyleUpgraded.Render(fmt.Sprintf("%d.", i+1)), ui.StyleSymbol.Render(r))
			}
		}

		// Alternative packages (if any)
		if len(g.AlternativePackages) > 0 {
			alts := g.AlternativePackages
			if len(alts) > 3 {
				alts = alts[:3]
			}
			fmt.Fprintf(w, "    %s %s\n",
				ui.StyleMeta.Render("Alternatives:"),
				ui.StylePath.Render(strings.Join(alts, ", ")))
		}

		// Reference (just first one to keep it concise)
		if len(g.References) > 0 {
			fmt.Fprintf(w, "    %s %s\n",
				ui.StyleMeta.Render("Reference:"),
				ui.StylePath.Render(g.References[0]))
		}
	}
}

// renderDependencyPath shows the dependency path to a transitive vulnerable package.
// Example output:
//
//	Path: go-git/v5 → ssh-agent → x/crypto
func renderDependencyPath(w io.Writer, v vulnerability.Consolidated, g *graph.Graph) {
	if g == nil || v.PURL == "" {
		return
	}

	// Find the shortest path to this vulnerable package
	paths := g.PathsTo(v.PURL)
	if len(paths) == 0 {
		return
	}

	// Get shortest path
	shortest := paths[0]
	for _, p := range paths[1:] {
		if len(p) < len(shortest) {
			shortest = p
		}
	}

	if len(shortest) <= 1 {
		// Direct dependency, no path to show
		return
	}

	// Format path: extract just package names for readability
	var pathParts []string
	for _, node := range shortest {
		name := shortPackageName(node.Name)
		if name != "" {
			pathParts = append(pathParts, name)
		}
	}

	if len(pathParts) <= 1 {
		return
	}

	pathStr := strings.Join(pathParts, " → ")
	pathRow := lipgloss.JoinHorizontal(
		lipgloss.Top,
		ui.StyleMeta.Render("Path:"),
		lipgloss.NewStyle().MarginLeft(1).Render(ui.StylePath.Render(pathStr)),
	)

	// Show path count if there are multiple paths
	if len(paths) > 1 {
		pathRow = lipgloss.JoinHorizontal(
			lipgloss.Top,
			pathRow,
			lipgloss.NewStyle().MarginLeft(1).Render(ui.StyleMeta.Render(fmt.Sprintf("(%d paths)", len(paths)))),
		)
	}

	fmt.Fprintln(w, "    "+pathRow)
}

// shortPackageName returns a shortened package name for display.
// e.g., "github.com/go-git/go-git/v5" -> "go-git/v5"
func shortPackageName(name string) string {
	if name == "" {
		return ""
	}

	// For Go packages, try to get a shorter name
	parts := strings.Split(name, "/")
	if len(parts) >= 2 {
		// Return last 2 parts for readability: "go-git/v5" instead of "github.com/go-git/go-git/v5"
		if len(parts) > 2 && (strings.Contains(parts[0], ".") || parts[0] == "golang.org") {
			// Skip domain parts
			return strings.Join(parts[len(parts)-2:], "/")
		}
	}

	return name
}
