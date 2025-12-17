package cmd

import (
	"cmp"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"

	pathpkg "path"

	"github.com/charmbracelet/lipgloss"
	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/output"
	remediation "github.com/picatz/deputy/internal/remediation"
	ui "github.com/picatz/deputy/internal/ui"
)

type vulnDisplayOptions struct {
	showSymbols      bool
	showDatabaseInfo bool
}

func resolveVulnDisplayOptions(opts []vulnDisplayOptions) vulnDisplayOptions {
	if len(opts) > 0 {
		return opts[0]
	}
	return vulnDisplayOptions{}
}

// DisplayVulnerabilities writes a styled vulnerability report to w with the default heading.
func DisplayVulnerabilities(w io.Writer, vulns []analysis.Vulnerability, opts ...vulnDisplayOptions) {
	DisplayVulnerabilitiesWithHeader(w, vulns, "Vulnerabilities Found:", opts...)
}

// DisplayPolicyFindings writes any policy actions emitted during a command to w.
func DisplayPolicyFindings(w io.Writer, findings []PolicyFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Policy Findings:"))
	for _, f := range findings {
		action := strings.ToUpper(strings.TrimSpace(f.Action))
		if action == "" {
			action = "ACTION"
		}
		source := strings.TrimSpace(f.Source)
		line := fmt.Sprintf("  %s [%s]", ui.StyleVersion.Render("•"), ui.StyleBold.Render(action))
		if source != "" {
			line += " " + ui.StyleMeta.Render(source)
		}
		fmt.Fprintln(w, line)

		msg := strings.TrimSpace(firstNonEmpty(f.Reason, f.Message))
		if msg != "" {
			fmt.Fprintln(w, "    "+ui.StyleSymbol.Render("• ")+msg)
		}
		if rem := strings.TrimSpace(f.Remediation); rem != "" {
			fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Remediation: ")+rem)
		}
	}
}

// DisplayVulnerabilitiesWithHeader writes a styled vulnerability report to w using the provided heading.
func DisplayVulnerabilitiesWithHeader(w io.Writer, vulns []analysis.Vulnerability, heading string, opts ...vulnDisplayOptions) {
	displayOpts := resolveVulnDisplayOptions(opts)
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleAdded.Render("✓ No vulnerabilities found"))
		return
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleDowngraded.Render("∴ ")+ui.StyleHeader.Render(heading))

	RenderVulnerabilityList(w, vulns, displayOpts)

	RenderVulnerabilitySummaryAndActions(w, vulns)
}

// scoreLabel returns a styled string representing the severity score.
func scoreLabel(score float64) string {
	switch {
	case score >= 9.0:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true).Render("[CRITICAL]")
	case score >= 7.0:
		return ui.StyleRemoved.Render("[HIGH]")
	case score >= 4.0:
		return ui.StyleDowngraded.Render("[MED]")
	case score >= 0.0:
		return ui.StyleVersion.Render("[LOW]")
	default:
		return ui.StyleVersion.Render("[?]")
	}
}

// consolidatedSeverityPriority returns a priority tuple (int, float64) for sorting vulnerabilities.
// Higher values indicate higher priority.
func consolidatedSeverityPriority(v analysis.ConsolidatedVulnerability) (int, float64) {
	sev := strings.ToUpper(strings.TrimSpace(v.Severity))
	if v.SeverityType == "GHSA" {
		switch sev {
		case "CRITICAL":
			return 400, 10.0
		case "HIGH":
			return 300, 8.0
		case "MODERATE", "MEDIUM":
			return 200, 5.0
		case "LOW":
			return 100, 2.0
		}
	}
	score := analysis.ParseCVSSScore(v.Severity)
	return int(score*10 + 0.5), score
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

// RenderVulnerabilityList writes per-package vulnerability details to w without headings or summary.
// Used by diff to compose combined views.
func RenderVulnerabilityList(w io.Writer, vulns []analysis.Vulnerability, opts vulnDisplayOptions) {
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		return
	}

	byPkg := map[string][]analysis.ConsolidatedVulnerability{}
	for _, v := range cons {
		byPkg[v.Package] = append(byPkg[v.Package], v)
	}

	pkgNames := slices.Sorted(maps.Keys(byPkg))

	for _, pkg := range pkgNames {
		list := byPkg[pkg]
		if len(list) == 0 {
			continue
		}
		slices.SortStableFunc(list, func(a, b analysis.ConsolidatedVulnerability) int {
			pa, sa := consolidatedSeverityPriority(a)
			pb, sb := consolidatedSeverityPriority(b)
			if pa != pb {
				return cmp.Compare(pb, pa) // descending
			}
			if sa != sb {
				return cmp.Compare(sb, sa) // descending
			}
			return strings.Compare(a.PrimaryID, b.PrimaryID)
		})

		hasDirect := slices.ContainsFunc(list, func(v analysis.ConsolidatedVulnerability) bool {
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
				if best := analysis.FindBestFixedVersion(v.FixedVersions, v.Version); best != "" {
					parts = append(parts, ui.StyleUpgraded.Render(fmt.Sprintf("(↑ %s)", best)))
				}
			}
			if v.RelatedCount > 1 {
				parts = append(parts, ui.StyleVersion.Render(fmt.Sprintf("[%d related]", v.RelatedCount)))
			}
			fmt.Fprintln(w, "  "+ui.StyleVersion.Render("• ")+strings.Join(parts, " "))

			if v.Summary != "" && len(v.Summary) < 120 {
				fmt.Fprintln(w, "    "+ui.StyleSymbol.Render(strings.TrimSpace(v.Summary)))
			}
			if opts.showSymbols && len(v.AffectedImports) > 0 {
				lines := formatImportSummaries(v.AffectedImports, 3, 4)
				if len(lines) > 0 {
					fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Symbol hints (Go/OSV):"))
					for _, line := range lines {
						fmt.Fprintln(w, "      "+ui.StylePath.Render(line))
					}
				}
			}
			if opts.showDatabaseInfo {
				if dbLines := formatDatabaseSpecificInfo(v.DatabaseSpecific, 3); len(dbLines) > 0 {
					fmt.Fprintln(w, "    "+ui.StyleMeta.Render("Database info:"))
					for _, line := range dbLines {
						fmt.Fprintln(w, "      "+ui.StyleMeta.Render(line))
					}
				}
			}
			if len(v.SecondaryIDs) > 0 {
				aliases := append([]string(nil), v.SecondaryIDs...)
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
			} else if v.HiddenAliasCount > 0 {
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

// manifestDisplayEntry represents a single manifest file in the display context.
type manifestDisplayEntry struct {
	Path   string
	Groups []string
}

// manifestDisplayGroup represents a group of manifests managed by a specific package manager.
type manifestDisplayGroup struct {
	Manager string
	Entries []manifestDisplayEntry
}

// artifactDisplayGroup represents a group of artifacts managed by a specific package manager.
type artifactDisplayGroup struct {
	Manager string
	Entries []string
}

// manifestDisplayContext holds the organized structure of sources and artifacts for display.
type manifestDisplayContext struct {
	Sources   []manifestDisplayGroup
	Artifacts []artifactDisplayGroup
}

// buildManifestDisplayContext constructs a manifestDisplayContext from a list of consolidated vulnerabilities.
func buildManifestDisplayContext(list []analysis.ConsolidatedVulnerability) manifestDisplayContext {
	ctx := manifestDisplayContext{}
	if len(list) == 0 {
		return ctx
	}
	manifestPaths := collections.NewSet[string]()
	groupEntries := map[string]map[string]*manifestDisplayEntry{}
	displayGroups := map[string]*manifestDisplayGroup{}
	manifestManagers := map[string]string{}
	dirManagers := map[string]string{}
	for _, v := range list {
		for _, ref := range v.ManifestRefs {
			path := strings.TrimSpace(ref.Path)
			manager := strings.TrimSpace(ref.Manager)
			if path == "" && manager == "" {
				continue
			}
			if path != "" {
				manifestPaths.Add(path)
				manifestManagers[path] = manager
				dir := strings.TrimPrefix(pathpkg.Dir(path), "./")
				if dir == "." {
					dir = ""
				}
				if manager != "" {
					dirManagers[dir] = manager
				}
			}
			key := strings.ToLower(manager)
			entries := groupEntries[key]
			if entries == nil {
				entries = map[string]*manifestDisplayEntry{}
				groupEntries[key] = entries
			}
			entry := entries[path]
			if entry == nil {
				entry = &manifestDisplayEntry{Path: path}
				entries[path] = entry
			}
			entry.Groups = mergeGroupNames(entry.Groups, ref.Groups)
			grp := displayGroups[key]
			if grp == nil {
				grp = &manifestDisplayGroup{Manager: manager}
				displayGroups[key] = grp
			}
			if manager != "" {
				grp.Manager = manager
			}
		}
	}

	managerKeys := slices.SortedFunc(maps.Keys(groupEntries), func(a, b string) int {
		ra := analysis.ManagerRank(a)
		rb := analysis.ManagerRank(b)
		if ra != rb {
			return cmp.Compare(ra, rb)
		}
		return strings.Compare(a, b)
	})

	for _, key := range managerKeys {
		entries := groupEntries[key]
		grp := displayGroups[key]
		if grp == nil {
			grp = &manifestDisplayGroup{Manager: key}
		}
		entryList := make([]manifestDisplayEntry, 0, len(entries))
		for _, entry := range entries {
			entry.Groups = uniqueSortedStrings(entry.Groups)
			entryList = append(entryList, *entry)
		}
		slices.SortFunc(entryList, func(a, b manifestDisplayEntry) int {
			return strings.Compare(a.Path, b.Path)
		})
		grp.Entries = entryList
		if grp.Manager == "" && len(entryList) > 0 {
			grp.Manager = key
		}
		ctx.Sources = append(ctx.Sources, *grp)
	}

	artifactGroups := map[string]collections.Set[string]{}
	artifactManagerNames := map[string]string{}
	for _, v := range list {
		for _, loc := range v.Locations {
			loc = strings.TrimSpace(loc)
			if loc == "" {
				continue
			}
			if manifestPaths.Has(loc) {
				continue
			}
			mgr := inferArtifactManager(loc, manifestManagers, dirManagers)
			key := strings.ToLower(mgr)
			if mgr == "" {
				key = ""
			}
			set := artifactGroups[key]
			if set == nil {
				set = collections.NewSet[string]()
				artifactGroups[key] = set
			}
			if !set.Add(loc) {
				continue
			}
			artifactManagerNames[key] = mgr
		}
	}

	artifactKeys := slices.SortedFunc(maps.Keys(artifactGroups), func(a, b string) int {
		ra := analysis.ManagerRank(artifactManagerNames[a])
		rb := analysis.ManagerRank(artifactManagerNames[b])
		if ra != rb {
			return cmp.Compare(ra, rb)
		}
		return strings.Compare(artifactManagerNames[a], artifactManagerNames[b])
	})

	for _, key := range artifactKeys {
		set := artifactGroups[key]
		entries := set.Slice()
		slices.Sort(entries)
		ctx.Artifacts = append(ctx.Artifacts, artifactDisplayGroup{
			Manager: artifactManagerNames[key],
			Entries: entries,
		})
	}
	return ctx
}

// lockfileManagers maps lockfile suffixes to their package managers.
var lockfileManagers = map[string]string{
	"package-lock.json": "npm",
	"yarn.lock":         "yarn",
	"pnpm-lock.yaml":    "pnpm",
	"composer.lock":     "composer",
	"Gemfile.lock":      "bundler",
	"Cargo.lock":        "cargo",
	"requirements.txt":  "pip",
	"poetry.lock":       "poetry",
	"package.json":      "npm",
}

// inferArtifactManager attempts to determine the package manager for a given artifact path.
func inferArtifactManager(path string, manifestManagers map[string]string, dirManagers map[string]string) string {
	if mgr := manifestManagers[path]; mgr != "" {
		return mgr
	}
	dir := strings.TrimPrefix(pathpkg.Dir(path), "./")
	if dir == "." {
		dir = ""
	}
	if mgr := dirManagers[dir]; mgr != "" {
		return mgr
	}
	if strings.HasSuffix(path, "go.sum") {
		candidate := strings.TrimSuffix(path, "go.sum") + "go.mod"
		if mgr := manifestManagers[candidate]; mgr != "" {
			return mgr
		}
		return "go"
	}
	for suffix, mgr := range lockfileManagers {
		if strings.HasSuffix(path, suffix) {
			return mgr
		}
	}
	return ""
}

// renderManifestContext writes the context (sources and artifacts) for a list of vulnerabilities.
func renderManifestContext(w io.Writer, list []analysis.ConsolidatedVulnerability) {
	ctx := buildManifestDisplayContext(list)
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

// mergeGroupNames merges two lists of group names, ensuring uniqueness and case-insensitivity.
func mergeGroupNames(base []string, extra []string) []string {
	set := collections.NewSet[string]()
	for _, g := range base {
		set.Add(strings.ToLower(g))
	}
	for _, g := range extra {
		gTrim := strings.TrimSpace(g)
		if gTrim == "" {
			continue
		}
		key := strings.ToLower(gTrim)
		if !set.Add(key) {
			continue
		}
		base = append(base, gTrim)
	}
	return base
}

// uniqueSortedStrings returns a sorted list of unique strings from the input.
func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	set := collections.NewSet[string]()
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !set.Add(v) {
			continue
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// RenderVulnerabilitySummaryAndActions writes the summary and recommended
// actions for a set of vulnerabilities without reprinting the list header.
func RenderVulnerabilitySummaryAndActions(w io.Writer, vulns []analysis.Vulnerability) {
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleAdded.Render("✓ No vulnerabilities found"))
		return
	}
	consolidated := analysis.CategorizeVulnerabilities(vulns)

	fmt.Fprintln(w)
	fmt.Fprintln(w, ui.StyleHeader.Render("Vulnerability Summary:"))
	high := consolidated.CriticalSev + consolidated.HighSeverity
	if high > 0 {
		fmt.Fprintln(w, "  "+ui.StyleSymbol.Render(ui.StyleRemoved.Render("!"))+" "+ui.StyleSymbol.Render(fmt.Sprintf("%d require immediate attention ", high))+ui.StyleRemoved.Render("(critical/high severity)"))
	}
	if consolidated.FixAvailable > 0 {
		fmt.Fprintln(w, "  "+ui.StyleSymbol.Render(ui.StyleUpgraded.Render("↑"))+" "+ui.StyleSymbol.Render(fmt.Sprintf("%d can be fixed by upgrading", consolidated.FixAvailable)))
	}
	unfixed := consolidated.UniqueVulns - consolidated.FixAvailable
	if unfixed > 0 {
		fmt.Fprintln(w, "  "+ui.StyleSymbol.Render(ui.StyleRemoved.Render("-"))+" "+ui.StyleSymbol.Render(fmt.Sprintf("%d have no fix available yet", unfixed)))
	}

	commands, stdlibRec := remediation.CommandsFromVulnerabilities(vulns)
	if len(commands) > 0 || stdlibRec != "" || unfixed > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleHeader.Render("Recommended Actions:"))
		step := 1
		if stdlibRec != "" {
			fmt.Fprintf(w, "  %d. %s %s %s\n", step, ui.StyleBold.Render("Upgrade Go toolchain to"), ui.StyleUpgraded.Render(stdlibRec), ui.StyleVersion.Render("(update 'go' directive in go.mod)"))
			step++
		}
		if len(commands) > 0 {
			high := consolidated.CriticalSev + consolidated.HighSeverity
			header := "Upgrade affected modules"
			if high > 0 {
				header = "Upgrade critical/high modules first"
			}
			fmt.Fprintf(w, "  %d. %s\n", step, ui.StyleBold.Render(header))
			renderRemediationCommands(w, commands, "       ", "         ")
			step++
		}
		if unfixed > 0 {
			fmt.Fprintf(w, "  %d. %s %s\n", step, ui.StyleBold.Render("Investigate remaining unfixed vulnerabilities"), ui.StyleVersion.Render("(monitor upstream / consider alternatives)"))
		}
	}
}
