package cmd

import (
	"fmt"
	"sort"
	"strings"

	pathpkg "path"

	"github.com/charmbracelet/lipgloss"
	analysis "github.com/picatz/deputy/internal/analysis"
	remediation "github.com/picatz/deputy/internal/remediation"
	ui "github.com/picatz/deputy/internal/ui"
)

// DisplayVulnerabilities renders a styled vulnerability report with the default heading.
func DisplayVulnerabilities(vulns []analysis.Vulnerability) {
	DisplayVulnerabilitiesWithHeader(vulns, "Vulnerabilities Found:")
}

// DisplayPolicyFindings renders any policy actions emitted during a command.
func DisplayPolicyFindings(findings []PolicyFinding) {
	if len(findings) == 0 {
		return
	}
	fmt.Println("\n" + ui.StyleHeader.Render("Policy Findings:"))
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
		fmt.Println(line)

		msg := strings.TrimSpace(firstNonEmpty(f.Reason, f.Message))
		if msg != "" {
			fmt.Println("    " + ui.StyleSymbol.Render("• ") + msg)
		}
		if rem := strings.TrimSpace(f.Remediation); rem != "" {
			fmt.Println("    " + ui.StyleMeta.Render("Remediation: ") + rem)
		}
	}
}

// DisplayVulnerabilitiesWithHeader renders a styled vulnerability report to stdout using the provided heading.
func DisplayVulnerabilitiesWithHeader(vulns []analysis.Vulnerability, heading string) {
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		fmt.Println("\n" + ui.StyleAdded.Render("✓ No vulnerabilities found"))
		return
	}
	fmt.Println("\n" + ui.StyleDowngraded.Render("∴ ") + ui.StyleHeader.Render(heading))

	RenderVulnerabilityList(vulns)

	RenderVulnerabilitySummaryAndActions(vulns)
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

// managerRank returns a ranking integer for package managers to enforce a consistent display order.
func managerRank(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "go":
		return 0
	case "npm":
		return 1
	case "pnpm":
		return 2
	case "yarn":
		return 3
	case "composer":
		return 4
	case "gem":
		return 5
	case "cargo":
		return 6
	case "pip":
		return 7
	case "pipenv":
		return 8
	case "poetry":
		return 9
	case "maven":
		return 10
	case "gradle":
		return 11
	default:
		return 100
	}
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

// RenderVulnerabilityList prints per-package vulnerability details without headings or summary.
// Used by diff to compose combined views.
func RenderVulnerabilityList(vulns []analysis.Vulnerability) {
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		return
	}

	byPkg := map[string][]analysis.ConsolidatedVulnerability{}
	for _, v := range cons {
		byPkg[v.Package] = append(byPkg[v.Package], v)
	}

	pkgNames := make([]string, 0, len(byPkg))
	for pkg := range byPkg {
		pkgNames = append(pkgNames, pkg)
	}
	sort.Strings(pkgNames)

	for _, pkg := range pkgNames {
		list := byPkg[pkg]
		if len(list) == 0 {
			continue
		}
		sort.SliceStable(list, func(i, j int) bool {
			pi, si := consolidatedSeverityPriority(list[i])
			pj, sj := consolidatedSeverityPriority(list[j])
			if pi != pj {
				return pi > pj
			}
			if si != sj {
				return si > sj
			}
			return list[i].PrimaryID < list[j].PrimaryID
		})

		hasDirect := false
		for _, v := range list {
			if v.IsDirect {
				hasDirect = true
				break
			}
		}
		depType := ui.StyleVersion.Render("[indirect]")
		if hasDirect {
			depType = ui.StyleUpgraded.Render("[direct]")
		}
		fmt.Printf("\n%s %s %s:\n", ui.StylePackageName.Render(pkg), ui.StyleVersion.Render(list[0].Version), depType)

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
			fmt.Println("  " + ui.StyleVersion.Render("• ") + strings.Join(parts, " "))

			if v.Summary != "" && len(v.Summary) < 120 {
				fmt.Println("    " + ui.StyleSymbol.Render(strings.TrimSpace(v.Summary)))
			}
			if len(v.SecondaryIDs) > 0 {
				aliases := append([]string(nil), v.SecondaryIDs...)
				sort.Strings(aliases)
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
				fmt.Println("    " + aliasRow)
			} else if v.HiddenAliasCount > 0 {
				aliasRow := lipgloss.JoinHorizontal(
					lipgloss.Top,
					ui.StyleMeta.Render("Aliases:"),
					lipgloss.NewStyle().MarginLeft(1).Render(ui.StyleMeta.Render(fmt.Sprintf("(+%d more)", v.HiddenAliasCount))),
				)
				fmt.Println("    " + aliasRow)
			}
			if v.Published != "" && len(v.Published) >= 10 {
				metaBlock := lipgloss.JoinHorizontal(lipgloss.Top, ui.StyleMeta.Render("Published:"), lipgloss.NewStyle().MarginLeft(1).Faint(true).Render(v.Published[:10]))
				fmt.Println("    " + metaBlock)
			}
		}

		renderManifestContext(list)
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
	manifestPaths := map[string]struct{}{}
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
				manifestPaths[path] = struct{}{}
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

	managerKeys := make([]string, 0, len(groupEntries))
	for key := range groupEntries {
		managerKeys = append(managerKeys, key)
	}
	sort.Slice(managerKeys, func(i, j int) bool {
		ri := managerRank(managerKeys[i])
		rj := managerRank(managerKeys[j])
		if ri != rj {
			return ri < rj
		}
		return managerKeys[i] < managerKeys[j]
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
		sort.Slice(entryList, func(i, j int) bool {
			return entryList[i].Path < entryList[j].Path
		})
		grp.Entries = entryList
		if grp.Manager == "" && len(entryList) > 0 {
			grp.Manager = key
		}
		ctx.Sources = append(ctx.Sources, *grp)
	}

	artifactGroups := map[string]map[string]struct{}{}
	artifactManagerNames := map[string]string{}
	for _, v := range list {
		for _, loc := range v.Locations {
			loc = strings.TrimSpace(loc)
			if loc == "" {
				continue
			}
			if _, ok := manifestPaths[loc]; ok {
				continue
			}
			mgr := inferArtifactManager(loc, manifestManagers, dirManagers)
			key := strings.ToLower(mgr)
			if mgr == "" {
				key = ""
			}
			set := artifactGroups[key]
			if set == nil {
				set = map[string]struct{}{}
				artifactGroups[key] = set
			}
			if _, ok := set[loc]; ok {
				continue
			}
			set[loc] = struct{}{}
			artifactManagerNames[key] = mgr
		}
	}

	artifactKeys := make([]string, 0, len(artifactGroups))
	for key := range artifactGroups {
		artifactKeys = append(artifactKeys, key)
	}
	sort.Slice(artifactKeys, func(i, j int) bool {
		ri := managerRank(artifactManagerNames[artifactKeys[i]])
		rj := managerRank(artifactManagerNames[artifactKeys[j]])
		if ri != rj {
			return ri < rj
		}
		return artifactManagerNames[artifactKeys[i]] < artifactManagerNames[artifactKeys[j]]
	})

	for _, key := range artifactKeys {
		set := artifactGroups[key]
		entries := make([]string, 0, len(set))
		for loc := range set {
			entries = append(entries, loc)
		}
		sort.Strings(entries)
		ctx.Artifacts = append(ctx.Artifacts, artifactDisplayGroup{
			Manager: artifactManagerNames[key],
			Entries: entries,
		})
	}
	return ctx
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
	switch {
	case strings.HasSuffix(path, "package-lock.json"):
		return "npm"
	case strings.HasSuffix(path, "yarn.lock"):
		return "yarn"
	case strings.HasSuffix(path, "pnpm-lock.yaml"):
		return "pnpm"
	case strings.HasSuffix(path, "composer.lock"):
		return "composer"
	case strings.HasSuffix(path, "Gemfile.lock"):
		return "bundler"
	case strings.HasSuffix(path, "Cargo.lock"):
		return "cargo"
	case strings.HasSuffix(path, "requirements.txt"):
		return "pip"
	case strings.HasSuffix(path, "poetry.lock"):
		return "poetry"
	case strings.HasSuffix(path, "package.json"):
		return "npm"
	}
	return ""
}

// renderManifestContext prints the context (sources and artifacts) for a list of vulnerabilities.
func renderManifestContext(list []analysis.ConsolidatedVulnerability) {
	ctx := buildManifestDisplayContext(list)
	if len(ctx.Sources) == 0 && len(ctx.Artifacts) == 0 {
		return
	}
	fmt.Println("    " + ui.StyleMeta.Render("Context:"))
	sourceEntryCount := 0
	for _, grp := range ctx.Sources {
		sourceEntryCount += len(grp.Entries)
	}
	if sourceEntryCount > 0 {
		fmt.Println("      " + ui.StyleMeta.Render("Sources:"))
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
				fmt.Println("        " + ui.StyleSymbol.Render("• ") + strings.Join(lineParts, " "))
			}
		}
	}
	if len(ctx.Artifacts) > 0 {
		fmt.Println("      " + ui.StyleMeta.Render("Artifacts:"))
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
				fmt.Println("        " + ui.StyleSymbol.Render("• ") + strings.Join(lineParts, " "))
			}
		}
	}
}

// mergeGroupNames merges two lists of group names, ensuring uniqueness and case-insensitivity.
func mergeGroupNames(base []string, extra []string) []string {
	set := map[string]struct{}{}
	for _, g := range base {
		set[strings.ToLower(g)] = struct{}{}
	}
	for _, g := range extra {
		gTrim := strings.TrimSpace(g)
		if gTrim == "" {
			continue
		}
		key := strings.ToLower(gTrim)
		if _, ok := set[key]; ok {
			continue
		}
		set[key] = struct{}{}
		base = append(base, gTrim)
	}
	return base
}

// uniqueSortedStrings returns a sorted list of unique strings from the input.
func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// RenderVulnerabilitySummaryAndActions prints the summary and recommended
// actions for a set of vulnerabilities without reprinting the list header.
func RenderVulnerabilitySummaryAndActions(vulns []analysis.Vulnerability) {
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		fmt.Println("\n" + ui.StyleAdded.Render("✓ No vulnerabilities found"))
		return
	}
	consolidated := analysis.CategorizeVulnerabilities(vulns)

	fmt.Println("\n" + ui.StyleHeader.Render("Vulnerability Summary:"))
	high := consolidated.CriticalSev + consolidated.HighSeverity
	if high > 0 {
		fmt.Println("  " + ui.StyleSymbol.Render(ui.StyleRemoved.Render("!")) + " " + ui.StyleSymbol.Render(fmt.Sprintf("%d require immediate attention ", high)) + ui.StyleRemoved.Render("(critical/high severity)"))
	}
	if consolidated.FixAvailable > 0 {
		fmt.Println("  " + ui.StyleSymbol.Render(ui.StyleUpgraded.Render("↑")) + " " + ui.StyleSymbol.Render(fmt.Sprintf("%d can be fixed by upgrading", consolidated.FixAvailable)))
	}
	unfixed := consolidated.UniqueVulns - consolidated.FixAvailable
	if unfixed > 0 {
		fmt.Println("  " + ui.StyleSymbol.Render(ui.StyleRemoved.Render("-")) + " " + ui.StyleSymbol.Render(fmt.Sprintf("%d have no fix available yet", unfixed)))
	}

	commands, stdlibRec := remediation.CommandsFromVulnerabilities(vulns)
	if len(commands) > 0 || stdlibRec != "" || unfixed > 0 {
		fmt.Println("\n" + ui.StyleHeader.Render("Recommended Actions:"))
		step := 1
		if stdlibRec != "" {
			fmt.Printf("  %d. %s %s %s\n", step, ui.StyleBold.Render("Upgrade Go toolchain to"), ui.StyleUpgraded.Render(stdlibRec), ui.StyleVersion.Render("(update 'go' directive in go.mod)"))
			step++
		}
		if len(commands) > 0 {
			high := consolidated.CriticalSev + consolidated.HighSeverity
			header := "Upgrade affected modules"
			if high > 0 {
				header = "Upgrade critical/high modules first"
			}
			fmt.Printf("  %d. %s\n", step, ui.StyleBold.Render(header))
			renderRemediationCommands(commands, "       ", "         ")
			step++
		}
		if unfixed > 0 {
			fmt.Printf("  %d. %s %s\n", step, ui.StyleBold.Render("Investigate remaining unfixed vulnerabilities"), ui.StyleVersion.Render("(monitor upstream / consider alternatives)"))
		}
	}
}
