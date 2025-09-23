package cmd

import (
	"fmt"
	"sort"
	"strings"

	pathpkg "path"

	"github.com/charmbracelet/lipgloss"
	analysis "github.com/picatz/deputy/internal/analysis"
	ui "github.com/picatz/deputy/internal/ui"
	"golang.org/x/mod/semver"
)

// DisplayVulnerabilities renders a styled vulnerability report with the default heading.

func DisplayVulnerabilities(vulns []analysis.Vulnerability) {
	DisplayVulnerabilitiesWithHeader(vulns, "Vulnerabilities Found:")
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

func scoreLabel(score float64) string {
	switch {
	case score >= 9.0:
		return lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true).Render(fmt.Sprintf("[CRITICAL %.1f]", score))
	case score >= 7.0:
		return ui.StyleRemoved.Render(fmt.Sprintf("[HIGH %.1f]", score))
	case score >= 4.0:
		return ui.StyleDowngraded.Render(fmt.Sprintf("[MED %.1f]", score))
	case score >= 0.0:
		return ui.StyleVersion.Render(fmt.Sprintf("[LOW %.1f]", score))
	default:
		return ui.StyleVersion.Render("[?]")
	}
}

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
	case "bundler":
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

type packageUpgrade struct {
	Name               string
	Current            string
	Recommended        string
	IsDirect           bool
	Ecosystem          string
	References         []analysis.ManifestReference
	Locations          []string
	PrimaryManager     string
	PrimaryManagerRank int
}

type commandRecommendation struct {
	Manager     string
	ManagerRank int
	IsDirect    bool
	Command     string
	Path        string
	Groups      []string
	Hint        string
}

func buildUpgradeRecommendations(vulns []analysis.ConsolidatedVulnerability) ([]packageUpgrade, string) {
	if len(vulns) == 0 {
		return nil, ""
	}
	type agg struct {
		current   string
		isDirect  bool
		rec       string
		ecosystem string
		refs      map[manifestRefKey]analysis.ManifestReference
		locations map[string]struct{}
	}
	byPkg := map[string]*agg{}
	var stdlibRec string
	for _, v := range vulns {
		if v.Package == "" {
			continue
		}
		a := byPkg[v.Package]
		if a == nil {
			a = &agg{
				current:   v.Version,
				isDirect:  v.IsDirect,
				ecosystem: v.Ecosystem,
				refs:      map[manifestRefKey]analysis.ManifestReference{},
				locations: map[string]struct{}{},
			}
			byPkg[v.Package] = a
		} else if v.IsDirect {
			a.isDirect = true
		}
		fix := analysis.FindBestFixedVersion(v.FixedVersions, v.Version)
		if fix == "" {
			continue
		}
		if a.rec == "" || semver.Compare(normalizeGoVersion(fix), normalizeGoVersion(a.rec)) > 0 {
			a.rec = fix
		}
		for _, ref := range v.ManifestRefs {
			key := manifestRefKey{manager: ref.Manager, path: ref.Path}
			existing := a.refs[key]
			existing.Manager = ref.Manager
			existing.Path = ref.Path
			existing.Groups = mergeGroupNames(existing.Groups, ref.Groups)
			a.refs[key] = existing
		}
		for _, loc := range v.Locations {
			if loc == "" {
				continue
			}
			a.locations[loc] = struct{}{}
		}
	}
	var out []packageUpgrade
	for name, a := range byPkg {
		if a.rec == "" {
			continue
		}
		if name == "stdlib" {
			if stdlibRec == "" || semver.Compare(normalizeGoVersion(a.rec), normalizeGoVersion(stdlibRec)) > 0 {
				stdlibRec = a.rec
			}
			continue
		}
		refs := make([]analysis.ManifestReference, 0, len(a.refs))
		for _, ref := range a.refs {
			ref.Groups = uniqueSortedStrings(ref.Groups)
			refs = append(refs, ref)
		}
		sort.Slice(refs, func(i, j int) bool {
			ri, rj := managerRank(refs[i].Manager), managerRank(refs[j].Manager)
			if ri != rj {
				return ri < rj
			}
			if refs[i].Manager != refs[j].Manager {
				return refs[i].Manager < refs[j].Manager
			}
			return refs[i].Path < refs[j].Path
		})
		locs := make([]string, 0, len(a.locations))
		for loc := range a.locations {
			locs = append(locs, loc)
		}
		sort.Strings(locs)
		primaryManager := ""
		primaryRank := 1 << 30
		for _, ref := range refs {
			rank := managerRank(ref.Manager)
			if rank < primaryRank || (rank == primaryRank && ref.Manager < primaryManager) {
				primaryRank = rank
				primaryManager = ref.Manager
			}
		}
		out = append(out, packageUpgrade{
			Name:               name,
			Current:            a.current,
			Recommended:        a.rec,
			IsDirect:           a.isDirect,
			Ecosystem:          a.ecosystem,
			References:         refs,
			Locations:          locs,
			PrimaryManager:     primaryManager,
			PrimaryManagerRank: primaryRank,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IsDirect != out[j].IsDirect {
			return out[i].IsDirect
		}
		if out[i].PrimaryManagerRank != out[j].PrimaryManagerRank {
			return out[i].PrimaryManagerRank < out[j].PrimaryManagerRank
		}
		if out[i].PrimaryManager != out[j].PrimaryManager {
			return out[i].PrimaryManager < out[j].PrimaryManager
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Recommended < out[j].Recommended
	})
	return out, stdlibRec
}

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
			var sevDisp string
			if v.SeverityType == "GHSA" {
				up := strings.ToUpper(v.Severity)
				switch up {
				case "CRITICAL":
					sevDisp = lipgloss.NewStyle().Foreground(lipgloss.Color("#FF00FF")).Bold(true).Render("[CRITICAL]")
				case "HIGH":
					sevDisp = ui.StyleRemoved.Render("[HIGH]")
				case "MEDIUM", "MODERATE":
					sevDisp = ui.StyleDowngraded.Render("[MED]")
				case "LOW":
					sevDisp = ui.StyleVersion.Render("[LOW]")
				default:
					score := analysis.ParseCVSSScore(v.Severity)
					sevDisp = scoreLabel(score)
				}
			} else {
				sevDisp = scoreLabel(analysis.ParseCVSSScore(v.Severity))
			}
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

type manifestDisplayEntry struct {
	Path   string
	Groups []string
}

type manifestDisplayGroup struct {
	Manager string
	Entries []manifestDisplayEntry
}

type artifactDisplayGroup struct {
	Manager string
	Entries []string
}

type manifestDisplayContext struct {
	Sources   []manifestDisplayGroup
	Artifacts []artifactDisplayGroup
}

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

func recommendCommand(manager, pkg, version string, groups []string) (string, string) {
	switch strings.ToLower(manager) {
	case "go":
		return fmt.Sprintf("go get %s@%s", pkg, version), ""
	case "npm":
		flag := npmFlag(groups)
		cmd := fmt.Sprintf("npm install %s@%s", pkg, version)
		if flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return cmd, ""
	case "yarn":
		flag := yarnFlag(groups)
		cmd := fmt.Sprintf("yarn add %s@%s", pkg, version)
		if flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return cmd, ""
	case "pnpm":
		flag := npmFlag(groups)
		cmd := fmt.Sprintf("pnpm add %s@%s", pkg, version)
		if flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return cmd, ""
	case "pip":
		return fmt.Sprintf("pip install --upgrade %s==%s", pkg, version), ""
	case "pipenv":
		return fmt.Sprintf("pipenv install %s==%s", pkg, version), ""
	case "poetry":
		return fmt.Sprintf("poetry add %s@%s", pkg, version), ""
	case "bundler":
		return fmt.Sprintf("bundle update %s", pkg), ""
	case "composer":
		return fmt.Sprintf("composer require %s:%s", pkg, version), ""
	case "cargo":
		return fmt.Sprintf("cargo update -p %s --precise %s", pkg, version), ""
	case "maven":
		return fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s -DdepVersion=%s", pkg, version), "consider running mvn versions:commit afterwards"
	case "gradle":
		return "", "update dependency declaration in build.gradle"
	}
	return "", ""
}

func npmFlag(groups []string) string {
	if hasGroup(groups, "dev", "devdependencies") {
		return "--save-dev"
	}
	if hasGroup(groups, "optional", "optionaldependencies") {
		return "--save-optional"
	}
	if hasGroup(groups, "peer", "peerdependencies") {
		return "--save-peer"
	}
	return ""
}

func yarnFlag(groups []string) string {
	if hasGroup(groups, "dev", "devdependencies") {
		return "--dev"
	}
	if hasGroup(groups, "optional", "optionaldependencies") {
		return "--optional"
	}
	if hasGroup(groups, "peer", "peerdependencies") {
		return "--peer"
	}
	return ""
}

func hasGroup(groups []string, candidates ...string) bool {
	if len(groups) == 0 {
		return false
	}
	lookup := map[string]struct{}{}
	for _, g := range groups {
		lookup[strings.ToLower(g)] = struct{}{}
	}
	for _, c := range candidates {
		if _, ok := lookup[strings.ToLower(c)]; ok {
			return true
		}
	}
	return false
}

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

	upgrades, stdlibRec := buildUpgradeRecommendations(cons)
	if consolidated.FixAvailable > 0 || stdlibRec != "" || unfixed > 0 {
		fmt.Println("\n" + ui.StyleHeader.Render("Recommended Actions:"))
		step := 1
		if stdlibRec != "" {
			fmt.Printf("  %d. %s %s %s\n", step, ui.StyleBold.Render("Upgrade Go toolchain to"), ui.StyleUpgraded.Render(stdlibRec), ui.StyleVersion.Render("(update 'go' directive in go.mod)"))
			step++
		}
		if len(upgrades) > 0 {
			high := consolidated.CriticalSev + consolidated.HighSeverity
			header := "Upgrade affected modules"
			if high > 0 {
				header = "Upgrade critical/high modules first"
			}
			fmt.Printf("  %d. %s\n", step, ui.StyleBold.Render(header))
			var commands []commandRecommendation
			seen := map[string]struct{}{}
			goManagerPresent := false
			goPaths := map[string]struct{}{}
			for _, u := range upgrades {
				for _, ref := range u.References {
					cmd, hint := recommendCommand(ref.Manager, u.Name, u.Recommended, ref.Groups)
					if cmd == "" {
						cmd = fmt.Sprintf("Update %s to %s", u.Name, u.Recommended)
					}
					path := strings.TrimSpace(ref.Path)
					groups := uniqueSortedStrings(append([]string(nil), ref.Groups...))
					groupsKey := strings.Join(groups, ",")
					key := strings.Join([]string{
						strings.ToLower(strings.TrimSpace(ref.Manager)),
						cmd,
						path,
						groupsKey,
						hint,
						fmt.Sprintf("%t", u.IsDirect),
					}, "|")
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					manager := strings.TrimSpace(ref.Manager)
					commands = append(commands, commandRecommendation{
						Manager:     manager,
						ManagerRank: managerRank(manager),
						IsDirect:    u.IsDirect,
						Command:     cmd,
						Path:        path,
						Groups:      groups,
						Hint:        hint,
					})
					if strings.EqualFold(manager, "go") {
						goManagerPresent = true
						if path != "" {
							goPaths[path] = struct{}{}
						}
					}
				}
			}
			if len(goPaths) > 0 {
				pathList := make([]string, 0, len(goPaths))
				for path := range goPaths {
					pathList = append(pathList, path)
				}
				sort.Strings(pathList)
				for _, path := range pathList {
					key := strings.Join([]string{"go", "go mod tidy", path, "", "", "false"}, "|")
					if _, ok := seen[key]; ok {
						continue
					}
					seen[key] = struct{}{}
					commands = append(commands, commandRecommendation{
						Manager:     "go",
						ManagerRank: managerRank("go"),
						Command:     "go mod tidy",
						Path:        path,
					})
				}
			} else if goManagerPresent {
				key := strings.Join([]string{"go", "go mod tidy", "", "", "", "false"}, "|")
				if _, ok := seen[key]; !ok {
					seen[key] = struct{}{}
					commands = append(commands, commandRecommendation{
						Manager:     "go",
						ManagerRank: managerRank("go"),
						Command:     "go mod tidy",
					})
				}
			}
			sort.SliceStable(commands, func(i, j int) bool {
				if commands[i].ManagerRank != commands[j].ManagerRank {
					return commands[i].ManagerRank < commands[j].ManagerRank
				}
				if commands[i].IsDirect != commands[j].IsDirect {
					return commands[i].IsDirect && !commands[j].IsDirect
				}
				if commands[i].Path != commands[j].Path {
					return commands[i].Path < commands[j].Path
				}
				if commands[i].Command != commands[j].Command {
					return commands[i].Command < commands[j].Command
				}
				groupsI := strings.Join(commands[i].Groups, ",")
				groupsJ := strings.Join(commands[j].Groups, ",")
				if groupsI != groupsJ {
					return groupsI < groupsJ
				}
				return commands[i].Hint < commands[j].Hint
			})
			pathOrder := []string{}
			grouped := map[string][]commandRecommendation{}
			groupIsPath := map[string]bool{}
			for _, rec := range commands {
				label := strings.TrimSpace(rec.Path)
				isPath := true
				if label == "" {
					label = strings.TrimSpace(rec.Manager)
					isPath = false
					if label == "" {
						label = "other"
					}
				}
				if _, ok := grouped[label]; !ok {
					pathOrder = append(pathOrder, label)
					groupIsPath[label] = isPath
				}
				grouped[label] = append(grouped[label], rec)
			}
			for _, label := range pathOrder {
				if groupIsPath[label] {
					fmt.Println("       " + ui.StylePath.Render(label) + ":")
				} else {
					fmt.Println("       " + ui.StyleManager.Render(label) + ":")
				}
				for _, rec := range grouped[label] {
					symbol := "›"
					if rec.Command == "go mod tidy" {
						symbol = "↻"
					}
					style := ui.StyleVersion
					if rec.IsDirect {
						style = ui.StyleUpgraded
					}
					marker := style.Render(symbol)
					contexts := []string{}
					if len(rec.Groups) > 0 {
						contexts = append(contexts, strings.Join(rec.Groups, ","))
					}
					if rec.Hint != "" {
						contexts = append(contexts, rec.Hint)
					}
					suffix := ""
					if len(contexts) > 0 {
						suffix = "  # " + strings.Join(contexts, "; ")
					}
					fmt.Printf("         %s %s%s\n", marker, rec.Command, suffix)
				}
			}
			step++
		}
		if unfixed > 0 {
			fmt.Printf("  %d. %s %s\n", step, ui.StyleBold.Render("Investigate remaining unfixed vulnerabilities"), ui.StyleVersion.Render("(monitor upstream / consider alternatives)"))
		}
	}
}
