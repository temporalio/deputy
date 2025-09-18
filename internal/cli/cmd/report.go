package cmd

import (
	"fmt"
	"sort"
	"strings"

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

type packageUpgrade struct {
	Name        string
	Current     string
	Recommended string
	IsDirect    bool
	Ecosystem   string
	References  []analysis.ManifestReference
	Locations   []string
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
			if refs[i].Manager == refs[j].Manager {
				return refs[i].Path < refs[j].Path
			}
			return refs[i].Manager < refs[j].Manager
		})
		locs := make([]string, 0, len(a.locations))
		for loc := range a.locations {
			locs = append(locs, loc)
		}
		sort.Strings(locs)
		out = append(out, packageUpgrade{
			Name:        name,
			Current:     a.current,
			Recommended: a.rec,
			IsDirect:    a.isDirect,
			Ecosystem:   a.ecosystem,
			References:  refs,
			Locations:   locs,
		})
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].IsDirect && !out[i].IsDirect || (out[j].IsDirect == out[i].IsDirect && out[j].Name < out[i].Name) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
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

// RenderVulnerabilityList prints only the per-package vulnerability details
// without headings or summary. Used by diff to compose combined views.
func RenderVulnerabilityList(vulns []analysis.Vulnerability) {
	cons := analysis.ConsolidateVulnerabilities(vulns)
	if len(cons) == 0 {
		return
	}

	byPkg := map[string][]analysis.ConsolidatedVulnerability{}
	for _, v := range cons {
		byPkg[v.Package] = append(byPkg[v.Package], v)
	}

	for pkg, list := range byPkg {
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
		renderManifestContext(list)
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
			fixInfo := ""
			if len(v.FixedVersions) > 0 {
				if best := analysis.FindBestFixedVersion(v.FixedVersions, v.Version); best != "" {
					fixInfo = ui.StyleUpgraded.Render(fmt.Sprintf("(↑ %s)", best))
				}
			}
			consInfo := ""
			if v.RelatedCount > 1 {
				consInfo = ui.StyleVersion.Render(fmt.Sprintf("[%d related]", v.RelatedCount))
			}
			fmt.Println("  " + ui.StyleVersion.Render("• ") + ui.StyleSymbol.Render(v.PrimaryID) + " " + sevDisp + " " + fixInfo + " " + consInfo)
			if v.Summary != "" && len(v.Summary) < 120 {
				fmt.Println("    " + ui.StyleSymbol.Render(v.Summary))
			}
			if len(v.SecondaryIDs) > 0 {
				aliasBlocks := []string{}
				for _, a := range v.SecondaryIDs {
					st := ui.StyleAliasOther
					if strings.HasPrefix(a, "CVE-") {
						st = ui.StyleAlias
					}
					aliasBlocks = append(aliasBlocks, st.Render(a))
				}
				aliasRow := lipgloss.JoinHorizontal(lipgloss.Top, ui.StyleMeta.Render("Aliases:"), lipgloss.NewStyle().MarginLeft(1).Render(strings.Join(aliasBlocks, ", ")))
				fmt.Println("    " + aliasRow)
			}
			if v.Published != "" && len(v.Published) >= 10 {
				metaBlock := lipgloss.JoinHorizontal(lipgloss.Top, ui.StyleMeta.Render("Published:"), lipgloss.NewStyle().MarginLeft(1).Faint(true).Render(v.Published[:10]))
				fmt.Println("    " + metaBlock)
			}
		}
	}
}

func renderManifestContext(list []analysis.ConsolidatedVulnerability) {
	if len(list) == 0 {
		return
	}
	first := list[0]
	if len(first.ManifestRefs) == 0 && len(first.Locations) == 0 {
		return
	}
	fmt.Println("    " + ui.StyleMeta.Render("Sources:"))
	for _, ref := range first.ManifestRefs {
		if ref.Path == "" && ref.Manager == "" {
			continue
		}
		parts := []string{}
		if ref.Path != "" {
			parts = append(parts, ref.Path)
		}
		if ref.Manager != "" {
			parts = append(parts, fmt.Sprintf("(%s)", ref.Manager))
		}
		if len(ref.Groups) > 0 {
			parts = append(parts, "["+strings.Join(ref.Groups, ",")+"]")
		}
		fmt.Println("      " + ui.StyleSymbol.Render("• ") + strings.Join(parts, " "))
	}
	if len(first.Locations) > 0 {
		fmt.Println("    " + ui.StyleMeta.Render("Artifacts:"))
		for _, loc := range first.Locations {
			fmt.Println("      " + ui.StyleSymbol.Render("• ") + loc)
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
			printedGoTidy := false
			for _, u := range upgrades {
				for _, ref := range u.References {
					cmd, hint := recommendCommand(ref.Manager, u.Name, u.Recommended, ref.Groups)
					if cmd == "" {
						cmd = fmt.Sprintf("Update %s to %s", u.Name, u.Recommended)
					}
					marker := ui.StyleVersion.Render("•")
					if u.IsDirect {
						marker = ui.StyleUpgraded.Render("•")
					}
					contextParts := []string{}
					if ref.Path != "" {
						contextParts = append(contextParts, ref.Path)
					}
					if len(ref.Groups) > 0 {
						contextParts = append(contextParts, strings.Join(ref.Groups, ","))
					}
					if hint != "" {
						contextParts = append(contextParts, hint)
					}
					ctx := ""
					if len(contextParts) > 0 {
						ctx = "  # " + strings.Join(contextParts, "; ")
					}
					fmt.Printf("       %s %s%s\n", marker, cmd, ctx)
					if ref.Manager == "go" {
						printedGoTidy = true
					}
				}
			}
			if printedGoTidy {
				fmt.Println("       " + ui.StyleVersion.Render("•") + " go mod tidy")
			}
			step++
		}
		if unfixed > 0 {
			fmt.Printf("  %d. %s %s\n", step, ui.StyleBold.Render("Investigate remaining unfixed vulnerabilities"), ui.StyleVersion.Render("(monitor upstream / consider alternatives)"))
		}
	}
}
