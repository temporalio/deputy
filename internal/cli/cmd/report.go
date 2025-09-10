package cmd

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	analysis "github.com/picatz/deputy/internal/analysis"
	ui "github.com/picatz/deputy/internal/ui"
	"golang.org/x/mod/semver"
)

// DisplayVulnerabilities renders a styled vulnerability report to stdout.
func DisplayVulnerabilities(vulns []analysis.Vulnerability) {
        cons := analysis.ConsolidateVulnerabilities(vulns)
        if len(cons) == 0 {
                fmt.Println("\n" + ui.StyleAdded.Render("✓ No vulnerabilities found"))
                return
        }
        consolidated := analysis.CategorizeVulnerabilities(vulns)

        fmt.Println("\n" + ui.StyleDowngraded.Render("∴ ") + ui.StyleHeader.Render("Vulnerabilities Found:"))

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

	// Recommended actions section (restores legacy remediation guidance)
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
			for _, u := range upgrades {
				marker := ui.StyleVersion.Render("•")
				if u.IsDirect {
					marker = ui.StyleUpgraded.Render("•")
				}
				fmt.Printf("       %s go get %s@%s\n", marker, ui.StylePackageName.Render(u.Name), ui.StyleVersion.Render(u.Recommended))
			}
			fmt.Println("       " + ui.StyleVersion.Render("•") + " go mod tidy")
			step++
		}
		if unfixed > 0 {
			fmt.Printf("  %d. %s %s\n", step, ui.StyleBold.Render("Investigate remaining unfixed vulnerabilities"), ui.StyleVersion.Render("(monitor upstream / consider alternatives)"))
		}
	}
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
	Name, Current, Recommended string
	IsDirect                   bool
}

func buildUpgradeRecommendations(vulns []analysis.ConsolidatedVulnerability) ([]packageUpgrade, string) {
	if len(vulns) == 0 {
		return nil, ""
	}
	type agg struct {
		current  string
		isDirect bool
		rec      string
	}
	byPkg := map[string]*agg{}
	var stdlibRec string
	for _, v := range vulns {
		if v.Package == "" {
			continue
		}
		a := byPkg[v.Package]
		if a == nil {
			a = &agg{current: v.Version, isDirect: v.IsDirect}
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
		out = append(out, packageUpgrade{Name: name, Current: a.current, Recommended: a.rec, IsDirect: a.isDirect})
	}
	// sort direct first by name
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
