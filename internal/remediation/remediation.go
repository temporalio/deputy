package remediation

import (
	"fmt"
	"path"
	"sort"
	"strings"

	analysis "github.com/picatz/deputy/internal/analysis"
)

// Command represents an actionable remediation step (shell command or manual edit).
type Command struct {
	Manager     string
	Command     string
	Path        string
	Groups      []string
	Hint        string
	IsDirect    bool
	Executable  bool
	managerRank int
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

// CommandsFromVulnerabilities derives recommended commands and stdlib upgrades.
func CommandsFromVulnerabilities(vs []analysis.Vulnerability) ([]Command, string) {
	cons := analysis.ConsolidateVulnerabilities(vs)
	upgrades, stdlib := buildUpgradeRecommendations(cons)
	cmds := dedupeCommands(upgrades)
	sort.Slice(cmds, func(i, j int) bool {
		if cmds[i].managerRank == cmds[j].managerRank {
			if cmds[i].Path == cmds[j].Path {
				return cmds[i].Command < cmds[j].Command
			}
			return cmds[i].Path < cmds[j].Path
		}
		return cmds[i].managerRank < cmds[j].managerRank
	})
	return cmds, stdlib
}

func buildUpgradeRecommendations(cons []analysis.ConsolidatedVulnerability) ([]packageUpgrade, string) {
	var stdlibRec string
	upgrades := []packageUpgrade{}

	for _, v := range cons {
		if v.FixedVersions == nil || len(v.FixedVersions) == 0 {
			continue
		}
		best := analysis.FindBestFixedVersion(v.FixedVersions, v.Version)
		if best == "" {
			continue
		}
		if strings.EqualFold(v.Package, "stdlib") {
			if stdlibRec == "" || best > stdlibRec {
				stdlibRec = best
			}
			continue
		}
		upgrades = append(upgrades, packageUpgrade{
			Name:        v.Package,
			Current:     v.Version,
			Recommended: best,
			IsDirect:    v.IsDirect,
			Ecosystem:   v.Ecosystem,
			References:  v.ManifestRefs,
			Locations:   v.Locations,
		})
	}

	return upgrades, stdlibRec
}

func dedupeCommands(upgrades []packageUpgrade) []Command {
	commands := []Command{}
	seen := map[string]struct{}{}
	goManagerPresent := false
	goPaths := map[string]struct{}{}

	for _, u := range upgrades {
		for _, ref := range u.References {
			cmd, hint, executable := recommendCommand(ref.Manager, ref.Path, u.Name, u.Recommended, ref.Groups)
			if cmd == "" {
				continue
			}
			pathStr := strings.TrimSpace(ref.Path)
			groups := uniqueSortedStrings(ref.Groups)
			groupsKey := strings.Join(groups, ",")
			key := strings.Join([]string{
				strings.ToLower(strings.TrimSpace(ref.Manager)),
				cmd,
				pathStr,
				groupsKey,
				hint,
				fmt.Sprintf("%t", u.IsDirect),
			}, "|")
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			manager := strings.TrimSpace(ref.Manager)
			commands = append(commands, Command{
				Manager:     manager,
				managerRank: managerRank(manager),
				Command:     cmd,
				Path:        pathStr,
				Groups:      groups,
				Hint:        hint,
				IsDirect:    u.IsDirect,
				Executable:  executable,
			})
			if strings.EqualFold(manager, "go") {
				goManagerPresent = true
				if pathStr != "" {
					goPaths[pathStr] = struct{}{}
				}
			}
		}
	}

	if goManagerPresent && len(goPaths) == 0 {
		commands = append(commands, Command{
			Manager:     "go",
			managerRank: managerRank("go"),
			Command:     "go mod tidy",
			Executable:  true,
		})
	} else if len(goPaths) > 0 {
		for path := range goPaths {
			commands = append(commands, Command{
				Manager:     "go",
				managerRank: managerRank("go"),
				Command:     "go mod tidy",
				Path:        path,
				Executable:  true,
			})
		}
	}

	return commands
}

func recommendCommand(manager, manifestPath, pkg, version string, groups []string) (string, string, bool) {
	switch strings.ToLower(manager) {
	case "go":
		return fmt.Sprintf("go get %s@%s", pkg, version), "", true
	case "npm":
		flag := npmFlag(groups)
		cmd := fmt.Sprintf("npm install %s@%s", pkg, version)
		if flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return cmd, "", true
	case "yarn":
		flag := yarnFlag(groups)
		cmd := fmt.Sprintf("yarn add %s@%s", pkg, version)
		if flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return cmd, "", true
	case "pnpm":
		flag := npmFlag(groups)
		cmd := fmt.Sprintf("pnpm add %s@%s", pkg, version)
		if flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return cmd, "", true
	case "pip":
		return fmt.Sprintf("pip install --upgrade %s==%s", pkg, version), "", true
	case "pipenv":
		return fmt.Sprintf("pipenv install %s==%s", pkg, version), "", true
	case "poetry":
		return fmt.Sprintf("poetry add %s@%s", pkg, version), "", true
	case "gem":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "gemfile.lock" || base == "gems.locked":
			return fmt.Sprintf("bundle update %s", pkg), "", true
		case base == "gemfile":
			return fmt.Sprintf("Edit Gemfile to require %s >= %s", pkg, version), "run bundle install afterwards", false
		case strings.HasSuffix(strings.ToLower(manifestPath), ".gemspec"):
			return fmt.Sprintf("Edit %s to require %s >= %s", path.Base(manifestPath), pkg, version), "", false
		default:
			return fmt.Sprintf("Update Ruby dependency for %s to %s", pkg, version), "", false
		}
	case "composer":
		return fmt.Sprintf("composer require %s:%s", pkg, version), "", true
	case "cargo":
		return fmt.Sprintf("cargo update -p %s --precise %s", pkg, version), "", true
	case "maven":
		return fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s -DdepVersion=%s", pkg, version), "consider running mvn versions:commit afterwards", true
	case "gradle":
		return fmt.Sprintf("Update dependency declaration for %s to %s", pkg, version), "", false
	}
	return "", "", false
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

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
