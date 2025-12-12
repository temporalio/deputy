package remediation

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/collections"
	"golang.org/x/mod/semver"
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

// packageUpgrade represents a suggested dependency update to resolve a vulnerability.
// It contains details about the package, the current version, and the target version.
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
	if stdlib != "" {
		if toolchainCmd, ok := buildGoToolchainCommand(stdlib); ok {
			cmds = append(cmds, toolchainCmd)
		}
	}
	slices.SortFunc(cmds, func(a, b Command) int {
		if n := cmp.Compare(a.managerRank, b.managerRank); n != 0 {
			return n
		}
		if n := strings.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		return strings.Compare(a.Command, b.Command)
	})
	return cmds, stdlib
}

// buildUpgradeRecommendations analyzes consolidated vulnerabilities to determine
// the best fixed versions for each affected package. It separates standard library
// upgrades from regular dependency upgrades. When multiple vulnerabilities affect
// the same package, it recommends the highest required version to fix all issues.
func buildUpgradeRecommendations(cons []analysis.ConsolidatedVulnerability) ([]packageUpgrade, string) {
	var stdlibRec string

	// Track the best (highest) recommended version per package
	pkgBest := map[string]*packageUpgrade{}

	for _, v := range cons {
		if len(v.FixedVersions) == 0 {
			continue
		}
		best := analysis.FindBestFixedVersion(v.FixedVersions, v.Version)
		if best == "" {
			continue
		}
		if strings.EqualFold(v.Package, "stdlib") {
			if stdlibRec == "" || compareVersions(best, stdlibRec) > 0 {
				stdlibRec = best
			}
			continue
		}

		existing, ok := pkgBest[v.Package]
		if !ok {
			pkgBest[v.Package] = &packageUpgrade{
				Name:        v.Package,
				Current:     v.Version,
				Recommended: best,
				IsDirect:    v.IsDirect,
				Ecosystem:   v.Ecosystem,
				References:  v.ManifestRefs,
				Locations:   v.Locations,
			}
		} else {
			// Keep the higher recommended version
			if compareVersions(best, existing.Recommended) > 0 {
				existing.Recommended = best
			}
			// Merge references
			existing.References = mergeManifestRefs(existing.References, v.ManifestRefs)
			existing.Locations = mergeStrings(existing.Locations, v.Locations)
			// IsDirect if any vuln is direct
			if v.IsDirect {
				existing.IsDirect = true
			}
		}
	}

	upgrades := make([]packageUpgrade, 0, len(pkgBest))
	for _, u := range pkgBest {
		upgrades = append(upgrades, *u)
	}

	return upgrades, stdlibRec
}

// compareVersions compares two version strings. Returns >0 if a > b, <0 if a < b, 0 if equal.
// Handles both semver (v1.2.3) and Go-style versions.
func compareVersions(a, b string) int {
	// Normalize to semver format
	aNorm := normalizeVersion(a)
	bNorm := normalizeVersion(b)

	// Use semver comparison if both are valid
	if semver.IsValid(aNorm) && semver.IsValid(bNorm) {
		return semver.Compare(aNorm, bNorm)
	}

	// Fallback to string comparison
	return strings.Compare(a, b)
}

// normalizeVersion ensures the version has a "v" prefix for semver comparison.
func normalizeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return v
	}
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}
	return v
}

// mergeManifestRefs combines two slices of manifest references, deduplicating by path+manager.
func mergeManifestRefs(a, b []analysis.ManifestReference) []analysis.ManifestReference {
	seen := collections.NewSet[string]()
	result := make([]analysis.ManifestReference, 0, len(a)+len(b))
	for _, ref := range a {
		key := ref.Path + "|" + ref.Manager
		if seen.Add(key) {
			result = append(result, ref)
		}
	}
	for _, ref := range b {
		key := ref.Path + "|" + ref.Manager
		if seen.Add(key) {
			result = append(result, ref)
		}
	}
	return result
}

// mergeStrings combines two slices of strings, deduplicating.
func mergeStrings(a, b []string) []string {
	seen := collections.NewSet[string]()
	result := make([]string, 0, len(a)+len(b))
	for _, s := range a {
		if seen.Add(s) {
			result = append(result, s)
		}
	}
	for _, s := range b {
		if seen.Add(s) {
			result = append(result, s)
		}
	}
	return result
}

// dedupeCommands converts a list of package upgrades into a set of unique,
// executable commands. It handles deduplication logic to avoid suggesting
// the same fix multiple times for the same context.
func dedupeCommands(upgrades []packageUpgrade) []Command {
	commands := []Command{}
	seen := collections.NewSet[string]()
	goManagerPresent := false
	goPaths := collections.NewSet[string]()

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
			if !seen.Add(key) {
				continue
			}
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
					goPaths.Add(pathStr)
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
		paths := goPaths.Slice()
		slices.Sort(paths)
		for _, path := range paths {
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

func buildGoToolchainCommand(version string) (Command, bool) {
	trimmed := strings.TrimSpace(version)
	if trimmed == "" {
		return Command{}, false
	}
	goVersion := strings.TrimPrefix(trimmed, "v")
	if goVersion == "" {
		return Command{}, false
	}
	cmd := fmt.Sprintf("go get go@%s", goVersion)
	return Command{
		Manager:     "go",
		managerRank: managerRank("go"),
		Command:     cmd,
		Path:        "go.mod",
		Hint:        "updates go directive",
		Executable:  true,
	}, true
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
	lookup := collections.NewSet[string]()
	for _, g := range groups {
		lookup.Add(strings.ToLower(g))
	}
	for _, c := range candidates {
		if lookup.Has(strings.ToLower(c)) {
			return true
		}
	}
	return false
}

func uniqueSortedStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v != "" {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
