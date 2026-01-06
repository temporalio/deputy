package remediation

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/ecosystem"
	"github.com/picatz/deputy/internal/vulnerability"
	"golang.org/x/mod/semver"
)

// Command represents an actionable remediation step for resolving a vulnerability.
// It can be either an executable shell command or a manual edit instruction.
type Command struct {
	// Manager identifies the package manager (e.g., "go", "npm", "pip", "gem").
	Manager string
	// Command is the shell command to execute or instruction to follow.
	Command string
	// Path is the manifest/lockfile path where this command should be run.
	Path string
	// Groups indicates dependency groups affected (e.g., "dev", "optional" for npm).
	Groups []string
	// Hint provides additional context (e.g., "run bundle install afterwards").
	Hint string
	// IsDirect indicates if the vulnerable package is a direct dependency.
	IsDirect bool
	// Executable indicates if Command can be run directly (true) or requires manual action (false).
	Executable bool
	// managerRank is used internally for sorting commands by package manager priority.
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
	References  []dependency.ManifestRef
	Locations   []string
}

// CommandsFromConsolidated derives recommended commands and stdlib upgrades.
func CommandsFromConsolidated(cons []vulnerability.Consolidated) ([]Command, string) {
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
		if n := cmp.Compare(a.Path, b.Path); n != 0 {
			return n
		}
		return cmp.Compare(a.Command, b.Command)
	})
	return cmds, stdlib
}

// buildUpgradeRecommendations analyzes consolidated vulnerabilities to determine
// the best fixed versions for each affected package. It separates standard library
// upgrades from regular dependency upgrades. When multiple vulnerabilities affect
// the same package, it recommends the highest required version to fix all issues.
func buildUpgradeRecommendations(cons []vulnerability.Consolidated) ([]packageUpgrade, string) {
	var stdlibRec string

	// Track the best (highest) recommended version per package
	pkgBest := map[string]*packageUpgrade{}

	for _, v := range cons {
		if len(v.FixedVersions) == 0 {
			continue
		}
		best := vulnerability.FindBestFixedVersion(v.FixedVersions, v.Version)
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
	return cmp.Compare(a, b)
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
func mergeManifestRefs(a, b []dependency.ManifestRef) []dependency.ManifestRef {
	seen := collections.NewSet[string]()
	result := make([]dependency.ManifestRef, 0, len(a)+len(b))
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
				collections.NormalizeLower(ref.Manager),
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
				managerRank: ecosystem.ManagerRank(manager),
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

	switch {
	case goManagerPresent && len(goPaths) == 0:
		commands = append(commands, Command{
			Manager:     "go",
			managerRank: ecosystem.ManagerRank("go"),
			Command:     "go mod tidy",
			Executable:  true,
		})
	case len(goPaths) > 0:
		paths := goPaths.Slice()
		slices.Sort(paths)
		for _, path := range paths {
			commands = append(commands, Command{
				Manager:     "go",
				managerRank: ecosystem.ManagerRank("go"),
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
		managerRank: ecosystem.ManagerRank("go"),
		Command:     cmd,
		Path:        "go.mod",
		Hint:        "updates go directive",
		Executable:  true,
	}, true
}

// jsPackageManagerCommands maps JS package managers to their install command verbs.
var jsPackageManagerCommands = map[string]string{
	"npm":  "npm install",
	"yarn": "yarn add",
	"pnpm": "pnpm add",
}

// pythonPackageManagerCommands maps Python package managers to their install patterns.
// Each entry specifies the command template with %s placeholders for package and version.
var pythonPackageManagerCommands = map[string]struct {
	template string // fmt template: package, version
	hint     string
}{
	"pip":    {template: "pip install --upgrade %s==%s", hint: ""},
	"pipenv": {template: "pipenv install %s==%s", hint: ""},
	"poetry": {template: "poetry add %s@%s", hint: ""},
	"uv":     {template: "uv add \"%s>=%s\"", hint: "run uv lock afterwards to update lockfile"},
	"pdm":    {template: "pdm add %s@%s", hint: ""},
	"conda":  {template: "conda install %s=%s", hint: "use -c conda-forge if needed"},
}

func recommendCommand(manager, manifestPath, pkg, version string, groups []string) (string, string, bool) {
	m := strings.ToLower(manager)

	// Handle JS package managers with a unified approach
	if installCmd, ok := jsPackageManagerCommands[m]; ok {
		cmd := fmt.Sprintf("%s %s@%s", installCmd, pkg, version)
		if flag := dependencyGroupFlag(m, groups); flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return cmd, "", true
	}

	// Handle Python package managers with a unified approach
	if pyCmd, ok := pythonPackageManagerCommands[m]; ok {
		cmd := fmt.Sprintf(pyCmd.template, pkg, version)
		hint := pyCmd.hint
		// Expand hint template if it contains placeholders
		if strings.Contains(hint, "%s") {
			hint = fmt.Sprintf(hint, pkg, version)
		}
		return cmd, hint, true
	}

	switch m {
	case "go":
		return fmt.Sprintf("go get %s@%s", pkg, version), "", true

	// Ruby/Bundler
	case "gem", "bundler":
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

	// PHP/Composer
	case "composer":
		return fmt.Sprintf("composer require %s:%s", pkg, version), "", true

	// Rust/Cargo
	case "cargo":
		return fmt.Sprintf("cargo update -p %s --precise %s", pkg, version), "", true

	// Java/Maven
	case "maven":
		return fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s -DdepVersion=%s", pkg, version), "consider running mvn versions:commit afterwards", true

	// Java/Gradle - now executable via gradle CLI
	case "gradle":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "gradle.lockfile" || base == "buildscript-gradle.lockfile":
			// For lockfiles, update via gradle command then regenerate lockfile
			return fmt.Sprintf("./gradlew dependencies --write-locks"), "update dependency version in build.gradle first", true
		case base == "build.gradle" || base == "build.gradle.kts":
			return fmt.Sprintf("Update %s to %s in %s", pkg, version, path.Base(manifestPath)), "run ./gradlew dependencies --write-locks afterwards", false
		default:
			return fmt.Sprintf("Update dependency %s to %s", pkg, version), "", false
		}

	// .NET/NuGet
	case "nuget", "dotnet":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "packages.lock.json":
			// Modern PackageReference format - use dotnet CLI
			return fmt.Sprintf("dotnet add package %s --version %s", pkg, version), "run dotnet restore afterwards", true
		case base == "packages.config":
			// Legacy packages.config format
			return fmt.Sprintf("Update-Package %s -Version %s", pkg, version), "run in Package Manager Console", true
		case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj"):
			return fmt.Sprintf("dotnet add package %s --version %s", pkg, version), "", true
		default:
			return fmt.Sprintf("dotnet add package %s --version %s", pkg, version), "", true
		}

	// Elixir/Hex
	case "hex", "mix":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "mix.lock":
			return fmt.Sprintf("mix deps.update %s", pkg), "ensure mix.exs has correct version constraint", true
		case base == "mix.exs":
			return fmt.Sprintf("Update %s to ~> %s in mix.exs", pkg, version), "run mix deps.get afterwards", false
		default:
			return fmt.Sprintf("mix deps.update %s", pkg), "", true
		}

	// Dart/Flutter/Pub
	case "pub", "dart", "flutter":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "pubspec.lock":
			return fmt.Sprintf("dart pub upgrade %s", pkg), "ensure pubspec.yaml has correct version constraint", true
		case base == "pubspec.yaml":
			return fmt.Sprintf("Update %s to ^%s in pubspec.yaml", pkg, version), "run dart pub get afterwards", false
		default:
			return fmt.Sprintf("dart pub upgrade %s", pkg), "", true
		}

	// Swift/CocoaPods
	case "cocoapods", "pod":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "podfile.lock":
			return fmt.Sprintf("pod update %s", pkg), "", true
		case base == "podfile":
			return fmt.Sprintf("Update %s to ~> %s in Podfile", pkg, version), "run pod install afterwards", false
		default:
			return fmt.Sprintf("pod update %s", pkg), "", true
		}

	// Swift Package Manager
	case "swift", "spm":
		return fmt.Sprintf("Update Package.swift to use %s version %s", pkg, version), "run swift package update afterwards", false

	// Haskell/Cabal
	case "cabal":
		return fmt.Sprintf("Update %s to %s in cabal file", pkg, version), "run cabal update && cabal build afterwards", false

	// Haskell/Stack
	case "stack":
		return fmt.Sprintf("Update %s to %s in stack.yaml or package.yaml", pkg, version), "run stack build afterwards", false

	// R/renv
	case "renv":
		return fmt.Sprintf("renv::install(\"%s@%s\")", pkg, version), "", true

	// C++/Conan
	case "conan":
		return fmt.Sprintf("conan install %s/%s@", pkg, version), "update conanfile.txt or conanfile.py first", true

	// GitHub Actions
	case "github-actions", "githubactions":
		base := strings.ToLower(path.Base(manifestPath))
		// Parse the action reference for better advice
		owner, repo := parseGitHubActionRef(pkg)
		switch {
		case strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
			// Provide specific version pinning advice
			if isCommitSHA(version) {
				return fmt.Sprintf("Action %s/%s is pinned to commit %s", owner, repo, version[:12]), "verify this commit in the action repository", false
			}
			// Return a deputy-internal command that will be handled by the fix applier
			// Format: deputy:action:update <file> <owner/repo> <new-version>
			actionRef := fmt.Sprintf("%s/%s", owner, repo)
			cmd := fmt.Sprintf("deputy:action:update %s %s %s", manifestPath, actionRef, version)
			return cmd, fmt.Sprintf("consider pinning to full commit SHA: %s/%s@<sha> # %s", owner, repo, version), true
		default:
			return fmt.Sprintf("Update action %s to %s", pkg, version), "edit workflow YAML file", false
		}

	// Dockerfile / Container Images
	case "docker", "oci", "container":
		base := strings.ToLower(path.Base(manifestPath))
		if isContainerfilePath(base) {
			// Return a deputy-internal command that will be handled by the fix applier
			// Format: deputy:dockerfile:update <file> <image> <new-version>
			cmd := fmt.Sprintf("deputy:dockerfile:update %s %s %s", manifestPath, pkg, version)
			return cmd, "pin to digest for reproducibility: FROM image@sha256:...", true
		}
		// Generic container image update (e.g., docker-compose.yml, k8s manifests)
		return fmt.Sprintf("Update container image %s to %s", pkg, version), "", false
	}

	return "", "", false
}

// parseGitHubActionRef extracts owner and repo from action reference.
func parseGitHubActionRef(ref string) (owner, repo string) {
	ref = strings.TrimSpace(ref)
	ref = strings.TrimPrefix(ref, "github.com/")
	parts := strings.Split(ref, "/")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	return ref, ""
}

// isCommitSHA checks if a version string looks like a git commit SHA.
func isCommitSHA(version string) bool {
	if len(version) != 40 {
		return false
	}
	for _, c := range version {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// isContainerfilePath checks if a filename looks like a Dockerfile or Containerfile.
// Matches: Dockerfile, Containerfile, *.dockerfile, *.containerfile, *Dockerfile, *Containerfile
func isContainerfilePath(name string) bool {
	lower := strings.ToLower(name)

	// Exact matches (case-insensitive)
	if lower == "dockerfile" || lower == "containerfile" {
		return true
	}

	// Extension patterns: *.dockerfile, *.containerfile
	if strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile") {
		return true
	}

	// Prefix patterns: dockerfile.*, containerfile.*
	if strings.HasPrefix(lower, "dockerfile.") || strings.HasPrefix(lower, "containerfile.") {
		return true
	}

	return false
}

// Dependency group names recognized across package managers.
const (
	groupDev      = "dev"
	groupDevDeps  = "devdependencies"
	groupOptional = "optional"
	groupOptDeps  = "optionaldependencies"
	groupPeer     = "peer"
	groupPeerDeps = "peerdependencies"
)

// managerGroupFlags maps package managers to their dependency group flags.
// The inner map keys are group categories, values are CLI flags.
var managerGroupFlags = map[string]map[string]string{
	// JavaScript/TypeScript
	"npm": {
		"dev":      "--save-dev",
		"optional": "--save-optional",
		"peer":     "--save-peer",
	},
	"pnpm": {
		"dev":      "--save-dev",
		"optional": "--save-optional",
		"peer":     "--save-peer",
	},
	"yarn": {
		"dev":      "--dev",
		"optional": "--optional",
		"peer":     "--peer",
	},
	// Python
	"poetry": {
		"dev": "--group dev",
	},
	"uv": {
		"dev": "--dev",
	},
	"pdm": {
		"dev": "--dev",
	},
	// Dart/Flutter
	"pub": {
		"dev": "--dev",
	},
	"dart": {
		"dev": "--dev",
	},
	"flutter": {
		"dev": "--dev",
	},
}

// dependencyGroupFlag returns the appropriate CLI flag for a given package manager
// and dependency groups. Returns empty string if no special flag is needed.
func dependencyGroupFlag(manager string, groups []string) string {
	flags, ok := managerGroupFlags[strings.ToLower(manager)]
	if !ok {
		return ""
	}
	if hasGroup(groups, groupDev, groupDevDeps) {
		return flags["dev"]
	}
	if hasGroup(groups, groupOptional, groupOptDeps) {
		return flags["optional"]
	}
	if hasGroup(groups, groupPeer, groupPeerDeps) {
		return flags["peer"]
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
