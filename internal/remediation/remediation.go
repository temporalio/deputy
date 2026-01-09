package remediation

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	"github.com/picatz/deputy/internal/collections"
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
	// FollowUp is an optional executable command to run after the main command
	// (e.g., "go mod tidy" after "go get", "uv lock" after "uv add").
	FollowUp string
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
	References  []dependencyv1.ManifestRef
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
		// Both "stdlib" (standard library) and "toolchain" (go command) vulnerabilities
		// are fixed by upgrading the Go version. OSV uses these package names:
		// - stdlib: vulnerabilities in standard library packages (crypto/tls, net/http, etc.)
		// - toolchain: vulnerabilities in the go command itself
		if strings.EqualFold(v.Package, "stdlib") || strings.EqualFold(v.Package, "toolchain") {
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
func mergeManifestRefs(a, b []dependencyv1.ManifestRef) []dependencyv1.ManifestRef {
	seen := collections.NewSet[string]()
	result := make([]dependencyv1.ManifestRef, 0, len(a)+len(b))
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
			rec := recommendCommand(ref.Manager, ref.Path, u.Name, u.Recommended, ref.Groups)
			if rec.command == "" {
				continue
			}
			pathStr := strings.TrimSpace(ref.Path)
			groups := uniqueSortedStrings(ref.Groups)
			groupsKey := strings.Join(groups, ",")
			key := strings.Join([]string{
				collections.NormalizeLower(ref.Manager),
				rec.command,
				pathStr,
				groupsKey,
				rec.hint,
				fmt.Sprintf("%t", u.IsDirect),
			}, "|")
			if !seen.Add(key) {
				continue
			}
			manager := strings.TrimSpace(ref.Manager)
			commands = append(commands, Command{
				Manager:     manager,
				managerRank: ecosystem.ManagerRank(manager),
				Command:     rec.command,
				Path:        pathStr,
				Groups:      groups,
				Hint:        rec.hint,
				FollowUp:    rec.followUp,
				IsDirect:    u.IsDirect,
				Executable:  rec.executable,
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
		IsDirect:    true, // Go toolchain is always a direct dependency (declared in go.mod)
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
// Each entry specifies the command template with %s placeholders for package and version,
// plus an optional follow-up command and hint for manual steps.
var pythonPackageManagerCommands = map[string]struct {
	template string // fmt template: package, version
	followUp string // executable follow-up command (e.g., lockfile sync)
	hint     string // hint for non-executable guidance
}{
	"pip":    {template: "pip install --upgrade %s==%s", followUp: "", hint: ""},
	"pipenv": {template: "pipenv install %s==%s", followUp: "pipenv lock", hint: ""},
	"poetry": {template: "poetry add %s@%s", followUp: "poetry lock", hint: ""},
	"uv":     {template: "uv add \"%s>=%s\"", followUp: "uv lock", hint: ""},
	"pdm":    {template: "pdm add %s@%s", followUp: "pdm lock", hint: ""},
	"conda":  {template: "conda install %s=%s", followUp: "", hint: "use -c conda-forge if needed"},
}

// commandResult holds the result of a command recommendation.
type commandResult struct {
	command    string
	followUp   string
	hint       string
	executable bool
}

func recommendCommand(manager, manifestPath, pkg, version string, groups []string) commandResult {
	m := strings.ToLower(manager)

	// Handle JS package managers with a unified approach
	if installCmd, ok := jsPackageManagerCommands[m]; ok {
		cmd := fmt.Sprintf("%s %s@%s", installCmd, pkg, version)
		if flag := dependencyGroupFlag(m, groups); flag != "" {
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return commandResult{command: cmd, executable: true}
	}

	// Handle Python package managers with a unified approach
	if pyCmd, ok := pythonPackageManagerCommands[m]; ok {
		cmd := fmt.Sprintf(pyCmd.template, pkg, version)
		hint := pyCmd.hint
		// Expand hint template if it contains placeholders
		if strings.Contains(hint, "%s") {
			hint = fmt.Sprintf(hint, pkg, version)
		}
		return commandResult{command: cmd, followUp: pyCmd.followUp, hint: hint, executable: true}
	}

	switch m {
	case "go":
		return commandResult{command: fmt.Sprintf("go get %s@%s", pkg, version), executable: true}

	// Ruby/Bundler
	case "gem", "bundler":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "gemfile.lock" || base == "gems.locked":
			return commandResult{command: fmt.Sprintf("bundle update %s", pkg), executable: true}
		case base == "gemfile":
			return commandResult{command: fmt.Sprintf("Edit Gemfile to require %s >= %s", pkg, version), followUp: "bundle install", hint: "edit Gemfile first", executable: false}
		case strings.HasSuffix(strings.ToLower(manifestPath), ".gemspec"):
			return commandResult{command: fmt.Sprintf("Edit %s to require %s >= %s", path.Base(manifestPath), pkg, version), executable: false}
		default:
			return commandResult{command: fmt.Sprintf("Update Ruby dependency for %s to %s", pkg, version), executable: false}
		}

	// PHP/Composer
	case "composer":
		return commandResult{command: fmt.Sprintf("composer require %s:%s", pkg, version), executable: true}

	// Rust/Cargo
	case "cargo":
		return commandResult{command: fmt.Sprintf("cargo update -p %s --precise %s", pkg, version), executable: true}

	// Java/Maven
	case "maven":
		return commandResult{command: fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s -DdepVersion=%s", pkg, version), followUp: "mvn versions:commit", executable: true}

	// Java/Gradle - now executable via gradle CLI
	case "gradle":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "gradle.lockfile" || base == "buildscript-gradle.lockfile":
			// For lockfiles, update via gradle command then regenerate lockfile
			return commandResult{command: "./gradlew dependencies --write-locks", hint: "update dependency version in build.gradle first", executable: true}
		case base == "build.gradle" || base == "build.gradle.kts":
			return commandResult{command: fmt.Sprintf("Update %s to %s in %s", pkg, version, path.Base(manifestPath)), followUp: "./gradlew dependencies --write-locks", executable: false}
		default:
			return commandResult{command: fmt.Sprintf("Update dependency %s to %s", pkg, version), executable: false}
		}

	// .NET/NuGet
	case "nuget", "dotnet":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "packages.lock.json":
			// Modern PackageReference format - use dotnet CLI
			return commandResult{command: fmt.Sprintf("dotnet add package %s --version %s", pkg, version), followUp: "dotnet restore", executable: true}
		case base == "packages.config":
			// Legacy packages.config format
			return commandResult{command: fmt.Sprintf("Update-Package %s -Version %s", pkg, version), hint: "run in Package Manager Console", executable: true}
		case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj"):
			return commandResult{command: fmt.Sprintf("dotnet add package %s --version %s", pkg, version), executable: true}
		default:
			return commandResult{command: fmt.Sprintf("dotnet add package %s --version %s", pkg, version), executable: true}
		}

	// Elixir/Hex
	case "hex", "mix":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "mix.lock":
			return commandResult{command: fmt.Sprintf("mix deps.update %s", pkg), hint: "ensure mix.exs has correct version constraint", executable: true}
		case base == "mix.exs":
			return commandResult{command: fmt.Sprintf("Update %s to ~> %s in mix.exs", pkg, version), followUp: "mix deps.get", executable: false}
		default:
			return commandResult{command: fmt.Sprintf("mix deps.update %s", pkg), executable: true}
		}

	// Dart/Flutter/Pub
	case "pub", "dart", "flutter":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "pubspec.lock":
			return commandResult{command: fmt.Sprintf("dart pub upgrade %s", pkg), hint: "ensure pubspec.yaml has correct version constraint", executable: true}
		case base == "pubspec.yaml":
			return commandResult{command: fmt.Sprintf("Update %s to ^%s in pubspec.yaml", pkg, version), followUp: "dart pub get", executable: false}
		default:
			return commandResult{command: fmt.Sprintf("dart pub upgrade %s", pkg), executable: true}
		}

	// Swift/CocoaPods
	case "cocoapods", "pod":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "podfile.lock":
			return commandResult{command: fmt.Sprintf("pod update %s", pkg), executable: true}
		case base == "podfile":
			return commandResult{command: fmt.Sprintf("Update %s to ~> %s in Podfile", pkg, version), followUp: "pod install", executable: false}
		default:
			return commandResult{command: fmt.Sprintf("pod update %s", pkg), executable: true}
		}

	// Swift Package Manager
	case "swift", "spm":
		return commandResult{command: fmt.Sprintf("Update Package.swift to use %s version %s", pkg, version), followUp: "swift package update", executable: false}

	// Haskell/Cabal
	case "cabal":
		return commandResult{command: fmt.Sprintf("Update %s to %s in cabal file", pkg, version), followUp: "cabal update && cabal build", executable: false}

	// Haskell/Stack
	case "stack":
		return commandResult{command: fmt.Sprintf("Update %s to %s in stack.yaml or package.yaml", pkg, version), followUp: "stack build", executable: false}

	// R/renv
	case "renv":
		return commandResult{command: fmt.Sprintf("renv::install(\"%s@%s\")", pkg, version), executable: true}

	// C++/Conan
	case "conan":
		return commandResult{command: fmt.Sprintf("conan install %s/%s@", pkg, version), hint: "update conanfile.txt or conanfile.py first", executable: true}

	// GitHub Actions
	case "github-actions", "githubactions":
		base := strings.ToLower(path.Base(manifestPath))
		// Parse the action reference for better advice
		owner, repo := parseGitHubActionRef(pkg)
		switch {
		case strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml"):
			// Provide specific version pinning advice
			if isCommitSHA(version) {
				return commandResult{command: fmt.Sprintf("Action %s/%s is pinned to commit %s", owner, repo, version[:12]), hint: "verify this commit in the action repository", executable: false}
			}
			// Return a deputy-internal command that will be handled by the fix applier
			// Format: deputy:action:update <file> <owner/repo> <new-version>
			actionRef := fmt.Sprintf("%s/%s", owner, repo)
			cmd := fmt.Sprintf("deputy:action:update %s %s %s", manifestPath, actionRef, version)
			return commandResult{command: cmd, hint: fmt.Sprintf("consider pinning to full commit SHA: %s/%s@<sha> # %s", owner, repo, version), executable: true}
		default:
			return commandResult{command: fmt.Sprintf("Update action %s to %s", pkg, version), hint: "edit workflow YAML file", executable: false}
		}

	// Dockerfile / Container Images
	case "docker", "oci", "container":
		base := strings.ToLower(path.Base(manifestPath))
		if isContainerfilePath(base) {
			// Return a deputy-internal command that will be handled by the fix applier
			// Format: deputy:dockerfile:update <file> <image> <new-version>
			cmd := fmt.Sprintf("deputy:dockerfile:update %s %s %s", manifestPath, pkg, version)
			return commandResult{command: cmd, hint: "pin to digest for reproducibility: FROM image@sha256:...", executable: true}
		}
		// Generic container image update (e.g., docker-compose.yml, k8s manifests)
		return commandResult{command: fmt.Sprintf("Update container image %s to %s", pkg, version), executable: false}
	}

	return commandResult{}
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
