package remediation

import (
	"cmp"
	"fmt"
	"path"
	"slices"
	"strings"

	"golang.org/x/mod/semver"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Command represents an actionable remediation step for resolving a vulnerability.
// It can be either an executable shell command or a manual edit instruction.
type Command struct {
	// Package identifies the vulnerable package this command remediates.
	Package string
	// Version is the vulnerable package version when known.
	Version string
	// PURL is the vulnerable package URL when known.
	PURL string
	// TargetVersion is the recommended fixed version when known.
	TargetVersion string
	// TargetModule is the module/package path to migrate to for migration fixes.
	TargetModule string
	// Migration indicates the fix requires changing package/module identity.
	Migration bool
	// Manager identifies the package manager (e.g., "go", "npm", "pip", "gem").
	Manager string
	// Command is the shell command to execute or instruction to follow.
	Command string
	// Args is the parsed executable command and arguments for safe execution.
	Args []string
	// Path is the manifest/lockfile path where this command should be run.
	Path string
	// Groups indicates dependency groups affected (e.g., "dev", "optional" for npm).
	Groups []string
	// Hint provides additional context (e.g., "run bundle install afterwards").
	Hint string
	// FollowUp is an optional executable command to run after the main command
	// (e.g., "go mod tidy" after "go get", "uv lock" after "uv add").
	FollowUp string
	// FollowUpArgs is the parsed follow-up command and arguments for safe execution.
	FollowUpArgs []string
	// IsDirect indicates if the vulnerable package is a direct dependency.
	IsDirect bool
	// Executable indicates if Command can be run directly (true) or requires manual action (false).
	Executable bool
	// Vulnerabilities are the finding IDs this command remediates, sorted and
	// unique. One command can address several findings because commands are
	// deduplicated per package and manifest.
	Vulnerabilities []string
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
	PURL        string
	References  []dependencyv1.ManifestRef
	Locations   []string
	// Migration marks an upgrade that requires moving to a different module
	// path (TargetModule) rather than a simple in-place version bump.
	Migration    bool
	TargetModule string
	// VulnIDs are the primary finding IDs that recommended this upgrade.
	VulnIDs []string
}

// CommandsFromConsolidated derives recommended commands and stdlib upgrades.
func CommandsFromConsolidated(cons []vulnerability.Consolidated) ([]Command, string) {
	upgrades, stdlib, stdlibRefs, stdlibVulnIDs, stdlibCurrents := buildUpgradeRecommendations(cons)
	cmds := dedupeCommands(upgrades)
	if stdlib != "" {
		// Only an unambiguous current version can safely target a declaration
		// (mixed currents would steer the mise edit at the wrong element).
		stdlibCurrent := ""
		if len(stdlibCurrents) == 1 {
			stdlibCurrent = stdlibCurrents[0]
		}
		cmds = append(cmds, stdlibCommands(stdlib, stdlibCurrent, stdlibRefs, stdlibVulnIDs)...)
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
// The final return value lists the unique current Go versions across the stdlib
// findings, so fixes that edit a manifest in place can target the vulnerable
// declaration when it is unambiguous.
func buildUpgradeRecommendations(cons []vulnerability.Consolidated) ([]packageUpgrade, string, []dependencyv1.ManifestRef, []string, []string) {
	var stdlibRec string
	var stdlibRefs []dependencyv1.ManifestRef
	var stdlibVulnIDs []string
	var stdlibCurrents []string

	// Track the best (highest) recommended version per package
	pkgBest := map[string]*packageUpgrade{}

	for _, v := range cons {
		// Prefer the resolved fix verdict (installability-verified) when present;
		// otherwise fall back to the advisory's claimed fixed version.
		best, targetModule, migration, ok := upgradeTargetFor(v)
		if !ok {
			continue
		}
		// Both "stdlib" (standard library) and "toolchain" (go command) vulnerabilities
		// are fixed by upgrading the Go version. OSV uses these package names:
		// - stdlib: vulnerabilities in standard library packages (crypto/tls, net/http, etc.)
		// - toolchain: vulnerabilities in the go command itself
		if !migration && (strings.EqualFold(v.Package, "stdlib") || strings.EqualFold(v.Package, "toolchain")) {
			if stdlibRec == "" || compareVersions(best, stdlibRec) > 0 {
				stdlibRec = best
			}
			// Retain the manifest sources so the fix can target each declarer of
			// the Go version (go.mod vs mise.toml vs .tool-versions) distinctly.
			stdlibRefs = mergeManifestRefs(stdlibRefs, v.ManifestRefs)
			stdlibVulnIDs = append(stdlibVulnIDs, v.PrimaryID)
			if cur := strings.TrimSpace(v.Version); cur != "" && !slices.Contains(stdlibCurrents, cur) {
				stdlibCurrents = append(stdlibCurrents, cur)
			}
			continue
		}

		existing, ok := pkgBest[v.Package]
		if !ok {
			pkgBest[v.Package] = &packageUpgrade{
				Name:         v.Package,
				Current:      v.Version,
				Recommended:  best,
				IsDirect:     v.IsDirect,
				Ecosystem:    v.Ecosystem,
				PURL:         v.PURL,
				References:   v.ManifestRefs,
				Locations:    v.Locations,
				Migration:    migration,
				TargetModule: targetModule,
				VulnIDs:      []string{v.PrimaryID},
			}
		} else {
			// Keep the higher recommended version
			if compareVersions(best, existing.Recommended) > 0 {
				existing.Recommended = best
			}
			// A migration requirement is "stickier" than an in-place bump: if any
			// finding for this package needs a path migration, surface that.
			if migration {
				existing.Migration = true
				existing.TargetModule = targetModule
			}
			// Merge references
			existing.References = mergeManifestRefs(existing.References, v.ManifestRefs)
			existing.Locations = mergeStrings(existing.Locations, v.Locations)
			if existing.PURL == "" {
				existing.PURL = v.PURL
			}
			// IsDirect if any vuln is direct
			if v.IsDirect {
				existing.IsDirect = true
			}
			existing.VulnIDs = append(existing.VulnIDs, v.PrimaryID)
		}
	}

	upgrades := make([]packageUpgrade, 0, len(pkgBest))
	for _, u := range pkgBest {
		upgrades = append(upgrades, *u)
	}

	return upgrades, stdlibRec, stdlibRefs, stdlibVulnIDs, stdlibCurrents
}

// upgradeTargetFor determines the remediation target for a consolidated
// finding. When a resolved fix verdict is present it is authoritative
// (distinguishing installable in-place upgrades from module migrations and
// dropping unreachable/unavailable fixes); otherwise it falls back to the
// advisory's best claimed fixed version. The bool reports whether any upgrade
// applies.
func upgradeTargetFor(v vulnerability.Consolidated) (best, targetModule string, migration, ok bool) {
	if v.Fix != nil {
		switch v.Fix.Status {
		case vulnerability.FixStatusInPlace, vulnerability.FixStatusUnverified:
			return v.Fix.Version, "", false, v.Fix.Version != ""
		case vulnerability.FixStatusMigration:
			return v.Fix.Version, v.Fix.TargetModule, true, v.Fix.Version != "" && v.Fix.TargetModule != ""
		default: // FixStatusUnavailable / FixStatusUnknown
			return "", "", false, false
		}
	}
	if len(v.FixedVersions) == 0 {
		return "", "", false, false
	}
	best = vulnerability.FindBestFixedVersion(v.FixedVersions, v.Version)
	return best, "", false, best != ""
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
	for i := range a {
		ref := &a[i]
		key := ref.Path + "|" + ref.Manager
		if seen.Add(key) {
			result = append(result, dependencyv1.ManifestRef{})
			dst := &result[len(result)-1]
			dst.Path = ref.Path
			dst.Manager = ref.Manager
			dst.Groups = slices.Clone(dependency.ManifestRefGroups(ref))
			dependency.SetManifestRefComponentKey(dst, dependency.ManifestRefComponentKey(ref))
		}
	}
	for i := range b {
		ref := &b[i]
		key := ref.Path + "|" + ref.Manager
		if seen.Add(key) {
			result = append(result, dependencyv1.ManifestRef{})
			dst := &result[len(result)-1]
			dst.Path = ref.Path
			dst.Manager = ref.Manager
			dst.Groups = slices.Clone(dependency.ManifestRefGroups(ref))
			dependency.SetManifestRefComponentKey(dst, dependency.ManifestRefComponentKey(ref))
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
		for i := range u.References {
			ref := &u.References[i]
			// Never remediate a manifest vendored inside a dependency-install tree
			// (e.g. a Cargo.toml under site-packages): it is a derived copy, not
			// the source of truth, so any edit is wiped on reinstall. The inventory
			// walk excludes these by default, but a manifest can still reach here
			// when that default is overridden, so guard remediation too.
			if inventory.IsDependencyInstallPath(ref.Path) {
				continue
			}
			var rec commandResult
			if u.Migration {
				rec = migrationCommand(u.TargetModule, u.Recommended, u.IsDirect)
			} else {
				rec = recommendCommand(ref.Manager, ref.Path, u.Name, u.Current, u.Recommended, dependency.ManifestRefGroups(ref), dependency.ManifestRefComponentKey(ref))
			}
			if rec.command == "" {
				continue
			}
			pathStr := strings.TrimSpace(ref.Path)
			groups := uniqueSortedStrings(dependency.ManifestRefGroups(ref))
			groupsKey := strings.Join(groups, ",")
			manager := strings.TrimSpace(ref.Manager)
			targetVersion := commandTargetVersion(manager, u.Recommended)
			key := strings.Join([]string{
				collections.NormalizeLower(manager),
				collections.NormalizeLower(u.Name),
				strings.TrimSpace(u.Current),
				strings.TrimSpace(u.PURL),
				strings.TrimSpace(targetVersion),
				strings.TrimSpace(u.TargetModule),
				fmt.Sprintf("%t", u.Migration),
				rec.command,
				pathStr,
				groupsKey,
				rec.hint,
				fmt.Sprintf("%t", u.IsDirect),
			}, "|")
			if !seen.Add(key) {
				continue
			}
			commands = append(commands, Command{
				Package:         u.Name,
				Version:         u.Current,
				PURL:            u.PURL,
				TargetVersion:   targetVersion,
				TargetModule:    u.TargetModule,
				Migration:       u.Migration,
				Manager:         manager,
				managerRank:     ecosystem.ManagerRank(manager),
				Command:         rec.command,
				Args:            rec.args,
				Path:            pathStr,
				Groups:          groups,
				Hint:            rec.hint,
				FollowUp:        rec.followUp,
				FollowUpArgs:    rec.followUpArgs,
				IsDirect:        u.IsDirect,
				Executable:      rec.executable,
				Vulnerabilities: uniqueSortedStrings(u.VulnIDs),
			})
			// Only an executable `go get` warrants a follow-up `go mod tidy`;
			// migration notes are manual and shouldn't imply tidy resolves them.
			if strings.EqualFold(manager, "go") && rec.executable {
				goManagerPresent = true
				if pathStr != "" {
					goPaths.Add(pathStr)
				}
			}
		}
	}

	// The go mod tidy follow-ups are hygiene steps, not fixes: they carry no
	// vulnerability IDs on purpose, so plan consumers do not credit them with
	// remediating anything.
	switch {
	case goManagerPresent && len(goPaths) == 0:
		commands = append(commands, Command{
			Package:     "go",
			Manager:     "go",
			managerRank: ecosystem.ManagerRank("go"),
			Command:     "go mod tidy",
			Args:        []string{"go", "mod", "tidy"},
			Executable:  true,
		})
	case len(goPaths) > 0:
		paths := goPaths.Slice()
		slices.Sort(paths)
		for _, path := range paths {
			commands = append(commands, Command{
				Package:     "go",
				Manager:     "go",
				managerRank: ecosystem.ManagerRank("go"),
				Command:     "go mod tidy",
				Args:        []string{"go", "mod", "tidy"},
				Path:        path,
				Executable:  true,
			})
		}
	}

	return commands
}

func commandTargetVersion(manager, version string) string {
	if strings.EqualFold(strings.TrimSpace(manager), "go") {
		return ecosystem.Go.NormalizeVersion(version)
	}
	return version
}

// migrationCommand renders the remediation for a fix that lives on a different
// module path (a Go major-version migration). It is always non-executable: a
// migration requires source/import changes (direct deps) or an upstream change
// (indirect deps) that no single command performs, so `deputy fix --apply` must
// not run it blindly.
//
// For a direct dependency, it surfaces the concrete `go get` for the new module
// plus the manual import-path step. For an indirect dependency there is no local
// migration (the module that pulls it in must migrate or be upgraded), so it
// points at that instead of an unrunnable `go get`.
func migrationCommand(targetModule, version string, isDirect bool) commandResult {
	v := ecosystem.Go.NormalizeVersion(version)
	if !isDirect {
		return commandResult{
			command:    "Upgrade the dependency that pulls this in (indirect; no in-place fix)",
			hint:       "use dependency graph context to find the direct dependency that pulls this in",
			executable: false,
		}
	}
	return commandResult{
		command:    fmt.Sprintf("go get %s@%s", targetModule, v),
		args:       []string{"go", "get", fmt.Sprintf("%s@%s", targetModule, v)},
		hint:       "update import paths, then go mod tidy",
		executable: false,
	}
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
		Package:       "go",
		TargetVersion: goVersion,
		Manager:       "go",
		managerRank:   ecosystem.ManagerRank("go"),
		Command:       cmd,
		Args:          []string{"go", "get", "go@" + goVersion},
		Path:          "go.mod",
		Hint:          "updates go directive",
		IsDirect:      true, // Go toolchain is always a direct dependency (declared in go.mod)
		Executable:    true,
	}, true
}

// stdlibCommands generates source-aware fix commands for a Go stdlib/toolchain
// upgrade. The same Go version may be declared in more than one place (go.mod,
// mise.toml, .tool-versions), each needing a distinct fix: a go.mod-sourced
// finding bumps the go directive (`go get go@X`), while a mise/asdf-sourced one
// bumps the tool in that config (a deputy:mise:update edit for mise). When both
// declare it, both commands are emitted. With no attributable source, it falls
// back to the go.mod command to preserve prior behavior. currentVersion is the
// vulnerable Go version when it is unambiguous across the findings ("" when
// unknown or mixed); the mise edit uses it to target the right element of a
// multi-version declaration.
func stdlibCommands(version, currentVersion string, refs []dependencyv1.ManifestRef, vulnIDs []string) []Command {
	var cmds []Command
	seen := collections.NewSet[string]()
	sawManaged := false
	sawGoMod := false
	survived := 0

	for i := range refs {
		ref := &refs[i]
		// Skip Go-version declarations vendored inside a dependency-install tree;
		// only a source-of-truth manifest should drive a toolchain bump.
		if inventory.IsDependencyInstallPath(ref.Path) {
			continue
		}
		survived++
		switch strings.ToLower(strings.TrimSpace(ref.Manager)) {
		case "mise", "asdf":
			sawManaged = true
			rec := recommendCommand(ref.Manager, ref.Path, "stdlib", currentVersion, version, nil, dependency.ManifestRefComponentKey(ref))
			if rec.command == "" {
				continue
			}
			if !seen.Add(strings.TrimSpace(ref.Manager) + "|" + rec.command + "|" + ref.Path) {
				continue
			}
			manager := strings.TrimSpace(ref.Manager)
			cmds = append(cmds, Command{
				Package:         "go",
				TargetVersion:   version,
				Manager:         manager,
				managerRank:     ecosystem.ManagerRank(manager),
				Command:         rec.command,
				Args:            rec.args,
				Path:            ref.Path,
				Hint:            rec.hint,
				FollowUp:        rec.followUp,
				FollowUpArgs:    rec.followUpArgs,
				IsDirect:        true,
				Executable:      rec.executable,
				Vulnerabilities: uniqueSortedStrings(vulnIDs),
			})
		case "go":
			sawGoMod = true
		}
	}

	// With no attributable source, fall back to a go.mod toolchain bump (prior
	// behavior). But when refs existed and were all vendored install copies
	// (none survived the filter), the finding came purely from a derived
	// manifest, so there is nothing actionable to bump and we emit nothing.
	allRefsVendored := len(refs) > 0 && survived == 0
	if !allRefsVendored && (sawGoMod || !sawManaged) {
		if tc, ok := buildGoToolchainCommand(version); ok {
			tc.Vulnerabilities = uniqueSortedStrings(vulnIDs)
			cmds = append(cmds, tc)
		}
	}
	return cmds
}

// jsPackageManagerCommands maps JS package managers to their install command verbs.
var jsPackageManagerCommands = map[string][]string{
	"npm":  {"npm", "install"},
	"yarn": {"yarn", "add"},
	"pnpm": {"pnpm", "add"},
}

// pythonPackageManagerCommands maps Python package managers to their install patterns.
// Each entry specifies the command template with %s placeholders for package and version,
// plus an optional follow-up command and hint for manual steps.
var pythonPackageManagerCommands = map[string]struct {
	template     string                        // fmt template: package, version
	args         func(string, string) []string // executable args
	followUp     string                        // executable follow-up command (e.g., lockfile sync)
	followUpArgs []string                      // parsed follow-up args
	hint         string                        // hint for non-executable guidance
}{
	"pip": {
		template: "pip install --upgrade %s==%s",
		args: func(pkg, version string) []string {
			return []string{"pip", "install", "--upgrade", fmt.Sprintf("%s==%s", pkg, version)}
		},
	},
	"pipenv": {
		template: "pipenv install %s==%s",
		args: func(pkg, version string) []string {
			return []string{"pipenv", "install", fmt.Sprintf("%s==%s", pkg, version)}
		},
		followUp:     "pipenv lock",
		followUpArgs: []string{"pipenv", "lock"},
	},
	"poetry": {
		template: "poetry add %s@%s",
		args: func(pkg, version string) []string {
			return []string{"poetry", "add", fmt.Sprintf("%s@%s", pkg, version)}
		},
		followUp:     "poetry lock",
		followUpArgs: []string{"poetry", "lock"},
	},
	"uv": {
		template:     "uv add \"%s>=%s\"",
		args:         func(pkg, version string) []string { return []string{"uv", "add", fmt.Sprintf("%s>=%s", pkg, version)} },
		followUp:     "uv lock",
		followUpArgs: []string{"uv", "lock"},
	},
	"pdm": {
		template:     "pdm add %s@%s",
		args:         func(pkg, version string) []string { return []string{"pdm", "add", fmt.Sprintf("%s@%s", pkg, version)} },
		followUp:     "pdm lock",
		followUpArgs: []string{"pdm", "lock"},
	},
	"conda": {
		template: "conda install %s=%s",
		args: func(pkg, version string) []string {
			return []string{"conda", "install", fmt.Sprintf("%s=%s", pkg, version)}
		},
		hint: "use -c conda-forge if needed",
	},
}

// commandResult holds the result of a command recommendation.
type commandResult struct {
	command      string
	args         []string
	followUp     string
	followUpArgs []string
	hint         string
	executable   bool
}

// quoteCommandArg quotes a command token for a display command string that
// round-trips through ParseCommandArgs (deputy-internal commands are re-parsed
// from the command text at apply time, so a manifest path with spaces must not
// split into separate tokens). Tokens without whitespace or quotes are
// returned unchanged to keep the common case readable.
func quoteCommandArg(s string) string {
	if !strings.ContainsAny(s, " \t\"'\\") {
		return s
	}
	replacer := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	return `"` + replacer.Replace(s) + `"`
}

// miseUpdateCommand renders the deputy-internal command that bumps a tool
// version in a mise config. Deputy edits the detected file in place instead of
// shelling out to `mise use`, which refuses untrusted configs (fatal in fresh
// checkouts and CI), picks its own write target rather than the detected
// manifest, and collapses multi-version arrays to a scalar. currentVersion
// targets the vulnerable element in array declarations and is appended only
// when known.
func miseUpdateCommand(manifestPath, tool, currentVersion, version string) commandResult {
	parts := []string{
		"deputy:mise:update",
		quoteCommandArg(manifestPath),
		quoteCommandArg(tool),
		quoteCommandArg(version),
	}
	if strings.TrimSpace(currentVersion) != "" {
		parts = append(parts, quoteCommandArg(currentVersion))
	}
	return commandResult{
		command:    strings.Join(parts, " "),
		hint:       "then run: mise install",
		executable: true,
	}
}

// miseToolName resolves the tool key to use in a mise/asdf fix command. It
// prefers the manifest-declared componentKey; otherwise it falls back to the
// advisory's package name, translating the Go runtime's canonical
// "stdlib"/"toolchain" names to the runtime tool (runtimeName).
func miseToolName(componentKey, pkg, runtimeName string) string {
	fallback := pkg
	if strings.EqualFold(pkg, "stdlib") || strings.EqualFold(pkg, "toolchain") {
		fallback = runtimeName
	}
	return cmp.Or(strings.TrimSpace(componentKey), fallback)
}

// recommendCommand builds the package-manager command for one upgrade at one
// manifest: executable command text and args when the manager supports a safe
// direct invocation, or manual guidance text with a hint otherwise. The
// componentKey targets the manifest's own name for a dependency when it
// differs from the reported package (e.g. mise tool keys). currentVersion is
// the installed version being fixed; managers whose fix edits the manifest in
// place (mise) use it to target the vulnerable declaration and it may be empty
// when unknown.
func recommendCommand(manager, manifestPath, pkg, currentVersion, version string, groups []string, componentKey string) commandResult {
	m := strings.ToLower(manager)

	// Handle JS package managers with a unified approach
	if installArgs, ok := jsPackageManagerCommands[m]; ok {
		pkgArg := fmt.Sprintf("%s@%s", pkg, version)
		args := append(append([]string(nil), installArgs...), pkgArg)
		cmd := strings.Join(args, " ")
		if flag := dependencyGroupFlag(m, groups); flag != "" {
			args = append(args, flag)
			cmd = fmt.Sprintf("%s %s", cmd, flag)
		}
		return commandResult{command: cmd, args: args, executable: true}
	}

	// Handle Python package managers with a unified approach
	if pyCmd, ok := pythonPackageManagerCommands[m]; ok {
		cmd := fmt.Sprintf(pyCmd.template, pkg, version)
		args := pyCmd.args(pkg, version)
		hint := pyCmd.hint
		// Expand hint template if it contains placeholders
		if strings.Contains(hint, "%s") {
			hint = fmt.Sprintf(hint, pkg, version)
		}
		return commandResult{
			command:      cmd,
			args:         args,
			followUp:     pyCmd.followUp,
			followUpArgs: pyCmd.followUpArgs,
			hint:         hint,
			executable:   true,
		}
	}

	switch m {
	case "go":
		// Go module versions must have a "v" prefix
		v := ecosystem.Go.NormalizeVersion(version)
		return commandResult{
			command:    fmt.Sprintf("go get %s@%s", pkg, v),
			args:       []string{"go", "get", fmt.Sprintf("%s@%s", pkg, v)},
			executable: true,
		}

	// mise / asdf toolchains: bump the tool version in the committed config.
	// componentKey is the tool exactly as declared (e.g. "npm:lodash", "go"),
	// which may carry a backend prefix the advisory's canonical name lacks, so we
	// prefer it. The Go runtime surfaces under the canonical names
	// "stdlib"/"toolchain"; map those back to the declared runtime tool.
	case "mise":
		tool := miseToolName(componentKey, pkg, "go")
		if strings.TrimSpace(manifestPath) == "" {
			// Without a detected manifest there is no file to edit; surface
			// manual guidance instead of a fix deputy cannot apply.
			return commandResult{
				command:    fmt.Sprintf("Update %s to %s in the mise config", tool, version),
				hint:       fmt.Sprintf("run: mise use %s@%s", tool, version),
				executable: false,
			}
		}
		return miseUpdateCommand(manifestPath, tool, currentVersion, version)
	case "asdf":
		tool := miseToolName(componentKey, pkg, "golang")
		// asdf has no single "set version + install" verb that edits
		// .tool-versions in one step, so surface a precise manual instruction.
		return commandResult{
			command:    fmt.Sprintf("Set %s %s in %s", tool, version, path.Base(manifestPath)),
			hint:       fmt.Sprintf("run: asdf install %s %s && asdf local %s %s", tool, version, tool, version),
			executable: false,
		}

	// Ruby/Bundler
	case "gem", "bundler":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "gemfile.lock" || base == "gems.locked":
			return commandResult{
				command:    fmt.Sprintf("bundle update %s", pkg),
				args:       []string{"bundle", "update", pkg},
				executable: true,
			}
		case base == "gemfile":
			return commandResult{
				command:      fmt.Sprintf("Edit Gemfile to require %s >= %s", pkg, version),
				followUp:     "bundle install",
				followUpArgs: []string{"bundle", "install"},
				hint:         "edit Gemfile first",
				executable:   false,
			}
		case strings.HasSuffix(strings.ToLower(manifestPath), ".gemspec"):
			return commandResult{command: fmt.Sprintf("Edit %s to require %s >= %s", path.Base(manifestPath), pkg, version), executable: false}
		default:
			return commandResult{command: fmt.Sprintf("Update Ruby dependency for %s to %s", pkg, version), executable: false}
		}

	// PHP/Composer
	case "composer":
		return commandResult{
			command:    fmt.Sprintf("composer require %s:%s", pkg, version),
			args:       []string{"composer", "require", fmt.Sprintf("%s:%s", pkg, version)},
			executable: true,
		}

	// Rust/Cargo
	case "cargo":
		return commandResult{
			command:    fmt.Sprintf("cargo update -p %s --precise %s", pkg, version),
			args:       []string{"cargo", "update", "-p", pkg, "--precise", version},
			executable: true,
		}

	// Java/Maven
	case "maven":
		return commandResult{
			command:      fmt.Sprintf("mvn versions:use-dep-version -Dincludes=%s -DdepVersion=%s", pkg, version),
			args:         []string{"mvn", "versions:use-dep-version", fmt.Sprintf("-Dincludes=%s", pkg), fmt.Sprintf("-DdepVersion=%s", version)},
			followUp:     "mvn versions:commit",
			followUpArgs: []string{"mvn", "versions:commit"},
			executable:   true,
		}

	// Java/Gradle - now executable via gradle CLI
	case "gradle":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "gradle.lockfile" || base == "buildscript-gradle.lockfile":
			// For lockfiles, update via gradle command then regenerate lockfile
			return commandResult{
				command:    "./gradlew dependencies --write-locks",
				args:       []string{"./gradlew", "dependencies", "--write-locks"},
				hint:       "update dependency version in build.gradle first",
				executable: true,
			}
		case base == "build.gradle" || base == "build.gradle.kts":
			return commandResult{
				command:      fmt.Sprintf("Update %s to %s in %s", pkg, version, path.Base(manifestPath)),
				followUp:     "./gradlew dependencies --write-locks",
				followUpArgs: []string{"./gradlew", "dependencies", "--write-locks"},
				executable:   false,
			}
		default:
			return commandResult{command: fmt.Sprintf("Update dependency %s to %s", pkg, version), executable: false}
		}

	// .NET/NuGet
	case "nuget", "dotnet":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "packages.lock.json":
			// Modern PackageReference format - use dotnet CLI
			return commandResult{
				command:      fmt.Sprintf("dotnet add package %s --version %s", pkg, version),
				args:         []string{"dotnet", "add", "package", pkg, "--version", version},
				followUp:     "dotnet restore",
				followUpArgs: []string{"dotnet", "restore"},
				executable:   true,
			}
		case base == "packages.config":
			// Legacy packages.config format
			return commandResult{command: fmt.Sprintf("Update-Package %s -Version %s", pkg, version), hint: "run in Package Manager Console", executable: false}
		case strings.HasSuffix(base, ".csproj") || strings.HasSuffix(base, ".fsproj") || strings.HasSuffix(base, ".vbproj"):
			return commandResult{
				command:    fmt.Sprintf("dotnet add package %s --version %s", pkg, version),
				args:       []string{"dotnet", "add", "package", pkg, "--version", version},
				executable: true,
			}
		default:
			return commandResult{
				command:    fmt.Sprintf("dotnet add package %s --version %s", pkg, version),
				args:       []string{"dotnet", "add", "package", pkg, "--version", version},
				executable: true,
			}
		}

	// Elixir/Hex
	case "hex", "mix":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "mix.lock":
			return commandResult{
				command:    fmt.Sprintf("mix deps.update %s", pkg),
				args:       []string{"mix", "deps.update", pkg},
				hint:       "ensure mix.exs has correct version constraint",
				executable: true,
			}
		case base == "mix.exs":
			return commandResult{
				command:      fmt.Sprintf("Update %s to ~> %s in mix.exs", pkg, version),
				followUp:     "mix deps.get",
				followUpArgs: []string{"mix", "deps.get"},
				executable:   false,
			}
		default:
			return commandResult{
				command:    fmt.Sprintf("mix deps.update %s", pkg),
				args:       []string{"mix", "deps.update", pkg},
				executable: true,
			}
		}

	// Dart/Flutter/Pub
	case "pub", "dart", "flutter":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "pubspec.lock":
			return commandResult{
				command:    fmt.Sprintf("dart pub upgrade %s", pkg),
				args:       []string{"dart", "pub", "upgrade", pkg},
				hint:       "ensure pubspec.yaml has correct version constraint",
				executable: true,
			}
		case base == "pubspec.yaml":
			return commandResult{
				command:      fmt.Sprintf("Update %s to ^%s in pubspec.yaml", pkg, version),
				followUp:     "dart pub get",
				followUpArgs: []string{"dart", "pub", "get"},
				executable:   false,
			}
		default:
			return commandResult{
				command:    fmt.Sprintf("dart pub upgrade %s", pkg),
				args:       []string{"dart", "pub", "upgrade", pkg},
				executable: true,
			}
		}

	// Swift/CocoaPods
	case "cocoapods", "pod":
		base := strings.ToLower(path.Base(manifestPath))
		switch {
		case base == "podfile.lock":
			return commandResult{
				command:    fmt.Sprintf("pod update %s", pkg),
				args:       []string{"pod", "update", pkg},
				executable: true,
			}
		case base == "podfile":
			return commandResult{
				command:      fmt.Sprintf("Update %s to ~> %s in Podfile", pkg, version),
				followUp:     "pod install",
				followUpArgs: []string{"pod", "install"},
				executable:   false,
			}
		default:
			return commandResult{
				command:    fmt.Sprintf("pod update %s", pkg),
				args:       []string{"pod", "update", pkg},
				executable: true,
			}
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
		expr := fmt.Sprintf("renv::install(\"%s@%s\")", pkg, version)
		return commandResult{
			command:    fmt.Sprintf("Rscript -e %q", expr),
			args:       []string{"Rscript", "-e", expr},
			executable: true,
		}

	// C++/Conan
	case "conan":
		return commandResult{
			command:    fmt.Sprintf("conan install %s/%s@", pkg, version),
			args:       []string{"conan", "install", fmt.Sprintf("%s/%s@", pkg, version)},
			hint:       "update conanfile.txt or conanfile.py first",
			executable: true,
		}

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
