package compare

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

// manifestDirectDepParsers maps non-Go manifest basenames to the parser that
// extracts direct dependency names from that manifest's contents. Both the
// workspace walk and the commit-tree walk dispatch through this table so the
// two collection paths cannot drift in ecosystem coverage. go.mod is handled
// separately by the CollectGoDirectModules* functions because of its module
// root and stdlib pseudo-dependency handling.
var manifestDirectDepParsers = map[string]func([]byte) map[string]bool{
	"package.json":     getNpmDirectDeps,
	"Cargo.toml":       getCargoDirectDeps,
	"pyproject.toml":   getPyprojectDirectDeps,
	"requirements.txt": getRequirementsDirectDeps,
}

// manifestWorkspaceAliasParsers maps manifest basenames to the parser that
// extracts the renames a workspace declares for its members to inherit, keyed
// by the name a member inherits them under. A workspace dependency table is a
// menu, not a dependency list, so nothing in it is direct until a member takes
// it; a member's own manifest records that. What a member's manifest cannot
// spell is a rename, because it names the alias and the workspace names the
// crate, so the renames are carried to the end of the walk and applied to the
// aliases members actually took. Ecosystems with no inheritance mechanism have
// no entry here.
var manifestWorkspaceAliasParsers = map[string]func([]byte) map[string]string{
	"Cargo.toml": getCargoWorkspaceAliases,
}

// collectManifestDependencies applies whichever parsers are registered for a
// manifest's basename to its contents, accumulating direct dependencies and
// workspace aliases. Both collection paths go through it so the workspace walk
// and the commit-tree walk cannot drift in coverage. The contents are read
// through read only once a parser wants them, and a file that fails to read is
// skipped best-effort.
func collectManifestDependencies(name string, read func() ([]byte, error), direct map[string]bool, aliases map[string]string) {
	base := path.Base(name)
	parseDeps, hasDeps := manifestDirectDepParsers[base]
	parseAliases, hasAliases := manifestWorkspaceAliasParsers[base]
	if !hasDeps && !hasAliases {
		return
	}
	if isVendoredManifestPath(name) {
		return
	}
	data, err := read()
	if err != nil {
		return
	}
	if hasDeps {
		mergeDirectDependencies(direct, parseDeps(data))
	}
	if hasAliases {
		maps.Copy(aliases, parseAliases(data))
	}
}

// resolveWorkspaceAliases records the crate behind every workspace rename a
// member actually inherited. An alias no member names stays out of the direct
// set, which is the whole point: a version declared centrally for inheritance
// is not by itself a dependency of anything, and counting it as one marks a
// transitive lockfile package direct in the SBOM and in pkg.direct.
func resolveWorkspaceAliases(direct map[string]bool, aliases map[string]string) {
	for alias, crate := range aliases {
		if direct[alias] {
			direct[crate] = true
		}
	}
}

// isVendoredManifestPath reports whether a slash-separated manifest path lies
// under a vendored or installed dependency tree (vendor/, node_modules/) or
// git metadata. Manifests there describe third-party packages, not the
// project's own direct dependencies, mirroring the directory skips applied
// during workspace walks.
func isVendoredManifestPath(p string) bool {
	for seg := range strings.SplitSeq(path.Clean(p), "/") {
		switch seg {
		case "vendor", "node_modules", ".git":
			return true
		}
	}
	return false
}

// CollectDirectDependenciesFromWorkspace scans the workspace for manifest files
// across multiple ecosystems and extracts direct dependencies. Returns a map
// keyed by the name a package goes by in its own ecosystem: a module path for
// Go, a scoped package name for npm, a crate name for Cargo, and a
// distribution name for PyPI. Cargo and PyPI keys are folded by
// [ecosystem.Ecosystem.NameEquivalenceKey], because a manifest and a lockfile
// are free to spell one package two ways; the map is a lookup table, so a
// folded key never becomes a name anyone reads. Values indicate if the
// dependency is direct (true) or indirect (false). Lookups go through
// proto.ExtractorPackageIsDirect, which keys the scanned package the same way,
// so both sides build one key.
//
// Supported ecosystems:
//   - Go (go.mod)
//   - npm (package.json)
//   - Cargo (Cargo.toml)
//   - PyPI (pyproject.toml, setup.py, requirements.txt)
//
// For Go, this delegates to CollectGoDirectModulesFromWorkspace for its
// specialized handling of module roots and the stdlib pseudo-dependency.
func CollectDirectDependenciesFromWorkspace(ws workspace.FS) map[string]bool {
	if ws == nil {
		return make(map[string]bool)
	}

	// Start with Go direct dependencies (handles stdlib specially)
	direct := CollectGoDirectModulesFromWorkspace(ws)
	aliases := make(map[string]string)

	// Walk workspace looking for other ecosystem manifests
	_ = fs.WalkDir(ws, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}
		collectManifestDependencies(p, func() ([]byte, error) { return ws.ReadFile(p) }, direct, aliases)
		return nil
	})

	// A workspace rename resolves only once the whole tree has been seen: the
	// member that inherits the alias and the root that defines it are two files.
	resolveWorkspaceAliases(direct, aliases)

	return direct
}

// CollectDirectDependenciesFromCommit extracts direct dependencies from
// manifest files present in a specific Git commit, covering the same
// ecosystems as CollectDirectDependenciesFromWorkspace (Go, npm, Cargo,
// PyPI). Ref-based scans must classify direct vs transitive dependencies with
// the same fidelity as working-tree scans, so both paths share the same
// per-manifest parsers; only the file source differs. Individual files that
// fail to read are skipped best-effort, matching the workspace walk.
func CollectDirectDependenciesFromCommit(repo *git.Repository, hash plumbing.Hash) (map[string]bool, error) {
	direct, err := CollectGoDirectModulesFromCommit(repo, hash)
	if err != nil {
		return nil, fmt.Errorf("collecting go direct modules at commit: %w", err)
	}
	if repo == nil {
		return direct, nil
	}
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, fmt.Errorf("getting commit %s: %w", hash, err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("getting tree for commit %s: %w", hash, err)
	}
	aliases := make(map[string]string)
	err = tree.Files().ForEach(func(f *object.File) error {
		collectManifestDependencies(f.Name, func() ([]byte, error) {
			contents, err := f.Contents()
			if err != nil {
				return nil, err
			}
			return []byte(contents), nil
		}, direct, aliases)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking commit tree: %w", err)
	}
	resolveWorkspaceAliases(direct, aliases)
	return direct, nil
}

// getNpmDirectDeps extracts direct dependencies from package.json.
// Returns map of package names to true (direct).
// devDependencies are marked as direct=true since they're explicitly declared.
// An aliased entry contributes both spellings, see [recordNpmDependency].
func getNpmDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return deps
	}

	for name, spec := range pkg.Dependencies {
		recordNpmDependency(deps, name, spec)
	}
	for name, spec := range pkg.DevDependencies {
		recordNpmDependency(deps, name, spec)
	}
	return deps
}

// recordNpmDependency records the names a single package.json entry can be
// reported under. The manifest key is one of them, and an aliased entry
// ("my-lodash": "npm:lodash@^4.17.21") adds the package the alias points at,
// because that is the name the lockfile carries and the name every npm
// extractor reports.
func recordNpmDependency(deps map[string]bool, name, spec string) {
	if name = strings.TrimSpace(name); name != "" {
		deps[name] = true
	}
	if aliased := npmAliasTarget(spec); aliased != "" {
		deps[aliased] = true
	}
}

// npmAliasTarget returns the package an "npm:" specifier aliases, without its
// version range, and "" for any other specifier. The range is separated by the
// last "@", which is never the one that opens a scope because a scope only
// leads the name.
func npmAliasTarget(spec string) string {
	target, ok := strings.CutPrefix(strings.TrimSpace(spec), "npm:")
	if !ok {
		return ""
	}
	if idx := strings.LastIndex(target, "@"); idx > 0 {
		target = target[:idx]
	}
	return strings.TrimSpace(target)
}

// cargoDependencyTables are the three dependency tables a Cargo manifest
// section can declare. Each entry's value is decoded as any because a
// dependency is either a version string or a table, and only the table form
// carries the "package" key that renames a crate.
type cargoDependencyTables struct {
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
}

// tables returns this section's dependency tables. Absent tables decode to nil
// maps, which range over nothing, so callers need no presence checks.
func (t cargoDependencyTables) tables() []map[string]any {
	return []map[string]any{t.Dependencies, t.DevDependencies, t.BuildDependencies}
}

// cargoManifest is the slice of Cargo.toml that bears on direct dependencies:
// the package's own tables, the per-target tables a platform-conditional
// dependency lives in, and the workspace tables a root manifest offers its
// members. The first two are places a project declares a dependency itself, so
// they are direct. The workspace tables are not: an entry there is a version
// available for inheritance, and a member has to reference it with
// "workspace = true" before anything depends on it. See
// [getCargoWorkspaceAliases].
type cargoManifest struct {
	cargoDependencyTables
	Target    map[string]cargoDependencyTables `toml:"target"`
	Workspace cargoDependencyTables            `toml:"workspace"`
}

// getCargoDirectDeps extracts direct dependencies from Cargo.toml, keyed by the
// crate names a scanned package can be reported under. A manifest that does not
// parse as TOML yields nothing: Cargo would not build it either.
func getCargoDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	var manifest cargoManifest
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return deps
	}

	sections := []cargoDependencyTables{manifest.cargoDependencyTables}
	for _, target := range manifest.Target {
		sections = append(sections, target)
	}
	for _, section := range sections {
		for _, table := range section.tables() {
			for name, entry := range table {
				recordCargoDependency(deps, name, entry)
			}
		}
	}

	return deps
}

// getCargoWorkspaceAliases returns the crate each [workspace.dependencies]
// entry renames, keyed by the name a member inherits it under. Only renamed
// entries are returned: a member that writes "serde.workspace = true" records
// "serde" from its own manifest already, while one that writes
// "my-serde.workspace = true" records a key crates.io has never heard of, and
// only the workspace manifest knows it means "serde".
//
// The entries themselves are deliberately not dependencies. Including the whole
// table marked a crate direct because its version happened to be declared
// centrally, even when no member inherited it and the lockfile only carries it
// as somebody else's transitive dependency.
func getCargoWorkspaceAliases(data []byte) map[string]string {
	var manifest cargoManifest
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil
	}
	aliases := make(map[string]string)
	for _, table := range manifest.Workspace.tables() {
		for name, entry := range table {
			details, isTable := entry.(map[string]any)
			if !isTable {
				continue
			}
			renamed, _ := details["package"].(string)
			alias := ecosystem.Cargo.NameEquivalenceKey(name)
			crate := ecosystem.Cargo.NameEquivalenceKey(renamed)
			if alias == "" || crate == "" || alias == crate {
				continue
			}
			aliases[alias] = crate
		}
	}
	return aliases
}

// recordCargoDependency records the crate names a single Cargo.toml dependency
// entry can be reported under. The manifest key is one of them because the
// Cargo.toml extractor reports it verbatim, and a renamed dependency
// (my-serde = { package = "serde" }) adds the crate it actually names, which is
// what Cargo.lock records and what crates.io and OSV know it as.
func recordCargoDependency(deps map[string]bool, name string, entry any) {
	if key := ecosystem.Cargo.NameEquivalenceKey(name); key != "" {
		deps[key] = true
	}
	table, ok := entry.(map[string]any)
	if !ok {
		return
	}
	renamed, _ := table["package"].(string)
	if key := ecosystem.Cargo.NameEquivalenceKey(renamed); key != "" {
		deps[key] = true
	}
}

// getPyprojectDirectDeps extracts direct dependencies from pyproject.toml.
// Supports both PEP 621 [project.dependencies] and Poetry [tool.poetry.dependencies].
func getPyprojectDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	lines := strings.Split(string(data), "\n")
	inProjectSection := false
	inPoetryDeps := false
	inDepsArray := false // Inside a multi-line dependencies = [ ... ] array

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track which section we're in
		if strings.HasPrefix(trimmed, "[") {
			// Exiting any array we were in
			inDepsArray = false

			inProjectSection = trimmed == "[project]"
			inPoetryDeps = trimmed == "[tool.poetry.dependencies]"
			continue
		}

		// Handle PEP 621 dependencies array start
		if inProjectSection && strings.HasPrefix(trimmed, "dependencies") && strings.Contains(trimmed, "=") {
			if idx := strings.Index(trimmed, "["); idx != -1 {
				// Check if it's a single-line array that also closes
				if strings.Contains(trimmed[idx:], "]") {
					parseInlineDepsArray(trimmed[idx:], deps)
				} else {
					// Multi-line array starting
					inDepsArray = true
					// Parse any deps on the opening line after [
					parseInlineDepsArray(trimmed[idx:]+"]", deps)
				}
			}
			continue
		}

		// Handle multi-line PEP 621 dependencies array
		if inDepsArray {
			if strings.Contains(trimmed, "]") {
				// Array closing - parse any remaining deps on this line
				if idx := strings.Index(trimmed, "]"); idx > 0 {
					parseInlineDepsArray("["+trimmed[:idx]+"]", deps)
				}
				inDepsArray = false
			} else if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				// Parse individual dependency line: "celery>=5.3.0",
				entry := strings.Trim(trimmed, ",\"'")
				if entry != "" {
					parsePyPIDep(entry, deps)
				}
			}
			continue
		}

		// Handle optional-dependencies section (key = [...] format)
		if strings.HasPrefix(trimmed, "[project.optional-dependencies") ||
			(inProjectSection && strings.Contains(line, "optional-dependencies")) {
			// Skip section header
			continue
		}

		// Handle Poetry-style dependencies
		if inPoetryDeps && !strings.HasPrefix(trimmed, "#") && trimmed != "" {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				pkgName := strings.Trim(strings.TrimSpace(parts[0]), `"'`)
				if pkgName != "" && pkgName != "python" {
					recordPyPIDirectDep(deps, pkgName)
				}
			}
		}
	}

	return deps
}

// pyPIRequirementSeparators are the characters that end the distribution name
// in a PEP 508 requirement. "@" is one of them: a direct reference is spelled
// "name @ https://...", so the name stops there too.
var pyPIRequirementSeparators = []string{">=", "<=", "==", "!=", "~=", "<", ">", "[", ";", "@"}

// pyPIRequirementName returns the distribution name a PEP 508 requirement
// declares, with the version specifier, extras, environment marker, and direct
// reference URL stripped. The name is returned as written; callers normalize.
func pyPIRequirementName(entry string) string {
	pkgName := entry
	for _, sep := range pyPIRequirementSeparators {
		if idx := strings.Index(pkgName, sep); idx != -1 {
			pkgName = pkgName[:idx]
		}
	}
	return strings.TrimSpace(pkgName)
}

// recordPyPIDirectDep records a declared distribution under the one key PyPI
// resolves its spellings to. The rule is
// [ecosystem.Ecosystem.NameEquivalenceKey], the same call the directness lookup
// makes on the scanned package's PURL name, so a manifest that writes
// "Flask-SQLAlchemy" and an extractor that reports "flask_sqlalchemy" agree on
// one key.
func recordPyPIDirectDep(deps map[string]bool, name string) {
	if key := ecosystem.PyPI.NameEquivalenceKey(name); key != "" {
		deps[key] = true
	}
}

// parsePyPIDep extracts and normalizes a single PyPI dependency string.
func parsePyPIDep(entry string, deps map[string]bool) {
	recordPyPIDirectDep(deps, pyPIRequirementName(entry))
}

// parseInlineDepsArray parses a Python dependency array like ["pkg1>=1.0", "pkg2"]
func parseInlineDepsArray(line string, deps map[string]bool) {
	// Find array content between [ ]
	start := strings.Index(line, "[")
	end := strings.LastIndex(line, "]")
	if start == -1 || end == -1 || end <= start {
		return
	}

	content := line[start+1 : end]
	// Split by comma and parse each entry
	for entry := range strings.SplitSeq(content, ",") {
		entry = strings.TrimSpace(entry)
		entry = strings.Trim(entry, "\"'")
		parsePyPIDep(entry, deps)
	}
}

// getRequirementsDirectDeps extracts package names from requirements.txt.
// All entries in requirements.txt are considered direct dependencies.
func getRequirementsDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip -r, -e, --index-url, etc.
		if strings.HasPrefix(line, "-") {
			continue
		}

		recordPyPIDirectDep(deps, pyPIRequirementName(line))
	}

	return deps
}
