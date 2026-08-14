package compare

import (
	"cmp"
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"path"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

// manifestDirectDepParsers maps non-Go manifest basenames to the parser that
// extracts direct dependency keys from that file's contents. Both the
// workspace walk and the commit-tree walk dispatch through this table so the
// two collection paths cannot drift in ecosystem coverage. go.mod is handled
// separately by the CollectGoDirectModules* functions because of its module
// root and stdlib pseudo-dependency handling.
//
// package-lock.json is a lockfile rather than a manifest, and it is here because
// a declaration and its resolution live in different files: package.json names
// the range, and only the lockfile says which version it resolved to. What it
// contributes is keyed by [DirectVersionKey], and the manifest beside it then
// contributes a bare name only for the declarations it did not answer.
var manifestDirectDepParsers = map[string]func([]byte) map[string]bool{
	npmManifestBase:    getNpmDirectDeps,
	npmLockBase:        getNpmLockDirectDeps,
	npmShrinkwrapBase:  getNpmLockDirectDeps,
	"Cargo.toml":       getCargoDirectDeps,
	"pyproject.toml":   getPyprojectDirectDeps,
	"requirements.txt": getRequirementsDirectDeps,
}

// The npm files whose contributions have to be combined per project rather than
// merged on sight: the manifest declares names, a lockfile says which versions
// they resolved to, and which lockfile is authoritative depends on whether the
// other one is beside it. See [manifestScan.resolve].
//
// npm-shrinkwrap.json is a package-lock.json under another name, published rather
// than kept local, so one parser reads both.
const (
	npmManifestBase   = "package.json"
	npmLockBase       = "package-lock.json"
	npmShrinkwrapBase = "npm-shrinkwrap.json"
)

// isNpmLockBase reports whether a filename is one of the npm lockfiles this
// collector resolves declarations against.
func isNpmLockBase(base string) bool {
	return base == npmLockBase || base == npmShrinkwrapBase
}

// DirectVersionKey is the key under which a declared dependency's resolved
// version is recorded, for the ecosystems whose lockfile says which version a
// declaration resolved to. It shares the direct set with the name-only keys
// rather than living in a second map, so every existing reader of the set is
// unaffected: the keys it adds are ones no name-only lookup constructs.
func DirectVersionKey(name, version string) string {
	return name + "@" + version
}

// LookupDirect reports whether a scanned package is a direct dependency, given
// the name it goes by in its own ecosystem and the version it was found at.
//
// Every entry in the set is a positive statement. A versioned key says "a project
// declared this name and it resolved to this version"; a name key says "a project
// declared this name, and which version that resolved to is not recorded". A
// package is direct when either holds, which makes the answer monotone in the
// set: adding an entry can make a package direct and can never take that away.
//
// Monotonicity is the property one flat map for a whole scan has to have, and it
// is why there is no key meaning "versions were resolved for this name". That is a
// statement about a project rather than about a package, and a scan-wide table
// cannot say which project it came from, so reading it as though it held
// everywhere denied another project's declaration: a repository with an npm-locked
// project beside a Yarn one had the Yarn project's explicitly declared version
// read as transitive. What a resolution suppresses is now decided where the
// projects are still distinguishable, in [manifestScan.resolve], so nothing
// reaching this function can contradict anything else in it.
//
// It is the one definition of the rule. [proto.ExtractorPackageIsDirect] calls
// it rather than reimplementing the key construction, for the same reason the
// name keys are folded on both sides by one function: two spellings of one rule
// is how the manifest side and the lookup side come to disagree.
func LookupDirect(direct map[string]bool, name, version string) bool {
	return direct[DirectVersionKey(name, version)] || direct[name]
}

// goDirectDepManifest is the manifest [CollectGoDirectModulesFromWorkspace] and
// [CollectGoDirectModulesFromCommit] read. It is named here rather than in
// [manifestDirectDepParsers] because those two collectors need the module root
// and the stdlib pseudo-dependency, which a content-only parser cannot see.
const goDirectDepManifest = "go.mod"

// ecosystemsWithDirectDependencyCollection returns the ecosystems whose direct
// dependencies these collectors actually read, sorted by canonical token. It is
// derived by matching the manifests the parsers above are registered for against
// the file patterns the ecosystem registry declares, so an ecosystem joins the
// answer when its parser is written and not when someone remembers to say so.
//
// It answers the question the directness contract cannot: an ecosystem nobody
// parses looks exactly like a project that declared nothing, because
// [proto.ExtractorPackageIsDirect] returns false for a key no collector ever
// wrote and is_direct is a bool. Ecosystems that are direct by construction (base
// images, workflow uses, mise and asdf tools) are classified from the PURL type
// instead and are deliberately absent.
//
// It is the input the reporting side of issue #246 needs, which is where an
// undetermined ecosystem becomes something a caller can render rather than a
// value it has to guess at. Exporting it belongs with that caller, whose needs
// are what make the signature knowable.
func ecosystemsWithDirectDependencyCollection() []ecosystem.Ecosystem {
	collected := make([]ecosystem.Ecosystem, 0, len(manifestDirectDepParsers)+1)
	for _, reg := range ecosystem.Default().All() {
		for _, pattern := range slices.Concat(reg.Manifests, reg.Lockfiles) {
			_, parsed := manifestDirectDepParsers[pattern]
			if parsed || pattern == goDirectDepManifest {
				collected = append(collected, reg.Ecosystem)
				break
			}
		}
	}
	slices.Sort(collected)
	return slices.Compact(collected)
}

// manifestWorkspaceAliasParsers maps manifest basenames to the parser that
// extracts the renames a workspace root declares for its members to inherit,
// keyed by the name a member inherits them under, and reports whether the
// manifest declares a workspace at all. A workspace dependency table is a menu,
// not a dependency list, so nothing in it is direct until a member takes it.
// What a member's manifest cannot spell is a rename, because it names the alias
// and the workspace names the crate, so the renames are carried to the end of
// the walk and applied to the aliases members of that root actually took.
// Ecosystems with no inheritance mechanism have no entry here.
//
// Root-ness is reported separately from the renames because a root that renames
// nothing still bounds its members' inheritance, see
// [manifestScan.governingRenames].
var manifestWorkspaceAliasParsers = map[string]func([]byte) (map[string]string, bool){
	"Cargo.toml": getCargoWorkspaceAliases,
}

// manifestWorkspaceInheritanceParsers maps manifest basenames to the parser
// that reports which of a manifest's own dependency keys are inherited from its
// workspace rather than declared locally. Taking the offer is what makes a
// workspace entry a dependency of anything, and it is the only thing that says
// so: the key a member writes for an inherited dependency is spelled exactly
// like the key it writes for a local one. Ecosystems with no inheritance
// mechanism have no entry here.
var manifestWorkspaceInheritanceParsers = map[string]func([]byte) map[string]bool{
	"Cargo.toml": getCargoInheritedDeps,
}

// manifestScope identifies the inheritance scope a manifest takes part in: the
// directory it sits in, and the kind of manifest it is. Both halves matter. A
// rename is offered by one workspace root to the members under it, so the
// directory is what tells a member's root from some other root in the same
// repository, and the kind is what keeps a member of one ecosystem from
// resolving against a root declared by another that happens to share a
// directory.
type manifestScope struct {
	kind string
	dir  string
}

// manifestScan accumulates what a walk over a tree's manifests learns. direct
// is the answer callers want. inherited and roots are the two halves of a
// workspace rename that no single manifest holds, since the member records the
// alias it took and its root records the crate that alias means, so they are
// carried until the walk ends and folded in by resolve. Both walks fill one of
// these, which is what stops either from collecting half the answer.
//
// Both are keyed by scope rather than pooled per repository: one repository can
// hold several independent workspace roots, and an alias means whatever the
// member's own root says it means.
// npmDeclared and npmLocks are the same idea for npm, and the reason they are
// scoped is that one repository can hold several npm projects with different
// tooling. Neither a package.json's names nor a lockfile's resolutions are merged
// on sight: whether a name needs its bare key depends on whether that project's
// lockfile resolved it, and which lockfile governs depends on what other lockfile
// sits beside it, so all three files are read independently and reconciled once
// the walk has seen them.
type manifestScan struct {
	direct      map[string]bool
	inherited   map[manifestScope]map[string]bool
	roots       map[manifestScope]map[string]string
	npmDeclared map[manifestScope]map[string]bool
	npmLocks    map[manifestScope]npmResolution
}

// npmResolution is what one npm lockfile contributes: the versioned keys naming
// each declaration it resolved, and the declaration spellings those keys answer
// for. The two differ for an aliased entry, which is declared under the alias and
// resolved under the package it really is, so both spellings have to be known
// here or the alias keeps a bare key that answers for every version of whatever
// else goes by that name.
type npmResolution struct {
	versionKeys map[string]bool
	resolved    map[string]bool
}

// newManifestScan starts a scan from the direct dependencies already collected
// for Go, whose manifest is walked separately for its module root and stdlib
// pseudo-dependency handling.
func newManifestScan(direct map[string]bool) *manifestScan {
	return &manifestScan{
		direct:      direct,
		inherited:   make(map[manifestScope]map[string]bool),
		roots:       make(map[manifestScope]map[string]string),
		npmDeclared: make(map[manifestScope]map[string]bool),
		npmLocks:    make(map[manifestScope]npmResolution),
	}
}

// recordNpmDeclarations defers the names a package.json declares until the walk
// ends. A name gets a bare key only if nothing resolved it to a version, and the
// lockfile that would have is a different file, possibly read later and possibly
// in a directory above this one.
func (s *manifestScan) recordNpmDeclarations(scope manifestScope, names map[string]bool) {
	declared, ok := s.npmDeclared[scope]
	if !ok {
		declared = make(map[string]bool, len(names))
		s.npmDeclared[scope] = declared
	}
	maps.Copy(declared, names)
}

// recordNpmLock notes what one lockfile contributes, under the directory and
// filename it was found at. Nothing is merged into the direct set yet, because a
// package-lock.json is only authoritative if no npm-shrinkwrap.json sits beside
// it, and the walk may not have reached the sibling.
func (s *manifestScan) recordNpmLock(scope manifestScope, resolution npmResolution) {
	existing, ok := s.npmLocks[scope]
	if !ok {
		s.npmLocks[scope] = resolution
		return
	}
	maps.Copy(existing.versionKeys, resolution.versionKeys)
	maps.Copy(existing.resolved, resolution.resolved)
}

// governingNpmLocks reduces the lockfiles the walk found to the one per directory
// that actually governs, applying npm's precedence: where an npm-shrinkwrap.json
// and a package-lock.json share a directory, the shrinkwrap wins and the
// package-lock is ignored outright.
//
// The precedence is not taken from npm's documentation but from what Deputy's own
// inventory does, since the two have to agree about which file is authoritative.
// OSV-SCALIBR's packagelockjson extractor returns nothing at all for a
// package-lock.json with a shrinkwrap beside it, so a stale package-lock resolving
// a name to a version the inventory never reports would otherwise suppress the
// declaration and leave the version inventory does report classified as
// transitive.
// Two lockfiles that survive for one directory are unioned rather than allowed
// to overwrite each other. The precedence above means that cannot happen with the
// two kinds npm has, but the result of this function must not depend on map
// iteration order, and a union is the answer that keeps every entry a positive
// fact if a third kind is ever read here.
func (s *manifestScan) governingNpmLocks() map[string]npmResolution {
	governing := make(map[string]npmResolution, len(s.npmLocks))
	for scope, resolution := range s.npmLocks {
		if scope.kind == npmLockBase {
			if _, shadowed := s.npmLocks[manifestScope{kind: npmShrinkwrapBase, dir: scope.dir}]; shadowed {
				continue
			}
		}
		existing, ok := governing[scope.dir]
		if !ok {
			governing[scope.dir] = npmResolution{
				versionKeys: maps.Clone(resolution.versionKeys),
				resolved:    maps.Clone(resolution.resolved),
			}
			continue
		}
		maps.Copy(existing.versionKeys, resolution.versionKeys)
		maps.Copy(existing.resolved, resolution.resolved)
	}
	return governing
}

// governingNpmResolutions returns the names resolved by the nearest npm lockfile
// at or above dir, which is the lockfile that governs a manifest there: npm
// workspace members keep their declarations in their own package.json while the
// lockfile sits at the workspace root.
//
// The search stops at the first lockfile it finds, for the same reason
// [manifestScan.governingRenames] does: a nearer lockfile is the only one that
// resolves a project's declarations, and reaching past it would let an unrelated
// project's resolutions decide what this one declared.
//
// Directories are spelled as [path.Dir] gives them, so the tree root is "." and
// the walk ends when it stops changing. Normalizing the root to "" instead left a
// workspace member searching for a key the root lockfile never wrote.
func governingNpmResolutions(governing map[string]npmResolution, dir string) map[string]bool {
	for {
		if resolution, ok := governing[dir]; ok {
			return resolution.resolved
		}
		parent := path.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// recordWorkspaceRoot notes that the manifest at a scope declares a workspace,
// along with the renames it offers its members. A root is recorded even when it
// renames nothing, because its presence is what stops its members from
// resolving against a root further up.
func (s *manifestScan) recordWorkspaceRoot(scope manifestScope, renames map[string]string) {
	root, ok := s.roots[scope]
	if !ok {
		root = make(map[string]string, len(renames))
		s.roots[scope] = root
	}
	maps.Copy(root, renames)
}

// recordInherited notes the dependency keys the manifest at a scope takes from
// its workspace.
func (s *manifestScan) recordInherited(scope manifestScope, keys map[string]bool) {
	taken, ok := s.inherited[scope]
	if !ok {
		taken = make(map[string]bool, len(keys))
		s.inherited[scope] = taken
	}
	maps.Copy(taken, keys)
}

// governingRenames returns the renames offered by the workspace root a scope
// inherits from: the manifest of the same kind in the nearest directory at or
// above it that declared a workspace. The search stops at the first root it
// finds, whether or not that root spells the alias being resolved, because a
// nearer root is the only one a member can inherit from and reaching past it
// would attribute a crate the member's own workspace never named.
//
// A scope with no root above it resolves nothing, rather than falling back to
// some other root's renames. That leaves a member whose root sits outside the
// scanned tree with the alias it wrote and without the crate behind it, which is
// the direction that cannot invent a dependency.
func (s *manifestScan) governingRenames(scope manifestScope) (map[string]string, bool) {
	for dir := scope.dir; ; dir = path.Dir(dir) {
		if renames, ok := s.roots[manifestScope{kind: scope.kind, dir: dir}]; ok {
			return renames, true
		}
		if parent := path.Dir(dir); parent == dir {
			return nil, false
		}
	}
}

// resolve records the crate behind every workspace rename a member actually
// inherited and returns the direct set. An alias no member inherited stays out,
// which is the whole point: a version declared centrally for inheritance is not
// by itself a dependency of anything, and counting it as one marks a transitive
// lockfile package direct in the SBOM and in pkg.direct.
//
// Inheritance is what is tested, not the presence of the alias in the direct
// set. A member is free to declare a local dependency under the same name as an
// alias nobody took, and the name alone cannot tell the two apart.
//
// Each member resolves against its own workspace root, so two roots that spell
// one alias differently stay apart and neither lends its renames to the other's
// members.
func (s *manifestScan) resolve() map[string]bool {
	for scope, taken := range s.inherited {
		renames, ok := s.governingRenames(scope)
		if !ok {
			continue
		}
		for alias := range taken {
			if crate, ok := renames[alias]; ok {
				s.direct[crate] = true
			}
		}
	}

	// An npm name gets a bare key only when the lockfile governing its project
	// did not resolve it to a version. A resolved name already has its versioned
	// key, and adding the bare one beside it would answer for every other copy
	// of that name in the scan, which is the over-claiming the resolution exists
	// to stop.
	//
	// Suppression is per name and per project, which is what keeps it from
	// deciding anything about a project it did not read. A declaration the
	// lockfile could not resolve keeps its bare key even when its neighbours in
	// the same manifest were resolved, and a project with no lockfile at all
	// keeps every one of them. The consequence, once a repository mixes an
	// npm-locked project with a Yarn or pnpm one that declares the same name, is
	// that the bare key from the unresolved project answers for every version of
	// it, so a transitive copy in the locked project reads direct. That is
	// over-claiming, which is the direction to fail in: the alternative denies a
	// dependency a project explicitly declared.
	// Only the governing lockfile's keys reach the set, so a package-lock that a
	// shrinkwrap displaces contributes neither a resolution nor a suppression.
	governing := s.governingNpmLocks()
	for _, resolution := range governing {
		mergeDirectDependencies(s.direct, resolution.versionKeys)
	}
	for scope, declared := range s.npmDeclared {
		resolved := governingNpmResolutions(governing, scope.dir)
		for name := range declared {
			if resolved[name] {
				continue
			}
			s.direct[name] = true
		}
	}
	return s.direct
}

// collectManifestDependencies applies whichever parsers are registered for a
// manifest's basename to its contents, accumulating direct dependencies and the
// two halves of a workspace rename under the scope the manifest occupies. Both
// collection paths go through it so the workspace walk and the commit-tree walk
// cannot drift in coverage. The contents are read through read only once a
// parser wants them, and a file that fails to read is skipped best-effort.
func collectManifestDependencies(name string, read func() ([]byte, error), scan *manifestScan) {
	base := path.Base(name)
	parseDeps, hasDeps := manifestDirectDepParsers[base]
	parseAliases, hasAliases := manifestWorkspaceAliasParsers[base]
	parseInherited, hasInherited := manifestWorkspaceInheritanceParsers[base]
	if !hasDeps && !hasAliases && !hasInherited {
		return
	}
	if isVendoredManifestPath(name) {
		return
	}
	data, err := read()
	if err != nil {
		return
	}
	scope := manifestScope{kind: base, dir: path.Dir(path.Clean(name))}
	if hasDeps {
		switch {
		case base == npmManifestBase:
			// Deferred: whether these names need a bare key depends on the
			// lockfile governing this directory, which is a file this call does
			// not have. See [manifestScan.resolve].
			scan.recordNpmDeclarations(scope, parseDeps(data))
		case isNpmLockBase(base):
			// Deferred too, because a package-lock.json beside an
			// npm-shrinkwrap.json contributes nothing at all and this call
			// cannot see its sibling.
			scan.recordNpmLock(scope, npmLockResolution(data))
		default:
			mergeDirectDependencies(scan.direct, parseDeps(data))
		}
	}
	if hasAliases {
		if renames, isRoot := parseAliases(data); isRoot {
			scan.recordWorkspaceRoot(scope, renames)
		}
	}
	if hasInherited {
		if keys := parseInherited(data); len(keys) > 0 {
			scan.recordInherited(scope, keys)
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
// The files parsed are exactly [manifestDirectDepParsers] plus go.mod:
//   - Go (go.mod)
//   - npm (package.json, and package-lock.json for the resolved versions)
//   - Cargo (Cargo.toml)
//   - PyPI (pyproject.toml, requirements.txt)
//
// Only npm resolves a declaration to a version. For every other ecosystem a
// declared name marks each copy of that name direct, which over-claims when a
// lockfile carries two versions of one declared package. Cargo is the case that
// can: see [LookupDirect] and issue #279.
//
// setup.py is not among them. It was listed here and never parsed, so a
// distribution declared only in install_requires was collected by nothing and
// read as indirect.
//
// Every other ecosystem Deputy inventories (Maven, RubyGems, NuGet, Hex, Pub,
// CocoaPods, Packagist, Hackage, CRAN, ConanCenter) contributes no key at all, so
// its packages are absent from the map rather than recorded as indirect. The
// distinction is invisible downstream: proto.ExtractorPackageIsDirect returns
// false for a missing key, and a direct-only rule reads that as "not a direct
// dependency" rather than "not determined for this ecosystem". Those ecosystems
// that are direct by construction (Docker and OCI base images, GitHub Actions
// uses, mise and asdf tools) are classified there instead and need no manifest
// parser here.
//
// For Go, this delegates to CollectGoDirectModulesFromWorkspace for its
// specialized handling of module roots and the stdlib pseudo-dependency.
func CollectDirectDependenciesFromWorkspace(ws workspace.FS) map[string]bool {
	if ws == nil {
		return make(map[string]bool)
	}

	// Start with Go direct dependencies (handles stdlib specially)
	scan := newManifestScan(CollectGoDirectModulesFromWorkspace(ws))

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
		collectManifestDependencies(p, func() ([]byte, error) { return ws.ReadFile(p) }, scan)
		return nil
	})

	// A workspace rename resolves only once the whole tree has been seen: the
	// member that inherits the alias and the root that defines it are two files.
	return scan.resolve()
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
	scan := newManifestScan(direct)
	err = tree.Files().ForEach(func(f *object.File) error {
		collectManifestDependencies(f.Name, func() ([]byte, error) {
			contents, err := f.Contents()
			if err != nil {
				return nil, err
			}
			return []byte(contents), nil
		}, scan)
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking commit tree: %w", err)
	}
	return scan.resolve(), nil
}

// getNpmDirectDeps extracts direct dependencies from package.json.
// Returns map of package names to true (direct).
//
// Every table a project declares for itself counts as direct: dependencies,
// devDependencies, and optionalDependencies. An optional dependency is installed
// like any other and the lockfile records it, so the extractor reports it as an
// installed package; what "optional" tolerates is a failed install, not the
// declaration. Leaving the table out left a package the project named itself
// looking transitive in the SBOM and in pkg.direct, and a direct-only rule
// skipped it.
//
// peerDependencies is deliberately not among them. A peer entry is a constraint
// on whoever installs this package ("bring your own react"), not a dependency
// this package declares for itself, so the project that satisfies it is the one
// that declares it.
//
// An aliased entry contributes both spellings, see [recordNpmDependency].
func getNpmDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return deps
	}

	for _, table := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.OptionalDependencies} {
		for name, spec := range table {
			recordNpmDependency(deps, name, spec)
		}
	}
	return deps
}

// npmLockfile is the slice of package-lock.json that says which version each of
// the project's declarations resolved to. Only the v2/v3 "packages" object can
// answer that: its "" entry holds the root's own dependency tables and names its
// workspace members, a member's entry holds that member's tables, and an install
// path such as "node_modules/<name>" holds the copy that got installed there.
// A v1 lockfile has a flat "dependencies" tree whose top level mixes the root's
// dependencies with hoisted transitive ones, which cannot distinguish the two, so
// it contributes nothing and the name-only answer stands.
type npmLockfile struct {
	Packages map[string]npmLockEntry `json:"packages"`
}

// npmLockEntry is one entry of a v2/v3 lockfile's "packages" object. The same
// shape serves the three kinds of entry the resolution needs: the root, whose
// Workspaces names its members, a member, whose dependency tables are
// declarations like the root's, and an installed copy, whose Version is the
// answer a declaration resolves to. Name is set on an installed copy when the
// directory it sits in is not the package's name, which is how an alias records
// the package it actually is.
type npmLockEntry struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Workspaces           []string          `json:"workspaces"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

// declarationTables returns the entry's dependency tables. Absent tables decode
// to nil maps, which range over nothing, so callers need no presence checks.
func (e npmLockEntry) declarationTables() []map[string]string {
	return []map[string]string{e.Dependencies, e.DevDependencies, e.OptionalDependencies}
}

// npmDeclarationSites returns the lockfile keys whose dependency tables are the
// project's own declarations: the root, plus every workspace member the root
// claims. A member is as much the project as the root is, and npm keeps its
// tables in the member's own entry rather than in the root's, so reading only the
// root left every member's declaration resolving to nothing.
//
// Membership is taken from the root's "workspaces" globs rather than from the
// shape of the key, because a path entry is not necessarily a member: a "file:"
// dependency is a local package the project depends on, and its dependency
// tables are its author's declarations, not the project's. A lockfile that
// declares no workspaces therefore contributes only the root, and a member whose
// glob this does not match resolves nothing and keeps the name-only answer.
func npmDeclarationSites(lock npmLockfile, root npmLockEntry) []string {
	sites := []string{""}
	if len(root.Workspaces) == 0 {
		return sites
	}
	for key := range lock.Packages {
		if key == "" || strings.Contains(key, "node_modules/") {
			continue
		}
		if isNpmWorkspaceMember(key, root.Workspaces) {
			sites = append(sites, key)
		}
	}
	slices.Sort(sites)
	return sites
}

// isNpmWorkspaceMember reports whether a lockfile key is one of the members the
// root's "workspaces" globs claim. A glob npm accepts but [path.Match] does not
// ("packages/**") matches nothing here, which leaves those members with the
// name-only answer rather than a wrong one.
func isNpmWorkspaceMember(key string, globs []string) bool {
	for _, glob := range globs {
		glob = strings.TrimSuffix(strings.TrimSpace(glob), "/")
		if glob == "" {
			continue
		}
		if glob == key {
			return true
		}
		if matched, err := path.Match(glob, key); err == nil && matched {
			return true
		}
	}
	return false
}

// resolveNpmInstall returns the entry for the copy of name that a declaration at
// site resolves to: the nearest node_modules from site upward, which is npm's own
// resolution order. A member that pins its own copy therefore resolves to the
// copy nested beside it, and a member whose declaration was hoisted resolves to
// the root's.
func resolveNpmInstall(lock npmLockfile, site, name string) (npmLockEntry, bool) {
	for dir := site; ; {
		candidate := "node_modules/" + name
		if dir != "" {
			candidate = dir + "/" + candidate
		}
		if entry, ok := lock.Packages[candidate]; ok {
			return entry, true
		}
		if dir == "" {
			return npmLockEntry{}, false
		}
		if parent := path.Dir(dir); parent != dir && parent != "." {
			dir = parent
			continue
		}
		dir = ""
	}
}

// getNpmLockDirectDeps records the resolved version of every dependency the
// project declares, keyed by [DirectVersionKey].
//
// This is what stops a lockfile's second copy of a declared package from reading
// as direct. npm nests a version that conflicts with the root's, so a project
// that declares lodash ^4.17.21 and depends on something pinning lodash 3.10.1
// gets two lodash packages from the extractor, which reports both under one name
// and discards the install path that told them apart. Without the resolution both
// were direct, so a direct-only view showed a transitive copy.
//
// A declaration whose version the lockfile does not give (a "file:" or "link"
// entry, or a name with no install path on the way up) contributes no key here, so
// [manifestScan.resolve] leaves it its bare name and it stays direct at whatever
// version it was found. Under-claiming a dependency the project really named is
// the one direction this must not introduce. A dependency on another workspace
// member is that case: its entry is a link with no version.
//
// Every declaration site contributes, and what they contribute is a union, which
// is the only answer a scan-wide bool can carry. Two members that declare
// different versions of one package make both versions direct, because each is
// declared by part of the project; a version one member declares and another
// receives transitively is direct, for the same reason a single package's
// declared dependency stays direct when something else also depends on it. Which
// member a package is direct for is a per-member fact that "direct" cannot hold
// today, and is the same gap as issue #246: the flag has one bit where the answer
// has structure.
func getNpmLockDirectDeps(data []byte) map[string]bool {
	return npmLockResolution(data).versionKeys
}

// npmLockResolution parses an npm lockfile into the versioned keys its
// declarations resolved to and the declaration spellings those keys answer for.
//
// The two sets are not the same, and deriving one from the other is what made an
// alias over-claim. An entry such as my-lodash: "npm:lodash@^4" is installed under
// the alias and records the package it really is, so the key is lodash@4.17.21 and
// reading the names back out of the keys yields only "lodash". The manifest,
// meanwhile, declares both spellings (see [recordNpmDependency]), so "my-lodash"
// was left unresolved and kept a bare key, which then answered for every version
// of any package genuinely called my-lodash that the tree happened to carry.
// Recording the spelling the declaration used, alongside the name it resolved to,
// is what suppresses both.
func npmLockResolution(data []byte) npmResolution {
	resolution := npmResolution{
		versionKeys: make(map[string]bool),
		resolved:    make(map[string]bool),
	}

	var lock npmLockfile
	if err := json.Unmarshal(data, &lock); err != nil {
		return resolution
	}
	root, ok := lock.Packages[""]
	if !ok {
		return resolution
	}

	for _, site := range npmDeclarationSites(lock, root) {
		for _, table := range lock.Packages[site].declarationTables() {
			for declared := range table {
				installed, ok := resolveNpmInstall(lock, site, declared)
				if !ok || installed.Version == "" {
					continue
				}
				// An aliased entry is installed under the alias and records the
				// package it actually is, which is the name every npm extractor
				// reports and therefore the name the lookup will ask about.
				name := cmp.Or(installed.Name, declared)
				resolution.versionKeys[DirectVersionKey(name, installed.Version)] = true
				resolution.resolved[name] = true
				resolution.resolved[declared] = true
			}
		}
	}
	return resolution
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
//
// Workspace is a pointer so that declaring a workspace can be told from not
// declaring one: a root that lists members and renames nothing decodes to an
// empty table, and that is still the root its members inherit from.
type cargoManifest struct {
	cargoDependencyTables
	Target    map[string]cargoDependencyTables `toml:"target"`
	Workspace *cargoDependencyTables           `toml:"workspace"`
}

// packageTables returns every dependency table the manifest declares for
// itself: its own, plus the per-target tables a platform-conditional dependency
// lives in. The workspace tables are not among them, since an entry there is a
// version offered for inheritance rather than a dependency.
//
// Both readers of a member's dependencies go through it, so a table one of them
// reaches cannot be a table the other misses.
func (m cargoManifest) packageTables() []map[string]any {
	tables := make([]map[string]any, 0, 3*(1+len(m.Target)))
	tables = append(tables, m.cargoDependencyTables.tables()...)
	for _, target := range m.Target {
		tables = append(tables, target.tables()...)
	}
	return tables
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

	for _, table := range manifest.packageTables() {
		for name, entry := range table {
			recordCargoDependency(deps, name, entry)
		}
	}

	return deps
}

// getCargoInheritedDeps returns the dependency keys a Cargo.toml takes from its
// workspace, folded the way every other Cargo key here is. Cargo spells that as
// "workspace = true" on the entry, either inline or as "name.workspace = true",
// which decode to the same table.
//
// It is what a workspace rename resolves against. The alternative, asking
// whether the alias is in the collected direct set, cannot tell an inherited
// dependency from a local one the member happens to have given the same name,
// and marked the renamed crate direct on the strength of the name alone.
func getCargoInheritedDeps(data []byte) map[string]bool {
	var manifest cargoManifest
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil
	}
	inherited := make(map[string]bool)
	for _, table := range manifest.packageTables() {
		for name, entry := range table {
			details, isTable := entry.(map[string]any)
			if !isTable {
				continue
			}
			if takesWorkspaceEntry, _ := details["workspace"].(bool); !takesWorkspaceEntry {
				continue
			}
			if key := ecosystem.Cargo.NameEquivalenceKey(name); key != "" {
				inherited[key] = true
			}
		}
	}
	return inherited
}

// getCargoWorkspaceAliases returns the crate each [workspace.dependencies]
// entry renames, keyed by the name a member inherits it under, and whether the
// manifest declares a workspace at all. Only renamed entries are returned: a
// member that writes "serde.workspace = true" records "serde" from its own
// manifest already, while one that writes "my-serde.workspace = true" records a
// key crates.io has never heard of, and only the workspace manifest knows it
// means "serde".
//
// The second result is reported for every root, renames or none, because a root
// is also a boundary: its members inherit from it and never from a root above
// it. A manifest that declares no workspace is not a root and offers nothing.
//
// The entries themselves are deliberately not dependencies. Including the whole
// table marked a crate direct because its version happened to be declared
// centrally, even when no member inherited it and the lockfile only carries it
// as somebody else's transitive dependency.
func getCargoWorkspaceAliases(data []byte) (map[string]string, bool) {
	var manifest cargoManifest
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return nil, false
	}
	if manifest.Workspace == nil {
		return nil, false
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
	return aliases, true
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

// pyprojectManifest is the slice of pyproject.toml that bears on direct
// dependencies. It exists so that the question "which tables constitute a
// declaration" is answered once, in a shape the TOML decoder enforces, rather
// than by a scanner that has to recognize each section header it cares about and
// therefore silently omits the ones nobody thought of.
//
// Every table here is a place the project names a distribution for itself, so
// every one of them is direct:
//
//   - [project] dependencies, the PEP 621 runtime requirements.
//   - [project.optional-dependencies], the PEP 621 extras. An extra is declared
//     by this project and resolves to a package the lock extractors report; what
//     "optional" governs is whether an installer selects the extra, not who
//     declared it. This is the same reasoning that puts npm's
//     optionalDependencies in [getNpmDirectDeps].
//   - [dependency-groups], the PEP 735 groups that development requirements
//     moved to. An entry is either a requirement string or an {include-group}
//     table naming another group in this same file, and the included group's own
//     entries are read from that table, so the reference itself declares nothing.
//   - [tool.poetry.dependencies] and [tool.poetry.group.*.dependencies], the
//     Poetry equivalents, plus [tool.poetry.dev-dependencies], which is where
//     Poetry kept development requirements before 1.2 and which real manifests
//     still carry.
//
// PEP 621 entries are PEP 508 requirement strings and Poetry entries are table
// keys, which is why the two decode differently and meet at
// [recordPyPIDirectDep]. A Poetry value is decoded as any because a constraint
// is a string, a table, or a list of tables, and only the key is needed.
type pyprojectManifest struct {
	Project struct {
		Dependencies         []string            `toml:"dependencies"`
		OptionalDependencies map[string][]string `toml:"optional-dependencies"`
	} `toml:"project"`
	DependencyGroups map[string][]any `toml:"dependency-groups"`
	Tool             struct {
		Poetry struct {
			Dependencies    map[string]any `toml:"dependencies"`
			DevDependencies map[string]any `toml:"dev-dependencies"`
			Group           map[string]struct {
				Dependencies map[string]any `toml:"dependencies"`
			} `toml:"group"`
		} `toml:"poetry"`
	} `toml:"tool"`
}

// poetryTables returns every Poetry dependency table the manifest declares: the
// main one, the legacy dev table, and one per named group.
func (m pyprojectManifest) poetryTables() []map[string]any {
	poetry := m.Tool.Poetry
	tables := make([]map[string]any, 0, 2+len(poetry.Group))
	tables = append(tables, poetry.Dependencies, poetry.DevDependencies)
	for _, group := range poetry.Group {
		tables = append(tables, group.Dependencies)
	}
	return tables
}

// requirementLists returns every list of PEP 508 requirement strings the
// manifest declares: the PEP 621 runtime list, one per extra, and one per PEP
// 735 dependency group. Group entries that are {include-group} tables rather
// than strings are dropped, since the group they name is read from its own table.
func (m pyprojectManifest) requirementLists() [][]string {
	lists := make([][]string, 0, 1+len(m.Project.OptionalDependencies)+len(m.DependencyGroups))
	lists = append(lists, m.Project.Dependencies)
	for _, extra := range m.Project.OptionalDependencies {
		lists = append(lists, extra)
	}
	for _, group := range m.DependencyGroups {
		requirements := make([]string, 0, len(group))
		for _, entry := range group {
			if requirement, isString := entry.(string); isString {
				requirements = append(requirements, requirement)
			}
		}
		lists = append(lists, requirements)
	}
	return lists
}

// getPyprojectDirectDeps extracts direct dependencies from pyproject.toml,
// covering every table [pyprojectManifest] declares: PEP 621 dependencies and
// extras, PEP 735 dependency groups, and Poetry's main, legacy dev, and named
// group tables.
//
// A manifest that does not parse as TOML yields nothing, matching
// [getCargoDirectDeps]: no installer would read it either. The line scanner this
// replaced would still scrape a malformed file, which sounds forgiving and is
// not, because the same leniency is what made it answer for [project] and
// [tool.poetry.dependencies] alone and report every other declaration as
// transitive.
func getPyprojectDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	var manifest pyprojectManifest
	if err := toml.Unmarshal(data, &manifest); err != nil {
		return deps
	}

	for _, requirements := range manifest.requirementLists() {
		for _, requirement := range requirements {
			parsePyPIDep(requirement, deps)
		}
	}

	for _, table := range manifest.poetryTables() {
		for name := range table {
			// python is the interpreter Poetry resolves against, not a
			// distribution any lockfile carries.
			if name == "python" {
				continue
			}
			recordPyPIDirectDep(deps, name)
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
