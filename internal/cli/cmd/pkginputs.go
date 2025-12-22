package cmd

import (
	"cmp"
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/purlx"
)

// packagesToInputs converts a slice of extractor.Package objects into
// analysis.PkgInput records suitable for OSV queries. It normalizes package
// names, deduplicates modules, and annotates whether each dependency is direct
// according to the provided dependency map.
// manifestResolver abstracts file reading for manifest parsing.
type manifestResolver interface {
	ReadFile(path string) ([]byte, error)
}

// manifestResolverFunc adapts a function to the manifestResolver interface.
type manifestResolverFunc func(string) ([]byte, error)

// ReadFile calls the underlying function.
func (f manifestResolverFunc) ReadFile(path string) ([]byte, error) {
	return f(path)
}

// packageInputOptions configures how packages are converted to inputs.
type packageInputOptions struct {
	GoDirect       map[string]bool
	DirectPackages map[string]bool
	Resolver       manifestResolver
}

type manifestRefKey struct {
	manager string
	path    string
}

type packageJSONData struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

// packageJSONCache caches parsed package.json files.
type packageJSONCache struct {
	resolver manifestResolver
	entries  map[string]*packageJSONData
	errs     map[string]error
}

func newPackageJSONCache(resolver manifestResolver) *packageJSONCache {
	if resolver == nil {
		return nil
	}
	return &packageJSONCache{
		resolver: resolver,
		entries:  make(map[string]*packageJSONData),
		errs:     make(map[string]error),
	}
}

func (c *packageJSONCache) get(path string) (*packageJSONData, error) {
	if c == nil {
		return nil, fmt.Errorf("no resolver")
	}
	if data, ok := c.entries[path]; ok {
		return data, nil
	}
	if err, ok := c.errs[path]; ok {
		return nil, err
	}
	content, err := c.resolver.ReadFile(path)
	if err != nil {
		c.errs[path] = err
		return nil, err
	}
	var pj packageJSONData
	if err := json.Unmarshal(content, &pj); err != nil {
		c.errs[path] = err
		return nil, err
	}
	c.entries[path] = &pj
	return &pj, nil
}

func (c *packageJSONCache) groupsForPackage(manifestPath, pkgName string) ([]string, error) {
	data, err := c.get(manifestPath)
	if err != nil || data == nil {
		return nil, err
	}
	groups := make([]string, 0, 4)
	if _, ok := data.Dependencies[pkgName]; ok {
		groups = append(groups, "dependencies")
	}
	if _, ok := data.DevDependencies[pkgName]; ok {
		groups = append(groups, "devDependencies")
	}
	if _, ok := data.OptionalDependencies[pkgName]; ok {
		groups = append(groups, "optionalDependencies")
	}
	if _, ok := data.PeerDependencies[pkgName]; ok {
		groups = append(groups, "peerDependencies")
	}
	return groups, nil
}

// uvLockCache lazily parses uv.lock files and memoizes their dependency metadata.
type uvLockCache struct {
	resolver manifestResolver
	entries  map[string]*uvLockData
	errs     map[string]error
}

type uvLockData struct {
	groups map[string][]string
	direct map[string]bool
}

func newUVLockCache(resolver manifestResolver) *uvLockCache {
	if resolver == nil {
		return nil
	}
	return &uvLockCache{
		resolver: resolver,
		entries:  make(map[string]*uvLockData),
		errs:     make(map[string]error),
	}
}

func (c *uvLockCache) packageInfo(manifestPath, pkgName string) ([]string, bool, error) {
	if c == nil {
		return nil, false, fmt.Errorf("no resolver")
	}
	data, err := c.get(manifestPath)
	if err != nil {
		return nil, false, err
	}
	key := normalizePythonName(pkgName)
	groups := slices.Clone(data.groups[key])
	return groups, data.direct[key], nil
}

func (c *uvLockCache) get(path string) (*uvLockData, error) {
	if data, ok := c.entries[path]; ok {
		return data, nil
	}
	if err, ok := c.errs[path]; ok {
		return nil, err
	}
	content, err := c.resolver.ReadFile(path)
	if err != nil {
		c.errs[path] = err
		return nil, err
	}
	data, err := parseUVLock(content)
	if err != nil {
		c.errs[path] = err
		return nil, err
	}
	c.entries[path] = data
	return data, nil
}

// uvLockDocument mirrors the top-level TOML structure produced by uv.lock.
type uvLockDocument struct {
	Packages []uvLockEntry `toml:"package"`
}

// uvLockEntry captures each [[package]] stanza including its dependency groups.
type uvLockEntry struct {
	Name         string                        `toml:"name"`
	Source       uvLockSource                  `toml:"source"`
	Dependencies []uvLockDependency            `toml:"dependencies"`
	Optional     map[string][]uvLockDependency `toml:"optional-dependencies"`
	Dev          map[string][]uvLockDependency `toml:"dev-dependencies"`
}

// uvLockSource indicates whether a package is virtual (the root) or from a registry.
type uvLockSource struct {
	Virtual string `toml:"virtual"`
}

// uvLockDependency references another package by name.
type uvLockDependency struct {
	Name string `toml:"name"`
}

// parseUVLock returns the dependency-group metadata for all packages in a uv.lock file.
func parseUVLock(content []byte) (*uvLockData, error) {
	var doc uvLockDocument
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, err
	}
	data := &uvLockData{
		groups: make(map[string][]string),
		direct: make(map[string]bool),
	}
	for _, pkg := range doc.Packages {
		if strings.TrimSpace(pkg.Source.Virtual) != "." {
			continue
		}
		for _, dep := range pkg.Dependencies {
			name := normalizePythonName(dep.Name)
			if name == "" {
				continue
			}
			data.direct[name] = true
			data.groups[name] = appendGroupLabel(data.groups[name], "dependencies")
		}
		for group, deps := range pkg.Optional {
			label := strings.TrimSpace(group)
			if label == "" {
				continue
			}
			for _, dep := range deps {
				name := normalizePythonName(dep.Name)
				if name == "" {
					continue
				}
				data.groups[name] = appendGroupLabel(data.groups[name], label)
			}
		}
		for group, deps := range pkg.Dev {
			label := strings.TrimSpace(group)
			if label == "" {
				label = "dev"
			}
			for _, dep := range deps {
				name := normalizePythonName(dep.Name)
				if name == "" {
					continue
				}
				data.groups[name] = appendGroupLabel(data.groups[name], label)
			}
		}
	}
	return data, nil
}

// appendGroupLabel adds label to the slice if it is not already present (case-insensitive).
func appendGroupLabel(existing []string, label string) []string {
	for _, v := range existing {
		if strings.EqualFold(v, label) {
			return existing
		}
	}
	return append(existing, label)
}

// cargoManifestCache parses Cargo.toml files and records dependency classifications.
type cargoManifestCache struct {
	resolver manifestResolver
	entries  map[string]*cargoManifestData
	errs     map[string]error
}

type cargoManifestData struct {
	groups map[string][]string
	direct map[string]bool
}

func newCargoManifestCache(resolver manifestResolver) *cargoManifestCache {
	if resolver == nil {
		return nil
	}
	return &cargoManifestCache{
		resolver: resolver,
		entries:  make(map[string]*cargoManifestData),
		errs:     make(map[string]error),
	}
}

func (c *cargoManifestCache) packageInfo(manifestPath, pkgName string) ([]string, bool, error) {
	if c == nil {
		return nil, false, fmt.Errorf("no resolver")
	}
	data, err := c.get(manifestPath)
	if err != nil {
		return nil, false, err
	}
	key := normalizeCrateName(pkgName)
	groups := slices.Clone(data.groups[key])
	return groups, data.direct[key], nil
}

func (c *cargoManifestCache) get(path string) (*cargoManifestData, error) {
	if data, ok := c.entries[path]; ok {
		return data, nil
	}
	if err, ok := c.errs[path]; ok {
		return nil, err
	}
	content, err := c.resolver.ReadFile(path)
	if err != nil {
		c.errs[path] = err
		return nil, err
	}
	data, err := parseCargoManifest(content)
	if err != nil {
		c.errs[path] = err
		return nil, err
	}
	c.entries[path] = data
	return data, nil
}

// cargoManifest represents the structure of a Cargo.toml file.
type cargoManifest struct {
	Dependencies      map[string]any         `toml:"dependencies"`
	DevDependencies   map[string]any         `toml:"dev-dependencies"`
	BuildDependencies map[string]any         `toml:"build-dependencies"`
	Workspace         cargoWorkspaceManifest `toml:"workspace"`
	Target            map[string]cargoTarget `toml:"target"`
}

type cargoWorkspaceManifest struct {
	Dependencies map[string]any `toml:"dependencies"`
}

type cargoTarget struct {
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
}

// parseCargoManifest extracts runtime/dev/build dependency classifications from Cargo.toml.
func parseCargoManifest(content []byte) (*cargoManifestData, error) {
	var doc cargoManifest
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, err
	}
	data := &cargoManifestData{
		groups: make(map[string][]string),
		direct: make(map[string]bool),
	}
	record := func(entries map[string]any, label string, direct bool) {
		for name := range entries {
			key := normalizeCrateName(name)
			if key == "" {
				continue
			}
			if label != "" {
				data.groups[key] = appendGroupLabel(data.groups[key], label)
			}
			if direct {
				data.direct[key] = true
			}
		}
	}
	record(doc.Dependencies, "dependencies", true)
	record(doc.Workspace.Dependencies, "workspace.dependencies", true)
	record(doc.DevDependencies, "dev-dependencies", false)
	record(doc.BuildDependencies, "build-dependencies", false)
	for targetName, target := range doc.Target {
		record(target.Dependencies, fmt.Sprintf("target:%s:dependencies", targetName), true)
		record(target.DevDependencies, fmt.Sprintf("target:%s:dev-dependencies", targetName), false)
		record(target.BuildDependencies, fmt.Sprintf("target:%s:build-dependencies", targetName), false)
	}
	return data, nil
}

func packagesToInputs(pkgs []*extractor.Package, opts packageInputOptions) []analysis.PkgInput {
	if len(pkgs) == 0 {
		return nil
	}
	if opts.GoDirect == nil {
		opts.GoDirect = map[string]bool{}
	}
	cache := newPackageJSONCache(opts.Resolver)
	cargoCache := newCargoManifestCache(opts.Resolver)
	uvCache := newUVLockCache(opts.Resolver)
	seen := map[string]*analysis.PkgInput{}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		name := strings.TrimSpace(pkg.Name)
		version := strings.TrimSpace(pkg.Version)
		if name == "" {
			continue
		}
		ecos := strings.TrimSpace(pkg.Ecosystem())
		if ecos == "" && pkg.PURLType != "" {
			ecos = pkg.PURLType
		}
		if strings.EqualFold(ecos, "github") || strings.EqualFold(ecos, purlx.TypeGitHubActions) {
			ecos = "GitHub Actions"
		}
		if strings.EqualFold(ecos, "golang") {
			ecos = "Go"
		}
		var purlStr string
		switch {
		case purlx.IsGitHubActionsType(pkg.PURLType):
			purlStr = purlx.GitHubActionsPURLFromPackage(pkg)
		case pkg.PURL() != nil:
			purlStr = pkg.PURL().String()
		}
		key := fmt.Sprintf("%s|%s|%s|%s", strings.ToLower(ecos), strings.ToLower(name), version, purlStr)
		entry := seen[key]
		if entry == nil {
			entry = &analysis.PkgInput{
				Name:      name,
				Version:   version,
				Ecosystem: ecos,
				PURL:      purlStr,
			}
			seen[key] = entry
		}
		entry.Locations = appendUnique(entry.Locations, pkg.Locations...)

		if opts.DirectPackages != nil && purlStr != "" {
			if opts.DirectPackages[purlStr] {
				entry.IsDirect = true
			}
		}

		if strings.EqualFold(ecos, "Go") {
			info := compare.ParseGoPackage(pkg)
			module := compare.GetModuleRoot(info.CanonicalName)
			if opts.GoDirect[module] {
				entry.IsDirect = true
			}
		}

		for _, loc := range pkg.Locations {
			manager, manifestPath, ok := detectManager(loc, pkg.PURLType)
			if !ok {
				continue
			}
			ref := analysis.ManifestReference{Path: manifestPath, Manager: manager}
			switch manager {
			case "go":
				// direct already handled via GoDirect map
			case purlx.TypeGitHubActions:
				entry.IsDirect = true
			case "npm", "yarn", "pnpm":
				if cache != nil {
					groups, err := cache.groupsForPackage(manifestPath, name)
					if err == nil && len(groups) > 0 {
						ref.Groups = groups
						if hasRuntimeDependencyGroup(groups) {
							entry.IsDirect = true
						}
					}
				}
			case "cargo":
				if cargoCache != nil {
					groups, direct, err := cargoCache.packageInfo(manifestPath, name)
					if err == nil {
						if len(groups) > 0 {
							ref.Groups = groups
						}
						if direct {
							entry.IsDirect = true
						}
					}
				}
			case "uv":
				if uvCache != nil {
					groups, direct, err := uvCache.packageInfo(manifestPath, name)
					if err == nil {
						if len(groups) > 0 {
							ref.Groups = groups
						}
						if direct {
							entry.IsDirect = true
						}
					}
				}
			default:
				if marksDirectByDefault(manager) {
					entry.IsDirect = true
				}
			}
			entry.ManifestRefs = mergeManifestReference(entry.ManifestRefs, ref)
		}
	}
	inputs := make([]analysis.PkgInput, 0, len(seen))
	for _, in := range seen {
		// sort locations and manifest refs for stable output
		in.Locations = sortedUnique(in.Locations)
		in.ManifestRefs = sortAndUniqueManifestRefs(in.ManifestRefs)
		inputs = append(inputs, *in)
	}
	slices.SortFunc(inputs, func(a, b analysis.PkgInput) int {
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Version, b.Version)
	})
	return inputs
}

// detectManager identifies the package manager and manifest path for a given location.
func detectManager(location, purlType string) (string, string, bool) {
	loc := filepath.ToSlash(location)
	if strings.HasPrefix(loc, ".github/workflows/") {
		ext := strings.ToLower(path.Ext(loc))
		if ext == ".yml" || ext == ".yaml" {
			return purlx.TypeGitHubActions, loc, true
		}
	}
	base := path.Base(loc)
	dir := path.Dir(loc)
	switch base {
	case "go.mod":
		return "go", loc, true
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm", path.Join(dir, "package.json"), true
	case "yarn.lock":
		return "yarn", path.Join(dir, "package.json"), true
	case "pnpm-lock.yaml", "pnpm-lock.yml":
		return "pnpm", path.Join(dir, "package.json"), true
	case "requirements.txt":
		return "pip", loc, true
	case "Pipfile.lock":
		return "pipenv", path.Join(dir, "Pipfile"), true
	case "poetry.lock":
		return "poetry", path.Join(dir, "pyproject.toml"), true
	case "Gemfile.lock", "gems.locked":
		return "gem", path.Join(dir, "Gemfile"), true
	case "composer.lock":
		return "composer", path.Join(dir, "composer.json"), true
	case "Cargo.toml":
		return "cargo", loc, true
	case "Cargo.lock":
		return "cargo", path.Join(dir, "Cargo.toml"), true
	case "uv.lock":
		return "uv", loc, true
	case "package.json":
		if strings.EqualFold(purlType, "npm") {
			return "npm", loc, true
		}
	case "action.yml", "action.yaml":
		return purlx.TypeGitHubActions, loc, true
	default:
		if strings.HasSuffix(base, ".gemspec") {
			return "gem", loc, true
		}
	}
	return "", "", false
}

// appendUnique adds strings to a slice if they are not already present.
func appendUnique(dst []string, src ...string) []string {
	seen := collections.NewSet[string]()
	for _, existing := range dst {
		seen.Add(existing)
	}
	for _, s := range src {
		s = filepath.ToSlash(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if !seen.Add(s) {
			continue
		}
		dst = append(dst, s)
	}
	return dst
}

// mergeManifestReference adds a manifest reference to the list, merging groups if it already exists.
func mergeManifestReference(existing []analysis.ManifestReference, ref analysis.ManifestReference) []analysis.ManifestReference {
	if ref.Path == "" || ref.Manager == "" {
		return existing
	}
	for i, cur := range existing {
		if cur.Manager == ref.Manager && cur.Path == ref.Path {
			merged := mergeGroups(cur.Groups, ref.Groups)
			existing[i].Groups = merged
			return existing
		}
	}
	ref.Groups = mergeGroups(nil, ref.Groups)
	return append(existing, ref)
}

// mergeGroups combines two lists of groups, removing duplicates.
func mergeGroups(base []string, extra []string) []string {
	set := collections.NewSet[string]()
	for _, g := range base {
		set.Add(g)
	}
	for _, g := range extra {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if !set.Add(g) {
			continue
		}
		base = append(base, g)
	}
	return base
}

// sortedUnique returns a sorted list of unique strings.
func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return values
	}
	set := collections.NewSet[string]()
	out := make([]string, 0, len(values))
	for _, v := range values {
		if !set.Add(v) {
			continue
		}
		out = append(out, v)
	}
	slices.Sort(out)
	return out
}

// sortAndUniqueManifestRefs deduplicates and sorts manifest references.
func sortAndUniqueManifestRefs(refs []analysis.ManifestReference) []analysis.ManifestReference {
	if len(refs) == 0 {
		return refs
	}
	merged := map[manifestRefKey]analysis.ManifestReference{}
	for _, ref := range refs {
		key := manifestRefKey{manager: ref.Manager, path: ref.Path}
		cur, ok := merged[key]
		if !ok {
			cur = analysis.ManifestReference{Manager: ref.Manager, Path: ref.Path}
		}
		cur.Groups = mergeGroups(cur.Groups, ref.Groups)
		merged[key] = cur
	}
	out := make([]analysis.ManifestReference, 0, len(merged))
	for _, ref := range merged {
		ref.Groups = sortedUnique(ref.Groups)
		out = append(out, ref)
	}
	slices.SortFunc(out, func(a, b analysis.ManifestReference) int {
		if c := cmp.Compare(a.Manager, b.Manager); c != 0 {
			return c
		}
		return cmp.Compare(a.Path, b.Path)
	})
	return out
}

// hasRuntimeDependencyGroup checks if any of the groups indicate a runtime dependency.
func hasRuntimeDependencyGroup(groups []string) bool {
	return slices.ContainsFunc(groups, func(g string) bool {
		return strings.EqualFold(strings.TrimSpace(g), "dependencies")
	})
}

// marksDirectByDefault returns true if the package manager considers dependencies direct by default.
func marksDirectByDefault(manager string) bool {
	switch strings.ToLower(manager) {
	case "pip", "pipenv", "poetry", "gem":
		return true
	default:
		return false
	}
}

// normalizePythonName folds underscores and case to match uv's lockfile naming.
func normalizePythonName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	return n
}

// normalizeCrateName normalizes Cargo package names for lookups.
func normalizeCrateName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// buildPackageDirectMap creates a map of direct dependencies from the input list.
func buildPackageDirectMap(inputs []analysis.PkgInput) map[string]bool {
	if len(inputs) == 0 {
		return nil
	}
	direct := make(map[string]bool)
	for _, in := range inputs {
		if !in.IsDirect {
			continue
		}
		if key := canonicalPackageKeyFromInput(in); key != "" {
			direct[key] = true
		}
	}
	if len(direct) == 0 {
		return nil
	}
	return direct
}

// mergeDirectMaps combines multiple direct dependency maps.
func mergeDirectMaps(maps ...map[string]bool) map[string]bool {
	result := make(map[string]bool)
	for _, m := range maps {
		for k, v := range m {
			if v {
				result[k] = true
			}
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// buildPackageSources creates a map of package sources from the input list.
func buildPackageSources(inputs []analysis.PkgInput) map[string][]string {
	if len(inputs) == 0 {
		return nil
	}
	out := map[string]collections.Set[string]{}
	for _, in := range inputs {
		key := canonicalPackageKeyFromInput(in)
		if key == "" {
			continue
		}
		for _, ref := range in.ManifestRefs {
			pathStr := strings.TrimSpace(ref.Path)
			if pathStr == "" {
				continue
			}
			if out[key] == nil {
				out[key] = collections.NewSet[string]()
			}
			out[key].Add(pathStr)
		}
	}
	if len(out) == 0 {
		return nil
	}
	result := make(map[string][]string, len(out))
	for key, entries := range out {
		if len(entries) == 0 {
			continue
		}
		sources := entries.Slice()
		slices.Sort(sources)
		result[key] = sources
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// canonicalPackageKeyFromInput generates a unique key for a package input.
func canonicalPackageKeyFromInput(in analysis.PkgInput) string {
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return ""
	}
	version := strings.ToLower(strings.TrimSpace(in.Version))
	ecos := strings.TrimSpace(in.Ecosystem)
	if strings.EqualFold(ecos, "Go") {
		pkg := &extractor.Package{Name: name}
		info := compare.ParseGoPackage(pkg)
		canonical := strings.ToLower(info.CanonicalName)
		if canonical == "" {
			canonical = strings.ToLower(name)
		}
		return fmt.Sprintf("go|%s|%s", canonical, version)
	}
	lowerName := strings.ToLower(name)
	if ecos == "" {
		return fmt.Sprintf("%s|%s", lowerName, version)
	}
	return fmt.Sprintf("%s|%s|%s", strings.ToLower(ecos), lowerName, version)
}
