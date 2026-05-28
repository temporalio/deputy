package inputs

import (
	"cmp"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/google/osv-scalibr/extractor"
	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/inventory/manifests"
	"github.com/temporalio/deputy/internal/purlx"
)

// Options configures how packages are converted to inputs.
type Options struct {
	GoDirect       map[string]bool
	DirectPackages map[string]bool
	Resolver       Resolver
}

// Convert transforms SCALIBR packages into OSV query inputs.
// It normalizes package names, deduplicates modules, and annotates whether
// each dependency is direct according to the provided options.
func Convert(pkgs []*extractor.Package, opts Options) []osv.PkgInput {
	if len(pkgs) == 0 {
		return nil
	}
	if opts.GoDirect == nil {
		opts.GoDirect = map[string]bool{}
	}
	pkgJSONCache := newPackageJSONCache(opts.Resolver)
	cargoCache := newCargoCache(opts.Resolver)
	uvCache := newUVCache(opts.Resolver)
	seen := map[string]*osv.PkgInput{}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		name := strings.TrimSpace(pkg.Name)
		version := strings.TrimSpace(pkg.Version)
		if name == "" {
			continue
		}
		ecos := strings.TrimSpace(pkg.Ecosystem().String())
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
			entry = &osv.PkgInput{
				QueryKey: osv.QueryKey{
					Name:      name,
					Version:   version,
					Ecosystem: ecos,
					PURL:      purlStr,
				},
			}
			seen[key] = entry
		}
		entry.Locations = appendUnique(entry.Locations, pkg.Locations...)

		// Preserve layer details from SCALIBR for container image scans.
		// Note: SCALIBR uses DiffID/ChainID (Go naming), we use DiffId/ChainId (proto naming).
		if entry.LayerDetails == nil && pkg.LayerDetails != nil {
			entry.LayerDetails = &containerv1.LayerDetails{
				Index:       int32(pkg.LayerDetails.Index),
				DiffId:      pkg.LayerDetails.DiffID,
				ChainId:     pkg.LayerDetails.ChainID,
				Command:     pkg.LayerDetails.Command,
				InBaseImage: pkg.LayerDetails.InBaseImage,
			}
		}

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
			manager, manifestPath, ok := manifests.DetectManager(loc, pkg.PURLType)
			if !ok {
				continue
			}
			ref := dependencyv1.ManifestRef{Path: manifestPath, Manager: manager}
			switch manager {
			case "go":
				// direct already handled via GoDirect map
			case purlx.TypeGitHubActions:
				entry.IsDirect = true
			case "npm", "yarn", "pnpm":
				if pkgJSONCache != nil {
					groups, err := pkgJSONCache.groupsForPackage(manifestPath, name)
					if err == nil && len(groups) > 0 {
						ref.Groups = groups
						if manifests.HasRuntimeDependencyGroup(groups) {
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
				if manifests.MarksDirectByDefault(manager) {
					entry.IsDirect = true
				}
			}
			entry.ManifestRefs = dependency.MergeManifestRef(entry.ManifestRefs, ref)
		}
	}
	inputs := make([]osv.PkgInput, 0, len(seen))
	for _, in := range seen {
		in.Locations = sortedUnique(in.Locations)
		in.ManifestRefs = dependency.SortAndUniqueManifestRefs(in.ManifestRefs)
		inputs = append(inputs, *in)
	}
	slices.SortFunc(inputs, func(a, b osv.PkgInput) int {
		if c := cmp.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return cmp.Compare(a.Version, b.Version)
	})
	return inputs
}

// BuildDirectMap creates a map of direct dependencies from the input list.
func BuildDirectMap(inputs []osv.PkgInput) map[string]bool {
	if len(inputs) == 0 {
		return nil
	}
	direct := make(map[string]bool)
	for _, in := range inputs {
		if !in.IsDirect {
			continue
		}
		if key := canonicalKey(in); key != "" {
			direct[key] = true
		}
	}
	if len(direct) == 0 {
		return nil
	}
	return direct
}

// MergeDirectMaps combines multiple direct dependency maps.
func MergeDirectMaps(maps ...map[string]bool) map[string]bool {
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

// BuildSourcesMap creates a map of package sources from the input list.
func BuildSourcesMap(inputs []osv.PkgInput) map[string][]string {
	if len(inputs) == 0 {
		return nil
	}
	out := map[string]collections.Set[string]{}
	for _, in := range inputs {
		key := canonicalKey(in)
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

// canonicalKey generates a unique key for a package input.
func canonicalKey(in osv.PkgInput) string {
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

// --- package.json parsing ---

type packageJSONData struct {
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
	PeerDependencies     map[string]string `json:"peerDependencies"`
}

type packageJSONCache struct {
	*cache[*packageJSONData]
}

func newPackageJSONCache(resolver Resolver) *packageJSONCache {
	mc := newCache(resolver, func(content []byte) (*packageJSONData, error) {
		var pj packageJSONData
		if err := json.Unmarshal(content, &pj); err != nil {
			return nil, err
		}
		return &pj, nil
	})
	if mc == nil {
		return nil
	}
	return &packageJSONCache{mc}
}

func (c *packageJSONCache) groupsForPackage(manifestPath, pkgName string) ([]string, error) {
	if c == nil {
		return nil, fmt.Errorf("no resolver")
	}
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

// --- uv.lock parsing ---

type uvLockCache struct {
	*cache[*uvLockData]
}

type uvLockData struct {
	groups map[string][]string
	direct map[string]bool
}

func newUVCache(resolver Resolver) *uvLockCache {
	mc := newCache(resolver, parseUVLock)
	if mc == nil {
		return nil
	}
	return &uvLockCache{mc}
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

type uvLockDocument struct {
	Packages []uvLockEntry `toml:"package"`
}

type uvLockEntry struct {
	Name         string                        `toml:"name"`
	Source       uvLockSource                  `toml:"source"`
	Dependencies []uvLockDependency            `toml:"dependencies"`
	Optional     map[string][]uvLockDependency `toml:"optional-dependencies"`
	Dev          map[string][]uvLockDependency `toml:"dev-dependencies"`
}

type uvLockSource struct {
	Virtual string `toml:"virtual"`
}

type uvLockDependency struct {
	Name string `toml:"name"`
}

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

func appendGroupLabel(existing []string, label string) []string {
	for _, v := range existing {
		if strings.EqualFold(v, label) {
			return existing
		}
	}
	return append(existing, label)
}

func normalizePythonName(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.ReplaceAll(n, "_", "-")
	return n
}

// --- Cargo.toml parsing ---

type cargoCache struct {
	*cache[*cargoData]
}

type cargoData struct {
	groups map[string][]string
	direct map[string]bool
}

func newCargoCache(resolver Resolver) *cargoCache {
	mc := newCache(resolver, parseCargoManifest)
	if mc == nil {
		return nil
	}
	return &cargoCache{mc}
}

func (c *cargoCache) packageInfo(manifestPath, pkgName string) ([]string, bool, error) {
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

func parseCargoManifest(content []byte) (*cargoData, error) {
	var doc cargoManifest
	if err := toml.Unmarshal(content, &doc); err != nil {
		return nil, err
	}
	data := &cargoData{
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

func normalizeCrateName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
