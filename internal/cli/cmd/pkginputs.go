package cmd

import (
	"encoding/json"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
)

// packagesToInputs converts a slice of extractor.Package objects into
// analysis.PkgInput records suitable for OSV queries. It normalizes package
// names, deduplicates modules, and annotates whether each dependency is direct
// according to the provided dependency map.
type manifestResolver interface {
	ReadFile(path string) ([]byte, error)
}

type manifestResolverFunc func(string) ([]byte, error)

func (f manifestResolverFunc) ReadFile(path string) ([]byte, error) {
	return f(path)
}

type packageInputOptions struct {
	GoDirect map[string]bool
	Resolver manifestResolver
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

func packagesToInputs(pkgs []*extractor.Package, opts packageInputOptions) []analysis.PkgInput {
	if len(pkgs) == 0 {
		return nil
	}
	if opts.GoDirect == nil {
		opts.GoDirect = map[string]bool{}
	}
	cache := newPackageJSONCache(opts.Resolver)
	seen := map[string]*analysis.PkgInput{}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		name := strings.TrimSpace(pkg.Name)
		version := strings.TrimSpace(pkg.Version)
		if name == "" || version == "" {
			continue
		}
		ecos := strings.TrimSpace(pkg.Ecosystem())
		if ecos == "" && pkg.PURLType != "" {
			ecos = pkg.PURLType
		}
		var purlStr string
		if pu := pkg.PURL(); pu != nil {
			purlStr = pu.String()
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

		if strings.EqualFold(ecos, "Go") {
			info := cmp.ParseGoPackage(pkg)
			module := cmp.GetModuleRoot(info.CanonicalName)
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
			case "npm", "yarn", "pnpm":
				if cache != nil {
					groups, err := cache.groupsForPackage(manifestPath, name)
					if err == nil && len(groups) > 0 {
						ref.Groups = groups
						entry.IsDirect = true
					}
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
	sort.Slice(inputs, func(i, j int) bool {
		if inputs[i].Name == inputs[j].Name {
			return inputs[i].Version < inputs[j].Version
		}
		return inputs[i].Name < inputs[j].Name
	})
	return inputs
}

func detectManager(location, purlType string) (string, string, bool) {
	loc := filepath.ToSlash(location)
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
	case "Gemfile.lock":
		return "bundler", path.Join(dir, "Gemfile"), true
	case "composer.lock":
		return "composer", path.Join(dir, "composer.json"), true
	case "Cargo.lock":
		return "cargo", path.Join(dir, "Cargo.toml"), true
	case "package.json":
		if strings.EqualFold(purlType, "npm") {
			return "npm", loc, true
		}
	}
	return "", "", false
}

func appendUnique(dst []string, src ...string) []string {
	seen := map[string]struct{}{}
	for _, existing := range dst {
		seen[existing] = struct{}{}
	}
	for _, s := range src {
		s = filepath.ToSlash(strings.TrimSpace(s))
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		dst = append(dst, s)
	}
	return dst
}

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

func mergeGroups(base []string, extra []string) []string {
	set := map[string]struct{}{}
	for _, g := range base {
		set[g] = struct{}{}
	}
	for _, g := range extra {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, ok := set[g]; ok {
			continue
		}
		set[g] = struct{}{}
		base = append(base, g)
	}
	return base
}

func sortedUnique(values []string) []string {
	if len(values) == 0 {
		return values
	}
	set := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, v := range values {
		if _, ok := set[v]; ok {
			continue
		}
		set[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

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
	sort.Slice(out, func(i, j int) bool {
		if out[i].Manager == out[j].Manager {
			return out[i].Path < out[j].Path
		}
		return out[i].Manager < out[j].Manager
	})
	return out
}
