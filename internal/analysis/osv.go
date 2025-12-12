package analysis

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/purlx"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
	"osv.dev/bindings/go/osvdev"
)

// OSVClient abstracts the subset of osv.dev client functionality required for
// batch querying and vulnerability expansion. It is satisfied by
// osvdev.DefaultClient enabling dependency injection in tests.
type OSVClient interface {
	QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error)
	GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error)
}

// PkgInput represents a single package@version query along with whether the
// dependency is direct (appears explicitly in go.mod). Directness influences
// downstream prioritization but not query mechanics.
type PkgInput struct {
	Name         string
	Version      string
	Ecosystem    string
	PURL         string
	IsDirect     bool
	Locations    []string
	ManifestRefs []ManifestReference
}

// getCachedVuln retrieves a vulnerability by ID using the provided client,
// consulting a local on-disk cache when available to avoid redundant network
// requests. Successful responses are cached for future lookups.
func getCachedVuln(ctx context.Context, client OSVClient, id string) (*osvschema.Vulnerability, error) {
	var v osvschema.Vulnerability
	if readCache("osv", id, &v) {
		return &v, nil
	}
	res, err := client.GetVulnByID(ctx, id)
	if err != nil {
		return nil, err
	}
	writeCache("osv", id, res)
	return res, nil
}

// QueryOSVBatch performs a batched OSV vulnerability lookup for the provided
// packages. For each minimal vulnerability match it expands full vulnerability
// details via GetVulnByID to populate rich fields (aliases, severity, ranges).
// The function is resilient: individual GetVulnByID failures are skipped so a
// single retrieval error does not abort the entire batch.
func QueryOSVBatch(ctx context.Context, client OSVClient, pkgs []PkgInput) ([]Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	var ghaPkgs []PkgInput
	var otherPkgs []PkgInput
	for _, p := range pkgs {
		if isGitHubActionsInput(p) {
			ghaPkgs = append(ghaPkgs, p)
			continue
		}
		otherPkgs = append(otherPkgs, p)
	}

	var out []Vulnerability
	if len(otherPkgs) > 0 {
		vv, err := queryOSVAPIBatch(ctx, client, otherPkgs)
		if err != nil {
			return nil, err
		}
		out = append(out, vv...)
	}
	if len(ghaPkgs) > 0 {
		vv, err := queryOSVGHABucketBatch(ctx, client, ghaPkgs)
		if err != nil {
			if len(out) > 0 {
				return out, err
			}
			return nil, err
		}
		out = append(out, vv...)
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

// isGitHubActionsInput reports whether the given package should be queried against
// the OSV GitHub Actions bucket instead of the OSV API.
func isGitHubActionsInput(p PkgInput) bool {
	eco := strings.ToLower(strings.TrimSpace(p.Ecosystem))
	switch eco {
	case "github actions", "github-actions", "githubactions", "gha":
		return true
	}
	if p.PURL != "" {
		if pu, err := purlx.ParseLoose(p.PURL); err == nil && purlx.IsGitHubActionsType(pu.Type) {
			return true
		}
	}
	return false
}

// queryOSVAPIBatch performs the standard OSV v1/querybatch flow.
func queryOSVAPIBatch(ctx context.Context, client OSVClient, pkgs []PkgInput) ([]Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	queries := make([]*osvdev.Query, 0, len(pkgs))
	meta := make([]PkgInput, 0, len(pkgs))
	for _, p := range pkgs {
		version := strings.TrimSpace(p.Version)
		if version == "" {
			continue
		}
		normalized := p
		normalized.Name = strings.TrimSpace(normalized.Name)
		normalized.Ecosystem = strings.TrimSpace(normalized.Ecosystem)
		normalized.PURL = strings.TrimSpace(normalized.PURL)
		normalized.Version = version
		if strings.EqualFold(normalized.Ecosystem, "go") {
			normalized.Version = normalizeGoVersion(normalized.Version)
		}
		pkgQuery := osvdev.Package{}
		var queryVersion string
		if normalized.PURL != "" {
			pkgQuery.PURL = normalized.PURL
			if pu, err := purl.FromString(normalized.PURL); err == nil {
				queryVersion = pu.Version
				pu.Version = ""
				pkgQuery.PURL = pu.String()
			}
		}
		if pkgQuery.PURL == "" {
			pkgQuery.Name = normalized.Name
			pkgQuery.Ecosystem = normalized.Ecosystem
			queryVersion = normalized.Version
		}
		if pkgQuery.Name == "" && pkgQuery.PURL == "" {
			continue
		}
		if queryVersion == "" {
			queryVersion = normalized.Version
		}
		if strings.EqualFold(normalized.Ecosystem, "go") {
			queryVersion = normalizeGoVersion(queryVersion)
		}

		queries = append(queries, &osvdev.Query{
			Package: pkgQuery,
			Version: queryVersion,
		})
		meta = append(meta, normalized)
	}
	if len(queries) == 0 {
		return nil, nil
	}
	resp, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return nil, fmt.Errorf("failed to query OSV API: %w", err)
	}
	var out []Vulnerability
	var mu sync.Mutex
	var aliasCache sync.Map
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(10)
	for i, res := range resp.Results {
		if i >= len(queries) || i >= len(meta) {
			break
		}
		i, res := i, res
		g.Go(func() error {
			pkgMeta := meta[i]
			ver := queries[i].Version
			displayVersion := pkgMeta.Version
			if ver != "" {
				displayVersion = ver
			}
			var local []Vulnerability
			for _, mv := range res.Vulns {
				full, err := getCachedVuln(ctx, client, mv.ID)
				if err != nil {
					return fmt.Errorf("expand vulnerability %s: %w", mv.ID, err)
				}
				if !isVersionAffected(*full, pkgMeta) {
					continue
				}
				pkgMeta.Version = displayVersion
				base := ProcessOSVVulnerability(*full, pkgMeta)
				base.Affected = true
				var extras []Vulnerability
				skip := false
				for _, alias := range full.Aliases {
					var aliasV *osvschema.Vulnerability
					if cached, ok := aliasCache.Load(alias); ok {
						aliasV = cached.(*osvschema.Vulnerability)
					} else {
						aliasV, err = getCachedVuln(ctx, client, alias)
						if err != nil {
							continue
						}
						aliasCache.Store(alias, aliasV)
					}
					if aliasV == nil {
						continue
					}
					if !slices.ContainsFunc(aliasV.Affected, func(a osvschema.Affected) bool {
						return matchesPackage(a.Package, pkgMeta)
					}) {
						continue
					}
					if !isVersionAffected(*aliasV, pkgMeta) {
						skip = true
						break
					}
					pkgMeta.Version = displayVersion
					pv := ProcessOSVVulnerability(*aliasV, pkgMeta)
					extras = append(extras, pv)
				}
				if skip {
					continue
				}
				all := append([]Vulnerability{base}, extras...)
				if sev, typ := FindBestSeverity(all); sev != "" {
					base.Severity, base.SeverityType = sev, typ
				}
				fixSet := collections.NewSet[string]()
				var importSets [][]AffectedImport
				if len(base.AffectedImports) > 0 {
					importSets = append(importSets, base.AffectedImports)
				}
				dbSpecific := cloneStringMap(base.DatabaseSpecific)
				for _, v := range all {
					for _, f := range v.FixedVersions {
						fixSet.Add(f)
					}
					base.Aliases = append(base.Aliases, v.Aliases...)
					if len(v.AffectedImports) > 0 {
						importSets = append(importSets, v.AffectedImports)
					}
					dbSpecific = mergeStringMap(dbSpecific, v.DatabaseSpecific)
				}
				aliasSet := collections.NewSet[string]()
				uniqAliases := make([]string, 0, len(base.Aliases))
				for _, a := range append([]string{base.ID}, base.Aliases...) {
					if !aliasSet.Add(a) {
						continue
					}
					if a != base.ID {
						uniqAliases = append(uniqAliases, a)
					}
				}
				base.Aliases = uniqAliases
				base.FixedVersions = base.FixedVersions[:0]
				for _, f := range fixSet.Slice() {
					base.FixedVersions = append(base.FixedVersions, f)
				}
				base.AffectedImports = MergeAffectedImports(importSets...)
				base.DatabaseSpecific = dbSpecific
				local = append(local, base)
			}
			if len(local) > 0 {
				mu.Lock()
				out = append(out, local...)
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return out, nil
}

// matchesPackage checks if an OSV package definition matches the target package input.
func matchesPackage(pkg osvschema.Package, target PkgInput) bool {
	if pkg.Purl != "" && target.PURL != "" {
		if equivalentPURL(pkg.Purl, target.PURL) {
			return true
		}
		return false
	}
	if pkg.Name != "" && target.Name != "" && !strings.EqualFold(pkg.Name, target.Name) {
		return false
	}
	if pkg.Ecosystem != "" && target.Ecosystem != "" && !strings.EqualFold(pkg.Ecosystem, target.Ecosystem) {
		return false
	}
	if pkg.Purl == "" && pkg.Name == "" {
		return false
	}
	return true
}

// equivalentPURL checks if two PURLs refer to the same package, ignoring version.
func equivalentPURL(a, b string) bool {
	return purlx.EquivalentIgnoringVersion(a, b)
}

// isVersionAffected reports whether the package metadata and version fall within
// any affected range of the provided vulnerability. For ecosystems other than Go
// we currently rely on OSV's matching and only ensure the package identity aligns.
func isVersionAffected(v osvschema.Vulnerability, pkg PkgInput) bool {
	if !strings.EqualFold(pkg.Ecosystem, "Go") {
		for _, a := range v.Affected {
			if matchesPackage(a.Package, pkg) {
				return true
			}
		}
		return false
	}
	cur := normalizeGoVersion(pkg.Version)
	for _, a := range v.Affected {
		if !matchesPackage(a.Package, pkg) {
			continue
		}
		for _, r := range a.Ranges {
			if strings.ToUpper(string(r.Type)) != "SEMVER" {
				continue
			}
			introduced := "v0.0.0"
			for _, e := range r.Events {
				if e.Introduced != "" {
					introduced = normalizeGoVersion(e.Introduced)
				}
				if e.Fixed != "" {
					fixed := normalizeGoVersion(e.Fixed)
					if semver.Compare(cur, introduced) >= 0 && semver.Compare(cur, fixed) < 0 {
						return true
					}
					introduced = "v0.0.0"
				}
			}
			if introduced != "v0.0.0" && semver.Compare(cur, introduced) >= 0 {
				return true
			}
		}
	}
	return false
}

// mergeStringMap merges string maps, keeping existing entries in base when keys collide.
func mergeStringMap(base map[string]string, extra map[string]string) map[string]string {
	if len(extra) == 0 {
		return base
	}
	if base == nil {
		base = map[string]string{}
	}
	for k, v := range extra {
		if k == "" || v == "" {
			continue
		}
		if _, ok := base[k]; ok {
			continue
		}
		base[k] = v
	}
	return base
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	return maps.Clone(src)
}
