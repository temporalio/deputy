package analysis

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/google/osv-scalibr/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
		query := &osvdev.Query{Package: pkgQuery}
		if queryVersion != "" {
			query.Version = queryVersion
		}
		queries = append(queries, query)
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
					continue
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
					hasPkg := false
					for _, a := range aliasV.Affected {
						if matchesPackage(a.Package, pkgMeta) {
							hasPkg = true
							break
						}
					}
					if hasPkg && !isVersionAffected(*aliasV, pkgMeta) {
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
				fixSet := map[string]struct{}{}
				for _, v := range all {
					for _, f := range v.FixedVersions {
						fixSet[f] = struct{}{}
					}
					base.Aliases = append(base.Aliases, v.Aliases...)
				}
				aliasSet := map[string]struct{}{}
				uniqAliases := make([]string, 0, len(base.Aliases))
				for _, a := range append([]string{base.ID}, base.Aliases...) {
					if _, ok := aliasSet[a]; ok {
						continue
					}
					aliasSet[a] = struct{}{}
					if a != base.ID {
						uniqAliases = append(uniqAliases, a)
					}
				}
				base.Aliases = uniqAliases
				base.FixedVersions = base.FixedVersions[:0]
				for f := range fixSet {
					base.FixedVersions = append(base.FixedVersions, f)
				}
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
	_ = g.Wait()
	return out, nil
}

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

func equivalentPURL(a, b string) bool {
	pa, errA := purl.FromString(a)
	pb, errB := purl.FromString(b)
	if errA != nil || errB != nil {
		return strings.EqualFold(a, b)
	}
	if !strings.EqualFold(pa.Type, pb.Type) {
		return false
	}
	if !strings.EqualFold(pa.Namespace, pb.Namespace) {
		return false
	}
	if !strings.EqualFold(pa.Name, pb.Name) {
		return false
	}
	return true
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
		return true
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
