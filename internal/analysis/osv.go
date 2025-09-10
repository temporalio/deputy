package analysis

import (
	"context"
	"fmt"
	"strings"
	"sync"

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
	Name     string
	Version  string
	IsDirect bool
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
		v := p.Version
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, "v") {
			v = "v" + v
		}
		queries = append(queries, &osvdev.Query{Package: osvdev.Package{Name: p.Name, Ecosystem: "Go"}, Version: v})
		meta = append(meta, p)
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
			pkgName := queries[i].Package.Name
			ver := queries[i].Version
			isDirect := meta[i].IsDirect
			var local []Vulnerability
			for _, mv := range res.Vulns {
				full, err := getCachedVuln(ctx, client, mv.ID)
				if err != nil {
					continue
				}
				if !isVersionAffected(*full, pkgName, ver) {
					continue
				}
				base := ProcessOSVVulnerability(*full, pkgName, ver, isDirect)
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
					// If the alias has affected ranges for this package and the current
					// version is outside those ranges, treat the vulnerability as fixed
					// and skip it entirely. This handles cases where a GO- record lacks
					// fixed version data but an alias (e.g. GHSA) provides it.
					hasPkg := false
					for _, a := range aliasV.Affected {
						if a.Package.Name != "" && strings.EqualFold(a.Package.Name, pkgName) {
							hasPkg = true
							break
						}
					}
					if hasPkg && !isVersionAffected(*aliasV, pkgName, ver) {
						skip = true
						break
					}
					pv := ProcessOSVVulnerability(*aliasV, pkgName, ver, isDirect)
					extras = append(extras, pv)
				}
				if skip {
					continue
				}
				// merge severity and fixes
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

// isVersionAffected reports whether version ver of package pkgName is within any
// affected range of the provided vulnerability. It defensively evaluates the
// ranges returned from OSV, skipping vulnerabilities that the API may
// mistakenly associate with already-fixed versions.
func isVersionAffected(v osvschema.Vulnerability, pkgName, ver string) bool {
	cur := normalizeGoVersion(ver)
	for _, a := range v.Affected {
		if a.Package.Name != "" && !strings.EqualFold(a.Package.Name, pkgName) {
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
			if introduced != "v0.0.0" {
				if semver.Compare(cur, introduced) >= 0 {
					return true
				}
			}
		}
	}
	return false
}
