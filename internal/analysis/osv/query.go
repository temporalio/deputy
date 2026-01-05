package osv

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/semantic"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/picatz/deputy/internal/cache/disk"
	"github.com/picatz/deputy/internal/collections"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/ecosystem"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/vulnerability"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"osv.dev/bindings/go/osvdev"
)

// Client abstracts the subset of osv.dev client functionality required for
// batch querying and vulnerability expansion. It is satisfied by
// osvdev.DefaultClient enabling dependency injection in tests.
type Client interface {
	QueryBatch(ctx context.Context, queries []*osvdev.Query) (*osvdev.BatchedResponse, error)
	GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error)
}

// PkgInput represents a single package@version query along with whether the
// dependency is direct (appears explicitly in go.mod). Directness influences
// downstream prioritization but not query mechanics.
type PkgInput struct {
	// Name is the package/module name (e.g., "github.com/foo/bar", "lodash").
	Name string
	// Version is the installed version string.
	Version string
	// Ecosystem identifies the package ecosystem for OSV queries (e.g., "Go", "npm").
	Ecosystem string
	// PURL is the Package URL providing a canonical identifier.
	PURL string
	// IsDirect indicates if this is a direct dependency.
	IsDirect bool
	// Locations lists file paths where the dependency was found.
	Locations []string
	// ManifestRefs describes manifest files declaring this dependency.
	ManifestRefs []dependency.ManifestRef
	// LayerDetails contains information about the container image layer where
	// the package was found. Nil for non-container-image scans.
	LayerDetails *dependency.LayerDetails
}

// getCachedVuln retrieves a vulnerability by ID using the provided client,
// consulting a local on-disk cache when available to avoid redundant network
// requests. Successful responses are cached for future lookups.
func getCachedVuln(ctx context.Context, client Client, id string) (*osvschema.Vulnerability, error) {
	var v osvschema.Vulnerability
	if disk.Read("osv", id, osvCacheTTL, &v) {
		otel.RecordOSVCacheAccess(ctx, true)
		return &v, nil
	}
	otel.RecordOSVCacheAccess(ctx, false)
	res, err := client.GetVulnByID(ctx, id)
	if err != nil {
		return nil, err
	}
	disk.Write("osv", id, res)
	return res, nil
}

const osvCacheTTL = 24 * time.Hour

// osvConcurrencyLimit controls the maximum number of concurrent GetVulnByID
// requests when expanding batch query results. This prevents overwhelming
// the OSV API with too many parallel requests.
const osvConcurrencyLimit = 10

// QueryOSVBatch performs a batched OSV vulnerability lookup for the provided
// packages. For each minimal vulnerability match it expands full vulnerability
// details via GetVulnByID to populate rich fields (aliases, severity, ranges).
// The function is resilient: individual GetVulnByID failures are skipped so a
// single retrieval error does not abort the entire batch.
func QueryOSVBatch(ctx context.Context, client Client, pkgs []PkgInput) ([]Vulnerability, error) {
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
func queryOSVAPIBatch(ctx context.Context, client Client, pkgs []PkgInput) ([]Vulnerability, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	startTime := time.Now()
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
	var aliasGroup singleflight.Group
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(osvConcurrencyLimit)
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
					// Use singleflight to deduplicate concurrent requests for the same alias
					result, err, _ := aliasGroup.Do(alias, func() (any, error) {
						return getCachedVuln(ctx, client, alias)
					})
					if err != nil {
						continue
					}
					aliasV := result.(*osvschema.Vulnerability)
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
				var importSets [][]vulnerability.AffectedImport
				if len(base.AffectedImports) > 0 {
					importSets = append(importSets, base.AffectedImports)
				}
				dbSpecific := maps.Clone(base.DatabaseSpecific)
				for _, v := range all {
					for _, f := range v.FixedVersions {
						fixSet.Add(f)
					}
					base.Aliases = append(base.Aliases, v.Aliases...)
					if len(v.AffectedImports) > 0 {
						importSets = append(importSets, v.AffectedImports)
					}
					dbSpecific = vulnerability.MergeStringMap(dbSpecific, v.DatabaseSpecific)
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
				for f := range fixSet.All() {
					base.FixedVersions = append(base.FixedVersions, f)
				}
				base.AffectedImports = vulnerability.MergeAffectedImports(importSets...)
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
		otel.RecordOSVQuery(ctx, time.Since(startTime).Seconds(), "batch", false)
		return nil, err
	}
	otel.RecordOSVQuery(ctx, time.Since(startTime).Seconds(), "batch", true)
	return out, nil
}

// normalizeGoVersion ensures Go module versions use the canonical v-prefix.
func normalizeGoVersion(v string) string {
	return ecosystem.Go.NormalizeVersion(v)
}

// matchesPackage checks if an OSV package definition matches the target package input.
func matchesPackage(pkg osvschema.Package, target PkgInput) bool {
	if pkg.Purl != "" && target.PURL != "" {
		return equivalentPURL(pkg.Purl, target.PURL)
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
// any affected range of the provided vulnerability. It uses ecosystem-specific
// version comparison (Debian, Alpine, npm, etc.) via OSV-SCALIBR's semantic package.
func isVersionAffected(v osvschema.Vulnerability, pkg PkgInput) bool {
	version := strings.TrimSpace(pkg.Version)
	if version == "" {
		return false
	}

	for _, a := range v.Affected {
		if !matchesPackage(a.Package, pkg) {
			continue
		}

		// If no ranges are specified, the package is unconditionally affected
		if len(a.Ranges) == 0 {
			return true
		}

		// Check each range
		for _, r := range a.Ranges {
			if versionInRange(version, pkg.Ecosystem, a.Package.Ecosystem, r) {
				return true
			}
		}
	}
	return false
}

// versionInRange checks if a version falls within an OSV affected range.
// It handles SEMVER, ECOSYSTEM, and GIT range types with ecosystem-specific comparison.
func versionInRange(version, pkgEcosystem, osvEcosystem string, r osvschema.Range) bool {
	rangeType := strings.ToUpper(string(r.Type))

	// GIT ranges require commit hash matching, which we don't support
	if rangeType == "GIT" {
		return false
	}

	// Determine the ecosystem for version comparison
	eco := resolveEcosystemForComparison(pkgEcosystem, osvEcosystem)

	// For Go ecosystem with SEMVER ranges, use golang.org/x/mod/semver
	if strings.EqualFold(eco, "Go") && rangeType == "SEMVER" {
		return versionInGoSemverRange(version, r)
	}

	// For other ecosystems, use OSV-SCALIBR's semantic version comparison
	return versionInEcosystemRange(version, eco, r)
}

// versionInGoSemverRange checks if a Go version falls within a SEMVER range.
func versionInGoSemverRange(version string, r osvschema.Range) bool {
	cur := normalizeGoVersion(version)
	if cur == "" || !semver.IsValid(cur) {
		return true // Can't compare, assume affected for safety
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
	// Check if still in an open-ended "introduced" range
	if introduced != "v0.0.0" && semver.Compare(cur, introduced) >= 0 {
		return true
	}
	return false
}

// versionInEcosystemRange checks if a version falls within an ECOSYSTEM or SEMVER range
// using OSV-SCALIBR's semantic version comparison for the appropriate ecosystem.
func versionInEcosystemRange(version, ecosystem string, r osvschema.Range) bool {
	// Map ecosystem to OSV-SCALIBR semantic package ecosystem name
	semanticEco := mapToSemanticEcosystem(ecosystem)
	if semanticEco == "" {
		// Unknown ecosystem - can't compare versions, assume affected for safety
		return true
	}

	// Parse the installed version
	installedVersion, err := semantic.Parse(version, semanticEco)
	if err != nil {
		// Can't parse version - assume affected for safety
		return true
	}

	// Track the current "introduced" boundary as we process events
	var introducedVersion semantic.Version
	introducedSet := false

	for _, e := range r.Events {
		if e.Introduced != "" {
			if e.Introduced == "0" {
				// "0" means all versions are affected from the beginning
				introducedSet = true
				introducedVersion = nil
			} else {
				intro, err := semantic.Parse(e.Introduced, semanticEco)
				if err == nil {
					introducedVersion = intro
					introducedSet = true
				}
			}
		}
		if e.Fixed != "" {
			fixedVersion, err := semantic.Parse(e.Fixed, semanticEco)
			if err != nil {
				continue
			}

			// Check if installed version is in range [introduced, fixed)
			if introducedSet {
				afterIntroduced := true
				if introducedVersion != nil {
					cmp, err := installedVersion.CompareStr(e.Introduced)
					if err == nil {
						afterIntroduced = cmp >= 0
					}
				}

				beforeFixed, err := installedVersion.CompareStr(e.Fixed)
				if err == nil && afterIntroduced && beforeFixed < 0 {
					return true
				}
			}

			// Reset introduced after processing a fixed event
			introducedSet = false
			introducedVersion = nil
			_ = fixedVersion // silence unused warning
		}
	}

	// Check if still in an open-ended "introduced" range (no fixed version)
	if introducedSet {
		if introducedVersion == nil {
			// Introduced from "0" with no fix means all versions affected
			return true
		}
		// Check if installed >= introduced
		cmp, err := introducedVersion.CompareStr(version)
		if err == nil && cmp <= 0 {
			return true
		}
	}

	return false
}

// resolveEcosystemForComparison determines the ecosystem to use for version comparison.
// It prefers the OSV vulnerability's ecosystem since it's authoritative.
func resolveEcosystemForComparison(pkgEcosystem, osvEcosystem string) string {
	// Prefer OSV ecosystem as it's authoritative for the vulnerability
	if osvEcosystem != "" {
		return osvEcosystem
	}
	return pkgEcosystem
}

// mapToSemanticEcosystem maps an ecosystem name to the format expected by
// OSV-SCALIBR's semantic package.
func mapToSemanticEcosystem(ecosystem string) string {
	eco := strings.TrimSpace(ecosystem)
	if eco == "" {
		return ""
	}

	// Handle ecosystems with version suffixes (e.g., "Debian:11" -> "Debian")
	if idx := strings.Index(eco, ":"); idx != -1 {
		eco = eco[:idx]
	}

	// Normalize to the canonical names expected by semantic.Parse
	switch strings.ToLower(eco) {
	case "debian":
		return "Debian"
	case "ubuntu":
		return "Ubuntu"
	case "alpine":
		return "Alpine"
	case "almalinux":
		return "AlmaLinux"
	case "rocky linux", "rocky":
		return "Rocky Linux"
	case "red hat", "rhel", "redhat":
		return "Red Hat"
	case "centos":
		return "Red Hat" // CentOS uses Red Hat versioning
	case "opensuse":
		return "openSUSE"
	case "suse", "sles":
		return "SUSE"
	case "mageia":
		return "Mageia"
	case "wolfi":
		return "Wolfi"
	case "chainguard":
		return "Chainguard"
	case "npm":
		return "npm"
	case "pypi", "python":
		return "PyPI"
	case "maven":
		return "Maven"
	case "nuget":
		return "NuGet"
	case "rubygems":
		return "RubyGems"
	case "crates.io", "cargo":
		return "crates.io"
	case "packagist", "composer":
		return "Packagist"
	case "go", "golang":
		return "Go"
	case "hex":
		return "Hex"
	case "pub":
		return "Pub"
	case "hackage":
		return "Hackage"
	case "cran":
		return "CRAN"
	case "bitnami":
		return "Bitnami"
	case "bioconductor":
		return "Bioconductor"
	case "conancenter":
		return "ConanCenter"
	case "ghc":
		return "GHC"
	case "swifturl":
		return "SwiftURL"
	default:
		return ""
	}
}
