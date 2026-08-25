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
	"golang.org/x/mod/semver"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
	"osv.dev/bindings/go/api"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/cache/disk"
	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Client abstracts the subset of osv.dev client functionality required for
// batch querying and vulnerability expansion. It is satisfied by
// osvdev.DefaultClient enabling dependency injection in tests.
type Client interface {
	QueryBatch(ctx context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error)
	GetVulnByID(ctx context.Context, id string) (*osvschema.Vulnerability, error)
}

// QueryKey identifies a package for OSV queries.
// This is the cacheable, query-focused subset of package identity.
type QueryKey struct {
	// Name is the package/module name (e.g., "github.com/foo/bar", "lodash").
	Name string
	// Version is the installed version string.
	Version string
	// Ecosystem identifies the package ecosystem for OSV queries (e.g., "Go", "npm").
	Ecosystem string
	// PURL is the Package URL providing a canonical identifier.
	PURL string
}

// PackageContext contains scan-time context about where a package was found.
// This information is not needed for OSV queries but is preserved for findings.
type PackageContext struct {
	// IsDirect indicates if this is a direct dependency.
	IsDirect bool
	// Locations lists file paths where the dependency was found.
	Locations []string
	// ManifestRefs describes manifest files declaring this dependency.
	ManifestRefs []dependencyv1.ManifestRef
	// LayerDetails contains information about the container image layer where
	// the package was found. Nil for non-container-image scans.
	LayerDetails *containerv1.LayerDetails
}

// PkgInput represents a single package@version query along with scan-time context.
// It combines QueryKey (for OSV queries) with PackageContext (for findings).
//
// For new code, prefer using QueryKey and PackageContext separately when possible.
type PkgInput struct {
	QueryKey
	PackageContext
}

// NewPkgInput creates a PkgInput from a QueryKey and PackageContext.
func NewPkgInput(key QueryKey, ctx PackageContext) PkgInput {
	return PkgInput{QueryKey: key, PackageContext: ctx}
}

// UnresolvedAdvisory records an advisory that a batch query attributed to a
// package but whose full record could not be retrieved, so the finding is
// absent from the results. It is returned alongside those results rather than
// as an error: a scan that lost one record must still report the rest, and must
// not be mistaken for a scan that found nothing.
type UnresolvedAdvisory struct {
	// ID is the advisory identifier the batch query returned.
	ID string
	// Package identifies the package the advisory was attributed to.
	Package string
	// Reason explains in one line why the record could not be retrieved.
	Reason string
}

// Warning renders the unresolved advisory for the scan's warning list. It leads
// with the omission rather than the cause, because the omission is what changes
// the reader's picture of their risk.
func (u UnresolvedAdvisory) Warning() string {
	return fmt.Sprintf("osv: advisory %s reported for %s is missing from this report: %s", u.ID, u.Package, u.Reason)
}

// unresolvedWithdrawnReason is the reason recorded when OSV will not serve a
// record it told us about. OSV drops a record when it is withdrawn, renamed, or
// merged into an alias, and none of those reverse on a retry.
const unresolvedWithdrawnReason = "OSV no longer serves the record and it could not be recovered through an alias"

// AdvisoryWarnings renders unresolved advisories as scan warnings, in the order
// given. It returns nil for an empty input so callers can assign the result
// straight onto a warning list without adding an empty entry.
func AdvisoryWarnings(unresolved []UnresolvedAdvisory) []string {
	if len(unresolved) == 0 {
		return nil
	}
	out := make([]string, 0, len(unresolved))
	for _, u := range unresolved {
		out = append(out, u.Warning())
	}
	return out
}

// getCachedVuln retrieves a vulnerability by ID using the provided client,
// consulting a local on-disk cache when available to avoid redundant network
// requests. Successful responses are cached for future lookups; failures are
// not, so a record that reappears upstream resolves on the next run.
func getCachedVuln(ctx context.Context, client Client, id string) (*osvschema.Vulnerability, error) {
	var v osvschema.Vulnerability
	if disk.ReadProto("osv", id, osvCacheTTL, &v) {
		otel.RecordOSVCacheAccess(ctx, true)
		return &v, nil
	}
	otel.RecordOSVCacheAccess(ctx, false)
	res, err := client.GetVulnByID(ctx, id)
	if err != nil {
		return nil, err
	}
	disk.WriteProto("osv", id, res)
	return res, nil
}

// resolveAdvisory retrieves the full OSV record for an advisory ID that a batch
// query reported.
//
// A not-found response is permanent: OSV withdrew, renamed, or merged the
// record, and asking again for the same ID will keep failing. That response
// names the IDs that do still exist, so resolveAdvisory retries against each of
// them, preferring the reviewed databases first, and returns the first record
// that is about pkg. The record it returns may therefore carry a different ID
// than the one requested. Requiring the recovered record to name pkg is what
// makes the recovery safe, because the alias list is read out of the response
// text rather than from a typed field: a misread ID resolves to a record about
// some other package and is rejected here.
//
// Whether pkg's installed version falls in the recovered record's affected
// ranges is deliberately left to the caller, so an alias that says "not
// affected" reads as the answer it is rather than as a failed recovery.
//
// Any other failure, including a cancelled context and a server error the
// client already retried, is returned unchanged so callers can keep treating it
// as fatal. Distinguishing the two rests on [IsNotFoundError].
func resolveAdvisory(ctx context.Context, client Client, id string, pkg PkgInput) (*osvschema.Vulnerability, error) {
	full, err := getCachedVuln(ctx, client, id)
	if err == nil {
		return full, nil
	}
	if !IsNotFoundError(err) {
		return nil, err
	}
	for _, alias := range SeverityAliasOrder(NotFoundAliases(err)) {
		if strings.EqualFold(alias, id) {
			continue
		}
		// A cancelled scan must never be reported as a withdrawn advisory, so
		// stop recovering instead of spending more lookups on a dead context.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		aliasVuln, aliasErr := getCachedVuln(ctx, client, alias)
		if aliasErr != nil || aliasVuln == nil {
			continue
		}
		if !slices.ContainsFunc(aliasVuln.GetAffected(), func(a *osvschema.Affected) bool {
			return matchesPackage(a.GetPackage(), pkg)
		}) {
			continue
		}
		return aliasVuln, nil
	}
	return nil, err
}

const osvCacheTTL = 24 * time.Hour

// osvConcurrencyLimit controls the maximum number of concurrent GetVulnByID
// requests when expanding batch query results. This prevents overwhelming
// the OSV API with too many parallel requests.
const osvConcurrencyLimit = 10

// Query performs a batched OSV vulnerability lookup and returns domain types.
// This is the primary API for scan operations that need findings and advisories.
// The third result lists advisories the batch query reported but whose records
// could not be retrieved; it is not an error, but callers must surface it rather
// than present the findings as the complete answer.
func Query(ctx context.Context, client Client, pkgs []PkgInput) ([]vulnerability.Finding, map[string]*vulnerabilityv1.Advisory, []UnresolvedAdvisory, error) {
	vulns, unresolved, err := QueryRaw(ctx, client, pkgs)
	if err != nil {
		return nil, nil, nil, err
	}
	findings, advisories, err := splitVulnerabilities(vulns)
	if err != nil {
		return nil, nil, nil, err
	}
	return findings, advisories, unresolved, nil
}

// QueryRaw performs a batched OSV vulnerability lookup and returns flat Vulnerability records.
// Use this when you need the raw OSV data format (e.g., for caching or policy evaluation maps).
// For scan operations that need domain types, use Query instead.
// The second result lists advisories whose records could not be retrieved, as
// described on [Query].
func QueryRaw(ctx context.Context, client Client, pkgs []PkgInput) ([]Vulnerability, []UnresolvedAdvisory, error) {
	return queryBatch(ctx, client, pkgs)
}

// QueryProto performs a batched OSV vulnerability lookup and returns proto types directly.
//
// Parameters:
//   - pkgs: slice of proto Package messages representing the packages to scan
//
// Returns:
//   - findings: slice of proto Finding messages
//   - advisories: map of advisory IDs to proto Advisory messages
//   - unresolved: advisories the batch query reported whose records could not be
//     retrieved, so the corresponding findings are missing from findings. Not an
//     error, but callers must surface it rather than present the result as
//     complete.
//   - error: any error encountered during the query
func QueryProto(ctx context.Context, client Client, pkgs []*dependencyv1.Package) ([]*vulnerabilityv1.Finding, map[string]*vulnerabilityv1.Advisory, []UnresolvedAdvisory, error) {
	if len(pkgs) == 0 {
		return nil, map[string]*vulnerabilityv1.Advisory{}, nil, nil
	}

	// Convert proto packages to PkgInput for the existing query infrastructure.
	// Nil packages are skipped entirely; a zero-value input slot would be
	// counted (and reported) as a package dropped for missing a version.
	inputs := make([]PkgInput, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}

		var manifestRefs []dependencyv1.ManifestRef
		for _, ref := range pkg.ManifestRefs {
			if ref != nil {
				manifestRefs = append(manifestRefs, dependencyv1.ManifestRef{})
				dst := &manifestRefs[len(manifestRefs)-1]
				dst.Path = ref.Path
				dst.Manager = ref.Manager
				dst.Groups = slices.Clone(dependency.ManifestRefGroups(ref))
				dependency.SetManifestRefComponentKey(dst, dependency.ManifestRefComponentKey(ref))
			}
		}

		inputs = append(inputs, PkgInput{
			QueryKey: QueryKey{
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: pkg.Ecosystem,
				PURL:      pkg.Purl,
			},
			PackageContext: PackageContext{
				IsDirect:     pkg.Direct,
				Locations:    pkg.Locations,
				ManifestRefs: manifestRefs,
				LayerDetails: pkg.LayerDetails,
			},
		})
	}

	// Query using existing infrastructure
	vulns, unresolved, err := queryBatch(ctx, client, inputs)
	if err != nil {
		return nil, nil, nil, err
	}

	// Convert to proto types
	findings, advisories, err := splitVulnerabilitiesToProto(vulns)
	if err != nil {
		return nil, nil, nil, err
	}
	return findings, advisories, unresolved, nil
}

// splitVulnerabilitiesToProto converts flat Vulnerability records to proto types.
func splitVulnerabilitiesToProto(vulns []Vulnerability) ([]*vulnerabilityv1.Finding, map[string]*vulnerabilityv1.Advisory, error) {
	if len(vulns) == 0 {
		return nil, map[string]*vulnerabilityv1.Advisory{}, nil
	}

	advisories := make(map[string]*vulnerabilityv1.Advisory, len(vulns))
	findings := make([]*vulnerabilityv1.Finding, 0, len(vulns))

	for _, v := range vulns {
		advisory, finding := splitVulnerabilityToProto(v)
		if advisory.Id != "" {
			if existing, ok := advisories[advisory.Id]; ok {
				advisories[advisory.Id] = vulnerability.MergeAdvisory(existing, advisory)
			} else {
				advisories[advisory.Id] = advisory
			}
		}
		findings = append(findings, finding)
	}

	return findings, advisories, nil
}

// VulnerabilitiesToFindings converts flat Vulnerability records to proto Findings.
func VulnerabilitiesToFindings(vulns []Vulnerability) []*vulnerabilityv1.Finding {
	if len(vulns) == 0 {
		return nil
	}
	findings := make([]*vulnerabilityv1.Finding, len(vulns))
	for i, v := range vulns {
		_, findings[i] = splitVulnerabilityToProto(v)
	}
	return findings
}

// splitVulnerabilityToProto converts a flat Vulnerability to proto types.
func splitVulnerabilityToProto(v Vulnerability) (*vulnerabilityv1.Advisory, *vulnerabilityv1.Finding) {
	advisory := &vulnerabilityv1.Advisory{
		Id:               v.ID,
		Aliases:          slices.Clone(v.Aliases),
		Summary:          v.Summary,
		Details:          v.Details,
		Cve:              v.CVE,
		Severity:         vulnerability.NewSeverity(v.Severity, v.SeverityType),
		References:       slices.Clone(v.References),
		FixedVersions:    slices.Clone(v.FixedVersions),
		PackageFixes:     vulnerability.ClonePackageFixes(v.PackageFixes),
		DatabaseSpecific: maps.Clone(v.DatabaseSpecific),
	}
	if t := vulnerability.ParseTimeRFC3339(v.Published); !t.IsZero() {
		vulnerability.SetAdvisoryPublished(advisory, t)
	}
	if t := vulnerability.ParseTimeRFC3339(v.Modified); !t.IsZero() {
		vulnerability.SetAdvisoryModified(advisory, t)
	}

	// Convert manifest refs to pointer slice
	manifestRefs := make([]*dependencyv1.ManifestRef, len(v.ManifestRefs))
	for i := range v.ManifestRefs {
		manifestRefs[i] = &dependencyv1.ManifestRef{
			Path:    v.ManifestRefs[i].Path,
			Manager: v.ManifestRefs[i].Manager,
			Groups:  dependency.ManifestRefGroups(&v.ManifestRefs[i]),
		}
		dependency.SetManifestRefComponentKey(manifestRefs[i], dependency.ManifestRefComponentKey(&v.ManifestRefs[i]))
	}

	// Convert affected imports to pointer slice
	affectedImports := make([]*vulnerabilityv1.AffectedImport, len(v.AffectedImports))
	for i := range v.AffectedImports {
		affectedImports[i] = &vulnerabilityv1.AffectedImport{
			Path:    v.AffectedImports[i].Path,
			Symbols: v.AffectedImports[i].Symbols,
		}
	}

	finding := &vulnerabilityv1.Finding{
		AdvisoryId: v.ID,
		Package: &dependencyv1.Package{
			Name:         v.Package,
			Ecosystem:    v.Ecosystem,
			Version:      v.Version,
			Purl:         v.PURL,
			Direct:       v.IsDirect,
			Locations:    slices.Clone(v.Locations),
			ManifestRefs: manifestRefs,
			LayerDetails: v.LayerDetails,
		},
		Affected:        v.Affected,
		AffectedImports: affectedImports,
		Advisory:        advisory,
	}

	return advisory, finding
}

// splitVulnerabilities converts flat Vulnerability records to domain types.
func splitVulnerabilities(vulns []Vulnerability) ([]vulnerability.Finding, map[string]*vulnerabilityv1.Advisory, error) {
	if len(vulns) == 0 {
		return nil, map[string]*vulnerabilityv1.Advisory{}, nil
	}
	advisories := make(map[string]*vulnerabilityv1.Advisory, len(vulns))
	findings := make([]vulnerability.Finding, 0, len(vulns))
	for _, v := range vulns {
		advisory, finding := splitVulnerability(v)
		if advisory.Id != "" {
			if existing, ok := advisories[advisory.Id]; ok {
				advisories[advisory.Id] = vulnerability.MergeAdvisory(existing, advisory)
			} else {
				advisories[advisory.Id] = advisory
			}
		}
		findings = append(findings, finding)
	}
	return findings, advisories, nil
}

// splitVulnerability converts a flat Vulnerability to domain types.
func splitVulnerability(v Vulnerability) (*vulnerabilityv1.Advisory, vulnerability.Finding) {
	advisory := &vulnerabilityv1.Advisory{
		Id:               v.ID,
		Aliases:          slices.Clone(v.Aliases),
		Summary:          v.Summary,
		Details:          v.Details,
		Cve:              v.CVE,
		Severity:         vulnerability.NewSeverity(v.Severity, v.SeverityType),
		References:       slices.Clone(v.References),
		FixedVersions:    slices.Clone(v.FixedVersions),
		PackageFixes:     vulnerability.ClonePackageFixes(v.PackageFixes),
		DatabaseSpecific: maps.Clone(v.DatabaseSpecific),
	}
	if t := vulnerability.ParseTimeRFC3339(v.Published); !t.IsZero() {
		vulnerability.SetAdvisoryPublished(advisory, t)
	}
	if t := vulnerability.ParseTimeRFC3339(v.Modified); !t.IsZero() {
		vulnerability.SetAdvisoryModified(advisory, t)
	}

	finding := vulnerability.Finding{
		AdvisoryID: v.ID,
		Dependency: dependency.ID{
			Name:      v.Package,
			Ecosystem: v.Ecosystem,
			PURL:      v.PURL,
		},
		Version:         v.Version,
		Direct:          v.IsDirect,
		Locations:       slices.Clone(v.Locations),
		ManifestRefs:    dependency.CloneManifestRefs(v.ManifestRefs),
		AffectedImports: vulnerability.CloneAffectedImports(v.AffectedImports),
		Affected:        v.Affected,
		LayerDetails:    dependency.CloneLayerDetails(v.LayerDetails),
	}
	return advisory, finding
}

// queryBatch performs a batched OSV vulnerability lookup for the provided packages,
// returning flat Vulnerability records. For each minimal vulnerability match it
// expands full vulnerability details via GetVulnByID to populate rich fields.
// Advisories whose records OSV would not serve are returned separately so the
// caller can report them; see [Query].
func queryBatch(ctx context.Context, client Client, pkgs []PkgInput) ([]Vulnerability, []UnresolvedAdvisory, error) {
	if len(pkgs) == 0 {
		return nil, nil, nil
	}
	var ghaPkgs []PkgInput
	var otherPkgs []PkgInput
	var skippedEcosystem int
	for _, p := range pkgs {
		if isGitHubActionsInput(p) {
			ghaPkgs = append(ghaPkgs, p)
			continue
		}
		if !osvAPIQueryable(p) {
			// OSV's querybatch rejects the entire batch if any query names an
			// ecosystem it does not recognize (e.g. Dockerfile base images,
			// mise/asdf tools). Skip those rather than aborting the whole scan;
			// OSV simply has no data for them.
			skippedEcosystem++
			continue
		}
		otherPkgs = append(otherPkgs, p)
	}
	if skippedEcosystem > 0 {
		logs.Debug(ctx, "deputy.osv.skipped_unsupported_ecosystem",
			"skipped", skippedEcosystem,
			"queryable", len(otherPkgs)+len(ghaPkgs),
			"total_input", len(pkgs),
		)
	}

	var out []Vulnerability
	var unresolved []UnresolvedAdvisory
	if len(otherPkgs) > 0 {
		vv, uu, err := queryOSVAPIBatch(ctx, client, otherPkgs)
		if err != nil {
			return nil, nil, err
		}
		out = append(out, vv...)
		unresolved = append(unresolved, uu...)
	}
	if len(ghaPkgs) > 0 {
		vv, err := queryOSVGHABucketBatch(ctx, client, ghaPkgs)
		if err != nil {
			if len(out) > 0 {
				return out, unresolved, err
			}
			return nil, unresolved, err
		}
		out = append(out, vv...)
	}
	if len(out) == 0 {
		return nil, unresolved, nil
	}
	return out, unresolved, nil
}

// osvAPIQueryable reports whether OSV's querybatch API can resolve this
// package's ecosystem. OSV only recognizes a fixed set of ecosystems; Deputy
// records that set as a non-empty OSVName in its ecosystem registry. Packages in
// ecosystems OSV does not cover (Dockerfile base images, mise/asdf tools, and
// anything unrecognized) must be excluded from the batch, because OSV rejects
// the whole request if a single query names an unknown ecosystem. GitHub Actions
// is queryable via the separate bucket path and is partitioned out before here.
func osvAPIQueryable(p PkgInput) bool {
	eco := strings.TrimSpace(p.Ecosystem)
	if eco == "" && p.PURL != "" {
		if pu, err := purlx.ParseLoose(p.PURL); err == nil {
			eco = pu.Type
		}
	}
	if ecosystem.Parse(eco).OSVQueryable() {
		return true
	}
	// OS-package ecosystems (Alpine:v3.19, Debian:12, ...) live outside the
	// package-manager ecosystem registry but are first-class in OSV.
	_, ok := OSFamilyOSVName(eco)
	return ok
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

// queryOSVAPIBatch performs the standard OSV v1/querybatch flow. Advisories the
// batch reported whose records OSV would not serve are returned as unresolved
// rather than failing the batch; see [resolveAdvisory] for which failures stay
// fatal.
func queryOSVAPIBatch(ctx context.Context, client Client, pkgs []PkgInput) ([]Vulnerability, []UnresolvedAdvisory, error) {
	if len(pkgs) == 0 {
		return nil, nil, nil
	}
	startTime := time.Now()
	queries := make([]*api.Query, 0, len(pkgs))
	meta := make([]PkgInput, 0, len(pkgs))
	var droppedNoVersion, droppedNoIdentifier int
	for _, p := range pkgs {
		normalized := normalizeQueryInput(p)
		version := strings.TrimSpace(normalized.Version)
		if version == "" {
			droppedNoVersion++
			continue
		}
		if strings.EqualFold(normalized.Ecosystem, "go") || strings.EqualFold(normalized.Ecosystem, "golang") {
			normalized.Version = normalizeGoVersion(normalized.Version)
		}
		pkgQuery, queryVersion := osvQueryPackage(normalized)
		if pkgQuery.GetName() == "" && pkgQuery.GetPurl() == "" {
			droppedNoIdentifier++
			continue
		}
		if queryVersion == "" {
			queryVersion = normalized.Version
		}
		if strings.EqualFold(normalized.Ecosystem, "go") {
			queryVersion = normalizeGoVersion(queryVersion)
		}

		queries = append(queries, &api.Query{
			Package: pkgQuery,
			Param:   &api.Query_Version{Version: queryVersion},
		})
		meta = append(meta, normalized)
	}

	// Log telemetry about dropped packages for observability.
	// Packages can be dropped due to missing versions or identifiers,
	// which may indicate upstream extraction issues or malformed manifests.
	if droppedNoVersion > 0 || droppedNoIdentifier > 0 {
		logs.Debug(ctx, "deputy.osv.packages_dropped",
			"dropped_no_version", droppedNoVersion,
			"dropped_no_identifier", droppedNoIdentifier,
			"queried", len(queries),
			"total_input", len(pkgs),
		)
		// Also add to OTel span for tracing visibility
		if span := otel.SpanFromContext(ctx); span != nil && span.IsRecording() {
			span.SetAttributes(
				otel.AttrOSVDroppedNoVersion.Int(droppedNoVersion),
				otel.AttrOSVDroppedNoIdentifier.Int(droppedNoIdentifier),
			)
		}
	}

	if len(queries) == 0 {
		return nil, nil, nil
	}
	resp, err := client.QueryBatch(ctx, queries)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to query OSV API: %w", err)
	}
	var out []Vulnerability
	var unresolved []UnresolvedAdvisory
	var mu sync.Mutex
	var aliasGroup singleflight.Group
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(osvConcurrencyLimit)
	for i, res := range resp.GetResults() {
		if i >= len(queries) || i >= len(meta) {
			break
		}
		g.Go(func() error {
			pkgMeta := meta[i]
			ver := queries[i].GetVersion()
			displayVersion := pkgMeta.Version
			if ver != "" {
				displayVersion = ver
			}
			var local []Vulnerability
			var localUnresolved []UnresolvedAdvisory
			// Alias recovery can land on a record the batch query already named
			// in its own right, since OSV lists a withdrawn ID alongside the
			// live alias that replaced it. Track what this package resolved to
			// so the same advisory is not reported against it twice.
			resolvedIDs := collections.NewSet[string]()
			for _, mv := range res.GetVulns() {
				full, err := resolveAdvisory(ctx, client, mv.GetId(), pkgMeta)
				if err != nil {
					if !IsNotFoundError(err) {
						// A transport failure, a server error the client already
						// retried, or a cancelled scan means the expansion path
						// is broken rather than one record having moved. Stay
						// fatal: results missing advisories for a reason that
						// will not reproduce must not be reported as complete.
						return fmt.Errorf("expand vulnerability %s: %w", mv.GetId(), err)
					}
					// One withdrawn record must not cost the caller every other
					// package's findings, so record the gap and keep going.
					label := packageLabel(pkgMeta, displayVersion)
					logs.Debug(ctx, "deputy.osv.advisory_unresolved",
						"advisory", mv.GetId(),
						"package", label,
						"error", err,
					)
					localUnresolved = append(localUnresolved, UnresolvedAdvisory{
						ID:      mv.GetId(),
						Package: label,
						Reason:  unresolvedWithdrawnReason,
					})
					continue
				}
				if !resolvedIDs.Add(full.GetId()) {
					continue
				}
				if !isVersionAffected(full, pkgMeta) {
					continue
				}
				pkgMeta.Version = displayVersion
				base := ProcessOSVVulnerability(full, pkgMeta)
				base.Affected = true
				var extras []Vulnerability
				skip := false
				for _, alias := range full.GetAliases() {
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
					if !slices.ContainsFunc(aliasV.GetAffected(), func(a *osvschema.Affected) bool {
						return matchesPackage(a.GetPackage(), pkgMeta)
					}) {
						continue
					}
					if !isVersionAffected(aliasV, pkgMeta) {
						skip = true
						break
					}
					pkgMeta.Version = displayVersion
					pv := ProcessOSVVulnerability(aliasV, pkgMeta)
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
				var importSets [][]vulnerabilityv1.AffectedImport
				if len(base.AffectedImports) > 0 {
					importSets = append(importSets, base.AffectedImports)
				}
				var packageFixSets [][]*vulnerabilityv1.PackageFix
				dbSpecific := maps.Clone(base.DatabaseSpecific)
				for _, v := range all {
					for _, f := range v.FixedVersions {
						fixSet.Add(f)
					}
					if len(v.PackageFixes) > 0 {
						packageFixSets = append(packageFixSets, v.PackageFixes)
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
				base.PackageFixes = vulnerability.MergePackageFixes(packageFixSets...)
				base.DatabaseSpecific = dbSpecific
				local = append(local, base)
			}
			if len(local) > 0 || len(localUnresolved) > 0 {
				mu.Lock()
				out = append(out, local...)
				unresolved = append(unresolved, localUnresolved...)
				mu.Unlock()
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		otel.RecordOSVQuery(ctx, time.Since(startTime).Seconds(), "batch", false)
		return nil, nil, err
	}
	otel.RecordOSVQuery(ctx, time.Since(startTime).Seconds(), "batch", true)
	if len(unresolved) > 0 {
		// Order by advisory then package so repeated scans of the same target
		// produce the same warnings: expansion runs concurrently, so arrival
		// order is not stable.
		slices.SortFunc(unresolved, func(a, b UnresolvedAdvisory) int {
			if c := strings.Compare(a.ID, b.ID); c != 0 {
				return c
			}
			return strings.Compare(a.Package, b.Package)
		})
		// Debug, not warn: the caller already surfaces these in the report, and
		// logging them again would say the same thing twice on one terminal.
		logs.Debug(ctx, "deputy.osv.advisories_unresolved",
			"unresolved", len(unresolved),
			"resolved", len(out),
		)
		if span := otel.SpanFromContext(ctx); span != nil && span.IsRecording() {
			span.SetAttributes(otel.AttrOSVUnresolvedAdvisories.Int(len(unresolved)))
		}
	}
	return out, unresolved, nil
}

// packageLabel names a package for a human-readable diagnostic, preferring
// name@version and falling back to the PURL when the input carried no name.
func packageLabel(pkg PkgInput, version string) string {
	if version == "" {
		version = pkg.Version
	}
	name := pkg.Name
	if name == "" {
		name = pkg.PURL
	}
	if name == "" {
		name = "unknown package"
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}

func normalizeQueryInput(p PkgInput) PkgInput {
	normalized := p
	normalized.Name = strings.TrimSpace(normalized.Name)
	normalized.Ecosystem = strings.TrimSpace(normalized.Ecosystem)
	normalized.PURL = strings.TrimSpace(normalized.PURL)
	normalized.Version = strings.TrimSpace(normalized.Version)

	if normalized.PURL == "" {
		return normalized
	}
	pu, err := purl.FromString(normalized.PURL)
	if err != nil {
		return normalized
	}
	normalized.PURL = pu.String()
	if normalized.Version == "" {
		normalized.Version = strings.TrimSpace(pu.Version)
	}
	if normalized.Name == "" {
		normalized.Name = purlPackageName(pu)
	}
	if normalized.Ecosystem == "" {
		normalized.Ecosystem = purlOSVEcosystem(pu)
	}
	return normalized
}

func osvQueryPackage(p PkgInput) (*osvschema.Package, string) {
	version := p.Version
	if p.Name != "" && p.Ecosystem != "" {
		return &osvschema.Package{
			Name:      p.Name,
			Ecosystem: normalizeOSVEcosystem(p.Ecosystem),
		}, version
	}

	pkgQuery := &osvschema.Package{}
	if p.PURL != "" {
		pkgQuery.Purl = p.PURL
		if pu, err := purl.FromString(p.PURL); err == nil {
			if version == "" {
				version = pu.Version
			}
			pu.Version = ""
			pkgQuery.Purl = pu.String()
		}
	}
	return pkgQuery, version
}

func normalizeOSVEcosystem(name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	if eco := ecosystem.Parse(name); eco != ecosystem.Unknown {
		return eco.OSVName()
	}
	return name
}

func purlOSVEcosystem(pu purl.PackageURL) string {
	if eco := ecosystem.Parse(pu.Type); eco != ecosystem.Unknown {
		return eco.OSVName()
	}
	return strings.TrimSpace(pu.Type)
}

func purlPackageName(pu purl.PackageURL) string {
	if pu.Name == "" {
		return ""
	}
	if pu.Namespace == "" {
		return pu.Name
	}
	if strings.EqualFold(pu.Type, "maven") {
		return pu.Namespace + ":" + pu.Name
	}
	return pu.Namespace + "/" + pu.Name
}

// normalizeGoVersion ensures Go module versions use the canonical v-prefix.
func normalizeGoVersion(v string) string {
	return ecosystem.Go.NormalizeVersion(v)
}

// matchesPackage checks if an OSV package definition matches the target package input.
func matchesPackage(pkg *osvschema.Package, target PkgInput) bool {
	if pkg.GetPurl() != "" && target.PURL != "" {
		return equivalentPURL(pkg.GetPurl(), target.PURL)
	}
	if pkg.GetName() != "" && target.Name != "" && !strings.EqualFold(pkg.GetName(), target.Name) {
		return false
	}
	if pkg.GetEcosystem() != "" && target.Ecosystem != "" && !strings.EqualFold(pkg.GetEcosystem(), target.Ecosystem) {
		return false
	}
	if pkg.GetPurl() == "" && pkg.GetName() == "" {
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
func isVersionAffected(v *osvschema.Vulnerability, pkg PkgInput) bool {
	version := strings.TrimSpace(pkg.Version)
	if version == "" {
		return false
	}

	for _, a := range v.GetAffected() {
		if !matchesPackage(a.GetPackage(), pkg) {
			continue
		}

		// If no ranges are specified, the package is unconditionally affected
		if len(a.GetRanges()) == 0 {
			return true
		}

		// Check each range
		for _, r := range a.GetRanges() {
			if versionInRange(version, pkg.Ecosystem, a.GetPackage().GetEcosystem(), r) {
				return true
			}
		}
	}
	return false
}

// versionInRange checks if a version falls within an OSV affected range.
// It handles SEMVER, ECOSYSTEM, and GIT range types with ecosystem-specific comparison.
func versionInRange(version, pkgEcosystem, osvEcosystem string, r *osvschema.Range) bool {
	rangeType := r.GetType().String()

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
func versionInGoSemverRange(version string, r *osvschema.Range) bool {
	cur := normalizeGoVersion(version)
	if cur == "" || !semver.IsValid(cur) {
		return true // Can't compare, assume affected for safety
	}

	var introduced string
	introducedSet := false
	introducedFromZero := false
	for _, e := range r.GetEvents() {
		if e.Introduced != "" {
			introducedSet = true
			introducedFromZero = strings.TrimSpace(e.Introduced) == "0"
			if introducedFromZero {
				introduced = ""
			} else {
				introduced = normalizeGoRangeVersion(e.Introduced)
			}
		}
		if e.Fixed != "" {
			fixed := normalizeGoRangeVersion(e.Fixed)
			if semver.IsValid(fixed) && goVersionAfterIntroduced(cur, introduced, introducedSet, introducedFromZero) && semver.Compare(cur, fixed) < 0 {
				return true
			}
			introduced = ""
			introducedSet = false
			introducedFromZero = false
		}
		if e.LastAffected != "" {
			lastAffected := normalizeGoRangeVersion(e.LastAffected)
			if semver.IsValid(lastAffected) && goVersionAfterIntroduced(cur, introduced, introducedSet, introducedFromZero) && semver.Compare(cur, lastAffected) <= 0 {
				return true
			}
			introduced = ""
			introducedSet = false
			introducedFromZero = false
		}
	}
	// Check if still in an open-ended "introduced" range
	if introducedSet && goVersionAfterIntroduced(cur, introduced, introducedSet, introducedFromZero) {
		return true
	}
	return false
}

func goVersionAfterIntroduced(cur, introduced string, introducedSet, introducedFromZero bool) bool {
	if !introducedSet || introducedFromZero {
		return true
	}
	if !semver.IsValid(introduced) {
		return true
	}
	return semver.Compare(cur, introduced) >= 0
}

func normalizeGoRangeVersion(v string) string {
	v = strings.TrimSpace(v)
	if v == "0" {
		return "v0.0.0"
	}
	return normalizeGoVersion(v)
}

// versionInEcosystemRange checks if a version falls within an ECOSYSTEM or SEMVER range
// using OSV-SCALIBR's semantic version comparison for the appropriate ecosystem.
func versionInEcosystemRange(version, ecosystem string, r *osvschema.Range) bool {
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

	for _, e := range r.GetEvents() {
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
			// An unparseable fixed version skips the event, leaving the
			// introduced range open: the conservative reading of bad
			// advisory data (report affected rather than assume fixed).
			if _, err := semantic.Parse(e.Fixed, semanticEco); err != nil {
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
