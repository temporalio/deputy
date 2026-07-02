package advisorysource

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/sync/errgroup"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/purlx"
)

// EcosystemGitHubActions is the canonical ecosystem label for GitHub Actions.
// OSV serves these from its advisory bucket, so it is a coverage label rather
// than an entry in the ecosystem registry.
const EcosystemGitHubActions = "github-actions"

// maxSourceConcurrency bounds concurrent source queries.
const maxSourceConcurrency = 8

// Registry aggregates advisory sources: it routes packages to the sources that
// cover them, merges results with union-with-provenance, and reports coverage.
type Registry struct {
	sources []Source
}

// NewRegistry builds a registry over the given sources (order is preserved for
// deterministic provenance ordering).
func NewRegistry(sources ...Source) *Registry {
	return &Registry{sources: slices.Clone(sources)}
}

// NewDefaultRegistry returns the registry scans use: the built-in OSV source
// plus any external sources explicitly configured via the config file
// (SetConfiguredSources) or DEPUTY_ADVISORY_SOURCES. A source that fails to
// load is skipped with a warning rather than failing the scan; the coverage
// report shows which sources actually answered.
func NewDefaultRegistry(ctx context.Context, client osv.Client) *Registry {
	sources := []Source{NewOSVSource(client)}
	external, err := materializeSources(ctx, allSourceConfigs())
	if err != nil {
		logs.Warn(ctx, "deputy.advisorysource.source_load_failed", "error", err)
	}
	return NewRegistry(append(sources, external...)...)
}

// AggregateResult is the merged answer across all sources plus a coverage report.
type AggregateResult struct {
	Findings   []*vulnerabilityv1.Finding
	Advisories map[string]*vulnerabilityv1.Advisory
	Coverage   *vulnerabilityv1.ScanCoverage
}

// Query routes pkgs to covering sources, runs them concurrently, and merges.
// A package no source covers is not an error: it is recorded in Coverage.Uncovered.
func (r *Registry) Query(ctx context.Context, pkgs []*dependencyv1.Package) (*AggregateResult, error) {
	sourceCaps := make([]capSet, len(r.sources))
	for i, src := range r.sources {
		sourceCaps[i] = newCapSet(src.Info().GetCapabilities())
	}

	// Route each package to covering sources; accumulate coverage per (eco, artifact).
	subsets := make([][]*dependencyv1.Package, len(r.sources))
	coverageAcc := map[coverageKey]*coverageAgg{}
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		eco, art := classify(p)
		key := coverageKey{eco: eco, art: art}
		agg := coverageAcc[key]
		if agg == nil {
			agg = &coverageAgg{}
			coverageAcc[key] = agg
		}
		agg.count++
		for i := range r.sources {
			if sourceCaps[i].covers(eco, art) {
				subsets[i] = append(subsets[i], p)
				name := r.sources[i].Info().GetName()
				if !slices.Contains(agg.sources, name) {
					agg.sources = append(agg.sources, name)
				}
			}
		}
	}

	// Query covering sources concurrently.
	results := make([]*Result, len(r.sources))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(maxSourceConcurrency)
	for i, src := range r.sources {
		if len(subsets[i]) == 0 {
			continue
		}
		i, src := i, src
		g.Go(func() error {
			res, err := src.Query(gctx, subsets[i])
			if err != nil {
				return fmt.Errorf("advisory source %q: %w", src.Info().GetName(), err)
			}
			results[i] = res
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}

	findings, advisories := mergeResults(results)
	return &AggregateResult{
		Findings:   findings,
		Advisories: advisories,
		Coverage:   buildCoverage(coverageAcc),
	}, nil
}

// mergeResults unions findings across sources, accumulating provenance in
// Finding.Sources, and merges advisory records by ID.
func mergeResults(results []*Result) ([]*vulnerabilityv1.Finding, map[string]*vulnerabilityv1.Advisory) {
	advisories := map[string]*vulnerabilityv1.Advisory{}
	byKey := map[string]*vulnerabilityv1.Finding{}
	var findings []*vulnerabilityv1.Finding

	for _, res := range results {
		if res == nil {
			continue
		}
		for id, adv := range res.Advisories {
			if _, ok := advisories[id]; !ok && adv != nil {
				advisories[id] = adv
			}
		}
		for _, f := range res.Findings {
			if f == nil {
				continue
			}
			key := findingKey(f)
			if existing, ok := byKey[key]; ok {
				existing.Sources = unionStrings(existing.GetSources(), f.GetSources())
				continue
			}
			byKey[key] = f
			findings = append(findings, f)
		}
	}
	return findings, advisories
}

// findingKey identifies a finding for dedup: advisory ID + package identity.
func findingKey(f *vulnerabilityv1.Finding) string {
	pkg := f.GetPackage()
	pkgKey := pkg.GetPurl()
	if pkgKey == "" {
		pkgKey = pkg.GetEcosystem() + "/" + pkg.GetName() + "@" + pkg.GetVersion()
	}
	return f.GetAdvisoryId() + "|" + pkgKey
}

func unionStrings(a, b []string) []string {
	out := slices.Clone(a)
	for _, s := range b {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// classify derives the coverage-routing ecosystem label and artifact kind for a
// package from its ecosystem/PURL.
func classify(p *dependencyv1.Package) (string, vulnerabilityv1.ArtifactKind) {
	ecoRaw := strings.TrimSpace(p.GetEcosystem())
	purlType := ""
	if pu, err := purlx.ParseLoose(p.GetPurl()); err == nil {
		purlType = pu.Type
	}

	switch {
	case isGitHubActions(ecoRaw, purlType):
		return EcosystemGitHubActions, vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_GITHUB_ACTION
	case isContainerImage(ecoRaw, purlType):
		return canonicalEco(ecoRaw, purlType), vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF
	case isOSPackage(ecoRaw, purlType):
		return canonicalEco(ecoRaw, purlType), vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_OS_PACKAGE
	default:
		return canonicalEco(ecoRaw, purlType), vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE
	}
}

// canonicalEco returns the canonical ecosystem name, preferring the registry's
// parse of the ecosystem string, then the PURL type, else the raw lowercased
// value so uncovered packages still group coherently in the coverage report.
func canonicalEco(ecoRaw, purlType string) string {
	if e := ecosystem.Parse(ecoRaw); e != ecosystem.Unknown {
		return e.String()
	}
	if e := ecosystem.Parse(purlType); e != ecosystem.Unknown {
		return e.String()
	}
	if ecoRaw != "" {
		return strings.ToLower(ecoRaw)
	}
	return strings.ToLower(purlType)
}

func isGitHubActions(ecoRaw, purlType string) bool {
	switch strings.ToLower(strings.ReplaceAll(ecoRaw, "_", "-")) {
	case "github", "github actions", "github-actions", "githubactions", "gha":
		return true
	}
	return purlx.IsGitHubActionsType(purlType)
}

func isContainerImage(ecoRaw, purlType string) bool {
	return strings.EqualFold(ecoRaw, "docker") || strings.EqualFold(ecoRaw, "oci") ||
		strings.EqualFold(purlType, "docker") || strings.EqualFold(purlType, "oci")
}

func isOSPackage(ecoRaw, purlType string) bool {
	osKinds := []string{"deb", "debian", "ubuntu", "apk", "alpine", "rpm", "redhat", "rhel", "suse", "wolfi", "chainguard"}
	v := strings.ToLower(ecoRaw)
	t := strings.ToLower(purlType)
	return slices.Contains(osKinds, v) || slices.Contains(osKinds, t)
}

// capSet is a source's coverage as fast-lookup sets.
type capSet struct {
	ecosystems map[string]bool
	artifacts  map[vulnerabilityv1.ArtifactKind]bool
}

func newCapSet(caps *pluginv1.SourceCapabilities) capSet {
	cs := capSet{ecosystems: map[string]bool{}, artifacts: map[vulnerabilityv1.ArtifactKind]bool{}}
	if caps == nil {
		return cs
	}
	for _, e := range caps.GetEcosystems() {
		cs.ecosystems[strings.ToLower(strings.TrimSpace(e))] = true
	}
	for _, a := range caps.GetArtifacts() {
		cs.artifacts[a] = true
	}
	return cs
}

func (c capSet) covers(eco string, art vulnerabilityv1.ArtifactKind) bool {
	if !c.ecosystems[strings.ToLower(eco)] {
		return false
	}
	if len(c.artifacts) == 0 {
		return true
	}
	return c.artifacts[art]
}

// coverageKey identifies an (ecosystem, artifact) combination.
type coverageKey struct {
	eco string
	art vulnerabilityv1.ArtifactKind
}

type coverageAgg struct {
	sources []string
	count   int
}

// buildCoverage turns per-combination source lists + counts into a ScanCoverage.
func buildCoverage(acc map[coverageKey]*coverageAgg) *vulnerabilityv1.ScanCoverage {
	keys := make([]coverageKey, 0, len(acc))
	for k := range acc {
		keys = append(keys, k)
	}
	slices.SortFunc(keys, func(a, b coverageKey) int {
		if c := strings.Compare(a.eco, b.eco); c != 0 {
			return c
		}
		return int(a.art) - int(b.art)
	})

	cov := &vulnerabilityv1.ScanCoverage{}
	for _, k := range keys {
		agg := acc[k]
		entry := &vulnerabilityv1.CoverageEntry{
			Ecosystem:    k.eco,
			Artifact:     k.art,
			Sources:      agg.sources,
			PackageCount: int32(agg.count),
		}
		if len(agg.sources) > 0 {
			cov.Covered = append(cov.Covered, entry)
		} else {
			cov.Uncovered = append(cov.Uncovered, entry)
		}
	}
	return cov
}
