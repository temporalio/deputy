// Package scanning provides scan orchestration for vulnerability analysis.
// It combines inventory collection with OSV vulnerability queries, serving as
// the canonical place for scan logic used by proto handlers.
package scanning

import (
	"context"
	"fmt"
	"maps"
	"path"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	packageurl "github.com/package-url/packageurl-go"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sync/errgroup"

	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/advisorysource"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/container/image"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/dockerfile"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/forge"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/inventory/manifests"
	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/policy"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/remediation/fixresolve"
	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// Result contains the output of a vulnerability scan.
type Result struct {
	// Target describes what was scanned.
	Target inventory.Target

	// Packages is the list of discovered dependencies.
	// May be nil when result is deserialized from proto (use PackagesScanned for count).
	Packages []*extractor.Package

	// PackagesScanned is the count of packages that were analyzed.
	// This is set explicitly and survives proto round-trips (unlike len(Packages)).
	PackagesScanned int

	// Direct maps package keys to whether they are direct dependencies.
	Direct map[string]bool

	// Findings lists all vulnerability findings.
	Findings []vulnerability.Finding

	// Consolidated holds the deduplicated findings with resolved fix verdicts
	// attached (when fix resolution ran). Renderers should prefer this over
	// re-consolidating Findings, so fix verdicts are not recomputed.
	Consolidated []vulnerability.Consolidated

	// Advisories maps advisory IDs to their full details.
	Advisories map[string]*vulnerabilityv1.Advisory

	// Stats contains vulnerability severity counts.
	Stats *vulnerabilityv1.Stats

	// Coverage reports which (ecosystem, artifact) combinations advisory sources
	// answered for, and which had no coverage (e.g. container base images).
	// Uncovered combinations are informational, not errors.
	Coverage *vulnerabilityv1.ScanCoverage

	// Graph contains the resolved dependency graph (when graph resolution is enabled).
	Graph *graph.Graph

	// ImageInfo contains container image configuration (for image targets).
	ImageInfo *image.Info

	// DockerfileInfo contains parsed Dockerfile data (for dockerfile targets).
	DockerfileInfo *dockerfile.Info

	// DockerfileAnalysis contains static analysis results (for dockerfile targets).
	DockerfileAnalysis *dockerfile.Analysis

	// Warnings contains non-fatal warnings from the scan.
	Warnings []string

	// PolicyActions contains results from policy evaluation.
	PolicyActions []policy.Action

	// GeneratedAt is when the scan completed.
	GeneratedAt time.Time
}

// Execution wraps a scan result with cleanup.
type Execution struct {
	Result  Result
	cleanup func()
}

// Close releases resources (e.g., cloned repositories).
func (e *Execution) Close() error {
	if e != nil && e.cleanup != nil {
		e.cleanup()
	}
	return nil
}

// Options configures vulnerability scanning.
type Options struct {
	// Ecosystems limits scanning to specific package ecosystems.
	Ecosystems []string

	// Platform specifies container image platform (e.g., "linux/amd64").
	Platform string

	// DetectBaseImage enables base image detection for container image scans.
	// When true, the baseimage enricher queries deps.dev to determine if layers
	// belong to known base images, populating LayerDetails.InBaseImage.
	// This requires network access and adds latency to the scan.
	DetectBaseImage bool

	// VerifyFixes enables fix-resolution: each finding's claimed fixed version
	// is verified for installability against the Go module proxy, and findings
	// whose fix lives on a different module path are reported as migrations.
	// Requires network access. Disable (via --no-verify-fixes) for offline scans
	// to fall back to trusting advisory-reported fixed versions verbatim.
	VerifyFixes bool

	// ResolveSeverities rates advisories whose matched record carries no
	// severity by consulting their alias records (GHSA first, then CVE), before
	// consolidation so stats and triage priorities reflect the resolved
	// ratings. The resulting Severity keeps its origin in type/raw. Opt-in via
	// scan enrichment: it adds network lookups and Deputy never substitutes an
	// alias rating silently.
	ResolveSeverities bool

	// GoProxyURL overrides the Go module proxy used for fix verification.
	// Empty uses the default (proxy.golang.org).
	GoProxyURL string

	// ExcludePaths lists glob patterns for directory paths to skip during the
	// filesystem walk (e.g., ".bin/**"). Matching subtrees are never inventoried.
	// See [inventory.CompileExcludePaths] for pattern semantics.
	ExcludePaths []string
}

// ScanRepository scans a repository for vulnerabilities.
func ScanRepository(ctx context.Context, target, ref string, refProvided bool, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scanning.repository",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
			attribute.String("deputy.target.ref", ref),
		))
	defer span.End()

	// Collect inventory
	invOpts := inventory.Options{Ecosystems: opts.Ecosystems, ExcludePaths: opts.ExcludePaths}
	invExec, err := inventory.CollectRepository(ctx, target, ref, refProvided, invOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {
		if invExec != nil {
			invExec.Close()
		}
	}

	// Query vulnerabilities
	findings, advisories, coverage, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct, invExec.Result.Target.OriginURL)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	cons, stats := consolidateAndResolve(ctx, findings, advisories, opts)

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Consolidated:    cons,
			Advisories:      advisories,
			Stats:           stats,
			Coverage:        coverage,
			GeneratedAt:     time.Now().UTC(),
		},
		cleanup: cleanup,
	}, nil
}

// ScanContainerImage scans a container image for vulnerabilities.
func ScanContainerImage(ctx context.Context, target string, targetOpts map[string]string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scanning.container_image",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
		))
	defer span.End()

	// Collect inventory
	invOpts := inventory.Options{
		Ecosystems:      opts.Ecosystems,
		Platform:        opts.Platform,
		DetectBaseImage: opts.DetectBaseImage,
	}
	invExec, err := inventory.CollectContainerImage(ctx, target, targetOpts, invOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {
		if invExec != nil {
			invExec.Close()
		}
	}

	// Query vulnerabilities
	findings, advisories, coverage, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct, invExec.Result.Target.OriginURL)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	cons, stats := consolidateAndResolve(ctx, findings, advisories, opts)

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Consolidated:    cons,
			Advisories:      advisories,
			Stats:           stats,
			Coverage:        coverage,
			ImageInfo:       invExec.Result.ImageInfo,
			GeneratedAt:     time.Now().UTC(),
		},
		cleanup: cleanup,
	}, nil
}

// ScanDirectory scans a local directory for vulnerabilities.
func ScanDirectory(ctx context.Context, path string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scanning.directory",
		trace.WithAttributes(
			attribute.String("deputy.target.path", path),
		))
	defer span.End()

	// Collect inventory
	invOpts := inventory.Options{Ecosystems: opts.Ecosystems, ExcludePaths: opts.ExcludePaths}
	invExec, err := inventory.CollectDirectory(ctx, path, invOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {
		if invExec != nil {
			invExec.Close()
		}
	}

	// Query vulnerabilities
	findings, advisories, coverage, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct, invExec.Result.Target.OriginURL)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	cons, stats := consolidateAndResolve(ctx, findings, advisories, opts)

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Consolidated:    cons,
			Advisories:      advisories,
			Stats:           stats,
			Coverage:        coverage,
			GeneratedAt:     time.Now().UTC(),
		},
		cleanup: cleanup,
	}, nil
}

// ScanVMImage scans a VM disk image or rootfs image for vulnerabilities.
// Supported formats: qcow2, vmdk, vhd, vhdx, vdi, raw, and ext4 rootfs images.
func ScanVMImage(ctx context.Context, target string, targetOpts map[string]string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scanning.vm_image",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
		))
	defer span.End()

	// Collect inventory
	invOpts := inventory.Options{Ecosystems: opts.Ecosystems, ExcludePaths: opts.ExcludePaths}
	invExec, err := inventory.CollectVMImage(ctx, target, targetOpts, invOpts)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {
		if invExec != nil {
			invExec.Close()
		}
	}

	// Query vulnerabilities
	findings, advisories, coverage, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct, invExec.Result.Target.OriginURL)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	cons, stats := consolidateAndResolve(ctx, findings, advisories, opts)

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Consolidated:    cons,
			Advisories:      advisories,
			Stats:           stats,
			Coverage:        coverage,
			GeneratedAt:     time.Now().UTC(),
		},
		cleanup: cleanup,
	}, nil
}

// Scan auto-detects target type and scans for vulnerabilities.
func Scan(ctx context.Context, target string, opts Options) (*Execution, error) {
	kind := targets.DetectKind(target)

	switch kind {
	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		return ScanContainerImage(ctx, target, targetOpts, opts)

	case targets.KindPURL:
		return ScanPURL(ctx, target, opts)

	default:
		return ScanRepository(ctx, target, "HEAD", false, opts)
	}
}

// ScanPURL scans a single PURL by querying OSV directly.
func ScanPURL(ctx context.Context, purlStr string, opts Options) (*Execution, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scanning.purl",
		trace.WithAttributes(
			attribute.String("deputy.target.purl", purlStr),
		))
	defer span.End()

	purlStr = strings.TrimSpace(purlStr)
	if purlStr == "" {
		err := fmt.Errorf("purl is required")
		otel.SetSpanError(span, err)
		return nil, err
	}

	pu, err := purlx.ParseLoose(purlStr)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, err
	}

	pu.Type = strings.TrimSpace(pu.Type)
	pu.Namespace = strings.TrimSpace(pu.Namespace)
	pu.Name = strings.TrimSpace(pu.Name)
	pu.Version = strings.TrimSpace(pu.Version)

	if pu.Name == "" {
		err := fmt.Errorf("purl %q is missing a name", purlStr)
		otel.SetSpanError(span, err)
		return nil, err
	}
	if pu.Version == "" {
		err := fmt.Errorf("purl %q is missing a version", purlStr)
		otel.SetSpanError(span, err)
		return nil, err
	}

	canonical := pu.String()
	name := purlDisplayName(pu)
	ecos := purlEcosystem(pu)

	inputs := []*dependencyv1.Package{
		{
			Name:      name,
			Version:   pu.Version,
			Ecosystem: ecos,
			Purl:      canonical,
			Direct:    true,
		},
	}

	pkgs := []*extractor.Package{
		{
			Name:     name,
			Version:  pu.Version,
			PURLType: pu.Type,
		},
	}

	direct := map[string]bool{}
	if canonical != "" {
		direct[canonical] = true
	}

	// Query advisory sources via the registry (OSV today).
	agg, err := advisorysource.NewDefaultRegistry(ctx, osv.NewClient()).Query(ctx, inputs)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}
	// Convert proto findings to domain once, at the boundary where consolidation
	// (a domain projection) begins. Everything upstream is proto.
	findings, advisories, coverage := vulnerability.FindingsFromProto(agg.Findings), agg.Advisories, agg.Coverage

	span.SetAttributes(attribute.Int("deputy.finding.count", len(findings)))

	cons, stats := consolidateAndResolve(ctx, findings, advisories, opts)

	return &Execution{
		Result: Result{
			Target: inventory.Target{
				Kind:        targets.KindPURL,
				DisplayPath: canonical,
			},
			Packages:        pkgs,
			PackagesScanned: len(pkgs),
			Direct:          direct,
			Findings:        findings,
			Consolidated:    cons,
			Advisories:      advisories,
			Stats:           stats,
			Coverage:        coverage,
			GeneratedAt:     time.Now().UTC(),
		},
	}, nil
}

func purlDisplayName(pu packageurl.PackageURL) string {
	if pu.Name == "" {
		return ""
	}
	if pu.Namespace == "" {
		return pu.Name
	}
	if strings.EqualFold(pu.Type, "maven") {
		return pu.Namespace + ":" + pu.Name
	}
	return path.Join(pu.Namespace, pu.Name)
}

func purlEcosystem(pu packageurl.PackageURL) string {
	if purlx.IsGitHubActionsType(pu.Type) {
		return "GitHub Actions"
	}
	eco := ecosystem.Parse(pu.Type)
	if eco != ecosystem.Unknown {
		return eco.OSVName()
	}
	return strings.TrimSpace(pu.Type)
}

// consolidateAndResolve deduplicates findings into consolidated records, then
// (when opts.VerifyFixes is set) resolves each record's fix verdict against the
// Go module proxy so downstream stats/rendering distinguish installable
// in-place upgrades from module migrations and unreachable advisory versions.
func consolidateAndResolve(ctx context.Context, findings []vulnerability.Finding, advisories map[string]*vulnerabilityv1.Advisory, opts Options) ([]vulnerability.Consolidated, *vulnerabilityv1.Stats) {
	if opts.ResolveSeverities {
		resolveUnratedSeverities(ctx, osv.NewClient(), advisories)
	}
	cons := vulnerability.Consolidate(findings, advisories)
	if opts.VerifyFixes {
		resolver := fixresolve.NewGoProxyResolver(opts.GoProxyURL)
		fixresolve.Annotate(ctx, cons, resolver, fixresolve.Options{Verify: true})
		// Persist verdicts onto the advisories so they survive the proto round-trip
		// to the CLI/renderers (Consolidated is not a proto type).
		persistFixVerdicts(cons, advisories)
	}
	return cons, vulnerability.StatsFromConsolidated(cons, len(findings))
}

// resolveSeverityLookups caps concurrent alias-record fetches during severity
// resolution.
const resolveSeverityLookups = 8

// resolveUnratedSeverities rates advisories whose matched record carries no
// severity by consulting their alias records in osv.SeverityAliasOrder. The
// resolved Severity is normalized through the same path as record-carried
// ratings and keeps its origin in type/raw. Advisories that stay unrated keep
// severity UNKNOWN: absence of a rating anywhere is itself the answer.
func resolveUnratedSeverities(ctx context.Context, client osv.Client, advisories map[string]*vulnerabilityv1.Advisory) {
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(resolveSeverityLookups)
	for _, adv := range advisories {
		if adv == nil || len(adv.GetAliases()) == 0 {
			continue
		}
		if adv.GetSeverity().GetLevel() != vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED {
			continue
		}
		g.Go(func() error {
			raw, rawType := osv.ResolveSeverityFromAliases(ctx, client, adv.GetAliases())
			if raw != "" {
				adv.Severity = vulnerability.NewSeverity(raw, rawType)
			}
			return nil
		})
	}
	_ = g.Wait()
}

// persistFixVerdicts writes each consolidated finding's resolved fix verdict
// back onto every advisory in its alias group, so the verdict crosses the
// proto boundary and is recovered when renderers re-consolidate.
func persistFixVerdicts(cons []vulnerability.Consolidated, advisories map[string]*vulnerabilityv1.Advisory) {
	for i := range cons {
		if cons[i].Fix == nil {
			continue
		}
		proto := cons[i].Fix.ToProto()
		for _, id := range cons[i].AllIDs {
			if adv, ok := advisories[id]; ok && adv != nil {
				adv.ResolvedFix = proto
			}
		}
	}
}

// queryVulnerabilities queries OSV for vulnerabilities and checks for
// supply-chain risks (e.g., unpinned GitHub Actions references).
func queryVulnerabilities(ctx context.Context, pkgs []*extractor.Package, direct map[string]bool, originURL string) ([]vulnerability.Finding, map[string]*vulnerabilityv1.Advisory, *vulnerabilityv1.ScanCoverage, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scanning.query_vulnerabilities",
		trace.WithAttributes(
			attribute.Int("deputy.package.count", len(pkgs)),
		))
	defer span.End()

	// Convert packages to OSV input format
	inputs := packagesToProto(pkgs, direct)

	// Query advisory sources (OSV today; more via the registry in future).
	// The registry routes each package only to sources that cover its ecosystem
	// and artifact kind, so an ecosystem no source covers is reported in
	// coverage rather than failing the scan.
	agg, err := advisorysource.NewDefaultRegistry(ctx, osv.NewClient()).Query(ctx, inputs)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, nil, nil, err
	}
	// Convert proto findings to domain at the consolidation boundary; supply-chain
	// findings below are already domain and append cleanly.
	findings, advisories := vulnerability.FindingsFromProto(agg.Findings), agg.Advisories

	// Check for supply-chain risks (unpinned actions, etc.)
	scFindings, scAdvisories := checkSupplyChain(ctx, pkgs, direct, forge.RepoSlugFromURL(originURL))
	if len(scFindings) > 0 {
		findings = append(findings, scFindings...)
		if advisories == nil {
			advisories = make(map[string]*vulnerabilityv1.Advisory)
		}
		maps.Copy(advisories, scAdvisories)
	}

	span.SetAttributes(attribute.Int("deputy.finding.count", len(findings)))
	return findings, advisories, agg.Coverage, nil
}

// packagesToProto converts extractor packages to the proto packages the
// advisory-source registry queries. A proto Package carries both the query
// coordinates (name/version/ecosystem/purl, possibly remapped for mise/asdf and
// language runtimes) and the scan context (direct/locations/manifest refs/layer
// details), so no separate query-input type is needed.
func packagesToProto(pkgs []*extractor.Package, direct map[string]bool) []*dependencyv1.Package {
	inputs := make([]*dependencyv1.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		purl := pkg.PURL()
		if purl == nil {
			continue
		}

		isDirect := false
		if purl.Type == "mise" || purl.Type == "asdf" {
			// Every mise/asdf tool is explicitly declared in its config, so it
			// is a direct dependency.
			isDirect = true
		} else if direct != nil {
			// For Go packages, check both exact module path and module root.
			// The direct map may contain:
			//   - Exact module paths with true (direct) or false (indirect)
			//   - Module roots with true (for subpackage matching)
			//
			// We first check the exact module path, then fall back to module root.
			// This handles Go submodules correctly: if go.mod has "foo" as direct
			// but "foo/loader" as indirect, "foo/loader" should be indirect.
			if purl.Type == "golang" {
				// Reconstruct module path from PURL namespace + name
				modulePath := pkg.Name
				if modulePath == "" {
					if purl.Namespace != "" {
						modulePath = purl.Namespace + "/" + purl.Name
					} else {
						modulePath = purl.Name
					}
				}
				// First check exact module path (handles submodules correctly)
				if val, exists := direct[modulePath]; exists {
					isDirect = val
				} else {
					// Fall back to module root for subpackage import paths
					moduleRoot := compare.GetModuleRoot(modulePath)
					isDirect = direct[moduleRoot]
				}
			} else {
				// For non-Go ecosystems, use PURL string as key
				isDirect = direct[purl.String()]
			}
		}

		locs := make([]string, len(pkg.Locations))
		copy(locs, pkg.Locations)

		// Build manifest references from locations
		var manifestRefs []*dependencyv1.ManifestRef
		for _, loc := range pkg.Locations {
			manager, manifestPath, ok := manifests.DetectManager(loc, pkg.PURLType)
			if !ok {
				continue
			}
			ref := &dependencyv1.ManifestRef{Path: manifestPath, Manager: manager}
			// For mise/asdf, record the tool key as declared in the config so
			// remediation targets the right entry even though the finding may be
			// reported under a remapped canonical name (e.g. "stdlib", "lodash").
			if manager == "mise" || manager == "asdf" {
				dependency.SetManifestRefComponentKey(ref, pkg.Name)
			}
			manifestRefs = append(manifestRefs, ref)
		}

		// Convert layer details from SCALIBR for container image scans.
		// Note: SCALIBR uses DiffID/ChainID (Go naming), we use DiffId/ChainId (proto naming).
		var layerDetails *containerv1.LayerDetails
		if pkg.LayerDetails != nil {
			layerDetails = &containerv1.LayerDetails{
				Index:       int32(pkg.LayerDetails.Index),
				DiffId:      pkg.LayerDetails.DiffID,
				ChainId:     pkg.LayerDetails.ChainID,
				Command:     pkg.LayerDetails.Command,
				InBaseImage: pkg.LayerDetails.InBaseImage,
			}
		}

		// mise/asdf tools carry a manager-level identity (pkg:mise / pkg:asdf)
		// that OSV does not index. For tools installed from a backend that maps
		// to a real packaging ecosystem (npm, cargo, pypi, gem, nuget), scan
		// against that canonical coordinate so OSV advisories are found, while
		// the package's own identity and locations are preserved. The exact
		// locked version (mise.lock) is preferred over a fuzzy declared one.
		// Prefer the exact locked version (mise.lock) when available on live
		// inventory; derivation otherwise works from the PURL alone so the same
		// resolution applies to SBOM-round-tripped components.
		scanVersion := pkg.Version
		if md, ok := pkg.Metadata.(*mise.Metadata); ok && md.LockedVersion != "" {
			scanVersion = md.LockedVersion
		}

		// mk builds a proto package for a query coordinate, carrying the shared
		// scan context (direct/locations/manifests/layer) for this inventory item.
		mk := func(name, version, eco, purlStr string) *dependencyv1.Package {
			return &dependencyv1.Package{
				Name:         name,
				Version:      version,
				Ecosystem:    eco,
				Purl:         purlStr,
				Direct:       isDirect,
				Locations:    locs,
				ManifestRefs: manifestRefs,
				LayerDetails: layerDetails,
			}
		}

		// Known language runtimes (e.g. the Go runtime) map to dedicated OSV
		// coordinates (Go stdlib/toolchain), which may be more than one query.
		if coords := mise.RuntimeScanCoords(purl.Type, pkg.Name, scanVersion); len(coords) > 0 {
			for _, c := range coords {
				inputs = append(inputs, mk(c.Name, c.Version, c.Ecosystem, c.PURL))
			}
			continue
		}

		qName := pkg.Name
		qVersion := pkg.Version
		qEcosystem := pkg.Ecosystem().String()
		qPURL := purl.String()
		// mise/asdf backend tools: scan against the backend's canonical ecosystem.
		if bp := mise.ScanPURL(purl.Type, pkg.Name, scanVersion); bp != "" {
			if pu, err := purlx.ParseLoose(bp); err == nil {
				qName = purlDisplayName(pu)
				qVersion = pu.Version
				qEcosystem = purlEcosystem(pu)
				qPURL = pu.String()
			}
		}

		inputs = append(inputs, mk(qName, qVersion, qEcosystem, qPURL))
	}
	return inputs
}
