// Package scanning provides scan orchestration for vulnerability analysis.
// It combines inventory collection with OSV vulnerability queries, serving as
// the canonical place for scan logic used by proto handlers.
package scanning

import (
	"context"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	packageurl "github.com/package-url/packageurl-go"
	containerv1 "github.com/temporalio/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/container/image"
	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/dockerfile"
	"github.com/temporalio/deputy/internal/ecosystem"
	"github.com/temporalio/deputy/internal/inventory"
	"github.com/temporalio/deputy/internal/inventory/manifests"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/policy"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/vulnerability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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

	// Advisories maps advisory IDs to their full details.
	Advisories map[string]*vulnerabilityv1.Advisory

	// Stats contains vulnerability severity counts.
	Stats vulnerabilityv1.Stats

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
	invOpts := inventory.Options{Ecosystems: opts.Ecosystems}
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
	findings, advisories, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	stats := vulnerability.ConsolidateAll(findings, advisories).Stats

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Advisories:      advisories,
			Stats:           stats,
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
	findings, advisories, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	stats := vulnerability.ConsolidateAll(findings, advisories).Stats

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Advisories:      advisories,
			Stats:           stats,
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
	invOpts := inventory.Options{Ecosystems: opts.Ecosystems}
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
	findings, advisories, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	stats := vulnerability.ConsolidateAll(findings, advisories).Stats

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Advisories:      advisories,
			Stats:           stats,
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
	invOpts := inventory.Options{Ecosystems: opts.Ecosystems}
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
	findings, advisories, err := queryVulnerabilities(ctx, invExec.Result.Packages, invExec.Result.Direct)
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	stats := vulnerability.ConsolidateAll(findings, advisories).Stats

	return &Execution{
		Result: Result{
			Target:          invExec.Result.Target,
			Packages:        invExec.Result.Packages,
			PackagesScanned: len(invExec.Result.Packages),
			Direct:          invExec.Result.Direct,
			Findings:        findings,
			Advisories:      advisories,
			Stats:           stats,
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

	inputs := []osv.PkgInput{
		osv.NewPkgInput(
			osv.QueryKey{
				Name:      name,
				Version:   pu.Version,
				Ecosystem: ecos,
				PURL:      canonical,
			},
			osv.PackageContext{
				IsDirect: true,
			},
		),
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

	// Query OSV
	client := osv.NewClient()
	findings, advisories, err := osv.Query(ctx, client, inputs)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("query vulnerabilities: %w", err)
	}

	span.SetAttributes(attribute.Int("deputy.finding.count", len(findings)))

	stats := vulnerability.ConsolidateAll(findings, advisories).Stats

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
			Advisories:      advisories,
			Stats:           stats,
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

// queryVulnerabilities queries OSV for vulnerabilities and checks for
// supply-chain risks (e.g., unpinned GitHub Actions references).
func queryVulnerabilities(ctx context.Context, pkgs []*extractor.Package, direct map[string]bool) ([]vulnerability.Finding, map[string]*vulnerabilityv1.Advisory, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scanning.query_vulnerabilities",
		trace.WithAttributes(
			attribute.Int("deputy.package.count", len(pkgs)),
		))
	defer span.End()

	// Convert packages to OSV input format
	inputs := packagesToInputs(pkgs, direct)

	// Query OSV
	client := osv.NewClient()
	findings, advisories, err := osv.Query(ctx, client, inputs)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, nil, err
	}

	// Check for supply-chain risks (unpinned actions, etc.)
	scFindings, scAdvisories := checkSupplyChain(ctx, pkgs, direct)
	if len(scFindings) > 0 {
		findings = append(findings, scFindings...)
		if advisories == nil {
			advisories = make(map[string]*vulnerabilityv1.Advisory)
		}
		for id, adv := range scAdvisories {
			advisories[id] = adv
		}
	}

	span.SetAttributes(attribute.Int("deputy.finding.count", len(findings)))
	return findings, advisories, nil
}

// packagesToInputs converts extractor packages to OSV query inputs.
func packagesToInputs(pkgs []*extractor.Package, direct map[string]bool) []osv.PkgInput {
	inputs := make([]osv.PkgInput, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		purl := pkg.PURL()
		if purl == nil {
			continue
		}

		isDirect := false
		if direct != nil {
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
		for i, loc := range pkg.Locations {
			locs[i] = loc
		}

		// Build manifest references from locations
		var manifestRefs []dependencyv1.ManifestRef
		for _, loc := range pkg.Locations {
			manager, manifestPath, ok := manifests.DetectManager(loc, pkg.PURLType)
			if !ok {
				continue
			}
			manifestRefs = append(manifestRefs, dependencyv1.ManifestRef{
				Path:    manifestPath,
				Manager: manager,
			})
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

		inputs = append(inputs, osv.NewPkgInput(
			osv.QueryKey{
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: pkg.Ecosystem().String(),
				PURL:      purl.String(),
			},
			osv.PackageContext{
				IsDirect:     isDirect,
				Locations:    locs,
				ManifestRefs: manifestRefs,
				LayerDetails: layerDetails,
			},
		))
	}
	return inputs
}
