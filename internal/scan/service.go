package scan

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/dependency/graph"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/logs"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/targets"
	"github.com/picatz/deputy/internal/targets/providers"
	"github.com/picatz/deputy/internal/vulnerability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// Scanner defines the interface for vulnerability scanning operations.
// This interface enables dependency injection and testing of scan consumers.
type Scanner interface {
	// ScanRepository scans a repository target (local path or remote) for vulnerabilities.
	ScanRepository(ctx context.Context, repoArg, ref string, refProvided bool, opts Options) (*Execution, error)

	// ScanDirectory scans a local directory for vulnerabilities.
	ScanDirectory(ctx context.Context, path string, opts Options) (*Execution, error)

	// ScanSBOM scans pre-extracted packages for vulnerabilities.
	ScanSBOM(ctx context.Context, pkgs []*extractor.Package, direct map[string]bool, opts Options) (*Execution, error)

	// ScanContainerImage scans a container image for vulnerabilities.
	ScanContainerImage(ctx context.Context, target string, targetOpts map[string]string, opts Options) (*Execution, error)

	// ScanDockerfile scans images referenced in a Dockerfile.
	ScanDockerfile(ctx context.Context, target string, opts Options) (*Execution, error)

	// ScanPURL scans a single package URL for vulnerabilities.
	ScanPURL(ctx context.Context, purlStr string, opts Options) (*Execution, error)
}

// Ensure Service implements Scanner at compile time.
var _ Scanner = (*Service)(nil)

// Service orchestrates vulnerability scans by combining inventory collection and OSV lookups.
type Service struct {
	collectInventory     func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error)
	queryVulnerabilities func(ctx context.Context, client osv.Client, pkgs []osv.PkgInput) ([]vulnerability.Finding, map[string]vulnerability.Advisory, error)
	osvClient            osv.Client
}

// ServiceConfig controls scan service dependencies.
type ServiceConfig struct {
	CollectInventory     func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error)
	QueryVulnerabilities func(ctx context.Context, client osv.Client, pkgs []osv.PkgInput) ([]vulnerability.Finding, map[string]vulnerability.Advisory, error)
	OSVClient            osv.Client
}

// NewService returns a Service configured with default inventory collection and OSV querying.
func NewService() *Service {
	return NewServiceWithConfig(nil)
}

// NewServiceWithConfig returns a Service configured with explicit dependencies.
func NewServiceWithConfig(cfg *ServiceConfig) *Service {
	service := &Service{
		collectInventory:     collectInventory,
		queryVulnerabilities: osv.Query,
		osvClient:            osv.NewClient(),
	}
	if cfg == nil {
		return service
	}
	if cfg.CollectInventory != nil {
		service.collectInventory = cfg.CollectInventory
	}
	if cfg.QueryVulnerabilities != nil {
		service.queryVulnerabilities = cfg.QueryVulnerabilities
	}
	if cfg.OSVClient != nil {
		service.osvClient = cfg.OSVClient
	}
	return service
}

func (s *Service) queryOSV(ctx context.Context, inputs []osv.PkgInput) ([]vulnerability.Finding, map[string]vulnerability.Advisory, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.scan.query_vulnerabilities",
		trace.WithAttributes(
			attribute.Int("deputy.osv.batch_size", len(inputs)),
		))
	defer span.End()

	query := s.queryVulnerabilities
	if query == nil {
		query = osv.Query
	}
	client := s.osvClient
	if client == nil {
		client = osv.NewClient()
	}
	findings, advisories, err := query(ctx, client, inputs)
	if err != nil {
		otel.SetSpanError(span, err)
	} else {
		span.SetAttributes(attribute.Int("deputy.vuln.count", len(findings)))
	}
	return findings, advisories, err
}

// ScanRepository scans a repository target (local path or remote) for vulnerabilities.
func (s *Service) ScanRepository(ctx context.Context, repoArg, ref string, refProvided bool, opts Options) (*Execution, error) {
	startTime := time.Now()
	ctx, span := otel.StartSpan(ctx, "deputy.scan.repository",
		trace.WithAttributes(
			attribute.String("deputy.target.path", repoArg),
			attribute.String("deputy.target.ref", ref),
		))
	defer span.End()

	logs.Info(ctx, "starting repository scan", "target", repoArg, "ref", ref)

	target, err := resolveTarget(ctx, repoArg, ref)
	if err != nil {
		logs.Error(ctx, "failed to resolve target", "error", err)
		otel.SetSpanError(span, err)
		return nil, err
	}
	ref = target.ref
	span.SetAttributes(attribute.Bool("deputy.target.remote", target.cloned))

	effRef := refOrHEAD(ref)
	if strings.EqualFold(effRef, "HEAD") && refProvided {
		effRef = "HEAD~0"
	}

	// Collect inventory with tracing
	logs.Debug(ctx, "collecting package inventory", "path", target.localRepoPath, "ref", effRef)
	inventoryCtx, inventorySpan := otel.StartSpan(ctx, "deputy.scan.collect_inventory")
	pkgs, err := s.collectInventory(inventoryCtx, target.localRepoPath, effRef, inv.ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		logs.Error(ctx, "failed to collect inventory", "error", err)
		otel.SetSpanError(inventorySpan, err)
		inventorySpan.End()
		target.cleanup()
		return nil, fmt.Errorf("failed to collect inventory: %w", err)
	}
	inventorySpan.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))
	inventorySpan.End()
	logs.Info(ctx, "collected package inventory", "package_count", len(pkgs))

	modInfo := resolveDirectModules(target.localRepoPath, effRef, target.workspace)
	inputs := PackagesToInputs(pkgs, PackageInputOptions{GoDirect: modInfo.goDirect, Resolver: modInfo.resolver})
	logs.Debug(ctx, "querying OSV for vulnerabilities", "input_count", len(inputs))
	findings, advisories, queryErr := s.queryOSV(ctx, inputs)

	// Build dependency graph if enabled
	var depGraph *graph.Graph
	if opts.Graph.Enabled {
		builder := NewGraphBuilder(opts.Graph)
		depGraph, _ = builder.BuildFromWorkspace(ctx, pkgs, modInfo.goDirect, findings, advisories, target.workspace)
	}

	result := buildResult(buildResultInput{
		target: Target{
			Kind:         target.kind,
			DisplayPath:  target.displayPath,
			LocalPath:    target.localRepoPath,
			Ref:          ref,
			EffectiveRef: effRef,
			Cloned:       target.cloned,
			Provenance:   target.mat.Meta.Provenance,
		},
		pkgs:       pkgs,
		direct:     modInfo.goDirect,
		findings:   findings,
		advisories: advisories,
		queryErr:   queryErr,
		opts:       opts,
		graph:      depGraph,
	})
	result.Target.CommitHash, result.Target.OriginURL = getRepoMetadata(target.localRepoPath, ref)

	// Record scan completion (both span and metrics)
	otel.RecordScanCompletion(ctx, otel.ScanCompletion{
		Span:         span,
		Duration:     time.Since(startTime).Seconds(),
		Ecosystem:    "go",
		PackageCount: result.PackagesScanned,
		Severity: otel.SeverityCounts{
			Critical: result.Stats.CriticalSev,
			High:     result.Stats.HighSeverity,
			Medium:   result.Stats.MedSeverity,
			Low:      result.Stats.LowSeverity,
		},
	})

	logs.Info(ctx, "scan completed",
		"packages_scanned", result.PackagesScanned,
		"vulnerabilities_found", result.Stats.UniqueVulns,
		"critical", result.Stats.CriticalSev,
		"high", result.Stats.HighSeverity,
		"medium", result.Stats.MedSeverity,
		"low", result.Stats.LowSeverity,
		"duration_seconds", time.Since(startTime).Seconds(),
	)

	return &Execution{Result: result, cleanup: target.cleanup}, nil
}

// ScanDirectory scans a local directory for vulnerabilities without Git context.
func (s *Service) ScanDirectory(ctx context.Context, path string, opts Options) (*Execution, error) {
	startTime := time.Now()
	ctx, span := otel.StartSpan(ctx, "deputy.scan.directory",
		trace.WithAttributes(
			attribute.String("deputy.target.path", path),
		))
	defer span.End()

	ws, err := workspace.NewDir(path)
	if err != nil {
		otel.SetSpanError(span, err)
		return nil, fmt.Errorf("failed to open directory: %w", err)
	}
	pkgs, err := inv.ScanPackagesWorking(ctx, ws, inv.ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		otel.SetSpanError(span, err)
		_ = ws.Close()
		return nil, fmt.Errorf("failed to scan packages: %w", err)
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	goDirect := compare.CollectGoDirectModulesFromWorkspace(ws)
	inputs := PackagesToInputs(pkgs, PackageInputOptions{GoDirect: goDirect, Resolver: NewWorkspaceManifestResolver(ws)})
	findings, advisories, queryErr := s.queryOSV(ctx, inputs)

	// Build dependency graph if enabled
	var depGraph *graph.Graph
	if opts.Graph.Enabled {
		builder := NewGraphBuilder(opts.Graph)
		depGraph, _ = builder.BuildFromWorkspace(ctx, pkgs, goDirect, findings, advisories, ws)
	}

	result := buildResult(buildResultInput{
		target:     Target{Kind: targets.KindDir, DisplayPath: path, LocalPath: path},
		pkgs:       pkgs,
		direct:     goDirect,
		findings:   findings,
		advisories: advisories,
		queryErr:   queryErr,
		opts:       opts,
		graph:      depGraph,
	})

	// Record scan completion (both span and metrics)
	otel.RecordScanCompletion(ctx, otel.ScanCompletion{
		Span:         span,
		Duration:     time.Since(startTime).Seconds(),
		Ecosystem:    "go",
		PackageCount: result.PackagesScanned,
		Severity: otel.SeverityCounts{
			Critical: result.Stats.CriticalSev,
			High:     result.Stats.HighSeverity,
			Medium:   result.Stats.MedSeverity,
			Low:      result.Stats.LowSeverity,
		},
	})

	return &Execution{
		Result:  result,
		cleanup: func() { _ = ws.Close() },
	}, nil
}

// ScanSBOM scans packages extracted from an SBOM document.
func (s *Service) ScanSBOM(ctx context.Context, pkgs []*extractor.Package, direct map[string]bool, opts Options) (*Execution, error) {
	startTime := time.Now()
	ctx, span := otel.StartSpan(ctx, "deputy.scan.sbom",
		trace.WithAttributes(
			attribute.Int("deputy.package.count", len(pkgs)),
		))
	defer span.End()

	inputs := PackagesToInputs(pkgs, PackageInputOptions{DirectPackages: direct})
	findings, advisories, queryErr := s.queryOSV(ctx, inputs)

	// Note: Graph resolution is not supported for SBOM scans since there's no
	// filesystem to parse lockfiles from. The SBOM itself should contain
	// dependency relationships if needed.
	result := buildResult(buildResultInput{
		target:     Target{Kind: targets.KindSBOM, DisplayPath: "sbom"},
		pkgs:       pkgs,
		direct:     direct,
		findings:   findings,
		advisories: advisories,
		queryErr:   queryErr,
		opts:       opts,
		graph:      nil,
	})

	// Record scan completion (both span and metrics)
	otel.RecordScanCompletion(ctx, otel.ScanCompletion{
		Span:         span,
		Duration:     time.Since(startTime).Seconds(),
		Ecosystem:    "sbom",
		PackageCount: result.PackagesScanned,
		Severity: otel.SeverityCounts{
			Critical: result.Stats.CriticalSev,
			High:     result.Stats.HighSeverity,
			Medium:   result.Stats.MedSeverity,
			Low:      result.Stats.LowSeverity,
		},
	})

	return &Execution{Result: result}, nil
}

// ScanContainerImage scans a container image target for vulnerabilities.
func (s *Service) ScanContainerImage(ctx context.Context, target string, targetOpts map[string]string, opts Options) (*Execution, error) {
	startTime := time.Now()
	ctx, span := otel.StartSpan(ctx, "deputy.scan.container_image",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
		))
	defer span.End()

	logs.Info(ctx, "starting container image scan", "target", target)

	mat, err := targets.Open(ctx, target, targetOpts)
	if err != nil {
		logs.Error(ctx, "failed to resolve container image target", "error", err)
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	// Extract scalibrimage.Image and optionally the v1.Image for config access
	var img scalibrimage.Image
	var imageInfo *image.Info
	var imageConfigWarning string

	switch data := mat.Data.(type) {
	case *providers.ContainerImageData:
		img = data
		// Extract image configuration if v1.Image is available
		if data.V1Image != nil {
			info, err := image.Extract(data.V1Image)
			if err != nil {
				slog.Debug("failed to extract image config", "target", target, "error", err)
				imageConfigWarning = fmt.Sprintf("image config extraction failed (policy evaluation may be limited): %v", err)
			} else {
				imageInfo = info
			}
		} else {
			slog.Debug("v1.Image not available, image config extraction skipped", "target", target)
		}
	case scalibrimage.Image:
		img = data
		// scalibrimage.Image doesn't expose config directly
		slog.Debug("image config extraction not supported for this image type", "target", target)
	default:
		cleanup()
		err := fmt.Errorf("target %q did not resolve to a container image", target)
		otel.SetSpanError(span, err)
		return nil, err
	}

	pkgs, err := inv.ScanPackagesContainerImage(ctx, img, inv.ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		cleanup()
		otel.SetSpanError(span, err)
		return nil, err
	}
	span.SetAttributes(attribute.Int("deputy.package.count", len(pkgs)))

	inputs := PackagesToInputs(pkgs, PackageInputOptions{})
	findings, advisories, queryErr := s.queryOSV(ctx, inputs)

	displayPath := target
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}

	// Note: Graph resolution is not supported for container image scans since
	// packages are extracted from the image filesystem, not from lockfiles.
	result := buildResult(buildResultInput{
		target: Target{
			Kind:        mat.Meta.Kind,
			DisplayPath: displayPath,
			LocalPath:   mat.Path,
			Provenance:  mat.Meta.Provenance,
		},
		pkgs:       pkgs,
		direct:     nil,
		findings:   findings,
		advisories: advisories,
		queryErr:   queryErr,
		opts:       opts,
		graph:      nil,
	})

	// Attach image configuration to result for policy evaluation
	result.ImageInfo = imageInfo

	// Add warning if image config extraction failed
	if imageConfigWarning != "" {
		result.Warnings = append(result.Warnings, imageConfigWarning)
	}

	otel.RecordScanCompletion(ctx, otel.ScanCompletion{
		Span:         span,
		Duration:     time.Since(startTime).Seconds(),
		Ecosystem:    string(targets.KindContainerImage),
		PackageCount: result.PackagesScanned,
		Severity: otel.SeverityCounts{
			Critical: result.Stats.CriticalSev,
			High:     result.Stats.HighSeverity,
			Medium:   result.Stats.MedSeverity,
			Low:      result.Stats.LowSeverity,
		},
	})

	return &Execution{Result: result, cleanup: cleanup}, nil
}

// ScanDockerfile scans a Dockerfile for policy evaluation (no vulnerability scanning).
// Dockerfiles don't contain packages directly - they reference images that contain packages.
// Use ScanContainerImage to scan the actual images referenced in the Dockerfile.
func (s *Service) ScanDockerfile(ctx context.Context, target string, opts Options) (*Execution, error) {
	startTime := time.Now()
	ctx, span := otel.StartSpan(ctx, "deputy.scan.dockerfile",
		trace.WithAttributes(
			attribute.String("deputy.target.path", target),
		))
	defer span.End()

	logs.Info(ctx, "starting dockerfile scan", "target", target)

	mat, err := targets.Open(ctx, target, nil)
	if err != nil {
		logs.Error(ctx, "failed to resolve dockerfile target", "error", err)
		otel.SetSpanError(span, err)
		return nil, err
	}

	cleanup := func() {}
	if mat.Cleanup != nil {
		cleanup = mat.Cleanup
	}

	data, ok := mat.Data.(*providers.DockerfileData)
	if !ok {
		cleanup()
		err := fmt.Errorf("target %q did not resolve to a dockerfile", target)
		otel.SetSpanError(span, err)
		return nil, err
	}

	displayPath := target
	if mat.Meta.Target != "" {
		displayPath = mat.Meta.Target
	}

	result := Result{
		Target: Target{
			Kind:        targets.KindDockerfile,
			DisplayPath: displayPath,
			LocalPath:   mat.Path,
		},
		GeneratedAt:        time.Now().UTC(),
		DockerfileInfo:     data.Info,
		DockerfileAnalysis: data.Analysis,
	}

	span.SetAttributes(
		attribute.Int("deputy.dockerfile.stage_count", len(data.Info.Stages)),
		attribute.Bool("deputy.dockerfile.multi_stage", data.Analysis.HasMultiStage),
	)

	logs.Info(ctx, "dockerfile scan completed",
		"stages", len(data.Info.Stages),
		"multi_stage", data.Analysis.HasMultiStage,
		"duration_seconds", time.Since(startTime).Seconds(),
	)

	return &Execution{Result: result, cleanup: cleanup}, nil
}

// buildResultInput holds all inputs for building a scan result.
// Using a struct avoids long parameter lists and makes it easier to extend.
type buildResultInput struct {
	target     Target
	pkgs       []*extractor.Package
	direct     map[string]bool
	findings   []vulnerability.Finding
	advisories map[string]vulnerability.Advisory
	queryErr   error
	opts       Options
	graph      *graph.Graph
}

func buildResult(in buildResultInput) Result {
	warnings := []string{}
	if in.queryErr != nil {
		warnings = append(warnings, fmt.Sprintf("OSV query failed: %v", in.queryErr))
	}
	if !in.opts.PublishedBefore.IsZero() || !in.opts.PublishedAfter.IsZero() {
		in.findings = filterFindingsByPublished(in.findings, in.advisories, in.opts.PublishedAfter, in.opts.PublishedBefore)
	}

	consolidated := vulnerability.ConsolidateAll(in.findings, in.advisories)

	return Result{
		Target:          in.target,
		GeneratedAt:     time.Now().UTC(),
		PackagesScanned: len(in.pkgs),
		Inventory: Inventory{
			Packages: in.pkgs,
			Direct:   in.direct,
		},
		Findings:   in.findings,
		Advisories: in.advisories,
		Stats:      consolidated.Stats,
		Graph:      in.graph,
		Warnings:   warnings,
	}
}
