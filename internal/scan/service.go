package scan

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/google/osv-scalibr/extractor"
	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/compare"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/vulnerability"
)

// Service orchestrates vulnerability scans by combining inventory collection and OSV lookups.
type Service struct {
	collectInventory     func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error)
	queryVulnerabilities func(ctx context.Context, client analysis.OSVClient, pkgs []analysis.PkgInput) ([]analysis.Vulnerability, error)
	osvClient            analysis.OSVClient
}

// ServiceConfig controls scan service dependencies.
type ServiceConfig struct {
	CollectInventory     func(ctx context.Context, repoPath, gitRef string, opts inv.ScanOptions) ([]*extractor.Package, error)
	QueryVulnerabilities func(ctx context.Context, client analysis.OSVClient, pkgs []analysis.PkgInput) ([]analysis.Vulnerability, error)
	OSVClient            analysis.OSVClient
}

// NewService returns a Service configured with default inventory collection and OSV querying.
func NewService() *Service {
	return NewServiceWithConfig(nil)
}

// NewServiceWithConfig returns a Service configured with explicit dependencies.
func NewServiceWithConfig(cfg *ServiceConfig) *Service {
	service := &Service{
		collectInventory:     collectInventory,
		queryVulnerabilities: analysis.QueryOSVBatch,
		osvClient:            analysis.NewOSVClient(),
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

func (s *Service) queryOSV(ctx context.Context, inputs []analysis.PkgInput) ([]analysis.Vulnerability, error) {
	query := s.queryVulnerabilities
	if query == nil {
		query = analysis.QueryOSVBatch
	}
	client := s.osvClient
	if client == nil {
		client = analysis.NewOSVClient()
	}
	return query(ctx, client, inputs)
}

// ScanRepository scans a repository target (local path or remote) for vulnerabilities.
func (s *Service) ScanRepository(ctx context.Context, repoArg, ref string, refProvided bool, opts Options) (*Execution, error) {
	target, err := resolveTarget(ctx, repoArg, ref)
	if err != nil {
		return nil, err
	}
	ref = target.ref

	effRef := refOrHEAD(ref)
	if strings.EqualFold(effRef, "HEAD") && refProvided {
		effRef = "HEAD~0"
	}

	pkgs, err := s.collectInventory(ctx, target.localRepoPath, effRef, inv.ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		target.cleanup()
		return nil, fmt.Errorf("failed to collect inventory: %w", err)
	}

	modInfo := resolveDirectModules(target.localRepoPath, effRef, target.workspace)
	inputs := PackagesToInputs(pkgs, PackageInputOptions{GoDirect: modInfo.goDirect, Resolver: modInfo.resolver})
	vulns, queryErr := s.queryOSV(ctx, inputs)

	result := buildResult(
		Target{
			DisplayPath:  target.displayPath,
			LocalPath:    target.localRepoPath,
			Ref:          ref,
			EffectiveRef: effRef,
			Cloned:       target.cloned,
		},
		pkgs,
		modInfo.goDirect,
		vulns,
		queryErr,
		opts,
	)
	result.Target.CommitHash, result.Target.OriginURL = getRepoMetadata(target.localRepoPath, ref)

	return &Execution{Result: result, cleanup: target.cleanup}, nil
}

// ScanDirectory scans a local directory for vulnerabilities without Git context.
func (s *Service) ScanDirectory(ctx context.Context, path string, opts Options) (*Execution, error) {
	ws, err := workspace.NewDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory: %w", err)
	}
	pkgs, err := inv.ScanPackagesWorking(ctx, ws, inv.ScanOptions{Ecosystems: opts.Ecosystems})
	if err != nil {
		_ = ws.Close()
		return nil, fmt.Errorf("failed to scan packages: %w", err)
	}

	goDirect := compare.CollectGoDirectModulesFromWorkspace(ws)
	inputs := PackagesToInputs(pkgs, PackageInputOptions{GoDirect: goDirect, Resolver: WorkspaceManifestResolver{ws: ws}})
	vulns, queryErr := s.queryOSV(ctx, inputs)

	result := buildResult(
		Target{DisplayPath: path, LocalPath: path},
		pkgs,
		goDirect,
		vulns,
		queryErr,
		opts,
	)

	return &Execution{
		Result:  result,
		cleanup: func() { _ = ws.Close() },
	}, nil
}

// ScanSBOM scans packages extracted from an SBOM document.
func (s *Service) ScanSBOM(ctx context.Context, pkgs []*extractor.Package, direct map[string]bool, opts Options) (*Execution, error) {
	inputs := PackagesToInputs(pkgs, PackageInputOptions{DirectPackages: direct})
	vulns, queryErr := s.queryOSV(ctx, inputs)

	result := buildResult(
		Target{DisplayPath: "sbom"},
		pkgs,
		direct,
		vulns,
		queryErr,
		opts,
	)

	return &Execution{Result: result}, nil
}

func buildResult(target Target, pkgs []*extractor.Package, direct map[string]bool, vulns []analysis.Vulnerability, queryErr error, opts Options) Result {
	warnings := []string{}
	if queryErr != nil {
		warnings = append(warnings, fmt.Sprintf("OSV query failed: %v", queryErr))
	}
	if !opts.PublishedBefore.IsZero() || !opts.PublishedAfter.IsZero() {
		vulns = analysis.FilterVulnerabilitiesByPublished(vulns, opts.PublishedAfter, opts.PublishedBefore)
	}

	findings, advisories := splitLegacyVulnerabilities(vulns)
	cons := vulnerability.Consolidate(findings, advisories)
	stats := vulnerability.StatsFromConsolidated(cons, len(findings))

	return Result{
		Target:          target,
		GeneratedAt:     time.Now().UTC(),
		PackagesScanned: len(pkgs),
		Inventory: Inventory{
			Packages: pkgs,
			Direct:   direct,
		},
		Findings:   findings,
		Advisories: advisories,
		Stats:      stats,
		Warnings:   warnings,
	}
}
