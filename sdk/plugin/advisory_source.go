package plugin

import (
	"context"

	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	"github.com/temporalio/deputy/gen/deputy/plugin/v1/pluginv1pluginrpc"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"pluginrpc.com/pluginrpc"
)

// Type aliases so advisory-source plugin authors can use plugin.* types without
// importing the generated proto packages directly.
type (
	// AdvisorySourceInfo describes a source's identity and declared coverage.
	AdvisorySourceInfo = pluginv1.AdvisorySourceInfo
	// SourceCapabilities declares the ecosystems, artifacts, and finding kinds a
	// source can answer for.
	SourceCapabilities = pluginv1.SourceCapabilities
	// Finding is a per-package advisory occurrence.
	Finding = vulnerabilityv1.Finding
	// Advisory is a full advisory record.
	Advisory = vulnerabilityv1.Advisory
	// ArtifactKind classifies what a source is asked about (package, os package…).
	ArtifactKind = vulnerabilityv1.ArtifactKind
	// FindingKind distinguishes vulnerabilities from malware.
	FindingKind = vulnerabilityv1.FindingKind
)

// Enum value constants re-exported so plugin authors declare capabilities and
// finding kinds without importing the generated proto packages.
const (
	ArtifactKindPackage           = vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_PACKAGE
	ArtifactKindOSPackage         = vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_OS_PACKAGE
	ArtifactKindContainerImageRef = vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_CONTAINER_IMAGE_REF
	ArtifactKindGitHubAction      = vulnerabilityv1.ArtifactKind_ARTIFACT_KIND_GITHUB_ACTION

	FindingKindVulnerability = vulnerabilityv1.FindingKind_FINDING_KIND_VULNERABILITY
	FindingKindMalware       = vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE
)

// AdvisorySource is the interface advisory-source plugins implement to provide
// vulnerability/malware intelligence for a set of packages. Deputy invokes it
// via pluginrpc (subprocess) and aggregates its results with other sources
// (union-with-provenance). Declare accurate Capabilities: Deputy routes only
// packages a source covers, and a source must ignore anything outside its
// declared coverage rather than erroring.
type AdvisorySource interface {
	// Info returns the source's identity and declared coverage.
	Info() *AdvisorySourceInfo
	// Query returns the advisories affecting the supplied packages, as findings
	// plus the full advisory records keyed by advisory ID.
	Query(ctx context.Context, packages []*Package) (findings []*Finding, advisories map[string]*Advisory, err error)
}

// MainAdvisorySource is the entry point for advisory-source plugins. Call it
// from main() with your AdvisorySource implementation:
//
//	func main() {
//	    plugin.MainAdvisorySource(&mySource{})
//	}
func MainAdvisorySource(source AdvisorySource) {
	pluginrpc.Main(func() (pluginrpc.Server, error) {
		return newAdvisorySourceServer(source)
	})
}

func newAdvisorySourceServer(source AdvisorySource) (pluginrpc.Server, error) {
	spec, err := pluginv1pluginrpc.AdvisorySourceServiceSpecBuilder{
		Info:  []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("info")},
		Query: []pluginrpc.ProcedureOption{pluginrpc.ProcedureWithArgs("query")},
	}.Build()
	if err != nil {
		return nil, err
	}

	serverRegistrar := pluginrpc.NewServerRegistrar()
	handler := pluginrpc.NewHandler(spec)
	sourceHandler := &advisorySourceHandlerAdapter{source: source}
	server := pluginv1pluginrpc.NewAdvisorySourceServiceServer(handler, sourceHandler)
	pluginv1pluginrpc.RegisterAdvisorySourceServiceServer(serverRegistrar, server)

	return pluginrpc.NewServer(spec, serverRegistrar)
}

// advisorySourceHandlerAdapter adapts the AdvisorySource interface to the
// generated pluginrpc handler.
type advisorySourceHandlerAdapter struct {
	source AdvisorySource
}

func (a *advisorySourceHandlerAdapter) Info(_ context.Context, _ *pluginv1.AdvisorySourceInfoRequest) (*pluginv1.AdvisorySourceInfoResponse, error) {
	return &pluginv1.AdvisorySourceInfoResponse{Info: a.source.Info()}, nil
}

func (a *advisorySourceHandlerAdapter) Query(ctx context.Context, req *pluginv1.AdvisoryQueryRequest) (*pluginv1.AdvisoryQueryResponse, error) {
	findings, advisories, err := a.source.Query(ctx, req.GetPackages())
	if err != nil {
		return nil, err
	}
	return &pluginv1.AdvisoryQueryResponse{Findings: findings, Advisories: advisories}, nil
}
