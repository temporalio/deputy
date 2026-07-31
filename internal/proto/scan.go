package proto

import (
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// PackageToProto converts internal finding data to proto Package.
func PackageToProto(f vulnerability.Finding) *dependencyv1.Package {
	return &dependencyv1.Package{
		Name:         f.Dependency.Name,
		Ecosystem:    f.Dependency.Ecosystem,
		Purl:         f.Dependency.PURL,
		Version:      f.Version,
		Direct:       f.Direct,
		Locations:    f.Locations,
		ManifestRefs: ManifestRefsToProto(f.ManifestRefs),
		LayerDetails: LayerDetailsToProto(f.LayerDetails),
	}
}

// FindingToProto converts internal vulnerability.Finding to proto Finding.
func FindingToProto(f vulnerability.Finding, advisory *vulnerabilityv1.Advisory) *vulnerabilityv1.Finding {
	pb := &vulnerabilityv1.Finding{
		AdvisoryId:      f.AdvisoryID,
		Package:         PackageToProto(f),
		Affected:        f.Affected,
		AffectedImports: AffectedImportsToProto(f.AffectedImports),
		Sources:         f.Sources,
		// Enrichment fields
		Epss:           f.EPSS,
		EpssPercentile: f.EPSSPercentile,
		InKev:          f.InKEV,
	}

	if advisory != nil {
		pb.Advisory = advisory
	}

	return pb
}

// FindingFromProto converts proto Finding to internal vulnerability.Finding.
// The conversion lives in internal/vulnerability (with the Finding type) so it
// is reusable without importing this package; this is a thin re-export.
func FindingFromProto(f *vulnerabilityv1.Finding) vulnerability.Finding {
	return vulnerability.FindingFromProto(f)
}

// FindingsToProto converts a slice of internal Findings to proto.
func FindingsToProto(findings []vulnerability.Finding, advisories map[string]*vulnerabilityv1.Advisory) []*vulnerabilityv1.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]*vulnerabilityv1.Finding, len(findings))
	for i, f := range findings {
		out[i] = FindingToProto(f, advisories[f.AdvisoryID])
	}
	return out
}

// FindingsFromProto converts a slice of proto Finding to internal. Thin
// re-export of vulnerability.FindingsFromProto (the single source of truth).
func FindingsFromProto(findings []*vulnerabilityv1.Finding) []vulnerability.Finding {
	return vulnerability.FindingsFromProto(findings)
}

// AdvisoriesToProto converts a map of internal advisories to proto.
// Since internal advisories are now pointers, this is essentially a pass-through.
func AdvisoriesToProto(advisories map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
	return advisories
}

// AdvisoriesFromProto converts a map of proto advisories to internal.
// Since internal advisories are now pointers, this is essentially a pass-through.
func AdvisoriesFromProto(advisories map[string]*vulnerabilityv1.Advisory) map[string]*vulnerabilityv1.Advisory {
	return advisories
}

// ScanningResultToProto converts scanning.Result to proto ScanResponse.
// This is used by handlers that use the scanning package directly.
func ScanningResultToProto(r *scanning.Result) *scanv1.ScanResponse {
	if r == nil {
		return nil
	}

	// Calculate stats from findings using consolidation
	stats := vulnerability.ConsolidateAll(r.Findings, r.Advisories).Stats

	// Use PackagesScanned if set (survives proto round-trips), else fall back to len(Packages)
	pkgCount := r.PackagesScanned
	if pkgCount == 0 && len(r.Packages) > 0 {
		pkgCount = len(r.Packages)
	}

	return &scanv1.ScanResponse{
		Target:          InventoryTargetToProto(r.Target),
		GeneratedAt:     timestamppb.New(r.GeneratedAt),
		PackagesScanned: int32(pkgCount),
		Packages:        ExtractorPackagesToProto(r.Packages, r.Direct),
		Findings:        FindingsToProto(r.Findings, r.Advisories),
		Advisories:      AdvisoriesToProto(r.Advisories),
		Stats:           StatsToProto(stats),
		Coverage:        r.Coverage,
		Graph:           DependencyGraphToScanProto(r.Graph),
		ImageInfo:       ImageInfoToScanProto(r.ImageInfo),
		DockerfileInfo:  DockerfileInfoWithAnalysisToProto(r.DockerfileInfo, r.DockerfileAnalysis),
		Warnings:        r.Warnings,
	}
}

// ScanningResultFromProto converts proto ScanResponse to scanning.Result.
// This enables CLI commands to work directly with the scanning package.
func ScanningResultFromProto(r *scanv1.ScanResponse) *scanning.Result {
	if r == nil {
		return nil
	}

	var generatedAt time.Time
	if r.GeneratedAt != nil {
		generatedAt = r.GeneratedAt.AsTime()
	}

	findings := FindingsFromProto(r.Findings)
	advisories := AdvisoriesFromProto(r.Advisories)
	stats := StatsFromProto(r.Stats)
	packages, direct := ExtractorPackagesFromProto(r.Packages)

	return &scanning.Result{
		Target:             InventoryTargetFromProto(r.Target),
		Packages:           packages,
		PackagesScanned:    int(r.PackagesScanned),
		Direct:             direct,
		Findings:           findings,
		Advisories:         advisories,
		Stats:              stats,
		Coverage:           r.Coverage,
		Graph:              DependencyGraphFromScanProto(r.Graph),
		ImageInfo:          ImageInfoFromScanProto(r.ImageInfo),
		DockerfileInfo:     DockerfileInfoFromProto(r.DockerfileInfo),
		DockerfileAnalysis: DockerfileAnalysisFromProtoNested(r.DockerfileInfo),
		Warnings:           r.Warnings,
		GeneratedAt:        generatedAt,
	}
}

// StatsToProto converts domain Stats (vulnerabilityv1) to proto Stats.
func StatsToProto(s *vulnerabilityv1.Stats) *vulnerabilityv1.Stats {
	if s == nil {
		return nil
	}
	return proto.Clone(s).(*vulnerabilityv1.Stats)
}

// StatsFromProto converts proto Stats to domain Stats. To preserve the
// never-nil invariant for renderers, a nil input yields an empty Stats.
func StatsFromProto(s *vulnerabilityv1.Stats) *vulnerabilityv1.Stats {
	if s == nil {
		return &vulnerabilityv1.Stats{}
	}
	return s
}
