package proto

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/policy"
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
func FindingFromProto(f *vulnerabilityv1.Finding) vulnerability.Finding {
	if f == nil {
		return vulnerability.Finding{}
	}

	finding := vulnerability.Finding{
		AdvisoryID:      f.AdvisoryId,
		Affected:        f.Affected,
		AffectedImports: AffectedImportsFromProto(f.AffectedImports),
		// Enrichment fields
		EPSS:           f.Epss,
		EPSSPercentile: f.EpssPercentile,
		InKEV:          f.InKev,
	}

	if f.Package != nil {
		finding.Dependency = dependency.ID{
			Name:      f.Package.Name,
			Ecosystem: f.Package.Ecosystem,
			PURL:      f.Package.Purl,
		}
		finding.Version = f.Package.Version
		finding.Direct = f.Package.Direct
		finding.Locations = f.Package.Locations
		finding.ManifestRefs = ManifestRefsFromProto(f.Package.ManifestRefs)
		finding.LayerDetails = LayerDetailsFromProto(f.Package.LayerDetails)
	}

	return finding
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

// FindingsFromProto converts a slice of proto Finding to internal.
func FindingsFromProto(findings []*vulnerabilityv1.Finding) []vulnerability.Finding {
	if len(findings) == 0 {
		return nil
	}
	out := make([]vulnerability.Finding, len(findings))
	for i, f := range findings {
		out[i] = FindingFromProto(f)
	}
	return out
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
		Findings:        FindingsToProto(r.Findings, r.Advisories),
		Advisories:      AdvisoriesToProto(r.Advisories),
		Stats:           StatsToProto(stats),
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

	return &scanning.Result{
		Target:             InventoryTargetFromProto(r.Target),
		Packages:           nil, // Not in proto response
		PackagesScanned:    int(r.PackagesScanned),
		Direct:             nil, // Not in proto response
		Findings:           findings,
		Advisories:         advisories,
		Stats:              stats,
		ImageInfo:          ImageInfoFromScanProto(r.ImageInfo),
		DockerfileInfo:     DockerfileInfoFromProto(r.DockerfileInfo),
		DockerfileAnalysis: DockerfileAnalysisFromProtoNested(r.DockerfileInfo),
		Warnings:           r.Warnings,
		GeneratedAt:        generatedAt,
	}
}

// StatsToProto converts domain Stats (vulnerabilityv1) to proto Stats.
func StatsToProto(s vulnerabilityv1.Stats) *vulnerabilityv1.Stats {
	return &vulnerabilityv1.Stats{
		Total:        s.Total,
		Unique:       s.Unique,
		Critical:     s.Critical,
		High:         s.High,
		Medium:       s.Medium,
		Low:          s.Low,
		Unknown:      s.Unknown,
		FixAvailable: s.FixAvailable,
		DirectDeps:   s.DirectDeps,
		IndirectDeps: s.IndirectDeps,
	}
}

// StatsFromProto converts proto Stats to domain Stats.
func StatsFromProto(s *vulnerabilityv1.Stats) vulnerabilityv1.Stats {
	if s == nil {
		return vulnerabilityv1.Stats{}
	}
	return *s
}

// PolicyActionsToProto converts internal policy.Action slice to proto Action slice.
func PolicyActionsToProto(actions []policy.Action) []*policyv1.Action {
	if len(actions) == 0 {
		return nil
	}
	out := make([]*policyv1.Action, len(actions))
	for i, a := range actions {
		out[i] = &policyv1.Action{
			Type:        policyActionTypeToProto(a.Type),
			PolicyName:  a.Source,
			RuleName:    "", // internal Action doesn't have a separate rule name
			Reason:      a.Reason,
			Remediation: a.Remediation,
		}
	}
	return out
}

// policyActionTypeToProto converts action type string to proto enum.
func policyActionTypeToProto(actionType string) policyv1.ActionType {
	switch strings.ToLower(actionType) {
	case "deny":
		return policyv1.ActionType_ACTION_TYPE_DENY
	case "warn":
		return policyv1.ActionType_ACTION_TYPE_WARN
	case "allow":
		return policyv1.ActionType_ACTION_TYPE_ALLOW
	default:
		return policyv1.ActionType_ACTION_TYPE_UNSPECIFIED
	}
}
