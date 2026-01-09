package proto

import (
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/dependency"
	"github.com/picatz/deputy/internal/scan"
	"github.com/picatz/deputy/internal/vulnerability"
)

// TargetToProto converts internal scan.Target to proto Target.
func TargetToProto(t scan.Target) *targetv1.Target {
	return &targetv1.Target{
		Kind:         targetv1.TargetKind(t.Kind),
		DisplayPath:  t.DisplayPath,
		LocalPath:    t.LocalPath,
		Ref:          t.Ref,
		EffectiveRef: t.EffectiveRef,
		CommitHash:   t.CommitHash,
		OriginUrl:    t.OriginURL,
		Cloned:       t.Cloned,
		Provenance:   t.Provenance,
	}
}

// TargetFromProto converts proto Target to internal scan.Target.
func TargetFromProto(t *targetv1.Target) scan.Target {
	if t == nil {
		return scan.Target{}
	}
	return scan.Target{
		Kind:         targetv1.TargetKind(t.Kind),
		DisplayPath:  t.DisplayPath,
		LocalPath:    t.LocalPath,
		Ref:          t.Ref,
		EffectiveRef: t.EffectiveRef,
		CommitHash:   t.CommitHash,
		OriginURL:    t.OriginUrl,
		Cloned:       t.Cloned,
		Provenance:   t.Provenance,
	}
}

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

// ScanOptionsFromProto converts proto ScanOptions to internal scan.Options.
func ScanOptionsFromProto(o *scanv1.ScanOptions) scan.Options {
	if o == nil {
		return scan.Options{}
	}

	opts := scan.Options{
		Ecosystems: o.Ecosystems,
		Platform:   o.Platform,
	}

	if o.PublishedBefore != nil {
		opts.PublishedBefore = o.PublishedBefore.AsTime()
	}
	if o.PublishedAfter != nil {
		opts.PublishedAfter = o.PublishedAfter.AsTime()
	}

	if o.GraphOptions != nil {
		opts.Graph = scan.GraphOptions{
			Enabled:         o.GraphOptions.Enabled,
			UseProxy:        o.GraphOptions.UseProxy,
			UseGit:          o.GraphOptions.UseGit,
			PrivatePatterns: o.GraphOptions.PrivatePatterns,
		}
	}

	if o.TargetHint != nil {
		opts.TargetHint = scan.TargetHint{
			Kind:           targetv1.TargetKind(o.TargetHint.Kind),
			ImageTransport: o.TargetHint.ImageTransport,
		}
	}

	return opts
}

// ScanOptionsToProto converts internal scan.Options to proto ScanOptions.
func ScanOptionsToProto(o scan.Options) *scanv1.ScanOptions {
	opts := &scanv1.ScanOptions{
		Ecosystems: o.Ecosystems,
		Platform:   o.Platform,
	}

	if !o.PublishedBefore.IsZero() {
		opts.PublishedBefore = timestamppb.New(o.PublishedBefore)
	}
	if !o.PublishedAfter.IsZero() {
		opts.PublishedAfter = timestamppb.New(o.PublishedAfter)
	}

	if o.Graph.Enabled {
		opts.GraphOptions = &scanv1.GraphOptions{
			Enabled:         o.Graph.Enabled,
			UseProxy:        o.Graph.UseProxy,
			UseGit:          o.Graph.UseGit,
			PrivatePatterns: o.Graph.PrivatePatterns,
		}
	}

	return opts
}

// ScanResultToProto converts internal scan.Result to proto ScanResponse.
func ScanResultToProto(r *scan.Result) *scanv1.ScanResponse {
	if r == nil {
		return nil
	}

	return &scanv1.ScanResponse{
		Target:          TargetToProto(r.Target),
		GeneratedAt:     timestamppb.New(r.GeneratedAt),
		PackagesScanned: int32(r.PackagesScanned),
		Findings:        FindingsToProto(r.Findings, r.Advisories),
		Advisories:      AdvisoriesToProto(r.Advisories),
		Stats:           StatsToProto(r.Stats),
		Warnings:        r.Warnings,
		ImageInfo:       ImageInfoToScanProto(r.ImageInfo),
		Graph:           DependencyGraphToScanProto(r.Graph),
		DockerfileInfo:  DockerfileInfoToProto(r.DockerfileInfo),
	}
}

// ScanResultFromProto converts proto ScanResponse to internal scan.Result.
func ScanResultFromProto(r *scanv1.ScanResponse) *scan.Result {
	if r == nil {
		return nil
	}

	var generatedAt time.Time
	if r.GeneratedAt != nil {
		generatedAt = r.GeneratedAt.AsTime()
	}

	return &scan.Result{
		Target:          TargetFromProto(r.Target),
		GeneratedAt:     generatedAt,
		PackagesScanned: int(r.PackagesScanned),
		Findings:        FindingsFromProto(r.Findings),
		Advisories:      AdvisoriesFromProto(r.Advisories),
		Stats:           StatsFromProto(r.Stats),
		Warnings:        r.Warnings,
		ImageInfo:       ImageInfoFromScanProto(r.ImageInfo),
		Graph:           DependencyGraphFromScanProto(r.Graph),
		DockerfileInfo:  DockerfileInfoFromProto(r.DockerfileInfo),
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
