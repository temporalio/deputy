package proto

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/picatz/deputy/gen/deputy/diff/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/vulnerability"
)

// ChangeKindToProto converts internal compare.ChangeType to proto diffv1.ChangeKind.
func ChangeKindToProto(ct compare.ChangeType) diffv1.ChangeKind {
	switch ct {
	case compare.Added:
		return diffv1.ChangeKind_CHANGE_KIND_ADDED
	case compare.Removed:
		return diffv1.ChangeKind_CHANGE_KIND_REMOVED
	case compare.Upgraded:
		return diffv1.ChangeKind_CHANGE_KIND_UPGRADED
	case compare.Downgraded:
		return diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED
	case compare.Updated:
		return diffv1.ChangeKind_CHANGE_KIND_UPDATED
	default:
		return diffv1.ChangeKind_CHANGE_KIND_UNSPECIFIED
	}
}

// ChangeKindFromProto converts proto diffv1.ChangeKind to internal compare.ChangeType.
func ChangeKindFromProto(ck diffv1.ChangeKind) compare.ChangeType {
	switch ck {
	case diffv1.ChangeKind_CHANGE_KIND_ADDED:
		return compare.Added
	case diffv1.ChangeKind_CHANGE_KIND_REMOVED:
		return compare.Removed
	case diffv1.ChangeKind_CHANGE_KIND_UPGRADED:
		return compare.Upgraded
	case diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED:
		return compare.Downgraded
	case diffv1.ChangeKind_CHANGE_KIND_UPDATED:
		return compare.Updated
	default:
		return compare.Updated
	}
}

// PackageChangeToProto converts an internal compare.Change to proto diffv1.PackageChange.
func PackageChangeToProto(c compare.Change) *diffv1.PackageChange {
	return &diffv1.PackageChange{
		Package: &dependencyv1.Package{
			Name:      c.Name,
			Version:   c.TargetVersion,
			Ecosystem: c.Ecosystem,
		},
		ChangeKind:    ChangeKindToProto(c.ChangeType),
		BaseVersion:   c.BaseVersion,
		TargetVersion: c.TargetVersion,
		OldName:       c.OldName,
		IsDirect:      c.IsDirect,
	}
}

// PackageChangeFromProto converts a proto diffv1.PackageChange to internal compare.Change.
func PackageChangeFromProto(pc *diffv1.PackageChange) compare.Change {
	if pc == nil {
		return compare.Change{}
	}
	c := compare.Change{
		ChangeType:    ChangeKindFromProto(pc.ChangeKind),
		BaseVersion:   pc.BaseVersion,
		TargetVersion: pc.TargetVersion,
		OldName:       pc.OldName,
		IsDirect:      pc.IsDirect,
	}
	if pc.Package != nil {
		c.Name = pc.Package.Name
		c.Ecosystem = pc.Package.Ecosystem
	}
	return c
}

// PackageChangesToProto converts a slice of internal changes to proto.
func PackageChangesToProto(changes []compare.Change) []*diffv1.PackageChange {
	if len(changes) == 0 {
		return nil
	}
	out := make([]*diffv1.PackageChange, len(changes))
	for i, c := range changes {
		out[i] = PackageChangeToProto(c)
	}
	return out
}

// PackageChangesFromProto converts proto PackageChanges to internal changes.
func PackageChangesFromProto(changes []*diffv1.PackageChange) []compare.Change {
	if len(changes) == 0 {
		return nil
	}
	out := make([]compare.Change, len(changes))
	for i, c := range changes {
		out[i] = PackageChangeFromProto(c)
	}
	return out
}

// DiffStatsToProto converts internal change counts to proto DiffStats.
func DiffStatsToProto(changes []compare.Change) *diffv1.DiffStats {
	stats := &diffv1.DiffStats{
		TotalChanges: int32(len(changes)),
	}
	for _, c := range changes {
		switch c.ChangeType {
		case compare.Added:
			stats.AddedCount++
		case compare.Removed:
			stats.RemovedCount++
		case compare.Upgraded:
			stats.UpgradedCount++
		case compare.Downgraded:
			stats.DowngradedCount++
		case compare.Updated:
			stats.UpdatedCount++
		}
	}
	return stats
}

// GitDiffReportToProto creates a DiffVulnerabilitiesResponse from git diff data.
// This is used for proto-first JSON output in the diff command.
func GitDiffReportToProto(
	repo, baseRef, targetRef string,
	changes []compare.Change,
	findings []vulnerability.Finding,
	advisories map[string]*vulnerabilityv1.Advisory,
) *diffv1.DiffVulnerabilitiesResponse {
	resp := &diffv1.DiffVulnerabilitiesResponse{
		BaseTarget: &targetv1.Target{
			DisplayPath: baseRef,
		},
		TargetTarget: &targetv1.Target{
			DisplayPath: targetRef,
		},
		GeneratedAt: timestamppb.Now(),
		Advisories:  advisories,
	}

	// All findings from the diff are considered "added" since we're scanning the target
	// The actual comparison logic is handled elsewhere
	protoFindings := make([]*vulnerabilityv1.Finding, 0, len(findings))
	for _, f := range findings {
		protoFindings = append(protoFindings, FindingToProto(f, advisories[f.AdvisoryID]))
	}
	resp.AddedVulnerabilities = protoFindings

	// Calculate stats
	resp.Stats = &diffv1.VulnerabilityDiffStats{
		AddedCount: int32(len(findings)),
	}

	return resp
}
