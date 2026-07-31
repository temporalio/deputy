package proto

import (
	"google.golang.org/protobuf/types/known/timestamppb"

	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	targetv1 "github.com/temporalio/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/compare"
)

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

// DiffStatsToProto summarizes dependency changes into proto DiffStats.
func DiffStatsToProto(changes []*diffv1.PackageChange) *diffv1.DiffStats {
	stats := &diffv1.DiffStats{
		TotalChanges: int32(len(changes)),
	}
	for _, c := range changes {
		switch c.GetChangeKind() {
		case diffv1.ChangeKind_CHANGE_KIND_ADDED:
			stats.AddedCount++
		case diffv1.ChangeKind_CHANGE_KIND_REMOVED:
			stats.RemovedCount++
		case diffv1.ChangeKind_CHANGE_KIND_UPGRADED:
			stats.UpgradedCount++
		case diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED:
			stats.DowngradedCount++
		case diffv1.ChangeKind_CHANGE_KIND_UPDATED:
			stats.UpdatedCount++
		}
	}
	return stats
}

// GitDiffReportToProto creates a DiffVulnerabilitiesResponse from git diff
// data. This is the `deputy diff --format json` output contract: it carries
// the dependency changes, the introduced and unchanged vulnerability sets,
// and structured policy results so consumers never parse rendered text.
//
// Added must contain only vulnerabilities the change set introduced (the same
// set the rendered report counts as new); unchanged carries the rest.
//
// RemovedVulnerabilities is left unset here: the CLI partitions target-side
// findings and never enumerates base-only ones, so it cannot fill the set the
// server handler does. See #135.
func GitDiffReportToProto(
	repo, baseRef, targetRef string,
	changes []*diffv1.PackageChange,
	added, unchanged []*vulnerabilityv1.Finding,
	advisories map[string]*vulnerabilityv1.Advisory,
	policyActions []*policyv1.Action,
	policyFilesEvaluated int,
) *diffv1.DiffVulnerabilitiesResponse {
	return &diffv1.DiffVulnerabilitiesResponse{
		BaseTarget: &targetv1.Target{
			DisplayPath: baseRef,
		},
		TargetTarget: &targetv1.Target{
			DisplayPath: targetRef,
		},
		GeneratedAt:              timestamppb.Now(),
		Advisories:               advisories,
		Changes:                  changes,
		ChangeStats:              DiffStatsToProto(changes),
		AddedVulnerabilities:     added,
		UnchangedVulnerabilities: unchanged,
		Stats: &diffv1.VulnerabilityDiffStats{
			AddedCount:     int32(len(added)),
			UnchangedCount: int32(len(unchanged)),
		},
		PolicyActions:        policyActions,
		PolicyFilesEvaluated: int32(policyFilesEvaluated),
	}
}
