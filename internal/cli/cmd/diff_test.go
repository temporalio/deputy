package cmd

import (
	"fmt"
	"slices"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/internal/report"
)

// TestReclassifyUnchangedVulns pins the diff's newly-introduced semantics:
// an advisory that already affected the updated package's base version
// (matched by ID or alias) moves to the pre-existing bucket, while advisories
// the change actually introduces stay in the changed set. A nil base map
// (lookup failed or nothing to check) reclassifies nothing, failing toward
// reporting.
func TestReclassifyUnchangedVulns(t *testing.T) {
	changed := []report.Vulnerability{
		{ID: "GO-2026-5932", Package: "golang.org/x/crypto", Version: "0.53.0"},
		{ID: "GHSA-new-1111-2222", Aliases: []string{"CVE-2026-9999"}, Package: "golang.org/x/crypto", Version: "0.53.0"},
		{ID: "GO-2026-7777", Package: "example.com/other", Version: "2.0.0"},
	}
	unchanged := []report.Vulnerability{
		{ID: "GO-2025-0001", Package: "example.com/stable", Version: "1.0.0"},
	}

	tests := []struct {
		name          string
		baseAffected  map[string]map[string]bool
		wantChanged   []string
		wantUnchanged []string
	}{
		{
			name: "id and alias matches move to pre-existing",
			baseAffected: map[string]map[string]bool{
				"golang.org/x/crypto": {"GO-2026-5932": true, "CVE-2026-9999": true},
			},
			wantChanged:   []string{"GO-2026-7777"},
			wantUnchanged: []string{"GO-2025-0001", "GO-2026-5932", "GHSA-new-1111-2222"},
		},
		{
			name: "matches are scoped per package",
			baseAffected: map[string]map[string]bool{
				"example.com/unrelated": {"GO-2026-5932": true},
			},
			wantChanged:   []string{"GO-2026-5932", "GHSA-new-1111-2222", "GO-2026-7777"},
			wantUnchanged: []string{"GO-2025-0001"},
		},
		{
			name:          "nil base map reclassifies nothing",
			baseAffected:  nil,
			wantChanged:   []string{"GO-2026-5932", "GHSA-new-1111-2222", "GO-2026-7777"},
			wantUnchanged: []string{"GO-2025-0001"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotChanged, gotUnchanged := reclassifyUnchangedVulns(changed, unchanged, tt.baseAffected)
			if got := vulnIDs(gotChanged); !slices.Equal(got, tt.wantChanged) {
				t.Errorf("changed = %v, want %v", got, tt.wantChanged)
			}
			if got := vulnIDs(gotUnchanged); !slices.Equal(got, tt.wantUnchanged) {
				t.Errorf("unchanged = %v, want %v", got, tt.wantUnchanged)
			}
		})
	}
}

// TestBaseQueryPackages pins which changes trigger a base-version advisory
// lookup: only version changes with a known base version qualify, the base
// name wins over a renamed target, and added or removed packages never query.
func TestBaseQueryPackages(t *testing.T) {
	tests := []struct {
		name    string
		changes []*diffv1.PackageChange
		want    []string // "name@version/ecosystem"
	}{
		{
			name: "updated upgraded downgraded qualify",
			changes: []*diffv1.PackageChange{
				{Package: &dependencyv1.Package{Name: "a", Version: "1.1.0", Ecosystem: "go"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_UPDATED, BaseVersion: "1.0.0", TargetVersion: "1.1.0"},
				{Package: &dependencyv1.Package{Name: "b", Version: "3.0.0", Ecosystem: "npm"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_UPGRADED, BaseVersion: "2.0.0", TargetVersion: "3.0.0"},
				{Package: &dependencyv1.Package{Name: "c", Version: "4.0.0", Ecosystem: "go"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED, BaseVersion: "5.0.0", TargetVersion: "4.0.0"},
			},
			want: []string{"a@1.0.0/go", "b@2.0.0/npm", "c@5.0.0/go"},
		},
		{
			name: "added and removed never query",
			changes: []*diffv1.PackageChange{
				{Package: &dependencyv1.Package{Name: "new", Version: "1.0.0", Ecosystem: "go"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_ADDED, TargetVersion: "1.0.0"},
				{Package: &dependencyv1.Package{Name: "gone", Ecosystem: "go"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_REMOVED, BaseVersion: "1.0.0"},
			},
			want: nil,
		},
		{
			name: "missing base version is skipped",
			changes: []*diffv1.PackageChange{
				{Package: &dependencyv1.Package{Name: "a", Version: "1.1.0", Ecosystem: "go"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_UPDATED, TargetVersion: "1.1.0"},
			},
			want: nil,
		},
		{
			name: "renamed package queries under its base name",
			changes: []*diffv1.PackageChange{
				{Package: &dependencyv1.Package{Name: "new/name", Version: "1.1.0", Ecosystem: "go"}, ChangeKind: diffv1.ChangeKind_CHANGE_KIND_UPDATED, OldName: "old/name", BaseVersion: "1.0.0", TargetVersion: "1.1.0"},
			},
			want: []string{"old/name@1.0.0/go"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []string
			for _, p := range baseQueryPackages(tt.changes) {
				got = append(got, fmt.Sprintf("%s@%s/%s", p.GetName(), p.GetVersion(), p.GetEcosystem()))
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("baseQueryPackages = %v, want %v", got, tt.want)
			}
		})
	}
}

// vulnIDs projects the vulnerability IDs in order.
func vulnIDs(vulns []report.Vulnerability) []string {
	ids := make([]string, 0, len(vulns))
	for _, v := range vulns {
		ids = append(ids, v.ID)
	}
	return ids
}
