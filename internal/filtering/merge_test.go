package filtering

import (
	"testing"
	"time"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/temporalio/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestMerge(t *testing.T) {
	now := time.Now()
	later := now.Add(time.Hour)

	tests := []struct {
		name             string
		base             *scanv1.ScanResponse
		extra            *scanv1.ScanResponse
		wantPackages     int
		wantFindings     int
		wantAdvisories   int
		wantLaterTime    bool
	}{
		{
			name:  "nil base",
			base:  nil,
			extra: &scanv1.ScanResponse{},
		},
		{
			name:  "nil extra",
			base:  &scanv1.ScanResponse{},
			extra: nil,
		},
		{
			name: "merge packages",
			base: &scanv1.ScanResponse{
				Packages: []*dependencyv1.Package{{Name: "pkg1"}},
			},
			extra: &scanv1.ScanResponse{
				Packages: []*dependencyv1.Package{{Name: "pkg2"}},
			},
			wantPackages: 2,
		},
		{
			name: "merge findings",
			base: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{AdvisoryId: "CVE-1"},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-1": {Id: "CVE-1"},
				},
			},
			extra: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{AdvisoryId: "CVE-2"},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2": {Id: "CVE-2"},
				},
			},
			wantFindings:   2,
			wantAdvisories: 2,
		},
		{
			name: "merge advisories with overlap",
			base: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{AdvisoryId: "CVE-1"},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-1": {Id: "CVE-1", Summary: "from base"},
				},
			},
			extra: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{AdvisoryId: "CVE-1"},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-1": {Id: "CVE-1", Summary: "from extra"},
				},
			},
			wantFindings:   2,
			wantAdvisories: 1, // Same ID, merged
		},
		{
			name: "use later timestamp",
			base: &scanv1.ScanResponse{
				GeneratedAt: timestamppb.New(now),
			},
			extra: &scanv1.ScanResponse{
				GeneratedAt: timestamppb.New(later),
			},
			wantLaterTime: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Merge(tt.base, tt.extra)

			if tt.base == nil {
				if got != tt.extra {
					t.Errorf("Merge() with nil base should return extra")
				}
				return
			}
			if tt.extra == nil {
				if got != tt.base {
					t.Errorf("Merge() with nil extra should return base")
				}
				return
			}

			if tt.wantPackages > 0 && len(got.Packages) != tt.wantPackages {
				t.Errorf("Merge() packages = %d, want %d", len(got.Packages), tt.wantPackages)
			}

			if tt.wantFindings > 0 && len(got.Findings) != tt.wantFindings {
				t.Errorf("Merge() findings = %d, want %d", len(got.Findings), tt.wantFindings)
			}

			if tt.wantAdvisories > 0 && len(got.Advisories) != tt.wantAdvisories {
				t.Errorf("Merge() advisories = %d, want %d", len(got.Advisories), tt.wantAdvisories)
			}

			if tt.wantLaterTime && got.GeneratedAt != nil {
				if !got.GeneratedAt.AsTime().Equal(later) {
					t.Errorf("Merge() timestamp = %v, want %v", got.GeneratedAt.AsTime(), later)
				}
			}
		})
	}
}
