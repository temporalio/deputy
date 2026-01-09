package filtering

import (
	"testing"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/ignore"
)

func TestFilterUnfixed(t *testing.T) {
	tests := []struct {
		name          string
		resp          *scanv1.ScanResponse
		wantFindings  int
		wantAdvisory  bool
	}{
		{
			name: "nil response",
			resp: nil,
			wantFindings: 0,
		},
		{
			name: "empty findings",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{},
			},
			wantFindings: 0,
		},
		{
			name: "finding with fix available",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-1234",
						Package: &dependencyv1.Package{
							Name:    "example",
							Version: "1.0.0",
						},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-1234": {
						Id:            "CVE-2021-1234",
						FixedVersions: []string{"1.1.0"},
					},
				},
			},
			wantFindings: 1,
			wantAdvisory: true,
		},
		{
			name: "finding without fix",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-1234",
						Package: &dependencyv1.Package{
							Name:    "example",
							Version: "1.0.0",
						},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-1234": {
						Id:            "CVE-2021-1234",
						FixedVersions: []string{}, // No fix
					},
				},
			},
			wantFindings: 0,
			wantAdvisory: false,
		},
		{
			name: "finding with fix but version already up to date",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-1234",
						Package: &dependencyv1.Package{
							Name:    "example",
							Version: "v2.0.0",
						},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-1234": {
						Id:            "CVE-2021-1234",
						FixedVersions: []string{"v1.1.0"}, // Fix is older than current
					},
				},
			},
			wantFindings: 0,
			wantAdvisory: false,
		},
		{
			name: "mixed findings - one with fix, one without",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-1234",
						Package: &dependencyv1.Package{
							Name:    "example",
							Version: "v1.0.0",
						},
					},
					{
						AdvisoryId: "CVE-2021-5678",
						Package: &dependencyv1.Package{
							Name:    "other",
							Version: "v2.0.0",
						},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-1234": {
						Id:            "CVE-2021-1234",
						FixedVersions: []string{"v1.1.0"}, // Has fix
					},
					"CVE-2021-5678": {
						Id:            "CVE-2021-5678",
						FixedVersions: []string{}, // No fix
					},
				},
			},
			wantFindings: 1,
			wantAdvisory: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FilterUnfixed(tt.resp)

			if tt.resp == nil {
				if got != nil {
					t.Errorf("FilterUnfixed() = %v, want nil", got)
				}
				return
			}

			if len(got.Findings) != tt.wantFindings {
				t.Errorf("FilterUnfixed() findings count = %d, want %d", len(got.Findings), tt.wantFindings)
			}

			if tt.wantAdvisory {
				if len(got.Advisories) == 0 {
					t.Error("FilterUnfixed() advisories should not be empty")
				}
			} else {
				if len(got.Advisories) != 0 {
					t.Errorf("FilterUnfixed() advisories = %d, want 0", len(got.Advisories))
				}
			}
		})
	}
}

func TestFilterIgnored(t *testing.T) {
	tests := []struct {
		name          string
		resp          *scanv1.ScanResponse
		rules         *ignore.Rules
		wantFindings  int
		wantIgnored   int
	}{
		{
			name:         "nil response",
			resp:         nil,
			rules:        ignore.NewRules(),
			wantFindings: 0,
			wantIgnored:  0,
		},
		{
			name: "nil rules",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{AdvisoryId: "CVE-2021-1234"},
				},
			},
			rules:        nil,
			wantFindings: 1,
			wantIgnored:  0,
		},
		{
			name: "finding matches ignore rule by ID",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-1234",
						Package: &dependencyv1.Package{
							Name:      "example",
							Ecosystem: "go",
						},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-1234": {Id: "CVE-2021-1234"},
				},
			},
			rules: func() *ignore.Rules {
				r := ignore.NewRules()
				r.Add(ignore.Rule{ID: "CVE-2021-1234"})
				return r
			}(),
			wantFindings: 0,
			wantIgnored:  1,
		},
		{
			name: "finding matches ignore rule by package",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-1234",
						Package: &dependencyv1.Package{
							Name:      "example",
							Ecosystem: "go",
						},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-1234": {Id: "CVE-2021-1234"},
				},
			},
			rules: func() *ignore.Rules {
				r := ignore.NewRules()
				r.Add(ignore.Rule{Package: "example"})
				return r
			}(),
			wantFindings: 0,
			wantIgnored:  1,
		},
		{
			name: "finding does not match ignore rule",
			resp: &scanv1.ScanResponse{
				Findings: []*vulnerabilityv1.Finding{
					{
						AdvisoryId: "CVE-2021-1234",
						Package: &dependencyv1.Package{
							Name:      "example",
							Ecosystem: "go",
						},
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2021-1234": {Id: "CVE-2021-1234"},
				},
			},
			rules: func() *ignore.Rules {
				r := ignore.NewRules()
				r.Add(ignore.Rule{ID: "CVE-2021-5678"})
				return r
			}(),
			wantFindings: 1,
			wantIgnored:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ignoredCount := FilterIgnored(tt.resp, tt.rules)

			if ignoredCount != tt.wantIgnored {
				t.Errorf("FilterIgnored() ignored = %d, want %d", ignoredCount, tt.wantIgnored)
			}

			if tt.resp == nil || tt.rules == nil {
				return
			}

			if len(got.Findings) != tt.wantFindings {
				t.Errorf("FilterIgnored() findings = %d, want %d", len(got.Findings), tt.wantFindings)
			}
		})
	}
}
