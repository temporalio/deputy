package dependency

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
)

func TestMergeManifestRef(t *testing.T) {
	tests := []struct {
		name     string
		existing []dependencyv1.ManifestRef
		ref      dependencyv1.ManifestRef
		wantLen  int
		check    func(t *testing.T, result []dependencyv1.ManifestRef)
	}{
		{
			name:     "empty path returns existing",
			existing: []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go"}},
			ref:      dependencyv1.ManifestRef{Path: "", Manager: "go"},
			wantLen:  1,
		},
		{
			name:     "empty manager returns existing",
			existing: []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go"}},
			ref:      dependencyv1.ManifestRef{Path: "go.mod", Manager: ""},
			wantLen:  1,
		},
		{
			name:     "new ref appended",
			existing: []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go"}},
			ref:      dependencyv1.ManifestRef{Path: "package.json", Manager: "npm"},
			wantLen:  2,
		},
		{
			name:     "duplicate merges groups",
			existing: []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go", Groups: []string{"direct"}}},
			ref:      dependencyv1.ManifestRef{Path: "go.mod", Manager: "go", Groups: []string{"test"}},
			wantLen:  1,
			check: func(t *testing.T, result []dependencyv1.ManifestRef) {
				if len(result[0].Groups) != 2 {
					t.Errorf("Groups len = %d, want 2", len(result[0].Groups))
				}
			},
		},
		{
			name:     "nil existing creates new slice",
			existing: nil,
			ref:      dependencyv1.ManifestRef{Path: "go.mod", Manager: "go"},
			wantLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeManifestRef(tt.existing, tt.ref)
			if len(got) != tt.wantLen {
				t.Errorf("MergeManifestRef() len = %d, want %d", len(got), tt.wantLen)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}

func TestSortAndUniqueManifestRefs(t *testing.T) {
	tests := []struct {
		name    string
		refs    []dependencyv1.ManifestRef
		wantLen int
		check   func(t *testing.T, result []dependencyv1.ManifestRef)
	}{
		{
			name:    "empty slice",
			refs:    []dependencyv1.ManifestRef{},
			wantLen: 0,
		},
		{
			name:    "nil slice",
			refs:    nil,
			wantLen: 0,
		},
		{
			name: "removes duplicates",
			refs: []dependencyv1.ManifestRef{
				{Path: "go.mod", Manager: "go"},
				{Path: "go.mod", Manager: "go"},
			},
			wantLen: 1,
		},
		{
			name: "merges groups on duplicate",
			refs: []dependencyv1.ManifestRef{
				{Path: "go.mod", Manager: "go", Groups: []string{"direct"}},
				{Path: "go.mod", Manager: "go", Groups: []string{"test"}},
			},
			wantLen: 1,
			check: func(t *testing.T, result []dependencyv1.ManifestRef) {
				if len(result[0].Groups) != 2 {
					t.Errorf("Groups len = %d, want 2", len(result[0].Groups))
				}
			},
		},
		{
			name: "sorts by manager then path",
			refs: []dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm"},
				{Path: "go.mod", Manager: "go"},
				{Path: "Gemfile", Manager: "bundler"},
			},
			wantLen: 3,
			check: func(t *testing.T, result []dependencyv1.ManifestRef) {
				if result[0].Manager != "bundler" {
					t.Errorf("first manager = %q, want bundler", result[0].Manager)
				}
				if result[1].Manager != "go" {
					t.Errorf("second manager = %q, want go", result[1].Manager)
				}
				if result[2].Manager != "npm" {
					t.Errorf("third manager = %q, want npm", result[2].Manager)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SortAndUniqueManifestRefs(tt.refs)
			if len(got) != tt.wantLen {
				t.Errorf("SortAndUniqueManifestRefs() len = %d, want %d", len(got), tt.wantLen)
			}
			if tt.check != nil {
				tt.check(t, got)
			}
		})
	}
}
