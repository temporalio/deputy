package dependency

import (
	"testing"
)

func TestMergeManifestRef(t *testing.T) {
	tests := []struct {
		name     string
		existing []ManifestRef
		ref      ManifestRef
		wantLen  int
		check    func(t *testing.T, result []ManifestRef)
	}{
		{
			name:     "empty path returns existing",
			existing: []ManifestRef{{Path: "go.mod", Manager: "go"}},
			ref:      ManifestRef{Path: "", Manager: "go"},
			wantLen:  1,
		},
		{
			name:     "empty manager returns existing",
			existing: []ManifestRef{{Path: "go.mod", Manager: "go"}},
			ref:      ManifestRef{Path: "go.mod", Manager: ""},
			wantLen:  1,
		},
		{
			name:     "new ref appended",
			existing: []ManifestRef{{Path: "go.mod", Manager: "go"}},
			ref:      ManifestRef{Path: "package.json", Manager: "npm"},
			wantLen:  2,
		},
		{
			name:     "duplicate merges groups",
			existing: []ManifestRef{{Path: "go.mod", Manager: "go", Groups: []string{"direct"}}},
			ref:      ManifestRef{Path: "go.mod", Manager: "go", Groups: []string{"test"}},
			wantLen:  1,
			check: func(t *testing.T, result []ManifestRef) {
				if len(result[0].Groups) != 2 {
					t.Errorf("Groups len = %d, want 2", len(result[0].Groups))
				}
			},
		},
		{
			name:     "nil existing creates new slice",
			existing: nil,
			ref:      ManifestRef{Path: "go.mod", Manager: "go"},
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
		refs    []ManifestRef
		wantLen int
		check   func(t *testing.T, result []ManifestRef)
	}{
		{
			name:    "empty slice",
			refs:    []ManifestRef{},
			wantLen: 0,
		},
		{
			name:    "nil slice",
			refs:    nil,
			wantLen: 0,
		},
		{
			name: "removes duplicates",
			refs: []ManifestRef{
				{Path: "go.mod", Manager: "go"},
				{Path: "go.mod", Manager: "go"},
			},
			wantLen: 1,
		},
		{
			name: "merges groups on duplicate",
			refs: []ManifestRef{
				{Path: "go.mod", Manager: "go", Groups: []string{"direct"}},
				{Path: "go.mod", Manager: "go", Groups: []string{"test"}},
			},
			wantLen: 1,
			check: func(t *testing.T, result []ManifestRef) {
				if len(result[0].Groups) != 2 {
					t.Errorf("Groups len = %d, want 2", len(result[0].Groups))
				}
			},
		},
		{
			name: "sorts by manager then path",
			refs: []ManifestRef{
				{Path: "package.json", Manager: "npm"},
				{Path: "go.mod", Manager: "go"},
				{Path: "Gemfile", Manager: "bundler"},
			},
			wantLen: 3,
			check: func(t *testing.T, result []ManifestRef) {
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
