package vuln

import (
	"slices"
	"testing"
)

func TestMergeManifestReference(t *testing.T) {
	tests := []struct {
		name     string
		existing []ManifestReference
		ref      ManifestReference
		wantLen  int
	}{
		{
			name:     "add to empty",
			existing: nil,
			ref:      ManifestReference{Manager: "npm", Path: "package.json"},
			wantLen:  1,
		},
		{
			name:     "add new ref",
			existing: []ManifestReference{{Manager: "npm", Path: "a/package.json"}},
			ref:      ManifestReference{Manager: "npm", Path: "b/package.json"},
			wantLen:  2,
		},
		{
			name:     "merge same ref",
			existing: []ManifestReference{{Manager: "npm", Path: "package.json", Groups: []string{"dependencies"}}},
			ref:      ManifestReference{Manager: "npm", Path: "package.json", Groups: []string{"devDependencies"}},
			wantLen:  1,
		},
		{
			name:     "skip empty path",
			existing: []ManifestReference{{Manager: "npm", Path: "package.json"}},
			ref:      ManifestReference{Manager: "npm", Path: ""},
			wantLen:  1,
		},
		{
			name:     "skip empty manager",
			existing: []ManifestReference{{Manager: "npm", Path: "package.json"}},
			ref:      ManifestReference{Manager: "", Path: "package.json"},
			wantLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeManifestReference(tt.existing, tt.ref)
			if len(got) != tt.wantLen {
				t.Errorf("MergeManifestReference() returned %d refs, want %d", len(got), tt.wantLen)
			}
		})
	}

	t.Run("groups merged correctly", func(t *testing.T) {
		existing := []ManifestReference{
			{Manager: "npm", Path: "package.json", Groups: []string{"dependencies"}},
		}
		ref := ManifestReference{Manager: "npm", Path: "package.json", Groups: []string{"devDependencies"}}
		got := MergeManifestReference(existing, ref)
		if len(got) != 1 {
			t.Fatalf("expected 1 ref, got %d", len(got))
		}
		if !slices.Contains(got[0].Groups, "dependencies") || !slices.Contains(got[0].Groups, "devDependencies") {
			t.Errorf("groups not merged correctly: %v", got[0].Groups)
		}
	})
}

func TestMergeGroups(t *testing.T) {
	tests := []struct {
		name  string
		base  []string
		extra []string
		want  []string
	}{
		{"nil base", nil, []string{"a", "b"}, []string{"a", "b"}},
		{"nil extra", []string{"a"}, nil, []string{"a"}},
		{"both nil", nil, nil, nil},
		{"no overlap", []string{"a"}, []string{"b"}, []string{"a", "b"}},
		{"with overlap", []string{"a", "b"}, []string{"b", "c"}, []string{"a", "b", "c"}},
		{"empty strings skipped", []string{"a"}, []string{"", "  "}, []string{"a"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mergeGroups(tt.base, tt.extra)
			if !slices.Equal(got, tt.want) {
				t.Errorf("mergeGroups(%v, %v) = %v, want %v", tt.base, tt.extra, got, tt.want)
			}
		})
	}
}

func TestSortAndUniqueManifestRefs(t *testing.T) {
	refs := []ManifestReference{
		{Manager: "npm", Path: "package.json", Groups: []string{"dev"}},
		{Manager: "npm", Path: "package.json", Groups: []string{"prod"}},
		{Manager: "go", Path: "go.mod"},
		{Manager: "go", Path: "go.mod", Groups: []string{"direct"}},
	}

	got := SortAndUniqueManifestRefs(refs)
	if len(got) != 2 {
		t.Fatalf("expected 2 refs, got %d", len(got))
	}
	if got[0].Manager != "go" || got[0].Path != "go.mod" {
		t.Fatalf("expected go.mod first, got %+v", got[0])
	}
	if got[1].Manager != "npm" || got[1].Path != "package.json" {
		t.Fatalf("expected package.json second, got %+v", got[1])
	}
}
