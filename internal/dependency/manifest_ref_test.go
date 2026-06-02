package dependency

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
)

type manifestRefFields struct {
	path         string
	manager      string
	componentKey string
}

func manifestRefFieldsOf(ref *dependencyv1.ManifestRef) manifestRefFields {
	return manifestRefFields{
		path:         ref.Path,
		manager:      ref.Manager,
		componentKey: ManifestRefComponentKey(ref),
	}
}

func TestCloneManifestRefsPreservesFields(t *testing.T) {
	// Guards a real regression: ComponentKey (the manifest-declared name used by
	// source-aware fixes, e.g. a mise tool key) must survive cloning.
	tests := []struct {
		name         string
		path         string
		manager      string
		componentKey string
		groups       []string
	}{
		{name: "mise tool key", path: "mise.toml", manager: "mise", componentKey: "npm:lodash"},
		{name: "mise go runtime", path: "mise.toml", manager: "mise", componentKey: "go"},
		{name: "go module with groups", path: "go.mod", manager: "go", groups: []string{"require"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CloneManifestRefs([]dependencyv1.ManifestRef{
				NewManifestRef(tt.path, tt.manager, tt.groups, tt.componentKey),
			})
			if len(got) != 1 {
				t.Fatalf("clone len = %d, want 1", len(got))
			}
			want := manifestRefFields{
				path:         tt.path,
				manager:      tt.manager,
				componentKey: tt.componentKey,
			}
			if got := manifestRefFieldsOf(&got[0]); got != want {
				t.Errorf("clone fields = %+v, want %+v", got, want)
			}
		})
	}
}

func TestMergeManifestRef(t *testing.T) {
	tests := []struct {
		name     string
		existing func() []dependencyv1.ManifestRef
		ref      func() *dependencyv1.ManifestRef
		wantLen  int
		check    func(t *testing.T, result []dependencyv1.ManifestRef)
	}{
		{
			name:     "empty path returns existing",
			existing: func() []dependencyv1.ManifestRef { return []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go"}} },
			ref:      func() *dependencyv1.ManifestRef { return &dependencyv1.ManifestRef{Path: "", Manager: "go"} },
			wantLen:  1,
		},
		{
			name:     "empty manager returns existing",
			existing: func() []dependencyv1.ManifestRef { return []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go"}} },
			ref:      func() *dependencyv1.ManifestRef { return &dependencyv1.ManifestRef{Path: "go.mod", Manager: ""} },
			wantLen:  1,
		},
		{
			name:     "new ref appended",
			existing: func() []dependencyv1.ManifestRef { return []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go"}} },
			ref: func() *dependencyv1.ManifestRef {
				return &dependencyv1.ManifestRef{Path: "package.json", Manager: "npm"}
			},
			wantLen: 2,
		},
		{
			name: "duplicate merges groups",
			existing: func() []dependencyv1.ManifestRef {
				return []dependencyv1.ManifestRef{{Path: "go.mod", Manager: "go", Groups: []string{"direct"}}}
			},
			ref: func() *dependencyv1.ManifestRef {
				return &dependencyv1.ManifestRef{Path: "go.mod", Manager: "go", Groups: []string{"test"}}
			},
			wantLen: 1,
			check: func(t *testing.T, result []dependencyv1.ManifestRef) {
				if len(result[0].Groups) != 2 {
					t.Errorf("Groups len = %d, want 2", len(result[0].Groups))
				}
			},
		},
		{
			name: "duplicate preserves component key",
			existing: func() []dependencyv1.ManifestRef {
				return []dependencyv1.ManifestRef{{Path: "mise.toml", Manager: "mise"}}
			},
			ref: func() *dependencyv1.ManifestRef {
				ref := NewManifestRef("mise.toml", "mise", nil, "npm:lodash")
				return &ref
			},
			wantLen: 1,
			check: func(t *testing.T, result []dependencyv1.ManifestRef) {
				if got := ManifestRefComponentKey(&result[0]); got != "npm:lodash" {
					t.Errorf("ComponentKey = %q, want npm:lodash", got)
				}
			},
		},
		{
			name:     "nil existing creates new slice",
			existing: func() []dependencyv1.ManifestRef { return nil },
			ref:      func() *dependencyv1.ManifestRef { return &dependencyv1.ManifestRef{Path: "go.mod", Manager: "go"} },
			wantLen:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeManifestRef(tt.existing(), tt.ref())
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
			name: "preserves component key on duplicate",
			refs: []dependencyv1.ManifestRef{
				{Path: "mise.toml", Manager: "mise"},
				NewManifestRef("mise.toml", "mise", nil, "npm:lodash"),
			},
			wantLen: 1,
			check: func(t *testing.T, result []dependencyv1.ManifestRef) {
				if got := ManifestRefComponentKey(&result[0]); got != "npm:lodash" {
					t.Errorf("ComponentKey = %q, want npm:lodash", got)
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
