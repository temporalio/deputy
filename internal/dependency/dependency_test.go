package dependency

import (
	"reflect"
	"testing"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
)

func TestCloneLayerDetails(t *testing.T) {
	tests := []struct {
		name string
		src  *containerv1.LayerDetails
		want *containerv1.LayerDetails
	}{
		{
			name: "nil input",
			src:  nil,
			want: nil,
		},
		{
			name: "empty struct",
			src:  &containerv1.LayerDetails{},
			want: &containerv1.LayerDetails{},
		},
		{
			name: "full struct",
			src: &containerv1.LayerDetails{
				Index:       2,
				DiffId:      "sha256:abc123",
				ChainId:     "sha256:def456",
				Command:     "RUN apt-get install -y curl",
				InBaseImage: true,
			},
			want: &containerv1.LayerDetails{
				Index:       2,
				DiffId:      "sha256:abc123",
				ChainId:     "sha256:def456",
				Command:     "RUN apt-get install -y curl",
				InBaseImage: true,
			},
		},
		{
			name: "partial struct",
			src: &containerv1.LayerDetails{
				Index:   0,
				Command: "FROM alpine:3.19",
			},
			want: &containerv1.LayerDetails{
				Index:   0,
				Command: "FROM alpine:3.19",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CloneLayerDetails(tt.src)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloneLayerDetails() = %+v, want %+v", got, tt.want)
			}

			// Verify independence (mutation test)
			if tt.src != nil && got != nil {
				if got == tt.src {
					t.Error("CloneLayerDetails() returned same pointer, expected new allocation")
				}
				// Mutate original and verify clone is unaffected
				original := tt.src.Command
				tt.src.Command = "mutated"
				if got.Command != original {
					t.Error("CloneLayerDetails() clone was affected by mutation to original")
				}
				tt.src.Command = original // restore
			}
		})
	}
}

func TestCloneManifestRefs(t *testing.T) {
	tests := []struct {
		name string
		refs []dependencyv1.ManifestRef
		want []dependencyv1.ManifestRef
	}{
		{
			name: "nil input",
			refs: nil,
			want: nil,
		},
		{
			name: "empty slice",
			refs: []dependencyv1.ManifestRef{},
			want: nil, // empty returns nil per implementation
		},
		{
			name: "single ref no groups",
			refs: []dependencyv1.ManifestRef{
				{Path: "go.mod", Manager: "gomod"},
			},
			want: []dependencyv1.ManifestRef{
				{Path: "go.mod", Manager: "gomod"},
			},
		},
		{
			name: "single ref with groups",
			refs: []dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm", Groups: []string{"dependencies", "devDependencies"}},
			},
			want: []dependencyv1.ManifestRef{
				{Path: "package.json", Manager: "npm", Groups: []string{"dependencies", "devDependencies"}},
			},
		},
		{
			name: "multiple refs",
			refs: []dependencyv1.ManifestRef{
				{Path: "go.mod", Manager: "gomod"},
				{Path: "go.sum", Manager: "gomod", Groups: []string{"indirect"}},
				{Path: "package.json", Manager: "npm", Groups: []string{"dependencies"}},
			},
			want: []dependencyv1.ManifestRef{
				{Path: "go.mod", Manager: "gomod"},
				{Path: "go.sum", Manager: "gomod", Groups: []string{"indirect"}},
				{Path: "package.json", Manager: "npm", Groups: []string{"dependencies"}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := CloneManifestRefs(tt.refs)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CloneManifestRefs() = %+v, want %+v", got, tt.want)
			}

			// Verify independence (mutation test)
			if len(tt.refs) > 0 && len(got) > 0 {
				// Check slice independence
				if &got[0] == &tt.refs[0] {
					t.Error("CloneManifestRefs() shares backing array with input")
				}

				// Mutate original and verify clone is unaffected
				originalPath := tt.refs[0].Path
				tt.refs[0].Path = "mutated"
				if got[0].Path != originalPath {
					t.Error("CloneManifestRefs() clone was affected by mutation to original")
				}
				tt.refs[0].Path = originalPath // restore

				// Mutate Groups slice
				if len(tt.refs[0].Groups) > 0 {
					originalGroup := tt.refs[0].Groups[0]
					tt.refs[0].Groups[0] = "mutated"
					if len(got[0].Groups) > 0 && got[0].Groups[0] != originalGroup {
						t.Error("CloneManifestRefs() Groups slice was affected by mutation to original")
					}
					tt.refs[0].Groups[0] = originalGroup // restore
				}
			}
		})
	}
}
