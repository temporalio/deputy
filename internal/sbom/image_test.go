package sbomx

import (
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/fake"
	"github.com/google/go-containerregistry/pkg/v1/types"
	"github.com/protobom/protobom/pkg/sbom"
)

func Test_parseOCILicenseExpression(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "single license",
			input: "MIT",
			want:  []string{"MIT"},
		},
		{
			name:  "single license with whitespace",
			input: "  Apache-2.0  ",
			want:  []string{"Apache-2.0"},
		},
		{
			name:  "OR expression",
			input: "MIT OR Apache-2.0",
			want:  []string{"Apache-2.0", "MIT"},
		},
		{
			name:  "AND expression",
			input: "MIT AND GPL-2.0",
			want:  []string{"GPL-2.0", "MIT"},
		},
		{
			name:  "lowercase or",
			input: "MIT or BSD-3-Clause",
			want:  []string{"BSD-3-Clause", "MIT"},
		},
		{
			name:  "comma separated",
			input: "MIT, Apache-2.0, BSD-3-Clause",
			want:  []string{"Apache-2.0", "BSD-3-Clause", "MIT"},
		},
		{
			name:  "semicolon separated",
			input: "MIT; Apache-2.0",
			want:  []string{"Apache-2.0", "MIT"},
		},
		{
			name:  "complex expression with parentheses",
			input: "(MIT OR Apache-2.0) AND GPL-2.0",
			want:  []string{"Apache-2.0", "GPL-2.0", "MIT"},
		},
		{
			name:  "duplicate licenses",
			input: "MIT OR MIT OR Apache-2.0",
			want:  []string{"Apache-2.0", "MIT"},
		},
		{
			name:  "WITH exception preserved",
			input: "GPL-2.0 WITH Classpath-exception-2.0",
			want:  []string{"GPL-2.0 WITH Classpath-exception-2.0"},
		},
		{
			name:  "SPDX license ID with plus",
			input: "GPL-2.0+",
			want:  []string{"GPL-2.0+"},
		},
		{
			name:  "mixed operators",
			input: "MIT OR Apache-2.0 AND BSD-3-Clause",
			want:  []string{"Apache-2.0", "BSD-3-Clause", "MIT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOCILicenseExpression(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("parseOCILicenseExpression(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseOCILicenseExpression(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

func Test_splitOnOperators(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "no operators",
			input: "MIT",
			want:  []string{"MIT"},
		},
		{
			name:  "OR operator",
			input: "MIT OR Apache-2.0",
			want:  []string{"MIT", "Apache-2.0"},
		},
		{
			name:  "AND operator",
			input: "MIT AND GPL-2.0",
			want:  []string{"MIT", "GPL-2.0"},
		},
		{
			name:  "multiple operators",
			input: "MIT OR Apache-2.0 AND BSD-3-Clause",
			want:  []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
		{
			name:  "lowercase operators",
			input: "MIT or Apache-2.0 and BSD-3-Clause",
			want:  []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := splitOnOperators(tt.input)
			if len(got) != len(tt.want) {
				t.Errorf("splitOnOperators(%q) = %v, want %v", tt.input, got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("splitOnOperators(%q)[%d] = %q, want %q", tt.input, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// mockImage creates a fake v1.Image with the specified labels.
func mockImage(labels map[string]string) v1.Image {
	return &fake.FakeImage{
		ConfigFileStub: func() (*v1.ConfigFile, error) {
			return &v1.ConfigFile{
				Config: v1.Config{
					Labels: labels,
				},
			}, nil
		},
		MediaTypeStub: func() (types.MediaType, error) {
			return types.DockerManifestSchema2, nil
		},
	}
}

func Test_extractOCILabelLicenses(t *testing.T) {
	tests := []struct {
		name   string
		labels map[string]string
		want   []string
	}{
		{
			name:   "no labels",
			labels: nil,
			want:   nil,
		},
		{
			name:   "no license label",
			labels: map[string]string{"foo": "bar"},
			want:   nil,
		},
		{
			name:   "empty license label",
			labels: map[string]string{ociLicensesAnnotation: ""},
			want:   nil,
		},
		{
			name:   "single license",
			labels: map[string]string{ociLicensesAnnotation: "MIT"},
			want:   []string{"MIT"},
		},
		{
			name:   "SPDX expression",
			labels: map[string]string{ociLicensesAnnotation: "Apache-2.0 OR MIT"},
			want:   []string{"Apache-2.0", "MIT"},
		},
		{
			name: "license with other labels",
			labels: map[string]string{
				"org.opencontainers.image.source":   "https://github.com/example/repo",
				"org.opencontainers.image.licenses": "BSD-3-Clause",
			},
			want: []string{"BSD-3-Clause"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := mockImage(tt.labels)
			got := extractOCILabelLicenses(img)
			if len(got) != len(tt.want) {
				t.Errorf("extractOCILabelLicenses() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("extractOCILabelLicenses()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func Test_extractOCILabelLicenses_nilImage(t *testing.T) {
	got := extractOCILabelLicenses(nil)
	if got != nil {
		t.Errorf("extractOCILabelLicenses(nil) = %v, want nil", got)
	}
}

func Test_enrichProtobomLicensesFromOCILabels(t *testing.T) {
	// Create a simple document with a root node
	doc := sbom.NewDocument()
	root := sbom.NewNode()
	root.Id = "root"
	root.Type = sbom.Node_PACKAGE
	root.Name = "test-image"
	doc.NodeList.Nodes = append(doc.NodeList.Nodes, root)
	doc.NodeList.RootElements = append(doc.NodeList.RootElements, root.Id)

	// Create image with license label
	img := mockImage(map[string]string{
		ociLicensesAnnotation: "Apache-2.0 OR MIT",
	})

	// Enrich licenses
	enrichProtobomLicensesFromOCILabels(doc, img)

	// Verify licenses were added to root node
	if len(root.Licenses) != 2 {
		t.Errorf("expected 2 licenses, got %d: %v", len(root.Licenses), root.Licenses)
		return
	}

	// Licenses should be sorted
	if root.Licenses[0] != "Apache-2.0" || root.Licenses[1] != "MIT" {
		t.Errorf("unexpected licenses: %v", root.Licenses)
	}
}

func Test_enrichProtobomLicensesFromOCILabels_appendsToExisting(t *testing.T) {
	// Create a document with a root node that already has a license
	doc := sbom.NewDocument()
	root := sbom.NewNode()
	root.Id = "root"
	root.Type = sbom.Node_PACKAGE
	root.Name = "test-image"
	root.Licenses = []string{"GPL-2.0"}
	doc.NodeList.Nodes = append(doc.NodeList.Nodes, root)
	doc.NodeList.RootElements = append(doc.NodeList.RootElements, root.Id)

	// Create image with license label
	img := mockImage(map[string]string{
		ociLicensesAnnotation: "MIT",
	})

	// Enrich licenses
	enrichProtobomLicensesFromOCILabels(doc, img)

	// Verify both licenses are present
	if len(root.Licenses) != 2 {
		t.Errorf("expected 2 licenses, got %d: %v", len(root.Licenses), root.Licenses)
		return
	}

	// Should contain both old and new licenses
	hasGPL := false
	hasMIT := false
	for _, l := range root.Licenses {
		if l == "GPL-2.0" {
			hasGPL = true
		}
		if l == "MIT" {
			hasMIT = true
		}
	}
	if !hasGPL || !hasMIT {
		t.Errorf("expected GPL-2.0 and MIT, got: %v", root.Licenses)
	}
}

func Test_enrichProtobomLicensesFromOCILabels_nilInputs(t *testing.T) {
	// Should not panic with nil inputs
	enrichProtobomLicensesFromOCILabels(nil, nil)

	doc := sbom.NewDocument()
	enrichProtobomLicensesFromOCILabels(doc, nil)

	img := mockImage(map[string]string{ociLicensesAnnotation: "MIT"})
	enrichProtobomLicensesFromOCILabels(nil, img)
}
