// Tests for Deputy-specific package post-processing behaviour, ensuring generic cleanup rules remain stable.
package inventory

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
)

// newGradleWrapperPackage constructs the enriched wrapper package emitted by the Deputy extractor.
func newGradleWrapperPackage(version string, locations ...string) *extractor.Package {
	if len(locations) == 0 {
		locations = []string{"gradle/wrapper/gradle-wrapper.properties"}
	}
	return &extractor.Package{
		Name:      gradleWrapperPackageName,
		Version:   version,
		PURLType:  purl.TypeMaven,
		Locations: append([]string(nil), locations...),
	}
}

// newGradleFallbackPackage constructs the legacy archive-based wrapper record.
func newGradleFallbackPackage(name string, locations ...string) *extractor.Package {
	if name == "" {
		name = "unknown"
	}
	if len(locations) == 0 {
		locations = []string{"gradle/wrapper/gradle-wrapper.jar"}
	}
	return &extractor.Package{
		Name:      name,
		Version:   "unknown",
		PURLType:  purl.TypeMaven,
		Locations: append([]string(nil), locations...),
	}
}

// newPackage constructs an arbitrary package used to ensure unrelated entries are unaffected.
func newPackage(name string, locations ...string) *extractor.Package {
	if len(locations) == 0 {
		locations = []string{"some/other/module"}
	}
	return &extractor.Package{
		Name:      name,
		Version:   "1.0.0",
		PURLType:  purl.TypeMaven,
		Locations: append([]string(nil), locations...),
	}
}

func TestPostProcessPackages(t *testing.T) {
	tests := []struct {
		name string
		in   []*extractor.Package
		want []*extractor.Package
	}{
		{
			name: "nil input",
			in:   nil,
			want: nil,
		},
		{
			name: "no gradle packages",
			in: []*extractor.Package{
				newPackage("example:demo"),
			},
			want: []*extractor.Package{
				newPackage("example:demo"),
			},
		},
		{
			name: "only fallback",
			in: []*extractor.Package{
				newGradleFallbackPackage("unknown"),
			},
			want: []*extractor.Package{
				newGradleFallbackPackage("unknown"),
			},
		},
		{
			name: "enriched only",
			in: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
			},
			want: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
			},
		},
		{
			name: "enriched with fallback removed",
			in: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
				newGradleFallbackPackage("unknown"),
			},
			want: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
			},
		},
		{
			name: "enriched with fallback and other packages",
			in: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
				newGradleFallbackPackage("unknown"),
				newPackage("example:demo"),
			},
			want: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
				newPackage("example:demo"),
			},
		},
		{
			name: "fallback without jar suffix kept",
			in: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
				newGradleFallbackPackage("unknown", "gradle/wrapper/other-file.txt"),
			},
			want: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
				newGradleFallbackPackage("unknown", "gradle/wrapper/other-file.txt"),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := postProcessPackages(clonePackages(tt.in))
			if diff := comparePackages(tt.want, got); diff != "" {
				t.Fatalf("postProcessPackages mismatch:\n%s", diff)
			}
		})
	}
}

func TestGradleWrapperRuleShouldDrop(t *testing.T) {
	rule := gradleWrapperRule{}
	tests := []struct {
		name string
		pkg  *extractor.Package
		all  []*extractor.Package
		want bool
	}{
		{
			name: "primary package",
			pkg:  newGradleWrapperPackage("8.9"),
			all:  []*extractor.Package{newGradleWrapperPackage("8.9")},
			want: false,
		},
		{
			name: "fallback without primary",
			pkg:  newGradleFallbackPackage("unknown"),
			all:  []*extractor.Package{newGradleFallbackPackage("unknown")},
			want: false,
		},
		{
			name: "fallback with primary present",
			pkg:  newGradleFallbackPackage("unknown"),
			all: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
				newGradleFallbackPackage("unknown"),
			},
			want: true,
		},
		{
			name: "fallback with different location",
			pkg:  newGradleFallbackPackage("unknown", "gradle/wrapper/other.txt"),
			all: []*extractor.Package{
				newGradleWrapperPackage("8.9"),
				newGradleFallbackPackage("unknown", "gradle/wrapper/other.txt"),
			},
			want: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := rule.shouldDrop(tt.pkg, tt.all)
			if got != tt.want {
				t.Fatalf("gradleWrapperRule.shouldDrop = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGradleWrapperPrimary(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want bool
	}{
		{"nil", nil, false},
		{"non-maven", newPackage("example:demo"), false},
		{"wrong name", newGradleFallbackPackage("something", "gradle/wrapper/gradle-wrapper.properties"), false},
		{"valid", newGradleWrapperPackage("8.9"), true},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := isGradleWrapperPrimary(tt.pkg); got != tt.want {
				t.Fatalf("isGradleWrapperPrimary() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsGradleWrapperFallback(t *testing.T) {
	tests := []struct {
		name string
		pkg  *extractor.Package
		want bool
	}{
		{"nil", nil, false},
		{"primary", newGradleWrapperPackage("8.9"), false},
		{"non-maven", newPackage("unknown"), false},
		{"fallback", newGradleFallbackPackage("unknown"), true},
		{"fallback other name", newGradleFallbackPackage("gradle-wrapper"), true},
		{"fallback wrong location", newGradleFallbackPackage("unknown", "gradle/wrapper/other.txt"), false},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			if got := isGradleWrapperFallback(tt.pkg); got != tt.want {
				t.Fatalf("isGradleWrapperFallback() = %v, want %v", got, tt.want)
			}
		})
	}
}

// clonePackages creates a deep copy of package slices so table tests do not share data between cases.
func clonePackages(pkgs []*extractor.Package) []*extractor.Package {
	if pkgs == nil {
		return nil
	}
	out := make([]*extractor.Package, len(pkgs))
	for i, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		cloned := *pkg
		if pkg.Locations != nil {
			cloned.Locations = append([]string(nil), pkg.Locations...)
		}
		out[i] = &cloned
	}
	return out
}

// comparePackages renders a helpful diff when DeepEqual fails.
func comparePackages(want, got []*extractor.Package) string {
	if reflect.DeepEqual(want, got) {
		return ""
	}
	return fmt.Sprintf("want=%#v\n got=%#v", want, got)
}
