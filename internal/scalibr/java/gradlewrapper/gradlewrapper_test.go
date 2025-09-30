package gradlewrapper

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestExtractorFileRequired(t *testing.T) {
	ext := &Extractor{}
	if !ext.FileRequired(fakeFileAPI{path: "gradle/wrapper/gradle-wrapper.properties"}) {
		t.Fatal("expected FileRequired to be true for gradle wrapper properties")
	}
	if ext.FileRequired(fakeFileAPI{path: "build.gradle"}) {
		t.Fatal("expected FileRequired to be false for unrelated file")
	}
}

func TestExtractorExtract(t *testing.T) {
	ext := &Extractor{}
	input := &filesystem.ScanInput{
		FS:     scalibrfs.DirFS("."),
		Path:   "gradle/wrapper/gradle-wrapper.properties",
		Reader: strings.NewReader("distributionUrl=https\\://services.gradle.org/distributions/gradle-8.8-bin.zip\n"),
	}

	inv, err := ext.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract error: %v", err)
	}
	if len(inv.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(inv.Packages))
	}
	pkg := inv.Packages[0]
	if got, want := pkg.Name, "org.gradle:gradle-wrapper"; got != want {
		t.Fatalf("package name mismatch: got %q want %q", got, want)
	}
	if got, want := pkg.Version, "8.8"; got != want {
		t.Fatalf("package version mismatch: got %q want %q", got, want)
	}
	if pkg.PURLType != "maven" {
		t.Fatalf("unexpected PURL type: %q", pkg.PURLType)
	}
	if len(pkg.Locations) != 1 || pkg.Locations[0] != input.Path {
		t.Fatalf("unexpected locations: %#v", pkg.Locations)
	}
}

func TestParseGradleWrapperVersion(t *testing.T) {
	data := []byte("distributionUrl=https\\://services.gradle.org/distributions/gradle-7.6-all.zip")
	if got, want := parseGradleWrapperVersion(data), "7.6"; got != want {
		t.Fatalf("parseGradleWrapperVersion mismatch: got %q want %q", got, want)
	}

	if got := parseGradleWrapperVersion([]byte("distributionUrl=invalid")); got != "" {
		t.Fatalf("expected empty version for invalid url, got %q", got)
	}
}

type fakeFileAPI struct{ path string }

func (f fakeFileAPI) Stat() (fs.FileInfo, error) { return nil, nil }

func (f fakeFileAPI) Path() string { return f.path }
