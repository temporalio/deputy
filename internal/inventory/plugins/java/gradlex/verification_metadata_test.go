package gradlex

import (
	"context"
	"io"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
)

func TestVerificationMetadataExtractor_FileRequired(t *testing.T) {
	e := NewVerificationMetadataExtractor()

	tests := []struct {
		path     string
		expected bool
	}{
		{"gradle/verification-metadata.xml", true},
		{"project/gradle/verification-metadata.xml", true},
		{"verification-metadata.xml", false},
		{"gradle/other.xml", false},
		{"build.gradle", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			api := simplefileapi.New(tt.path, nil)
			got := e.FileRequired(api)
			if got != tt.expected {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestParseVerificationMetadata(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata>
   <components>
      <component group="io.grpc" name="grpc-api" version="1.58.1">
         <artifact name="grpc-api-1.58.1.jar">
            <sha256 value="abc123"/>
         </artifact>
      </component>
      <component group="com.google.guava" name="guava" version="32.0.1-jre">
         <artifact name="guava-32.0.1-jre.jar">
            <sha256 value="def456"/>
         </artifact>
      </component>
      <component group="org.slf4j" name="slf4j-api" version="1.7.36">
         <artifact name="slf4j-api-1.7.36.jar">
            <sha256 value="ghi789"/>
         </artifact>
      </component>
   </components>
</verification-metadata>`)

	deps, err := ParseVerificationMetadata(content)
	if err != nil {
		t.Fatalf("ParseVerificationMetadata failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	expected := []struct {
		groupID    string
		artifactID string
		version    string
	}{
		{"io.grpc", "grpc-api", "1.58.1"},
		{"com.google.guava", "guava", "32.0.1-jre"},
		{"org.slf4j", "slf4j-api", "1.7.36"},
	}

	for i, exp := range expected {
		if deps[i].GroupID != exp.groupID {
			t.Errorf("deps[%d].GroupID = %q, want %q", i, deps[i].GroupID, exp.groupID)
		}
		if deps[i].ArtifactID != exp.artifactID {
			t.Errorf("deps[%d].ArtifactID = %q, want %q", i, deps[i].ArtifactID, exp.artifactID)
		}
		if deps[i].Version != exp.version {
			t.Errorf("deps[%d].Version = %q, want %q", i, deps[i].Version, exp.version)
		}
	}
}

func TestMavenDependency_IsResolved(t *testing.T) {
	tests := []struct {
		dep      MavenDependency
		expected bool
	}{
		{MavenDependency{GroupID: "com.example", ArtifactID: "lib", Version: "1.0.0"}, true},
		{MavenDependency{GroupID: "com.example", ArtifactID: "lib", Version: ""}, false},
		{MavenDependency{GroupID: "com.example", ArtifactID: "lib", Version: "${version}"}, false},
		{MavenDependency{GroupID: "com.example", ArtifactID: "lib", Version: "$version"}, false},
		{MavenDependency{GroupID: "com.example", ArtifactID: "lib", Version: "[1.0,2.0)"}, false},
		{MavenDependency{GroupID: "com.example", ArtifactID: "lib", Version: "1.+"}, false},
		{MavenDependency{GroupID: "com.example", ArtifactID: "lib", Version: "latest.release"}, false},
	}

	for _, tt := range tests {
		got := tt.dep.IsResolved()
		if got != tt.expected {
			t.Errorf("IsResolved(%v) = %v, want %v", tt.dep, got, tt.expected)
		}
	}
}

func TestMavenDependency_PURL(t *testing.T) {
	dep := MavenDependency{
		GroupID:    "io.grpc",
		ArtifactID: "grpc-api",
		Version:    "1.58.1",
	}

	expected := "pkg:maven/io.grpc/grpc-api@1.58.1"
	got := dep.PURL()
	if got != expected {
		t.Errorf("PURL() = %q, want %q", got, expected)
	}
}

func TestVerificationMetadataExtractor_Extract(t *testing.T) {
	content := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<verification-metadata>
   <components>
      <component group="io.grpc" name="grpc-api" version="1.58.1">
         <artifact name="grpc-api-1.58.1.jar">
            <sha256 value="abc123"/>
         </artifact>
      </component>
   </components>
</verification-metadata>`)

	e := NewVerificationMetadataExtractor()
	input := &filesystem.ScanInput{
		Path:   "gradle/verification-metadata.xml",
		Reader: newBytesReader(content),
	}

	inv, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(inv.Packages) != 1 {
		t.Fatalf("expected 1 package, got %d", len(inv.Packages))
	}

	pkg := inv.Packages[0]
	if pkg.Name != "io.grpc:grpc-api" {
		t.Errorf("Package.Name = %q, want %q", pkg.Name, "io.grpc:grpc-api")
	}
	if pkg.Version != "1.58.1" {
		t.Errorf("Package.Version = %q, want %q", pkg.Version, "1.58.1")
	}
}

// bytesReader wraps []byte to implement io.Reader
type bytesReader struct {
	data []byte
	pos  int
}

func newBytesReader(data []byte) *bytesReader {
	return &bytesReader{data: data}
}

func (r *bytesReader) Read(p []byte) (n int, err error) {
	if r.pos >= len(r.data) {
		return 0, io.EOF
	}
	n = copy(p, r.data[r.pos:])
	r.pos += n
	return n, nil
}
