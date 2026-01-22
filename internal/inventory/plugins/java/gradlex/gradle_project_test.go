package gradlex

import (
	"context"
	"io"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

func TestGradleProjectExtractor_FileRequired(t *testing.T) {
	e := NewGradleProjectExtractor()

	tests := []struct {
		path     string
		expected bool
	}{
		{"settings.gradle", true},
		{"settings.gradle.kts", true},
		{"project/settings.gradle", true},
		{"project/settings.gradle.kts", true},
		{"build.gradle", false},
		{"build.gradle.kts", false},
		{"gradle.properties", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			api := &testFileAPI{path: tt.path}
			got := e.FileRequired(api)
			if got != tt.expected {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestGradleProjectExtractor_Extract(t *testing.T) {
	// Create an in-memory filesystem representing a Gradle project
	memFS := fstest.MapFS{
		"settings.gradle": &fstest.MapFile{
			Data: []byte(`rootProject.name = 'test-project'`),
		},
		"gradle.properties": &fstest.MapFile{
			Data: []byte(`grpcVersion=1.58.1
guavaVersion=32.0.1-jre`),
		},
		"build.gradle": &fstest.MapFile{
			Data: []byte(`
plugins {
    id 'java'
}

ext {
    jacksonVersion = '2.15.4'
}

dependencies {
    implementation "io.grpc:grpc-api:$grpcVersion"
    implementation "com.google.guava:guava:$guavaVersion"
    implementation "com.fasterxml.jackson.core:jackson-core:$jacksonVersion"
    testImplementation "junit:junit:4.13.2"
}
`),
		},
	}

	e := NewGradleProjectExtractor()
	input := &filesystem.ScanInput{
		Path:   "settings.gradle",
		FS:     &mapFSAdapter{memFS},
		Reader: newBytesReader(memFS["settings.gradle"].Data),
	}

	inv, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(inv.Packages) == 0 {
		t.Fatal("expected packages to be extracted")
	}

	// Verify specific packages were extracted with resolved versions
	foundPackages := make(map[string]string)
	for _, pkg := range inv.Packages {
		foundPackages[pkg.Name] = pkg.Version
	}

	expected := map[string]string{
		"io.grpc:grpc-api":                    "1.58.1",
		"com.google.guava:guava":              "32.0.1-jre",
		"com.fasterxml.jackson.core:jackson-core": "2.15.4",
		"junit:junit":                         "4.13.2",
	}

	for name, version := range expected {
		if foundPackages[name] != version {
			t.Errorf("package %q: got version %q, want %q", name, foundPackages[name], version)
		}
	}
}

func TestGradleProjectExtractor_ExtractWithVersionCatalog(t *testing.T) {
	memFS := fstest.MapFS{
		"settings.gradle": &fstest.MapFile{
			Data: []byte(`rootProject.name = 'catalog-project'`),
		},
		"gradle/libs.versions.toml": &fstest.MapFile{
			Data: []byte(`
[versions]
grpc = "1.60.0"
guava = "33.0.0-jre"

[libraries]
grpc-api = { group = "io.grpc", name = "grpc-api", version.ref = "grpc" }
guava = "com.google.guava:guava:33.0.0-jre"
`),
		},
		"build.gradle": &fstest.MapFile{
			Data: []byte(`
plugins {
    id 'java'
}

dependencies {
    implementation libs.grpc.api
    implementation libs.guava
}
`),
		},
	}

	e := NewGradleProjectExtractor()
	input := &filesystem.ScanInput{
		Path:   "settings.gradle",
		FS:     &mapFSAdapter{memFS},
		Reader: newBytesReader(memFS["settings.gradle"].Data),
	}

	inv, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Version catalog libraries should be included
	foundGrpc := false
	foundGuava := false
	for _, pkg := range inv.Packages {
		if pkg.Name == "io.grpc:grpc-api" && pkg.Version == "1.60.0" {
			foundGrpc = true
		}
		if pkg.Name == "com.google.guava:guava" && pkg.Version == "33.0.0-jre" {
			foundGuava = true
		}
	}

	if !foundGrpc {
		t.Error("expected to find io.grpc:grpc-api:1.60.0 from version catalog")
	}
	if !foundGuava {
		t.Error("expected to find com.google.guava:guava:33.0.0-jre from version catalog")
	}
}

func TestGradleProjectExtractor_ExtractWithVerificationMetadata(t *testing.T) {
	memFS := fstest.MapFS{
		"settings.gradle": &fstest.MapFile{
			Data: []byte(`rootProject.name = 'verified-project'`),
		},
		"gradle/verification-metadata.xml": &fstest.MapFile{
			Data: []byte(`<?xml version="1.0" encoding="UTF-8"?>
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
   </components>
</verification-metadata>`),
		},
		"build.gradle": &fstest.MapFile{
			Data: []byte(`
dependencies {
    implementation "io.grpc:grpc-api"
    implementation "com.google.guava:guava"
}
`),
		},
	}

	e := NewGradleProjectExtractor()
	input := &filesystem.ScanInput{
		Path:   "settings.gradle",
		FS:     &mapFSAdapter{memFS},
		Reader: newBytesReader(memFS["settings.gradle"].Data),
	}

	inv, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Should use verification-metadata.xml as the source (most reliable)
	if len(inv.Packages) != 2 {
		t.Fatalf("expected 2 packages from verification metadata, got %d", len(inv.Packages))
	}

	for _, pkg := range inv.Packages {
		// All packages from verification metadata should have concrete versions
		if pkg.Version == "" {
			t.Errorf("package %s has empty version", pkg.Name)
		}
	}
}

func TestGradleProjectExtractor_MultiModule(t *testing.T) {
	memFS := fstest.MapFS{
		"settings.gradle": &fstest.MapFile{
			Data: []byte(`
rootProject.name = 'multi-module'
include 'core'
include 'api'
`),
		},
		"gradle.properties": &fstest.MapFile{
			Data: []byte(`commonVersion=1.0.0`),
		},
		"build.gradle": &fstest.MapFile{
			Data: []byte(`
subprojects {
    dependencies {
        implementation "org.slf4j:slf4j-api:1.7.36"
    }
}
`),
		},
		"core/build.gradle": &fstest.MapFile{
			Data: []byte(`
dependencies {
    implementation "com.google.guava:guava:32.0.1-jre"
}
`),
		},
		"api/build.gradle": &fstest.MapFile{
			Data: []byte(`
dependencies {
    implementation "io.grpc:grpc-api:1.58.1"
}
`),
		},
	}

	e := NewGradleProjectExtractor()
	input := &filesystem.ScanInput{
		Path:   "settings.gradle",
		FS:     &mapFSAdapter{memFS},
		Reader: newBytesReader(memFS["settings.gradle"].Data),
	}

	inv, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	// Should find dependencies from all modules
	foundPackages := make(map[string]bool)
	for _, pkg := range inv.Packages {
		foundPackages[pkg.Name] = true
	}

	expectedDeps := []string{
		"org.slf4j:slf4j-api",
		"com.google.guava:guava",
		"io.grpc:grpc-api",
	}

	for _, dep := range expectedDeps {
		if !foundPackages[dep] {
			t.Errorf("expected to find %s in multi-module project", dep)
		}
	}
}

func TestParseSettingsGradle(t *testing.T) {
	tests := []struct {
		name            string
		content         string
		expectedName    string
		expectedModules []string
	}{
		{
			name: "simple project",
			content: `rootProject.name = 'my-project'`,
			expectedName:    "my-project",
			expectedModules: nil,
		},
		{
			name: "multi-module groovy",
			content: `
rootProject.name = 'parent'
include 'core'
include 'api'
include 'web'
`,
			expectedName:    "parent",
			expectedModules: []string{"core", "api", "web"},
		},
		{
			name: "kotlin DSL",
			content: `
rootProject.name = "kotlin-project"
include("module-a")
include("module-b")
`,
			expectedName:    "kotlin-project",
			expectedModules: []string{"module-a", "module-b"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			settings, err := ParseSettingsGradle([]byte(tt.content))
			if err != nil {
				t.Fatalf("ParseSettingsGradle failed: %v", err)
			}

			if settings.RootProjectName != tt.expectedName {
				t.Errorf("RootProjectName = %q, want %q", settings.RootProjectName, tt.expectedName)
			}

			if len(tt.expectedModules) > 0 {
				if !settings.IsMultiModule() {
					t.Error("expected IsMultiModule() to be true")
				}
				for _, mod := range tt.expectedModules {
					found := false
					for _, inc := range settings.Includes {
						if inc == mod {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("expected module %q in includes", mod)
					}
				}
			}
		})
	}
}

// testFileAPI implements filesystem.FileAPI for testing FileRequired.
type testFileAPI struct {
	path string
}

func (f *testFileAPI) Path() string { return f.path }
func (f *testFileAPI) Stat() (fs.FileInfo, error) { return nil, nil }
func (f *testFileAPI) Open() (io.ReadCloser, error) { return nil, nil }

// mapFSAdapter wraps fstest.MapFS to implement scalibrfs.FS.
type mapFSAdapter struct {
	fstest.MapFS
}

func (m *mapFSAdapter) Open(name string) (fs.File, error) {
	return m.MapFS.Open(name)
}
