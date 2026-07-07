package gradlex

import (
	"testing"
)

func TestParseBuildGradle_StringNotation(t *testing.T) {
	content := []byte(`
plugins {
    id 'java'
}

dependencies {
    implementation "io.grpc:grpc-api:1.58.1"
    api 'com.google.guava:guava:32.0.1-jre'
    testImplementation "junit:junit:4.13.2"
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	expected := []struct {
		groupID    string
		artifactID string
		version    string
		scope      string
	}{
		{"io.grpc", "grpc-api", "1.58.1", "compile"},
		{"com.google.guava", "guava", "32.0.1-jre", "compile"},
		{"junit", "junit", "4.13.2", "test"},
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

func TestParseBuildGradle_VersionVariables(t *testing.T) {
	content := []byte(`
ext {
    grpcVersion = '1.58.1'
}

dependencies {
    implementation "io.grpc:grpc-api:$grpcVersion"
    api "com.google.guava:guava:${guavaVersion}"
}
`)

	props := map[string]string{
		"guavaVersion": "32.0.1-jre",
	}

	deps, err := ParseBuildGradle(content, props)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	// First dep should have version from ext block
	if deps[0].Version != "1.58.1" {
		t.Errorf("deps[0].Version = %q, want %q", deps[0].Version, "1.58.1")
	}

	// Second dep should have version from props
	if deps[1].Version != "32.0.1-jre" {
		t.Errorf("deps[1].Version = %q, want %q", deps[1].Version, "32.0.1-jre")
	}
}

func TestParseBuildGradle_Platform(t *testing.T) {
	content := []byte(`
dependencies {
    implementation platform("io.grpc:grpc-bom:1.58.1")
    implementation enforcedPlatform("org.springframework.boot:spring-boot-dependencies:2.7.18")
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	if deps[0].GroupID != "io.grpc" || deps[0].ArtifactID != "grpc-bom" {
		t.Errorf("deps[0] = %v, want io.grpc:grpc-bom", deps[0])
	}
	if deps[1].GroupID != "org.springframework.boot" || deps[1].ArtifactID != "spring-boot-dependencies" {
		t.Errorf("deps[1] = %v, want org.springframework.boot:spring-boot-dependencies", deps[1])
	}
}

func TestParseBuildGradle_MapNotation(t *testing.T) {
	content := []byte(`
dependencies {
    implementation group: 'io.grpc', name: 'grpc-api', version: '1.58.1'
    api group: "com.google.guava", name: "guava", version: "32.0.1-jre"
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	if deps[0].GroupID != "io.grpc" || deps[0].ArtifactID != "grpc-api" || deps[0].Version != "1.58.1" {
		t.Errorf("deps[0] = %v, want io.grpc:grpc-api:1.58.1", deps[0])
	}
}

func TestParseGradleProperties(t *testing.T) {
	content := []byte(`
# This is a comment
grpcVersion=1.58.1
guavaVersion = 32.0.1-jre
jacksonVersion= 2.15.4

# System property (should be skipped)
systemProp.http.proxyHost=proxy.example.com

# Continuation line
longValue=this is a \
  continued line
`)

	props := ParseGradleProperties(content)

	expected := map[string]string{
		"grpcVersion":    "1.58.1",
		"guavaVersion":   "32.0.1-jre",
		"jacksonVersion": "2.15.4",
		"longValue":      "this is a continued line",
	}

	for k, v := range expected {
		if props[k] != v {
			t.Errorf("props[%q] = %q, want %q", k, props[k], v)
		}
	}

	// Verify system property was skipped
	if _, ok := props["systemProp.http.proxyHost"]; ok {
		t.Error("systemProp.http.proxyHost should have been skipped")
	}
}

func TestParseExtBlock(t *testing.T) {
	content := []byte(`
buildscript {
    ext {
        grpcVersion = '1.58.1'
        jacksonVersion = "2.15.4"
    }
}

ext.guavaVersion = "32.0.1-jre"
`)

	props := ParseExtBlock(content)

	expected := map[string]string{
		"grpcVersion":    "1.58.1",
		"jacksonVersion": "2.15.4",
		"guavaVersion":   "32.0.1-jre",
	}

	for k, v := range expected {
		if props[k] != v {
			t.Errorf("props[%q] = %q, want %q", k, props[k], v)
		}
	}
}

func TestParseBuildGradle_KotlinDSL(t *testing.T) {
	content := []byte(`
plugins {
    kotlin("jvm") version "1.9.0"
}

dependencies {
    implementation("io.grpc:grpc-api:1.58.1")
    api("com.google.guava:guava:32.0.1-jre")
    testImplementation("junit:junit:4.13.2")
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	if len(deps) != 3 {
		t.Fatalf("expected 3 dependencies, got %d", len(deps))
	}

	if deps[0].GroupID != "io.grpc" || deps[0].ArtifactID != "grpc-api" {
		t.Errorf("deps[0] = %v, want io.grpc:grpc-api", deps[0])
	}
}

func TestParseBuildGradle_TemporalioBuildGradle(t *testing.T) {
	// Simplified version of temporalio/sdk-java's build.gradle
	content := []byte(`
buildscript {
    ext {
        palantirGitVersionVersion = "0.15.0"
    }
}

plugins {
    id 'net.ltgt.errorprone' version '4.1.0' apply false
    id 'org.jetbrains.kotlin.jvm' version '1.9.24' apply false
}

allprojects {
    repositories {
        mavenCentral()
    }
}

ext {
    grpcVersion = '1.58.1'
    jacksonVersion = '2.15.4'
    guavaVersion = '32.0.1-jre'
    slf4jVersion = '1.7.36'
    protoVersion = '3.25.8'
}

subprojects {
    dependencies {
        implementation "com.google.guava:guava:$guavaVersion"
    }
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	// Should find the guava dependency with resolved version
	found := false
	for _, dep := range deps {
		if dep.GroupID == "com.google.guava" && dep.ArtifactID == "guava" {
			found = true
			if dep.Version != "32.0.1-jre" {
				t.Errorf("guava version = %q, want %q", dep.Version, "32.0.1-jre")
			}
		}
	}

	if !found {
		t.Error("expected to find com.google.guava:guava dependency")
	}
}

func TestParseBuildGradle_BOMDependency(t *testing.T) {
	// Dependencies managed by a BOM have no version in build.gradle
	content := []byte(`
dependencies {
    // Import BOM
    implementation platform("io.grpc:grpc-bom:1.58.1")

    // Dependencies managed by BOM (no version specified)
    implementation "io.grpc:grpc-api"
    implementation "io.grpc:grpc-stub"

    // Dependency with explicit version
    implementation "com.google.guava:guava:32.0.1-jre"
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	// Should have 4 dependencies
	if len(deps) != 4 {
		t.Fatalf("expected 4 dependencies, got %d", len(deps))
	}

	// Check BOM itself has version
	var bomFound bool
	for _, dep := range deps {
		if dep.ArtifactID == "grpc-bom" {
			bomFound = true
			if dep.Version != "1.58.1" {
				t.Errorf("grpc-bom version = %q, want %q", dep.Version, "1.58.1")
			}
		}
	}
	if !bomFound {
		t.Error("expected to find grpc-bom")
	}

	// Check BOM-managed deps have empty versions
	for _, dep := range deps {
		if dep.ArtifactID == "grpc-api" || dep.ArtifactID == "grpc-stub" {
			if dep.Version != "" {
				t.Errorf("BOM-managed %s should have empty version, got %q", dep.ArtifactID, dep.Version)
			}
		}
	}

	// Check explicit version dep
	for _, dep := range deps {
		if dep.ArtifactID == "guava" {
			if dep.Version != "32.0.1-jre" {
				t.Errorf("guava version = %q, want %q", dep.Version, "32.0.1-jre")
			}
		}
	}
}

func TestParseBuildGradle_ExcludeBlock(t *testing.T) {
	// Ensure exclusion blocks don't create false dependencies
	content := []byte(`
dependencies {
    implementation ("com.fasterxml.jackson.module:jackson-module-kotlin:2.15.4") {
        exclude group: 'org.jetbrains.kotlin', module: 'kotlin-reflect'
        exclude group: 'org.jetbrains.kotlin', module: 'kotlin-stdlib'
    }
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	// Should only find the jackson-module-kotlin dependency, not the exclusions
	if len(deps) != 1 {
		t.Fatalf("expected 1 dependency, got %d: %+v", len(deps), deps)
	}

	if deps[0].ArtifactID != "jackson-module-kotlin" {
		t.Errorf("expected jackson-module-kotlin, got %s", deps[0].ArtifactID)
	}
}

func TestParseBuildGradle_TernaryExpression(t *testing.T) {
	// Ternary expressions in versions are a known limitation
	// The parser cannot evaluate project.hasProperty() calls
	content := []byte(`
ext {
    // Simple version
    grpcVersion = '1.58.1'
    // Ternary expression (known limitation - won't be parsed)
    micrometerVersion = project.hasProperty("edgeDepsTest") ? '1.13.6' : '1.9.9'
}

dependencies {
    implementation "io.grpc:grpc-api:$grpcVersion"
    implementation "io.micrometer:micrometer-core:$micrometerVersion"
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	// Check that grpc-api has resolved version
	var grpcResolved, micrometerUnresolved bool
	for _, dep := range deps {
		if dep.ArtifactID == "grpc-api" {
			grpcResolved = dep.Version == "1.58.1"
		}
		if dep.ArtifactID == "micrometer-core" {
			// Ternary expression leaves variable unresolved
			micrometerUnresolved = dep.Version == "$micrometerVersion"
		}
	}

	if !grpcResolved {
		t.Error("grpc-api should have resolved version 1.58.1")
	}
	if !micrometerUnresolved {
		t.Error("micrometer-core should have unresolved version (ternary limitation)")
	}
}

func TestParseBuildGradle_NestedDependenciesBlock(t *testing.T) {
	// Dependencies in subprojects/allprojects blocks
	content := []byte(`
ext {
    guavaVersion = '32.0.1-jre'
}

subprojects {
    dependencies {
        implementation "com.google.guava:guava:$guavaVersion"
    }
}

allprojects {
    dependencies {
        testImplementation "junit:junit:4.13.2"
    }
}
`)

	deps, err := ParseBuildGradle(content, nil)
	if err != nil {
		t.Fatalf("ParseBuildGradle failed: %v", err)
	}

	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	// Check guava has resolved version
	for _, dep := range deps {
		if dep.ArtifactID == "guava" && dep.Version != "32.0.1-jre" {
			t.Errorf("guava version = %q, want %q", dep.Version, "32.0.1-jre")
		}
	}
}

func TestMavenDependency_IsResolved_Comprehensive(t *testing.T) {
	tests := []struct {
		name     string
		dep      MavenDependency
		expected bool
	}{
		// Resolved cases
		{"simple version", MavenDependency{Version: "1.0.0"}, true},
		{"version with qualifier", MavenDependency{Version: "1.0.0-jre"}, true},
		{"version with rc", MavenDependency{Version: "1.0.0-rc1"}, true},
		{"version with SNAPSHOT", MavenDependency{Version: "1.0.0-SNAPSHOT"}, true},

		// Unresolved cases
		{"empty version", MavenDependency{Version: ""}, false},
		{"$variable", MavenDependency{Version: "$grpcVersion"}, false},
		{"${variable}", MavenDependency{Version: "${grpcVersion}"}, false},
		{"nested variable", MavenDependency{Version: "${rootProject.ext.grpcVersion}"}, false},
		{"version range [,)", MavenDependency{Version: "[1.0,2.0)"}, false},
		{"version range (,]", MavenDependency{Version: "(1.0,2.0]"}, false},
		{"dynamic +", MavenDependency{Version: "1.+"}, false},
		{"latest.release", MavenDependency{Version: "latest.release"}, false},
		{"latest.integration", MavenDependency{Version: "latest.integration"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.dep.IsResolved()
			if got != tt.expected {
				t.Errorf("IsResolved() = %v, want %v for version %q", got, tt.expected, tt.dep.Version)
			}
		})
	}
}

func TestIsValidMavenCoordinate(t *testing.T) {
	tests := []struct {
		group    string
		artifact string
		valid    bool
	}{
		// Valid coordinates
		{"io.grpc", "grpc-api", true},
		{"com.google.guava", "guava", true},
		{"junit", "junit", true}, // short but >= 3 chars
		{"org.slf4j", "slf4j-api", true},

		// Invalid coordinates
		{"", "artifact", false},                 // empty group
		{"group", "", false},                    // empty artifact
		{"a", "artifact", false},                // group too short, no dot
		{"ab", "artifact", false},               // group too short, no dot
		{", module", " ", false},                // exclusion syntax fragment
		{"group", "a", false},                   // artifact too short
		{"com.example, other", "x", false},      // comma in group
		{"com.example", "artifact name", false}, // space in artifact
	}

	for _, tt := range tests {
		t.Run(tt.group+":"+tt.artifact, func(t *testing.T) {
			got := isValidMavenCoordinate(tt.group, tt.artifact)
			if got != tt.valid {
				t.Errorf("isValidMavenCoordinate(%q, %q) = %v, want %v", tt.group, tt.artifact, got, tt.valid)
			}
		})
	}
}
