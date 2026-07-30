package graph

import (
	"testing"
)

func TestMavenResolver_Ecosystem(t *testing.T) {
	r := NewMavenResolver()
	if got := r.Ecosystem(); got != "Maven" {
		t.Errorf("Ecosystem() = %q, want %q", got, "Maven")
	}
}

func TestMavenResolver_ResolveEdges_PomXML(t *testing.T) {
	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>myapp</artifactId>
    <version>1.0.0</version>

    <properties>
        <spring.version>5.3.20</spring.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>${spring.version}</version>
        </dependency>
        <dependency>
            <groupId>com.google.guava</groupId>
            <artifactId>guava</artifactId>
            <version>31.1-jre</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>`

	files := &mockFileReader{
		files: map[string][]byte{
			"pom.xml": []byte(pomXML),
		},
	}

	g := New()
	r := NewMavenResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have root + 2 runtime deps (junit is test scope, skipped)
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}

	// Expect: myapp (root) + spring-core + guava = 3 nodes
	if nodeCount < 3 {
		t.Errorf("Expected at least 3 nodes, got %d", nodeCount)
	}

	// Check spring-core with property resolution
	springPURL := "pkg:maven/org.springframework/spring-core@5.3.20"
	if node := g.Node(springPURL); node == nil {
		t.Errorf("Expected node %s to exist", springPURL)
	}

	// Check guava
	guavaPURL := "pkg:maven/com.google.guava/guava@31.1-jre"
	if node := g.Node(guavaPURL); node == nil {
		t.Errorf("Expected node %s to exist", guavaPURL)
	}

	// Check test dependency was skipped
	junitPURL := "pkg:maven/junit/junit@4.13.2"
	if node := g.Node(junitPURL); node != nil {
		t.Errorf("Expected test scope dependency %s to be skipped", junitPURL)
	}

	// Check edges exist
	edgeCount := 0
	for range g.Edges() {
		edgeCount++
	}
	if edgeCount < 2 {
		t.Errorf("Expected at least 2 edges, got %d", edgeCount)
	}
}

func TestMavenResolver_ResolveEdges_GradleLockfile(t *testing.T) {
	gradleLock := `# This is a Gradle generated file for dependency locking.
# Manual edits can break the build and are not advised.
# This file is expected to be part of source control.
com.google.code.gson:gson:2.10.1=compileClasspath,runtimeClasspath
org.slf4j:slf4j-api:2.0.7=compileClasspath,runtimeClasspath
org.apache.commons:commons-lang3:3.12.0=compileClasspath,runtimeClasspath
empty=`

	files := &mockFileReader{
		files: map[string][]byte{
			"gradle.lockfile": []byte(gradleLock),
		},
	}

	g := New()
	r := NewMavenResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have 3 packages
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}
	if nodeCount != 3 {
		t.Errorf("Expected 3 nodes, got %d", nodeCount)
	}

	// Check gson
	gsonPURL := "pkg:maven/com.google.code.gson/gson@2.10.1"
	if node := g.Node(gsonPURL); node == nil {
		t.Errorf("Expected node %s to exist", gsonPURL)
	} else if node.Name != "com.google.code.gson:gson" {
		t.Errorf("Expected name %q, got %q", "com.google.code.gson:gson", node.Name)
	}

	// Check slf4j
	slf4jPURL := "pkg:maven/org.slf4j/slf4j-api@2.0.7"
	if node := g.Node(slf4jPURL); node == nil {
		t.Errorf("Expected node %s to exist", slf4jPURL)
	}

	// Check commons-lang3
	commonsPURL := "pkg:maven/org.apache.commons/commons-lang3@3.12.0"
	if node := g.Node(commonsPURL); node == nil {
		t.Errorf("Expected node %s to exist", commonsPURL)
	}
}

func TestMavenResolver_ResolveEdges_ParentInheritance(t *testing.T) {
	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.example</groupId>
        <artifactId>parent-pom</artifactId>
        <version>2.0.0</version>
    </parent>

    <artifactId>child-module</artifactId>

    <dependencies>
        <dependency>
            <groupId>org.apache.logging.log4j</groupId>
            <artifactId>log4j-core</artifactId>
            <version>2.20.0</version>
        </dependency>
    </dependencies>
</project>`

	files := &mockFileReader{
		files: map[string][]byte{
			"pom.xml": []byte(pomXML),
		},
	}

	g := New()
	r := NewMavenResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Root should inherit groupId and version from parent
	rootPURL := "pkg:maven/com.example/child-module@2.0.0"
	if node := g.Node(rootPURL); node == nil {
		t.Errorf("Expected root node %s with inherited coordinates", rootPURL)
	}

	// Check log4j dependency
	log4jPURL := "pkg:maven/org.apache.logging.log4j/log4j-core@2.20.0"
	if node := g.Node(log4jPURL); node == nil {
		t.Errorf("Expected node %s to exist", log4jPURL)
	}
}

func TestMavenResolver_ResolveEdges_DependencyManagement(t *testing.T) {
	pomXML := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>managed-deps</artifactId>
    <version>1.0.0</version>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-databind</artifactId>
                <version>2.15.2</version>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
        </dependency>
    </dependencies>
</project>`

	files := &mockFileReader{
		files: map[string][]byte{
			"pom.xml": []byte(pomXML),
		},
	}

	g := New()
	r := NewMavenResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// jackson-databind should get version from dependency management
	jacksonPURL := "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.15.2"
	if node := g.Node(jacksonPURL); node == nil {
		t.Errorf("Expected node %s with version from dependency management", jacksonPURL)
	}
}

func TestMavenResolver_ResolveEdges_NoFiles(t *testing.T) {
	files := &mockFileReader{
		files: map[string][]byte{},
	}

	g := New()
	r := NewMavenResolver()

	err := r.ResolveEdges(t.Context(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges() error = %v", err)
	}

	// Should have no nodes
	nodeCount := 0
	for range g.Nodes() {
		nodeCount++
	}
	if nodeCount != 0 {
		t.Errorf("Expected 0 nodes, got %d", nodeCount)
	}
}

func TestMavenPkgToPURL(t *testing.T) {
	tests := []struct {
		groupID    string
		artifactID string
		version    string
		want       string
	}{
		{
			groupID:    "com.google.guava",
			artifactID: "guava",
			version:    "31.1-jre",
			want:       "pkg:maven/com.google.guava/guava@31.1-jre",
		},
		{
			groupID:    "org.springframework",
			artifactID: "spring-core",
			version:    "5.3.20",
			want:       "pkg:maven/org.springframework/spring-core@5.3.20",
		},
		{
			groupID:    "junit",
			artifactID: "junit",
			version:    "",
			want:       "pkg:maven/junit/junit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.groupID+":"+tt.artifactID, func(t *testing.T) {
			got := mavenPkgToPURL(tt.groupID, tt.artifactID, tt.version)
			if got != tt.want {
				t.Errorf("mavenPkgToPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMavenNameToPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "com.google.guava:guava",
			version: "31.1-jre",
			want:    "pkg:maven/com.google.guava/guava@31.1-jre",
		},
		{
			name:    "org.springframework:spring-core",
			version: "5.3.20",
			want:    "pkg:maven/org.springframework/spring-core@5.3.20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mavenNameToPURL(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("mavenNameToPURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
