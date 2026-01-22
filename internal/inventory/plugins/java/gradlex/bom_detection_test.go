package gradlex

import (
	"testing"
)

func TestParseBOMs_Platform(t *testing.T) {
	content := []byte(`
plugins {
    id 'java'
}

dependencies {
    implementation platform("org.springframework.boot:spring-boot-dependencies:3.2.0")
    implementation 'org.springframework.boot:spring-boot-starter-web'
}
`)

	boms := ParseBOMs(content, nil)
	if len(boms) != 1 {
		t.Fatalf("expected 1 BOM, got %d", len(boms))
	}

	bom := boms[0]
	if bom.GroupID != "org.springframework.boot" {
		t.Errorf("expected groupId 'org.springframework.boot', got '%s'", bom.GroupID)
	}
	if bom.ArtifactID != "spring-boot-dependencies" {
		t.Errorf("expected artifactId 'spring-boot-dependencies', got '%s'", bom.ArtifactID)
	}
	if bom.Version != "3.2.0" {
		t.Errorf("expected version '3.2.0', got '%s'", bom.Version)
	}
	if bom.Source != "platform" {
		t.Errorf("expected source 'platform', got '%s'", bom.Source)
	}
}

func TestParseBOMs_EnforcedPlatform(t *testing.T) {
	content := []byte(`
dependencies {
    implementation enforcedPlatform("io.grpc:grpc-bom:1.60.0")
    implementation 'io.grpc:grpc-netty-shaded'
}
`)

	boms := ParseBOMs(content, nil)
	if len(boms) != 1 {
		t.Fatalf("expected 1 BOM, got %d", len(boms))
	}

	bom := boms[0]
	if bom.GroupID != "io.grpc" {
		t.Errorf("expected groupId 'io.grpc', got '%s'", bom.GroupID)
	}
	if bom.ArtifactID != "grpc-bom" {
		t.Errorf("expected artifactId 'grpc-bom', got '%s'", bom.ArtifactID)
	}
	if bom.Version != "1.60.0" {
		t.Errorf("expected version '1.60.0', got '%s'", bom.Version)
	}
}

func TestParseBOMs_SpringBootPlugin(t *testing.T) {
	content := []byte(`
plugins {
    id 'java'
    id 'org.springframework.boot' version '3.2.0'
    id 'io.spring.dependency-management' version '1.1.4'
}

dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-web'
}
`)

	boms := ParseBOMs(content, nil)
	if len(boms) != 1 {
		t.Fatalf("expected 1 BOM (from spring-boot plugin), got %d", len(boms))
	}

	bom := boms[0]
	if bom.GroupID != "org.springframework.boot" {
		t.Errorf("expected groupId 'org.springframework.boot', got '%s'", bom.GroupID)
	}
	if bom.ArtifactID != "spring-boot-dependencies" {
		t.Errorf("expected artifactId 'spring-boot-dependencies', got '%s'", bom.ArtifactID)
	}
	if bom.Version != "3.2.0" {
		t.Errorf("expected version '3.2.0', got '%s'", bom.Version)
	}
	if bom.Source != "plugin" {
		t.Errorf("expected source 'plugin', got '%s'", bom.Source)
	}
}

func TestParseBOMs_QuarkusPlugin(t *testing.T) {
	content := []byte(`
plugins {
    id 'java'
    id 'io.quarkus' version '3.6.0'
}

dependencies {
    implementation 'io.quarkus:quarkus-resteasy'
}
`)

	boms := ParseBOMs(content, nil)
	if len(boms) != 1 {
		t.Fatalf("expected 1 BOM (from quarkus plugin), got %d", len(boms))
	}

	bom := boms[0]
	if bom.GroupID != "io.quarkus.platform" {
		t.Errorf("expected groupId 'io.quarkus.platform', got '%s'", bom.GroupID)
	}
	if bom.ArtifactID != "quarkus-bom" {
		t.Errorf("expected artifactId 'quarkus-bom', got '%s'", bom.ArtifactID)
	}
	if bom.Version != "3.6.0" {
		t.Errorf("expected version '3.6.0', got '%s'", bom.Version)
	}
}

func TestParseBOMs_MultipleBOMs(t *testing.T) {
	content := []byte(`
plugins {
    id 'org.springframework.boot' version '3.2.0'
}

dependencies {
    implementation platform("com.fasterxml.jackson:jackson-bom:2.15.3")
    implementation 'com.fasterxml.jackson.core:jackson-databind'
    implementation 'org.springframework.boot:spring-boot-starter-web'
}
`)

	boms := ParseBOMs(content, nil)
	if len(boms) != 2 {
		t.Fatalf("expected 2 BOMs, got %d", len(boms))
	}

	// Check that we have both Spring Boot (from plugin) and Jackson (from platform)
	foundSpringBoot := false
	foundJackson := false
	for _, bom := range boms {
		if bom.GroupID == "org.springframework.boot" && bom.ArtifactID == "spring-boot-dependencies" {
			foundSpringBoot = true
		}
		if bom.GroupID == "com.fasterxml.jackson" && bom.ArtifactID == "jackson-bom" {
			foundJackson = true
		}
	}

	if !foundSpringBoot {
		t.Error("expected to find Spring Boot BOM")
	}
	if !foundJackson {
		t.Error("expected to find Jackson BOM")
	}
}

func TestParseBOMs_KotlinDSL(t *testing.T) {
	content := []byte(`
plugins {
    java
    id("org.springframework.boot") version "3.2.0"
    id("io.spring.dependency-management") version "1.1.4"
}

dependencies {
    implementation(platform("org.junit:junit-bom:5.10.0"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}
`)

	boms := ParseBOMs(content, nil)
	if len(boms) != 2 {
		t.Fatalf("expected 2 BOMs, got %d", len(boms))
	}
}

func TestParseBOMs_VersionVariable(t *testing.T) {
	content := []byte(`
ext {
    springBootVersion = "3.2.0"
}

dependencies {
    implementation platform("org.springframework.boot:spring-boot-dependencies:$springBootVersion")
}
`)

	props := map[string]string{
		"springBootVersion": "3.2.0",
	}

	boms := ParseBOMs(content, props)
	if len(boms) != 1 {
		t.Fatalf("expected 1 BOM, got %d", len(boms))
	}

	bom := boms[0]
	if bom.Version != "3.2.0" {
		t.Errorf("expected version '3.2.0' (resolved from variable), got '%s'", bom.Version)
	}
}

func TestParseBOMs_NoBOMs(t *testing.T) {
	content := []byte(`
plugins {
    id 'java'
}

dependencies {
    implementation 'com.google.guava:guava:32.1.0-jre'
    testImplementation 'junit:junit:4.13.2'
}
`)

	boms := ParseBOMs(content, nil)
	if len(boms) != 0 {
		t.Fatalf("expected 0 BOMs, got %d", len(boms))
	}
}
