package gradlex

import (
	"testing"
)

func TestParseVersionCatalog_Versions(t *testing.T) {
	content := []byte(`
[versions]
kotlin = "1.9.0"
grpc = "1.58.1"
guava = "32.0.1-jre"
`)

	catalog, err := ParseVersionCatalog(content)
	if err != nil {
		t.Fatalf("ParseVersionCatalog failed: %v", err)
	}

	expected := map[string]string{
		"kotlin": "1.9.0",
		"grpc":   "1.58.1",
		"guava":  "32.0.1-jre",
	}

	for k, v := range expected {
		if catalog.Versions[k] != v {
			t.Errorf("Versions[%q] = %q, want %q", k, catalog.Versions[k], v)
		}
	}
}

func TestParseVersionCatalog_Libraries(t *testing.T) {
	content := []byte(`
[versions]
grpc = "1.58.1"

[libraries]
grpc-api = { group = "io.grpc", name = "grpc-api", version.ref = "grpc" }
guava = "com.google.guava:guava:32.0.1-jre"
jackson-core = { module = "com.fasterxml.jackson.core:jackson-core", version = "2.15.4" }
`)

	catalog, err := ParseVersionCatalog(content)
	if err != nil {
		t.Fatalf("ParseVersionCatalog failed: %v", err)
	}

	if len(catalog.Libraries) != 3 {
		t.Fatalf("expected 3 libraries, got %d", len(catalog.Libraries))
	}

	// Check grpc-api (using version.ref)
	if lib, ok := catalog.Libraries["grpc-api"]; ok {
		if lib.Group != "io.grpc" {
			t.Errorf("grpc-api.Group = %q, want %q", lib.Group, "io.grpc")
		}
		if lib.Name != "grpc-api" {
			t.Errorf("grpc-api.Name = %q, want %q", lib.Name, "grpc-api")
		}
		if lib.Version != "1.58.1" {
			t.Errorf("grpc-api.Version = %q, want %q", lib.Version, "1.58.1")
		}
	} else {
		t.Error("grpc-api library not found")
	}

	// Check guava (string shorthand)
	if lib, ok := catalog.Libraries["guava"]; ok {
		if lib.Group != "com.google.guava" {
			t.Errorf("guava.Group = %q, want %q", lib.Group, "com.google.guava")
		}
		if lib.Name != "guava" {
			t.Errorf("guava.Name = %q, want %q", lib.Name, "guava")
		}
		if lib.Version != "32.0.1-jre" {
			t.Errorf("guava.Version = %q, want %q", lib.Version, "32.0.1-jre")
		}
	} else {
		t.Error("guava library not found")
	}

	// Check jackson-core (using module shorthand)
	if lib, ok := catalog.Libraries["jackson-core"]; ok {
		if lib.Group != "com.fasterxml.jackson.core" {
			t.Errorf("jackson-core.Group = %q, want %q", lib.Group, "com.fasterxml.jackson.core")
		}
		if lib.Name != "jackson-core" {
			t.Errorf("jackson-core.Name = %q, want %q", lib.Name, "jackson-core")
		}
		if lib.Version != "2.15.4" {
			t.Errorf("jackson-core.Version = %q, want %q", lib.Version, "2.15.4")
		}
	} else {
		t.Error("jackson-core library not found")
	}
}

func TestParseVersionCatalog_Bundles(t *testing.T) {
	content := []byte(`
[libraries]
grpc-api = "io.grpc:grpc-api:1.58.1"
grpc-stub = "io.grpc:grpc-stub:1.58.1"

[bundles]
grpc = ["grpc-api", "grpc-stub"]
`)

	catalog, err := ParseVersionCatalog(content)
	if err != nil {
		t.Fatalf("ParseVersionCatalog failed: %v", err)
	}

	if len(catalog.Bundles) != 1 {
		t.Fatalf("expected 1 bundle, got %d", len(catalog.Bundles))
	}

	bundle, ok := catalog.Bundles["grpc"]
	if !ok {
		t.Fatal("grpc bundle not found")
	}

	if len(bundle) != 2 {
		t.Fatalf("expected 2 libraries in bundle, got %d", len(bundle))
	}

	if bundle[0] != "grpc-api" || bundle[1] != "grpc-stub" {
		t.Errorf("bundle = %v, want [grpc-api, grpc-stub]", bundle)
	}
}

func TestParseVersionCatalog_Plugins(t *testing.T) {
	content := []byte(`
[versions]
kotlin = "1.9.0"

[plugins]
kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
shadow = { id = "com.github.johnrengelman.shadow", version = "8.1.1" }
`)

	catalog, err := ParseVersionCatalog(content)
	if err != nil {
		t.Fatalf("ParseVersionCatalog failed: %v", err)
	}

	if len(catalog.Plugins) != 2 {
		t.Fatalf("expected 2 plugins, got %d", len(catalog.Plugins))
	}

	// Check kotlin-jvm (using version.ref)
	if plugin, ok := catalog.Plugins["kotlin-jvm"]; ok {
		if plugin.ID != "org.jetbrains.kotlin.jvm" {
			t.Errorf("kotlin-jvm.ID = %q, want %q", plugin.ID, "org.jetbrains.kotlin.jvm")
		}
		if plugin.Version != "1.9.0" {
			t.Errorf("kotlin-jvm.Version = %q, want %q", plugin.Version, "1.9.0")
		}
	} else {
		t.Error("kotlin-jvm plugin not found")
	}

	// Check shadow (direct version)
	if plugin, ok := catalog.Plugins["shadow"]; ok {
		if plugin.ID != "com.github.johnrengelman.shadow" {
			t.Errorf("shadow.ID = %q, want %q", plugin.ID, "com.github.johnrengelman.shadow")
		}
		if plugin.Version != "8.1.1" {
			t.Errorf("shadow.Version = %q, want %q", plugin.Version, "8.1.1")
		}
	} else {
		t.Error("shadow plugin not found")
	}
}

func TestVersionCatalog_GetLibraries(t *testing.T) {
	content := []byte(`
[versions]
grpc = "1.58.1"

[libraries]
grpc-api = { group = "io.grpc", name = "grpc-api", version.ref = "grpc" }
guava = "com.google.guava:guava:32.0.1-jre"
`)

	catalog, err := ParseVersionCatalog(content)
	if err != nil {
		t.Fatalf("ParseVersionCatalog failed: %v", err)
	}

	deps := catalog.GetLibraries()
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies, got %d", len(deps))
	}

	// Verify all deps have resolved versions
	for _, dep := range deps {
		if !dep.IsResolved() {
			t.Errorf("dependency %s has unresolved version: %s", dep.Name(), dep.Version)
		}
	}
}

func TestVersionCatalog_ToProperties(t *testing.T) {
	content := []byte(`
[versions]
kotlin = "1.9.0"
grpc = "1.58.1"
`)

	catalog, err := ParseVersionCatalog(content)
	if err != nil {
		t.Fatalf("ParseVersionCatalog failed: %v", err)
	}

	props := catalog.ToProperties()

	// Should have both raw and Version-suffixed entries
	expectedKeys := []string{"kotlin", "kotlinVersion", "grpc", "grpcVersion"}
	for _, key := range expectedKeys {
		if _, ok := props[key]; !ok {
			t.Errorf("expected key %q in properties", key)
		}
	}
}

func TestVersionCatalog_GetBundleLibraries(t *testing.T) {
	content := []byte(`
[libraries]
grpc-api = "io.grpc:grpc-api:1.58.1"
grpc-stub = "io.grpc:grpc-stub:1.58.1"
guava = "com.google.guava:guava:32.0.1-jre"

[bundles]
grpc = ["grpc-api", "grpc-stub"]
`)

	catalog, err := ParseVersionCatalog(content)
	if err != nil {
		t.Fatalf("ParseVersionCatalog failed: %v", err)
	}

	deps := catalog.GetBundleLibraries("grpc")
	if len(deps) != 2 {
		t.Fatalf("expected 2 dependencies in grpc bundle, got %d", len(deps))
	}

	// Verify guava is not included
	for _, dep := range deps {
		if dep.GroupID == "com.google.guava" {
			t.Error("guava should not be in grpc bundle")
		}
	}
}
