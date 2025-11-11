package cmd

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	scalpurl "github.com/google/osv-scalibr/purl"
	analysis "github.com/picatz/deputy/internal/analysis"
	cmp "github.com/picatz/deputy/internal/compare"
)

// Test that packagesToInputs includes all packages and determines directness
// using go.mod in the current working directory.
func TestPackagesToInputs_AllPackages(t *testing.T) {
	goMod := `module example.com/app

require (
    github.com/golang-jwt/jwt/v4 v4.5.1
    github.com/indirect/pkg v1.2.3 // indirect
)`
	deps := cmp.GetDirectDependenciesFromGoMod([]byte(goMod))

	pkgs := []*extractor.Package{
		{Name: "github.com/golang-jwt/jwt/v4", Version: "v4.5.1", PURLType: scalpurl.TypeGolang},
		{Name: "github.com/indirect/pkg", Version: "v1.2.3", PURLType: scalpurl.TypeGolang},
	}

	inputs := packagesToInputs(pkgs, packageInputOptions{GoDirect: deps})
	if len(inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(inputs))
	}

	var directFound, indirectFound bool
	for _, in := range inputs {
		switch in.Name {
		case "github.com/golang-jwt/jwt/v4":
			if !in.IsDirect {
				t.Errorf("expected jwt dependency to be direct")
			}
			directFound = true
		case "github.com/indirect/pkg":
			if in.IsDirect {
				t.Errorf("expected indirect/pkg to be indirect")
			}
			indirectFound = true
		}
	}
	if !directFound || !indirectFound {
		t.Fatalf("missing expected inputs: %+v", inputs)
	}
}

// Ensure gopkg.in modules retain their original import path and directness.
func TestPackagesToInputs_GopkgInPreserved(t *testing.T) {
	goMod := `module example.com/app

require (
    gopkg.in/yaml.v3 v3.0.1
    gopkg.in/indirect.v3 v3.0.0 // indirect
)`
	deps := cmp.GetDirectDependenciesFromGoMod([]byte(goMod))

	pkgs := []*extractor.Package{
		{Name: "gopkg.in/yaml.v3", Version: "v3.0.1", PURLType: scalpurl.TypeGolang},
		{Name: "gopkg.in/indirect.v3", Version: "v3.0.0", PURLType: scalpurl.TypeGolang},
	}

	inputs := packagesToInputs(pkgs, packageInputOptions{GoDirect: deps})
	if len(inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(inputs))
	}

	for _, in := range inputs {
		switch in.Name {
		case "gopkg.in/yaml.v3":
			if !in.IsDirect {
				t.Errorf("expected yaml to be direct")
			}
		case "gopkg.in/indirect.v3":
			if in.IsDirect {
				t.Errorf("expected indirect to be indirect")
			}
		default:
			t.Errorf("unexpected package %s", in.Name)
		}
	}
}

func TestPackagesToInputs_NPMDirectDetection(t *testing.T) {
	files := map[string]string{
		"web/package.json": `{
		  "name": "web",
		  "dependencies": {
		    "react": "18.2.0"
		  },
		  "devDependencies": {
		    "typescript": "5.1.0"
		  }
		}`,
	}
	resolver := manifestResolverFunc(func(rel string) ([]byte, error) {
		if data, ok := files[filepath.ToSlash(rel)]; ok {
			return []byte(data), nil
		}
		return nil, fmt.Errorf("not found: %s", rel)
	})

	pkgs := []*extractor.Package{
		{
			Name:      "react",
			Version:   "18.2.0",
			PURLType:  scalpurl.TypeNPM,
			Locations: []string{"web/package-lock.json"},
		},
		{
			Name:      "typescript",
			Version:   "5.1.0",
			PURLType:  scalpurl.TypeNPM,
			Locations: []string{"web/package-lock.json"},
		},
		{
			Name:      "left-pad",
			Version:   "1.3.0",
			PURLType:  scalpurl.TypeNPM,
			Locations: []string{"web/package-lock.json"},
		},
	}

	inputs := packagesToInputs(pkgs, packageInputOptions{Resolver: resolver})
	if len(inputs) != 3 {
		t.Fatalf("expected 3 inputs, got %d", len(inputs))
	}

	lookup := map[string]analysis.PkgInput{}
	for _, in := range inputs {
		lookup[in.Name] = in
	}

	if !lookup["react"].IsDirect {
		t.Fatalf("react should be direct due to dependencies")
	}
	if len(lookup["react"].ManifestRefs) == 0 || lookup["react"].ManifestRefs[0].Manager != "npm" {
		t.Fatalf("react manifest reference missing or incorrect: %+v", lookup["react"].ManifestRefs)
	}
	if !containsGroup(lookup["react"].ManifestRefs[0].Groups, "dependencies") {
		t.Fatalf("react expected dependencies group: %+v", lookup["react"].ManifestRefs[0].Groups)
	}
	if lookup["typescript"].IsDirect {
		t.Fatalf("typescript dev dependency should be indirect")
	}
	if !containsGroup(lookup["typescript"].ManifestRefs[0].Groups, "devDependencies") {
		t.Fatalf("typescript expected devDependencies group: %+v", lookup["typescript"].ManifestRefs[0].Groups)
	}
	if lookup["left-pad"].IsDirect {
		t.Fatalf("left-pad should remain indirect")
	}
}

func TestPackagesToInputs_UVLockDirectDetection(t *testing.T) {
	uvLock := `version = 1

[[package]]
name = "runtime-one"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "runtime-two"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "optional-one"
version = "0.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "project"
version = "0.0.1"
source = { virtual = "." }
dependencies = [
    { name = "runtime-one" },
    { name = "runtime-two" },
]
[package.optional-dependencies]
extras = [
    { name = "optional-one" },
]
[package.dev-dependencies]
dev = [
    { name = "pytest" },
]
`
	resolver := manifestResolverFunc(func(rel string) ([]byte, error) {
		if filepath.ToSlash(rel) == "uv.lock" {
			return []byte(uvLock), nil
		}
		return nil, fmt.Errorf("not found")
	})

	pkgs := []*extractor.Package{
		{Name: "runtime-one", Version: "1.0.0", PURLType: scalpurl.TypePyPi, Locations: []string{"uv.lock"}},
		{Name: "optional-one", Version: "0.1.0", PURLType: scalpurl.TypePyPi, Locations: []string{"uv.lock"}},
		{Name: "pytest", Version: "7.0.0", PURLType: scalpurl.TypePyPi, Locations: []string{"uv.lock"}},
		{Name: "transitive", Version: "0.0.1", PURLType: scalpurl.TypePyPi, Locations: []string{"uv.lock"}},
	}

	inputs := packagesToInputs(pkgs, packageInputOptions{Resolver: resolver})
	if len(inputs) != 4 {
		t.Fatalf("expected 4 inputs, got %d", len(inputs))
	}
	lookup := map[string]analysis.PkgInput{}
	for _, in := range inputs {
		lookup[in.Name] = in
	}
	if !lookup["runtime-one"].IsDirect {
		t.Fatalf("runtime-one should be direct from uv.lock")
	}
	if lookup["optional-one"].IsDirect {
		t.Fatalf("optional-one should not be direct (optional group)")
	}
	if groups := lookup["optional-one"].ManifestRefs[0].Groups; len(groups) == 0 || groups[0] != "extras" {
		t.Fatalf("expected optional-one groups to include extras, got %+v", lookup["optional-one"].ManifestRefs)
	}
	if lookup["pytest"].IsDirect {
		t.Fatalf("pytest (dev) should not be direct")
	}
	if len(lookup["runtime-one"].ManifestRefs) == 0 || lookup["runtime-one"].ManifestRefs[0].Manager != "uv" {
		t.Fatalf("runtime-one manifest ref should point to uv.lock")
	}
}

func TestPackagesToInputs_CargoDirectDetection(t *testing.T) {
	cargoToml := `[package]
name = "demo"
version = "0.1.0"

[dependencies]
tokio = "1.0"
bytes = { version = "1.0" }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"

[workspace.dependencies]
serde = "1.0"

[target."cfg(unix)".dependencies]
libc = "0.2"
`
	resolver := manifestResolverFunc(func(rel string) ([]byte, error) {
		if filepath.ToSlash(rel) == "Cargo.toml" {
			return []byte(cargoToml), nil
		}
		return nil, fmt.Errorf("not found: %s", rel)
	})
	pkgs := []*extractor.Package{
		{Name: "tokio", Version: "1.0.0", PURLType: scalpurl.TypeCargo, Locations: []string{"Cargo.lock"}},
		{Name: "criterion", Version: "0.5.0", PURLType: scalpurl.TypeCargo, Locations: []string{"Cargo.lock"}},
		{Name: "serde", Version: "1.0.0", PURLType: scalpurl.TypeCargo, Locations: []string{"Cargo.lock"}},
		{Name: "cc", Version: "1.0.0", PURLType: scalpurl.TypeCargo, Locations: []string{"Cargo.lock"}},
		{Name: "libc", Version: "0.2.0", PURLType: scalpurl.TypeCargo, Locations: []string{"Cargo.lock"}},
	}
	inputs := packagesToInputs(pkgs, packageInputOptions{Resolver: resolver})
	if len(inputs) != 5 {
		t.Fatalf("expected 5 inputs, got %d", len(inputs))
	}
	lookup := map[string]analysis.PkgInput{}
	for _, in := range inputs {
		lookup[strings.ToLower(in.Name)] = in
	}
	if !lookup["tokio"].IsDirect {
		t.Fatalf("tokio should be marked direct from dependencies")
	}
	if lookup["criterion"].IsDirect {
		t.Fatalf("criterion is a dev-dependency and should remain indirect")
	}
	if !lookup["serde"].IsDirect {
		t.Fatalf("serde should be direct via workspace.dependencies")
	}
	if lookup["cc"].IsDirect {
		t.Fatalf("build dependency cc should not be direct")
	}
	if !lookup["libc"].IsDirect {
		t.Fatalf("target-specific dependency libc should be direct")
	}
}

func TestPackagesToInputs_PythonRequirementsMarkedDirect(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:      "requests",
			Version:   "2.32.0",
			PURLType:  scalpurl.TypePyPi,
			Locations: []string{"requirements.txt"},
		},
	}
	inputs := packagesToInputs(pkgs, packageInputOptions{})
	if len(inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(inputs))
	}
	if !inputs[0].IsDirect {
		t.Fatalf("expected python requirement to be marked direct")
	}
	if len(inputs[0].ManifestRefs) != 1 || inputs[0].ManifestRefs[0].Manager != "pip" {
		t.Fatalf("expected manifest ref for pip, got %+v", inputs[0].ManifestRefs)
	}
}

func containsGroup(groups []string, want string) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}
