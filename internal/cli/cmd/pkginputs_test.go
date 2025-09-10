package cmd

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
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
		{Name: "github.com/golang-jwt/jwt/v4", Version: "v4.5.1"},
		{Name: "github.com/indirect/pkg", Version: "v1.2.3"},
	}

	inputs := packagesToInputs(pkgs, deps)
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
		{Name: "gopkg.in/yaml.v3", Version: "v3.0.1"},
		{Name: "gopkg.in/indirect.v3", Version: "v3.0.0"},
	}

	inputs := packagesToInputs(pkgs, deps)
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
