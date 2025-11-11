package cmd

import (
	"fmt"
	"path/filepath"
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

func containsGroup(groups []string, want string) bool {
	for _, g := range groups {
		if g == want {
			return true
		}
	}
	return false
}
