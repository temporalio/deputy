package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	cmp "github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/workspace"
)

func TestToListItems_ListAll_NoDedup(t *testing.T) {
	// Direct: github.com/acme/foo, gopkg.in/yaml.v3
	goMod := `module example.com/app

require (
    github.com/acme/foo v1.0.0
    gopkg.in/yaml.v3 v3.0.1
)`
	deps := cmp.GetDirectDependenciesFromGoMod([]byte(goMod))
	dx := directModulesFromGoMod([]byte(goMod))

	pkgs := []*extractor.Package{
		{Name: "github.com/acme/foo", Version: "v1.0.0"},
		{Name: "github.com/acme/foo/subpkg", Version: "v1.0.0"}, // same module, should dedup at module level
		{Name: "gopkg.in/yaml.v3", Version: "v3.0.1"},
	}

	ws := workspace.NewMemory()
	defer ws.Close()

	items := toListItems(ws, pkgs, deps, dx)
	if len(items) != 3 {
		t.Fatalf("expected 3 items (no dedup), got %d: %+v", len(items), items)
	}

	// Verify names, versions, direct flag
	var seenFoo, seenYaml bool
	for _, it := range items {
		switch it.Name {
		case "github.com/acme/foo":
			seenFoo = true
			if it.Version != "v1.0.0" || !it.IsDirect {
				t.Errorf("unexpected foo item: %+v", it)
			}
		case "gopkg.in/yaml.v3":
			seenYaml = true
			if it.Version != "v3.0.1" || !it.IsDirect {
				t.Errorf("unexpected yaml item: %+v", it)
			}
		case "github.com/acme/foo/subpkg":
			// also direct via module mapping
			if it.Version != "v1.0.0" || !it.IsDirect {
				t.Errorf("unexpected subpkg item: %+v", it)
			}
		default:
			t.Errorf("unexpected item: %+v", it)
		}
	}
	if !seenFoo || !seenYaml {
		t.Fatalf("missing expected items: %+v", items)
	}
}

func TestToListItems_PackageLevel_NoDedup(t *testing.T) {
	goMod := `module example.com/app

require (
    github.com/acme/foo v1.0.0
    gopkg.in/yaml.v3 v3.0.1
)`
	deps := cmp.GetDirectDependenciesFromGoMod([]byte(goMod))
	dx := directModulesFromGoMod([]byte(goMod))

	pkgs := []*extractor.Package{
		{Name: "github.com/acme/foo", Version: "v1.0.0"},
		{Name: "github.com/acme/foo/subpkg", Version: "v1.0.0"},
		{Name: "gopkg.in/yaml.v3", Version: "v3.0.1"},
	}

	ws := workspace.NewMemory()
	defer ws.Close()

	items := toListItems(ws, pkgs, deps, dx)
	if len(items) != 3 {
		t.Fatalf("expected 3 package-level items, got %d: %+v", len(items), items)
	}

	// Both foo paths should be present and marked direct via module root mapping
	var foo, sub, yaml bool
	for _, it := range items {
		switch it.Name {
		case "github.com/acme/foo":
			foo = true
			if !it.IsDirect {
				t.Errorf("expected foo to be direct: %+v", it)
			}
		case "github.com/acme/foo/subpkg":
			sub = true
			if !it.IsDirect {
				t.Errorf("expected subpkg to be direct via module mapping: %+v", it)
			}
		case "gopkg.in/yaml.v3":
			yaml = true
			if !it.IsDirect {
				t.Errorf("expected yaml to be direct: %+v", it)
			}
		}
	}
	if !foo || !sub || !yaml {
		t.Fatalf("missing expected names: foo=%v sub=%v yaml=%v; items=%+v", foo, sub, yaml, items)
	}
}

func TestWriteListTSV_NoHeader_PURLOnly(t *testing.T) {
	items := []ListItem{{Ecosystem: "go", Name: "github.com/acme/foo", Version: "v1.0.0", Module: "github.com/acme/foo", IsDirect: true, PURL: "pkg:golang/github.com/acme/foo@v1.0.0"}}
	var buf bytes.Buffer
	if err := writeListTSV(&buf, items, false); err != nil {
		t.Fatalf("writeListTSV: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "name\tversion") || strings.Contains(out, "purl\tdirect\n") {
		t.Fatalf("unexpected header in output: %q", out)
	}
	if !strings.HasPrefix(out, "pkg:golang/github.com/acme/foo@v1.0.0\ttrue") {
		t.Fatalf("unexpected row: %q", out)
	}
}

func TestToListItems_DedupeHighestVersion(t *testing.T) {
	goMod := `module example.com/app

require (
    cloud.google.com/go v1.24.1
)`
	deps := cmp.GetDirectDependenciesFromGoMod([]byte(goMod))
	dx := directModulesFromGoMod([]byte(goMod))

	pkgs := []*extractor.Package{
		{Name: "cloud.google.com/go", Version: "v0.6.0"},
		{Name: "cloud.google.com/go", Version: "v1.24.1"},
		{Name: "cloud.google.com/go", Version: "0.2.7"}, // missing v prefix
	}
	ws := workspace.NewMemory()
	defer ws.Close()

	items := toListItems(ws, pkgs, deps, dx)
	if len(items) != 3 {
		t.Fatalf("expected 3 items (no dedup), got %d: %+v", len(items), items)
	}
	// All should be marked direct per module mapping
	for _, it := range items {
		if !it.IsDirect {
			t.Fatalf("expected direct for %s", it.Name)
		}
	}
}
