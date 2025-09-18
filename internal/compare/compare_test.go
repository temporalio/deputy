package compare

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/workspace"
)

func TestGetModuleRoot(t *testing.T) {
	cases := []struct{ in, want string }{
		{"github.com/user/repo/sub/pkg", "github.com/user/repo"},
		{"github.com/user/repo", "github.com/user/repo"},
		{"github.com/user/repo/", "github.com/user/repo"}, // trailing slash handled by split/join logic implicitly
		{"example.com/mod/sub", "example.com/mod"},
		{"example.com/mod", "example.com/mod"},
		{"single", "single"},
		{"", ""},
	}
	for _, c := range cases {
		if got := GetModuleRoot(c.in); got != c.want {
			t.Fatalf("GetModuleRoot(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func Test_normalizeGoVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", ""},
		{"v1.2.3", "v1.2.3"},
		{"1.2.3", "v1.2.3"},
		{"v0.0.0", "v0.0.0"},
	}
	for _, c := range cases {
		if got := normalizeGoVersion(c.in); got != c.want {
			t.Fatalf("normalizeGoVersion(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func Test_allDigits(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", true}, // empty treated as true by current implementation
		{"0", true},
		{"12345", true},
		{"12a45", false},
		{"abc", false},
	}
	for _, c := range cases {
		if got := allDigits(c.in); got != c.want {
			t.Fatalf("allDigits(%q)=%v want %v", c.in, got, c.want)
		}
	}
}

func TestGetDirectDependencies(t *testing.T) {
	ws, err := workspace.NewTempDir("cmp-go-mod")
	if err != nil {
		t.Fatalf("new workspace: %v", err)
	}
	defer ws.Close()

	goMod := `module example.com/app

require (
    github.com/a/b v1.2.3
    github.com/c/d v0.0.1 // indirect
    github.com/e/f v2.0.0
)`
	if err := ws.WriteFile("go.mod", []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	deps := GetDirectDependencies(ws)
	if !deps["github.com/a/b"] || !deps["github.com/e/f"] {
		t.Fatalf("expected direct deps present: %v", deps)
	}
	if deps["github.com/c/d"] {
		t.Fatalf("indirect dep erroneously marked direct")
	}
}

func TestGetDirectDependenciesFromGoMod_GopkgIn(t *testing.T) {
	goMod := `module example.com/app

require (
    gopkg.in/yaml.v3 v3.0.1
    gopkg.in/indirect.v3 v3.0.0 // indirect
)`
	deps := GetDirectDependenciesFromGoMod([]byte(goMod))
	if !deps["github.com/go-yaml/yaml"] {
		t.Fatalf("expected canonical root for yaml: %+v", deps)
	}
	if deps["gopkg.in/indirect.v3"] {
		t.Fatalf("indirect dependency erroneously marked direct")
	}
}

func Test_ComparePackages_basic(t *testing.T) {
	ws, err := workspace.NewTempDir("cmp-compare")
	if err != nil {
		t.Fatalf("new workspace: %v", err)
	}
	defer ws.Close()
	goMod := `module example.com/app

require (
    github.com/new/added v1.0.0
    github.com/keep/updated v1.1.0
)`
	if err := ws.WriteFile("go.mod", []byte(goMod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}

	oldPkgs := []*extractor.Package{
		{Name: "github.com/keep/updated", Version: "v1.0.0"},
		{Name: "github.com/old/removed", Version: "v0.9.0"},
	}
	newPkgs := []*extractor.Package{
		{Name: "github.com/keep/updated", Version: "v1.1.0"}, // updated
		{Name: "github.com/new/added", Version: "v1.0.0"},    // added
	}
	deps := GetDirectDependencies(ws)
	changes := ComparePackages(oldPkgs, newPkgs, deps, ws)
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes got %d: %+v", len(changes), changes)
	}

	var added, removed, upgraded bool
	for _, c := range changes {
		switch c.ChangeType {
		case Added:
			if c.Name != "github.com/new/added" || c.TargetVersion != "v1.0.0" || !c.IsDirect {
				t.Fatalf("bad added: %+v", c)
			}
			added = true
		case Removed:
			if c.Name != "github.com/old/removed" || c.BaseVersion != "v0.9.0" {
				t.Fatalf("bad removed: %+v", c)
			}
			removed = true
		case Upgraded:
			if c.Name != "github.com/keep/updated" || c.BaseVersion != "v1.0.0" || c.TargetVersion != "v1.1.0" || !c.IsDirect {
				t.Fatalf("bad upgraded: %+v", c)
			}
			upgraded = true
		}
	}
	if !added || !removed || !upgraded {
		t.Fatalf("missing change types: added=%v removed=%v upgraded=%v", added, removed, upgraded)
	}
}

func TestComparePackages_DowngradeAndRename(t *testing.T) {
	oldPkgs := []*extractor.Package{
		{Name: "github.com/example/down", Version: "v1.2.0"},
		{Name: "github.com/example/rename", Version: "v1.0.0"},
	}
	newPkgs := []*extractor.Package{
		{Name: "github.com/example/down", Version: "v1.1.0"},
		{Name: "github.com/example/rename/v2", Version: "v1.0.0"},
	}
	deps := map[string]bool{
		"github.com/example/down":   true,
		"github.com/example/rename": true,
	}
	changes := ComparePackages(oldPkgs, newPkgs, deps, nil)
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes got %d: %+v", len(changes), changes)
	}
	seen := map[ChangeType]bool{}
	for _, c := range changes {
		switch c.ChangeType {
		case Downgraded:
			seen[Downgraded] = true
			if c.Name != "github.com/example/down" || c.BaseVersion != "v1.2.0" || c.TargetVersion != "v1.1.0" {
				t.Fatalf("unexpected downgrade change: %+v", c)
			}
		case Updated:
			seen[Updated] = true
			if c.Name != "github.com/example/rename/v2" || c.OldName != "github.com/example/rename" {
				t.Fatalf("unexpected rename change: %+v", c)
			}
		default:
			t.Fatalf("unexpected change type %v", c.ChangeType)
		}
	}
	if !seen[Downgraded] || !seen[Updated] {
		t.Fatalf("missing expected change types: %+v", seen)
	}
}
