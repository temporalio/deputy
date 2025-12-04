package compare

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/osv-scalibr/extractor"
	scalpurl "github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/repository/workspace"
)

func TestGetModuleRoot(t *testing.T) {
	cases := []struct{ in, want string }{
		{in: "github.com/user/repo/sub/pkg", want: "github.com/user/repo"},
		{in: "github.com/user/repo", want: "github.com/user/repo"},
		{in: "github.com/user/repo/", want: "github.com/user/repo"}, // trailing slash handled by split/join logic implicitly
		{in: "example.com/mod/sub", want: "example.com/mod"},
		{in: "example.com/mod", want: "example.com/mod"},
		{in: "single", want: "single"},
		{in: "", want: ""},
	}
	for _, c := range cases {
		if got := GetModuleRoot(c.in); got != c.want {
			t.Fatalf("GetModuleRoot(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func Test_normalizeGoVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{in: "", want: ""},
		{in: "v1.2.3", want: "v1.2.3"},
		{in: "1.2.3", want: "v1.2.3"},
		{in: "v0.0.0", want: "v0.0.0"},
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
		{in: "", want: true}, // empty treated as true by current implementation
		{in: "0", want: true},
		{in: "12345", want: true},
		{in: "12a45", want: false},
		{in: "abc", want: false},
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
		{Name: "github.com/keep/updated", Version: "v1.0.0", PURLType: scalpurl.TypeGolang},
		{Name: "github.com/old/removed", Version: "v0.9.0", PURLType: scalpurl.TypeGolang},
	}
	newPkgs := []*extractor.Package{
		{Name: "github.com/keep/updated", Version: "v1.1.0", PURLType: scalpurl.TypeGolang}, // updated
		{Name: "github.com/new/added", Version: "v1.0.0", PURLType: scalpurl.TypeGolang},    // added
	}
	deps := GetDirectDependencies(ws)
	changes := ComparePackages(oldPkgs, newPkgs, deps, nil, ws)
	if len(changes) != 3 {
		t.Fatalf("expected 3 changes got %d: %+v", len(changes), changes)
	}

	var added, removed, upgraded bool
	for _, c := range changes {
		switch c.ChangeType {
		case Added:
			if c.Name != "github.com/new/added" || c.TargetVersion != "v1.0.0" || !c.IsDirect || c.Ecosystem != "Go" {
				t.Fatalf("bad added: %+v", c)
			}
			added = true
		case Removed:
			if c.Name != "github.com/old/removed" || c.BaseVersion != "v0.9.0" || c.Ecosystem != "Go" {
				t.Fatalf("bad removed: %+v", c)
			}
			removed = true
		case Upgraded:
			if c.Name != "github.com/keep/updated" || c.BaseVersion != "v1.0.0" || c.TargetVersion != "v1.1.0" || !c.IsDirect || c.Ecosystem != "Go" {
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
		{Name: "github.com/example/down", Version: "v1.2.0", PURLType: scalpurl.TypeGolang},
		{Name: "github.com/example/rename", Version: "v1.0.0", PURLType: scalpurl.TypeGolang},
	}
	newPkgs := []*extractor.Package{
		{Name: "github.com/example/down", Version: "v1.1.0", PURLType: scalpurl.TypeGolang},
		{Name: "github.com/example/rename/v2", Version: "v1.0.0", PURLType: scalpurl.TypeGolang},
	}
	deps := map[string]bool{
		"github.com/example/down":   true,
		"github.com/example/rename": true,
	}
	changes := ComparePackages(oldPkgs, newPkgs, deps, nil, nil)
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes got %d: %+v", len(changes), changes)
	}
	seen := map[ChangeType]bool{}
	for _, c := range changes {
		switch c.ChangeType {
		case Downgraded:
			seen[Downgraded] = true
			if c.Name != "github.com/example/down" || c.BaseVersion != "v1.2.0" || c.TargetVersion != "v1.1.0" || c.Ecosystem != "Go" {
				t.Fatalf("unexpected downgrade change: %+v", c)
			}
		case Updated:
			seen[Updated] = true
			if c.Name != "github.com/example/rename/v2" || c.OldName != "github.com/example/rename" || c.Ecosystem != "Go" {
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

func TestComparePackages_NonGo(t *testing.T) {
	oldPkgs := []*extractor.Package{
		{Name: "left-pad", Version: "1.0.0", PURLType: scalpurl.TypeNPM},
	}
	newPkgs := []*extractor.Package{
		{Name: "left-pad", Version: "1.1.0", PURLType: scalpurl.TypeNPM},
		{Name: "colors", Version: "2.0.0", PURLType: scalpurl.TypeNPM},
	}
	changes := ComparePackages(oldPkgs, newPkgs, nil, nil, nil)
	if len(changes) != 2 {
		t.Fatalf("expected 2 changes got %d: %+v", len(changes), changes)
	}
	var added, updated bool
	for _, c := range changes {
		if c.Ecosystem != scalpurl.TypeNPM {
			t.Fatalf("unexpected ecosystem for npm package: %+v", c)
		}
		switch c.ChangeType {
		case Added:
			if c.Name != "colors" || c.TargetVersion != "2.0.0" || c.IsDirect {
				t.Fatalf("unexpected added change: %+v", c)
			}
			added = true
		case Upgraded:
			if c.Name != "left-pad" || c.BaseVersion != "1.0.0" || c.TargetVersion != "1.1.0" || c.IsDirect {
				t.Fatalf("unexpected upgraded change: %+v", c)
			}
			updated = true
		default:
			t.Fatalf("unexpected change type %v", c.ChangeType)
		}
	}
	if !added || !updated {
		t.Fatalf("missing npm change types added=%v updated=%v", added, updated)
	}
}

func TestComparePackages_NonGoDirectness(t *testing.T) {
	oldPkgs := []*extractor.Package{
		{Name: "react", Version: "1.0.0", PURLType: scalpurl.TypeNPM},
	}
	newPkgs := []*extractor.Package{
		{Name: "react", Version: "1.0.1", PURLType: scalpurl.TypeNPM},
	}
	pkgDirect := map[string]bool{
		"npm|react": true,
	}
	changes := ComparePackages(oldPkgs, newPkgs, nil, pkgDirect, nil)
	if len(changes) != 1 {
		t.Fatalf("expected 1 change got %d: %+v", len(changes), changes)
	}
	if !changes[0].IsDirect {
		t.Fatalf("expected react change to be direct: %+v", changes[0])
	}
}

func TestSelectChangeType_SemverEcosystems(t *testing.T) {
	cases := []struct {
		name       string
		ecosystem  string
		base       string
		target     string
		wantChange ChangeType
	}{
		{name: "npm upgrade", ecosystem: "npm", base: "1.0.0", target: "1.1.0", wantChange: Upgraded},
		{name: "npm downgrade", ecosystem: "npm", base: "2.0.0", target: "1.5.0", wantChange: Downgraded},
		{name: "composer upgrade", ecosystem: "composer", base: "1.2.3", target: "1.2.4", wantChange: Upgraded},
		{name: "pypi upgrade", ecosystem: "pypi", base: "1.0.0", target: "1.0.1", wantChange: Upgraded},
		{name: "pypi downgrade", ecosystem: "pypi", base: "2.0.0", target: "1.9.0", wantChange: Downgraded},
		{name: "unknown ecosystem", ecosystem: "custom", base: "1.0.0", target: "2.0.0", wantChange: Updated},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := selectChangeType(tc.ecosystem, tc.base, tc.target); got != tc.wantChange {
				t.Fatalf("selectChangeType(%q,%q,%q)=%v want %v", tc.ecosystem, tc.base, tc.target, got, tc.wantChange)
			}
		})
	}
}

func TestCollectGoDirectModulesFromWorkspaceMulti(t *testing.T) {
	ws, err := workspace.NewTempDir("cmp-direct-ws")
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()
	if err := ws.MkdirAll("moduleA", 0o755); err != nil {
		t.Fatalf("mkdir moduleA: %v", err)
	}
	if err := ws.MkdirAll(filepath.Join("moduleB", "nested"), 0o755); err != nil {
		t.Fatalf("mkdir moduleB: %v", err)
	}
	modA := `module example.com/a

require (
    github.com/one/two v1.0.0
    github.com/skip/indirect v0.1.0 // indirect
)`
	modB := `module example.com/b

require github.com/three/four v2.0.0`
	if err := ws.WriteFile(filepath.Join("moduleA", "go.mod"), []byte(modA), 0o644); err != nil {
		t.Fatalf("write moduleA go.mod: %v", err)
	}
	if err := ws.WriteFile(filepath.Join("moduleB", "nested", "go.mod"), []byte(modB), 0o644); err != nil {
		t.Fatalf("write moduleB go.mod: %v", err)
	}
	deps := CollectGoDirectModulesFromWorkspace(ws)
	if !deps["github.com/one/two"] || !deps["github.com/three/four"] {
		t.Fatalf("expected direct deps present: %+v", deps)
	}
	if deps["github.com/skip/indirect"] {
		t.Fatalf("indirect dependency marked direct: %+v", deps)
	}
}

func TestCollectGoDirectModulesFromDisk(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "moduleC"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	content := `module example.com/c

require github.com/direct/only v0.9.0`
	if err := os.WriteFile(filepath.Join(root, "moduleC", "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	deps := CollectGoDirectModulesFromDisk(root)
	if !deps["github.com/direct/only"] {
		t.Fatalf("expected direct dep present: %+v", deps)
	}
}

func TestCollectGoDirectModulesFromCommit(t *testing.T) {
	root := t.TempDir()
	repo, err := git.PlainInit(root, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}
	modPath := filepath.Join(root, "moduleD")
	if err := os.MkdirAll(modPath, 0o755); err != nil {
		t.Fatalf("mkdir moduleD: %v", err)
	}
	mod := `module example.com/d

require github.com/commit/dependency v1.2.3`
	if err := os.WriteFile(filepath.Join(modPath, "go.mod"), []byte(mod), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add(filepath.Join("moduleD", "go.mod")); err != nil {
		t.Fatalf("add go.mod: %v", err)
	}
	hash, err := wt.Commit("add go mod", &git.CommitOptions{
		Author: &object.Signature{Name: "Tester", Email: "tester@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	deps, err := CollectGoDirectModulesFromCommit(repo, hash)
	if err != nil {
		t.Fatalf("collect from commit: %v", err)
	}
	if !deps["github.com/commit/dependency"] {
		t.Fatalf("expected dependency from commit: %+v", deps)
	}
}
