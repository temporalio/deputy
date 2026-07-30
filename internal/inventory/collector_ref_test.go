package inventory_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/temporalio/deputy/internal/inventory"
	// Register the target providers CollectRepository resolves through.
	_ "github.com/temporalio/deputy/internal/targets/providers"
)

// commitGoMod writes go.mod with the given require line and commits it,
// returning the commit hash.
func commitGoMod(t *testing.T, dir string, repo *git.Repository, requireLine, message string) string {
	t.Helper()
	content := "module example.com/app\n\ngo 1.24\n\nrequire " + requireLine + "\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("add: %v", err)
	}
	hash, err := wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: "tester", Email: "tester@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return hash.String()
}

// packageVersion returns the version of the named package in the execution's
// inventory, or "" when absent.
func packageVersion(exec *inventory.Execution, name string) string {
	for _, pkg := range exec.Result.Packages {
		if pkg.Name == name {
			return pkg.Version
		}
	}
	return ""
}

// TestCollectRepositoryHonorsRef pins a live-spin regression: a scan
// requesting a committed snapshot (HEAD~1, tags, branches) must read that
// commit's tree, not the working tree. The broken behavior silently scanned
// the working tree for every ref, which made diff_refs compare a commit
// against itself.
func TestCollectRepositoryHonorsRef(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	firstCommit := commitGoMod(t, dir, repo, "github.com/pkg/errors v0.8.1", "initial")
	secondCommit := commitGoMod(t, dir, repo, "github.com/pkg/errors v0.9.1", "bump errors")
	ctx := t.Context()

	t.Run("HEAD~1 reads the previous commit's tree", func(t *testing.T) {
		exec, err := inventory.CollectRepository(ctx, dir, "HEAD~1", true, inventory.Options{})
		if err != nil {
			t.Fatalf("CollectRepository: %v", err)
		}
		defer exec.Close()
		if got := packageVersion(exec, "github.com/pkg/errors"); got != "0.8.1" {
			t.Errorf("errors version at HEAD~1 = %q, want 0.8.1", got)
		}
		if got := exec.Result.Target.CommitHash; got != firstCommit {
			t.Errorf("commit echo = %s, want %s (HEAD~1)", got, firstCommit)
		}
	})

	t.Run("working-tree refs read uncommitted state", func(t *testing.T) {
		content := "module example.com/app\n\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.2\n"
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(content), 0o644); err != nil {
			t.Fatalf("write go.mod: %v", err)
		}
		for _, ref := range []string{"HEAD", "WORKING", "HEAD~0"} {
			exec, err := inventory.CollectRepository(ctx, dir, ref, true, inventory.Options{})
			if err != nil {
				t.Fatalf("CollectRepository(%s): %v", ref, err)
			}
			if got := packageVersion(exec, "github.com/pkg/errors"); got != "0.9.2" {
				t.Errorf("errors version at %s = %q, want uncommitted 0.9.2", ref, got)
			}
			if got := exec.Result.Target.CommitHash; got != secondCommit {
				t.Errorf("commit echo at %s = %s, want HEAD %s", ref, got, secondCommit)
			}
			exec.Close()
		}
	})
}

// commitFiles writes the given files (paths relative to dir, slash-separated)
// and commits them all, returning the commit hash. It exists so ref-based
// tests can stage multi-ecosystem trees without repeating git plumbing.
func commitFiles(t *testing.T, dir string, repo *git.Repository, files map[string]string, message string) string {
	t.Helper()
	for name, content := range files {
		full := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", name, err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if err := wt.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		t.Fatalf("add: %v", err)
	}
	hash, err := wt.Commit(message, &git.CommitOptions{
		Author: &object.Signature{Name: "tester", Email: "tester@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}
	return hash.String()
}

// TestCollectRepositoryAtRefDetectsMultiEcosystemDirects pins a regression:
// ref-based collection used Go-only direct detection, so `deputy scan --ref X`
// on an npm/Cargo/PyPI project marked every direct dependency as transitive.
// Direct detection at a ref must cover the same ecosystems as the working-tree
// path (Go, npm, Cargo, PyPI).
func TestCollectRepositoryAtRefDetectsMultiEcosystemDirects(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	hash := commitFiles(t, dir, repo, map[string]string{
		"go.mod":           "module example.com/app\n\ngo 1.24\n\nrequire github.com/pkg/errors v0.9.1\n",
		"package.json":     `{"name":"app","dependencies":{"lodash":"^4.17.21"}}`,
		"Cargo.toml":       "[package]\nname = \"app\"\nversion = \"0.1.0\"\n\n[dependencies]\ntokio = \"1.26\"\n",
		"requirements.txt": "flask==2.3.0\n",
	}, "multi-ecosystem manifests")

	exec, err := inventory.CollectRepository(t.Context(), dir, hash, true, inventory.Options{})
	if err != nil {
		t.Fatalf("CollectRepository: %v", err)
	}
	defer exec.Close()
	if got := exec.Result.Target.CommitHash; got != hash {
		t.Fatalf("commit echo = %s, want %s", got, hash)
	}

	tests := []struct {
		name string
		key  string
	}{
		{name: "go direct module", key: "github.com/pkg/errors"},
		{name: "npm direct dependency", key: "lodash"},
		{name: "cargo direct dependency", key: "tokio"},
		{name: "pypi direct dependency", key: "flask"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !exec.Result.Direct[tt.key] {
				t.Errorf("Direct[%q] = false, want true (direct at ref %s)", tt.key, hash)
			}
		})
	}

	// The snapshot workspace must survive collection: graph edge resolution
	// reads the ref's manifests from it, and a nil workspace silently
	// downgrades ref-based graphs to disconnected basic graphs.
	if exec.Workspace == nil {
		t.Fatal("Workspace = nil, want the ref's snapshot workspace")
	}
	data, err := exec.Workspace.ReadFile("go.mod")
	if err != nil {
		t.Fatalf("reading go.mod from snapshot workspace: %v", err)
	}
	if !strings.Contains(string(data), "example.com/app") {
		t.Fatalf("snapshot go.mod = %q, want the committed manifest", data)
	}
}
