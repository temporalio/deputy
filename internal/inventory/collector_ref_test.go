package inventory_test

import (
	"context"
	"os"
	"path/filepath"
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
	ctx := context.Background()

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
