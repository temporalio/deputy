package providers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/temporalio/deputy/internal/targets"
)

func TestTargetsOpenLocalDirectory(t *testing.T) {
	dir := t.TempDir()
	mat, err := targets.Open(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("open local dir: %v", err)
	}
	if mat.Meta.Kind != targets.KindDir {
		t.Fatalf("expected KindDir, got %s", mat.Meta.Kind)
	}
	if mat.Path == "" {
		t.Fatalf("expected path for local dir")
	}
}

func TestTargetsOpenLocalGitRepo(t *testing.T) {
	dir := initGitRepo(t, false)
	mat, err := targets.Open(context.Background(), dir, nil)
	if err != nil {
		t.Fatalf("open local git repo: %v", err)
	}
	if mat.Meta.Kind != targets.KindGit {
		t.Fatalf("expected KindGit, got %s", mat.Meta.Kind)
	}
	if mat.Cleanup == nil {
		t.Fatalf("expected cleanup for git target")
	}
	mat.Cleanup()
}

func TestTargetsOpenRemoteGitFileURL(t *testing.T) {
	origin := initGitRepo(t, false)
	remote := fmt.Sprintf("file://%s", origin)
	mat, err := targets.Open(context.Background(), remote, map[string]string{"ref": "HEAD"})
	if err != nil {
		t.Fatalf("open remote git repo: %v", err)
	}
	if mat.Meta.Provenance["cloned"] != "true" {
		t.Fatalf("expected cloned provenance flag, got %v", mat.Meta.Provenance)
	}
	if mat.Path == "" {
		t.Fatalf("expected path for cloned repo")
	}
	if mat.Cleanup == nil {
		t.Fatalf("expected cleanup for cloned repo")
	}
	mat.Cleanup()
}

func initGitRepo(t *testing.T, bare bool) string {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, bare)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}
	if bare {
		return dir
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.24"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("test"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("add go.mod: %v", err)
	}
	if _, err := wt.Add("README.md"); err != nil {
		t.Fatalf("add README: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()}}); err != nil {
		t.Fatalf("commit: %v", err)
	}
	return dir
}
