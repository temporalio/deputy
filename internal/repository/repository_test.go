package repository

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func newTempRepo(t *testing.T) (string, *git.Repository) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := wt.Commit("init", &git.CommitOptions{Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()}}); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return dir, repo
}

func TestOpen(t *testing.T) {
	dir, _ := newTempRepo(t)
	src, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer src.Close()
	if src.Workspace().RootPath() != dir {
		t.Fatalf("unexpected root path: %s", src.Workspace().RootPath())
	}
	if _, err := src.Workspace().ReadFile("go.mod"); err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
}

func TestCloneInMemory_Local(t *testing.T) {
	dir, _ := newTempRepo(t)
	ctx := t.Context()
	src, err := Clone(ctx, &git.CloneOptions{URL: dir, Depth: 1, SingleBranch: true, Tags: git.NoTags}, true)
	if err != nil {
		t.Fatalf("Clone in memory: %v", err)
	}
	defer src.Close()
	if !src.Workspace().IsVirtual() {
		t.Fatalf("expected virtual workspace")
	}
	if _, err := src.Workspace().ReadFile("go.mod"); err != nil {
		t.Fatalf("read go.mod: %v", err)
	}
}

func TestCloneToDir_Local(t *testing.T) {
	dir, _ := newTempRepo(t)
	ctx := t.Context()
	src, err := Clone(ctx, &git.CloneOptions{URL: dir, Depth: 1, SingleBranch: true, Tags: git.NoTags}, false)
	if err != nil {
		t.Fatalf("Clone to dir: %v", err)
	}
	root := src.Workspace().RootPath()
	if root == "" {
		t.Fatalf("expected non-empty root path")
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected go.mod in cloned repo: %v", err)
	}
	if err := src.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("expected temp dir removed, stat err=%v", err)
	}
}
