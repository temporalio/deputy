package gitutil

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestCloneContext_InvalidURL(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	_, cleanup, err := CloneContext(ctx, dir, &git.CloneOptions{
		URL: "https://invalid.example.com/nonexistent/repo.git",
	})
	if err == nil {
		cleanup()
		t.Error("expected error for invalid URL")
	}
}

func TestCloneContext_CancelledContext(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately

	_, cleanup, err := CloneContext(ctx, dir, &git.CloneOptions{
		URL: "https://github.com/golang/go.git",
	})
	if err == nil {
		cleanup()
		t.Error("expected error for cancelled context")
	}
}

func TestCloneContext_LocalRepo(t *testing.T) {
	// Create a local repo to clone from
	srcDir := t.TempDir()
	repo, err := git.PlainInit(srcDir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	file := filepath.Join(srcDir, "README.md")
	if err := os.WriteFile(file, []byte("# Test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("README.md"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Clone to a new directory
	destDir := t.TempDir()
	ctx := t.Context()

	clonedRepo, cleanup, err := CloneContext(ctx, destDir, &git.CloneOptions{
		URL: srcDir,
	})
	if err != nil {
		t.Fatalf("CloneContext: %v", err)
	}
	defer cleanup()

	// Verify the clone worked
	head, err := clonedRepo.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	if head == nil {
		t.Error("expected HEAD to be non-nil")
	}

	// Verify README.md exists in clone
	clonedFile := filepath.Join(destDir, "README.md")
	data, err := os.ReadFile(clonedFile)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(data) != "# Test\n" {
		t.Errorf("unexpected file content: %q", string(data))
	}
}
