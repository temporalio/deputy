package gitutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestCheckFilesChanged_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	// Don't init a repo

	_, err := CheckFilesChanged(dir, "main", "HEAD")
	if err == nil {
		t.Error("expected error for non-repo directory")
	}
}

func TestCheckFilesChanged_InvalidBaseRef(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	// Create initial commit
	dummy := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(dummy, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("file.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	_, err = CheckFilesChanged(dir, "nonexistent-branch-xyz", "HEAD")
	if err == nil {
		t.Error("expected error for invalid base reference")
	}
}

func TestCheckFilesChanged_InvalidPRRef(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	// Create initial commit
	dummy := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(dummy, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("file.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	_, err = CheckFilesChanged(dir, "HEAD", "nonexistent-branch-xyz")
	if err == nil {
		t.Error("expected error for invalid PR reference")
	}
}

func TestCheckFilesChanged_Success(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}

	// First commit
	file1 := filepath.Join(dir, "file1.txt")
	if err := os.WriteFile(file1, []byte("initial"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := wt.Add("file1.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	commit1, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Second commit with a new file
	file2 := filepath.Join(dir, "file2.txt")
	if err := os.WriteFile(file2, []byte("new file"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := wt.Add("file2.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	commit2, err := wt.Commit("add file2", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}

	files, err := CheckFilesChanged(dir, commit1.String(), commit2.String())
	if err != nil {
		t.Fatalf("CheckFilesChanged: %v", err)
	}
	if len(files) != 1 || files[0] != "file2.txt" {
		t.Errorf("expected [file2.txt], got %v", files)
	}
}
