package gitutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func initTestRepo(t *testing.T) (dir string, head string) {
	t.Helper()
	dir = t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("file.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	commit, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	return dir, commit.String()
}

func TestResolveRefToCommit(t *testing.T) {
	dir, head := initTestRepo(t)

	tests := []struct {
		name string
		ref  string
		want string
	}{
		{name: "HEAD resolves to its commit", ref: "HEAD", want: head},
		{name: "HEAD~0 resolves to its commit", ref: "HEAD~0", want: head},
		{name: "full SHA resolves to itself", ref: head, want: head},
		{name: "short SHA resolves to full SHA", ref: head[:7], want: head},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveRefToCommit(dir, tt.ref)
			if err != nil {
				t.Fatalf("ResolveRefToCommit(%q) error: %v", tt.ref, err)
			}
			if got != tt.want {
				t.Errorf("ResolveRefToCommit(%q) = %q, want %q", tt.ref, got, tt.want)
			}
		})
	}

	t.Run("from a subdirectory of the repo", func(t *testing.T) {
		sub := filepath.Join(dir, "sub")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatalf("Mkdir: %v", err)
		}
		got, err := ResolveRefToCommit(sub, "HEAD")
		if err != nil {
			t.Fatalf("ResolveRefToCommit from subdir error: %v", err)
		}
		if got != head {
			t.Errorf("ResolveRefToCommit from subdir = %q, want %q", got, head)
		}
	})

	t.Run("unknown ref errors", func(t *testing.T) {
		if _, err := ResolveRefToCommit(dir, "no-such-ref-xyz"); err == nil {
			t.Error("expected error for unknown ref")
		}
	})

	t.Run("non-repo directory errors", func(t *testing.T) {
		if _, err := ResolveRefToCommit(t.TempDir(), "HEAD"); err == nil {
			t.Error("expected error for non-repo directory")
		}
	})
}
