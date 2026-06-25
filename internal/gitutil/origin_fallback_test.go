package gitutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
)

func TestShouldTryOriginFallback(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		{"main", true},
		{"fix/foo", true},                      // slashed branch name: must still get the fallback
		{"feature/a/b", true},                  // multi-slash branch name
		{"  fix/foo  ", true},                  // whitespace-padded slashed branch still gets the fallback
		{"origin/main", false},                 // already remote-qualified
		{"origin/fix/foo", false},              // already remote-qualified, slashed
		{"remotes/origin/fix/foo", false},      // remotes-qualified
		{"refs/remotes/origin/fix/foo", false}, // fully-qualified remote-tracking ref
		{"refs/heads/main", false},             // fully-qualified local ref
		{" origin/main ", false},               // whitespace + already remote-qualified
	}
	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			if got := shouldTryOriginFallback(tt.ref); got != tt.want {
				t.Errorf("shouldTryOriginFallback(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

// slashedBranchRemoteOnlyRepo builds a repo that mirrors a CI checkout: a commit
// reachable only through a remote-tracking ref (refs/remotes/origin/fix/foo),
// with no local branch of that name. It returns the repo and the commit hash.
func slashedBranchRemoteOnlyRepo(t *testing.T) (*git.Repository, plumbing.Hash) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "file.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("file.txt"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	hash, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	})
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	// Remote-tracking ref only; deliberately no local refs/heads/fix/foo.
	remoteRef := plumbing.NewHashReference("refs/remotes/origin/fix/foo", hash)
	if err := repo.Storer.SetReference(remoteRef); err != nil {
		t.Fatalf("SetReference: %v", err)
	}
	return repo, hash
}

// TestResolveRevisionEnhanced_SlashedBranchViaOrigin is the regression for the
// PR-gate failure: a slashed branch name present only as a remote-tracking ref
// must resolve via the origin/ fallback rather than being rejected for
// containing a slash.
func TestResolveRevisionEnhanced_SlashedBranchViaOrigin(t *testing.T) {
	repo, want := slashedBranchRemoteOnlyRepo(t)

	got, err := ResolveRevisionEnhanced(repo, "fix/foo")
	if err != nil {
		t.Fatalf("ResolveRevisionEnhanced(fix/foo): %v", err)
	}
	if got == nil || *got != want {
		t.Errorf("resolved %v, want %v", got, want)
	}

	// A genuinely unknown slashed ref still errors (no silent success).
	if _, err := ResolveRevisionEnhanced(repo, "fix/does-not-exist"); err == nil {
		t.Error("expected error for an unknown slashed ref")
	}
}

func TestValidateReference_SlashedBranchViaOrigin(t *testing.T) {
	repo, _ := slashedBranchRemoteOnlyRepo(t)

	if err := validateReference(repo, "fix/foo"); err != nil {
		t.Errorf("validateReference(fix/foo) = %v, want nil", err)
	}
	if err := validateReference(repo, "fix/does-not-exist"); err == nil {
		t.Error("expected error for an unknown slashed ref")
	}
}
