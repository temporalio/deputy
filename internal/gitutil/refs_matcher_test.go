package gitutil

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	inv "github.com/picatz/deputy/internal/inventory"
)

// TestParseReferencesDetectsWorkingChangesForNonGoManifests confirms that the
// matcher-aware reference parsing flips to WORKING when only a non-Go manifest
// (pnpm-lock.yaml) changes.
func TestParseReferencesDetectsWorkingChangesForNonGoManifests(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	lockPath := filepath.Join(dir, "pnpm-lock.yaml")
	if err := os.WriteFile(lockPath, []byte("lockfileVersion: 6\n"), 0o644); err != nil {
		t.Fatalf("write lock: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("pnpm-lock.yaml"); err != nil {
		t.Fatalf("add: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "tester", Email: "tester@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	matcher, err := inv.GetDependencyMatcher(inv.ScanOptions{Ecosystems: []string{"all"}})
	if err != nil {
		t.Fatalf("GetDependencyMatcher: %v", err)
	}

	base, target, err := ParseReferences(dir, nil, matcher)
	if err != nil {
		t.Fatalf("ParseReferences: %v", err)
	}
	if target != "HEAD" {
		t.Fatalf("expected target HEAD after clean commit, got %s (base=%s)", target, base)
	}

	// Modify lockfile without committing to simulate pnpm change.
	if err := os.WriteFile(lockPath, []byte("lockfileVersion: 7\npackages: {}\n"), 0o644); err != nil {
		t.Fatalf("modify lock: %v", err)
	}
	base, target, err = ParseReferences(dir, nil, matcher)
	if err != nil {
		t.Fatalf("ParseReferences (dirty): %v", err)
	}
	if target != "WORKING" {
		t.Fatalf("expected WORKING target when pnpm-lock.yaml changed; got base=%s target=%s", base, target)
	}
}
