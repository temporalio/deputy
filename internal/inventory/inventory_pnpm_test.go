package inventory

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/repository/workspace"
)

const pnpmLockFixture = `lockfileVersion: 5.3

specifiers:
  acorn: ^8.7.0

dependencies:
  acorn: 8.7.0

packages:

  /acorn/8.7.0:
    resolution: {integrity: sha512-V/LGr1APy+PXIwKebEWrkZPwoeoF+w1jiOBUmuxuiUIaOHtob8Qc9BTrYo7VuI5fR8tqsy+buA2WFooR5olqvQ==}
    engines: {node: '>=0.4.0'}
    hasBin: true
    dev: false
`

const invalidPnpmLockFixture = `{{{{`

func writePnpmRepo(t *testing.T, lockfile string) (string, *git.Repository) {
	t.Helper()
	dir := t.TempDir()

	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}

	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{\n  \"name\": \"demo\",\n  \"version\": \"1.0.0\"\n}\n"), 0o644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pnpm-lock.yaml"), []byte(lockfile), 0o644); err != nil {
		t.Fatalf("write pnpm-lock.yaml: %v", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}
	if _, err := wt.Add("package.json"); err != nil {
		t.Fatalf("add package.json: %v", err)
	}
	if _, err := wt.Add("pnpm-lock.yaml"); err != nil {
		t.Fatalf("add pnpm-lock.yaml: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{Author: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()}}); err != nil {
		t.Fatalf("commit: %v", err)
	}

	return dir, repo
}

func TestScanPackagesWorking_PnpmLock(t *testing.T) {
	dir, _ := writePnpmRepo(t, pnpmLockFixture)

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()

	pkgs, err := ScanPackagesWorking(t.Context(), ws, ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPackagesWorking: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("expected pnpm packages in working tree")
	}
	if pkgs[0].PURL() == nil || pkgs[0].PURL().Type != purl.TypeNPM {
		t.Fatalf("expected npm purl got %v", pkgs[0].PURL())
	}
}

func TestScanPackagesAtCommitSnapshot_PnpmLock(t *testing.T) {
	_, repo := writePnpmRepo(t, pnpmLockFixture)
	head, err := repo.Head()
	if err != nil {
		t.Fatalf("head: %v", err)
	}

	pkgs, err := ScanPackagesAtCommitSnapshot(t.Context(), repo, head.Hash(), ScanOptions{})
	if err != nil {
		t.Fatalf("ScanPackagesAtCommitSnapshot: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("expected pnpm packages at commit snapshot")
	}
	if got := pkgs[0].PURL(); got == nil || got.Type != purl.TypeNPM {
		t.Fatalf("expected npm purl got %v", got)
	}
}

func TestScanPackagesWorking_InvalidPnpmLock(t *testing.T) {
	dir, _ := writePnpmRepo(t, invalidPnpmLockFixture)

	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()

	pkgs, err := ScanPackagesWorking(t.Context(), ws, ScanOptions{})
	if err == nil {
		t.Fatalf("expected error for invalid lockfile, got %d packages", len(pkgs))
	}
}
