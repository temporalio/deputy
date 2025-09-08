package git

import (
    "os"
    "path/filepath"
    "strings"
    "testing"
    "time"

    git "github.com/go-git/go-git/v5"
    "github.com/go-git/go-git/v5/plumbing"
    "github.com/go-git/go-git/v5/plumbing/object"
)

// commitFile creates/updates a file and commits it, returning the new commit hash.
func commitFile(t *testing.T, repo *git.Repository, wt *git.Worktree, repoPath, filename, content, message string) plumbing.Hash {
    t.Helper()
    full := filepath.Join(repoPath, filename)
    if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
        t.Fatalf("mkdir: %v", err)
    }
    if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
        t.Fatalf("write: %v", err)
    }
    if _, err := wt.Add(filename); err != nil {
        t.Fatalf("add: %v", err)
    }
    h, err := wt.Commit(message, &git.CommitOptions{
        Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
        Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: time.Now()},
    })
    if err != nil {
        t.Fatalf("commit: %v", err)
    }
    return h
}

// commitFileAt is like commitFile but sets the commit timestamp to 'when'.
func commitFileAt(t *testing.T, repo *git.Repository, wt *git.Worktree, repoPath, filename, content, message string, when time.Time) plumbing.Hash {
    t.Helper()
    full := filepath.Join(repoPath, filename)
    if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
        t.Fatalf("mkdir: %v", err)
    }
    if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
        t.Fatalf("write: %v", err)
    }
    if _, err := wt.Add(filename); err != nil {
        t.Fatalf("add: %v", err)
    }
    h, err := wt.Commit(message, &git.CommitOptions{
        Author:    &object.Signature{Name: "Test", Email: "test@example.com", When: when},
        Committer: &object.Signature{Name: "Test", Email: "test@example.com", When: when},
    })
    if err != nil {
        t.Fatalf("commit: %v", err)
    }
    return h
}

func Test_parseTimeShorthandToISO_basic(t *testing.T) {
    iso := ParseTimeShorthandToISO("yesterday")
    if iso == "" {
        t.Fatalf("expected non-empty iso for 'yesterday'")
    }
    ts, err := time.Parse(time.RFC3339, iso)
    if err != nil {
        t.Fatalf("parse RFC3339: %v (got %q)", err, iso)
    }
    d := time.Since(ts)
    if d < 20*time.Hour || d > 28*time.Hour {
        t.Fatalf("unexpected delta for yesterday: %v", d)
    }

    iso2 := ParseTimeShorthandToISO("10.week.ago")
    if iso2 == "" {
        t.Fatalf("expected non-empty iso for '10.week.ago'")
    }
    ts2, err := time.Parse(time.RFC3339, iso2)
    if err != nil {
        t.Fatalf("parse RFC3339: %v (got %q)", err, iso2)
    }
    if time.Since(ts2) < 65*24*time.Hour { // ~9.3 weeks lower bound
        t.Fatalf("expected ~10 weeks ago, got delta %v", time.Since(ts2))
    }
}

func Test_normalizeGitRefForGoGit_transformsInsideBraces(t *testing.T) {
    out := NormalizeGitRefForGoGit("HEAD@{yesterday}")
    if !strings.HasPrefix(out, "HEAD@{") || !strings.HasSuffix(out, "}") {
        t.Fatalf("unexpected format: %q", out)
    }
    inner := strings.TrimSuffix(strings.TrimPrefix(out, "HEAD@{"), "}")
    if _, err := time.Parse(time.RFC3339, inner); err != nil {
        t.Fatalf("inner not RFC3339: %q (%v)", inner, err)
    }
}

func Test_ResolveRevision_withTimeRef_HEAD(t *testing.T) {
    dir := t.TempDir()
    repo, err := git.PlainInit(dir, false)
    if err != nil {
        t.Fatalf("init repo: %v", err)
    }
    wt, err := repo.Worktree()
    if err != nil {
        t.Fatalf("worktree: %v", err)
    }

    // First commit
    h1 := commitFile(t, repo, wt, dir, "go.mod", "module example.com/mod\n\n", "init")
    time.Sleep(3 * time.Second)
    // Second commit
    _ = commitFile(t, repo, wt, dir, "go.mod", "module example.com/mod\nrequire example.com/dep v0.1.0\n", "add dep")
    time.Sleep(1 * time.Second)

    // Resolve HEAD as of 2 seconds ago (between two commits)
    h, err := ResolveRevisionEnhanced(repo, "HEAD@{2.second.ago}")
    if err != nil {
        t.Fatalf("ResolveRevisionEnhanced: %v", err)
    }
    if *h != h1 {
        t.Fatalf("expected hash %s, got %s", h1.String(), h.String())
    }
}

func Test_checkFilesChanged_withTimeRef(t *testing.T) {
    dir := t.TempDir()
    repo, err := git.PlainInit(dir, false)
    if err != nil {
        t.Fatalf("init repo: %v", err)
    }
    wt, err := repo.Worktree()
    if err != nil {
        t.Fatalf("worktree: %v", err)
    }

    // Create commits with controlled timestamps
    now := time.Now().UTC()
    _ = commitFileAt(t, repo, wt, dir, "go.mod", "module example.com/mod\n\n", "init", now.Add(-2*time.Minute))
    _ = commitFileAt(t, repo, wt, dir, "go.mod", "module example.com/mod\nrequire example.com/dep v0.1.0\n", "add dep", now.Add(-1*time.Minute))
    _ = commitFileAt(t, repo, wt, dir, "go.mod", "module example.com/mod\nrequire example.com/dep v0.2.0\n", "bump dep", now)

    // Ask for base ~30 seconds ago, expect to diff from the 1-minute-old commit to HEAD
    files, err := CheckFilesChanged(dir, "HEAD@{30.second.ago}", "HEAD")
    if err != nil {
        t.Fatalf("CheckFilesChanged: %v", err)
    }
    found := false
    for _, f := range files {
        if f == "go.mod" { found = true; break }
    }
    if !found {
        t.Fatalf("expected go.mod in changed files, got %v", files)
    }
}

func Test_ResolveRevision_withMonthYearRefs(t *testing.T) {
    dir := t.TempDir()
    repo, err := git.PlainInit(dir, false)
    if err != nil {
        t.Fatalf("init repo: %v", err)
    }
    wt, err := repo.Worktree()
    if err != nil {
        t.Fatalf("worktree: %v", err)
    }

    now := time.Now().UTC()
    // Create commits spread across months
    hOld := commitFileAt(t, repo, wt, dir, "file.txt", "old", "old", now.AddDate(0, -5, 0)) // ~5 months ago
    hMid := commitFileAt(t, repo, wt, dir, "file.txt", "mid", "mid", now.AddDate(0, -2, 0)) // ~2 months ago
    _ = commitFileAt(t, repo, wt, dir, "file.txt", "new", "new", now)                       // now

    // 4.month.ago should select the ~5 months ago commit (newest <= 4 months ago)
    h, err := ResolveRevisionEnhanced(repo, "HEAD@{4.month.ago}")
    if err != nil {
        t.Fatalf("resolve 4.month.ago: %v", err)
    }
    if *h != hOld {
        t.Fatalf("expected %s for 4.month.ago, got %s", hOld.String(), h.String())
    }

    // 1.month.ago should select the ~2 months ago commit (newest <= 1 month ago)
    h2, err := ResolveRevisionEnhanced(repo, "HEAD@{1.month.ago}")
    if err != nil {
        t.Fatalf("resolve 1.month.ago: %v", err)
    }
    if *h2 != hMid {
        t.Fatalf("expected %s for 1.month.ago, got %s", hMid.String(), h2.String())
    }

    // 1.year.ago — before all commits — expect oldest commit (hOld)
    h3, err := ResolveRevisionEnhanced(repo, "HEAD@{1.year.ago}")
    if err != nil {
        t.Fatalf("resolve 1.year.ago: %v", err)
    }
    if *h3 != hOld {
        t.Fatalf("expected oldest %s for 1.year.ago, got %s", hOld.String(), h3.String())
    }
}

