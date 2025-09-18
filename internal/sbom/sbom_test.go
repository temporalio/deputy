package sbomx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/picatz/deputy/internal/repository/workspace"
)

// helper to create a temporary git repo with an initial commit and optional branches
func newTempGitRepo(t *testing.T, branches ...string) (string, *git.Repository) {
	t.Helper()
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init repo: %v", err)
	}
	// write go.mod minimal
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/test\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	// initial file
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("test"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
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
	// create extra branches
	for _, b := range branches {
		if b == "main" {
			continue
		} // skip duplicate
		refName := plumbing.NewBranchReferenceName(b)
		headRef, err := repo.Head()
		if err != nil {
			t.Fatalf("head: %v", err)
		}
		if err := repo.Storer.SetReference(plumbing.NewHashReference(refName, headRef.Hash())); err != nil {
			t.Fatalf("create branch %s: %v", b, err)
		}
	}
	return dir, repo
}

func Test_ToHTTPSGitURL(t *testing.T) {
	cases := map[string]string{
		"":                           "",
		"github.com/foo/bar":         "https://github.com/foo/bar.git",
		"https://github.com/foo/bar": "https://github.com/foo/bar.git",
		"http://github.com/foo/bar":  "http://github.com/foo/bar.git",
	}
	for in, want := range cases {
		if got := ToHTTPSGitURL(in); got != want {
			t.Errorf("ToHTTPSGitURL(%q)=%q want %q", in, got, want)
		}
	}
}

func Test_ResolveReferenceName_DefaultBranch(t *testing.T) {
	_, repo := newTempGitRepo(t)
	// Add master and main to test selection preference
	head, _ := repo.Head()
	if err := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName("master"), head.Hash())); err != nil {
		t.Fatalf("master ref: %v", err)
	}
	if err := repo.Storer.SetReference(plumbing.NewHashReference(plumbing.NewBranchReferenceName("main"), head.Hash())); err != nil {
		t.Fatalf("main ref: %v", err)
	}

	ctx := t.Context()
	// We can't easily make ResolveReferenceName talk to our local repo without starting a server;
	// just ensure discovery fallback returns something plausible when remote can't be contacted.
	ref, err := ResolveReferenceName(ctx, "https://github.com/this/should-not-exist-12345.git", nil, "")
	if err != nil {
		t.Fatalf("ResolveReferenceName unexpected error: %v", err)
	}
	if ref.String() == "" {
		t.Fatalf("expected non-empty default branch ref")
	}
}

func Test_LooksLikeTag(t *testing.T) {
	if !looksLikeTag("v1.2.3") {
		t.Error("expected v1.2.3 to look like tag")
	}
	if looksLikeTag("feature-branch") {
		t.Error("feature-branch shouldn't look like a tag")
	}
}

func Test_DiscoverDefaultBranch_Fallback(t *testing.T) {
	ctx := t.Context()
	got := discoverDefaultBranch(ctx, "https://github.com/example/nonexistent-one-two-three.git", nil)
	if got != "refs/heads/main" {
		t.Fatalf("expected fallback refs/heads/main got %s", got)
	}
}

func Test_NormalizeGolangPURLString(t *testing.T) {
	dir := t.TempDir()
	// create go.mod with module path
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/example/project\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	cases := []struct{ in, want string }{
		{"", ""},
		{"pkg:golang/github.com/foo/bar@v1.0.0", "pkg:golang/github.com/foo/bar@v1.0.0"},
		{"pkg:golang/.@v1.2.3", "pkg:golang/github.com/example/project@v1.2.3"},
		{"pkg:golang/./sub@v0.0.1", "pkg:golang/github.com/example/project/sub@v0.0.1"},
	}
	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()
	for _, c := range cases {
		if got := normalizeGolangPURLString(c.in, ws); got != c.want {
			t.Errorf("normalizeGolangPURLString(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func Test_ReadModulePath(t *testing.T) {
	dir := t.TempDir()
	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()
	if p := readModulePath(ws); p != "" {
		t.Errorf("expected empty without go.mod got %q", p)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/xyz\n\n go 1.23\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if p := readModulePath(ws); p != "example.com/xyz" {
		t.Errorf("readModulePath got %q want example.com/xyz", p)
	}
}

func Test_DeriveDisplayName(t *testing.T) {
	cases := []struct{ name, purl, want string }{
		{"plain", "", "plain"},
		{"ignored", "pkg:golang/github.com/foo/bar@v1.0.0", "bar"},
	}
	for _, c := range cases {
		if got := deriveDisplayName(c.name, c.purl); got != c.want {
			t.Errorf("deriveDisplayName(%q,%q)=%q want %q", c.name, c.purl, got, c.want)
		}
	}
}

func Test_SPDXSafeIDFromPURL_and_Sanitize(t *testing.T) {
	cases := []struct{ in string }{
		{"pkg:golang/github.com/foo/bar@v1.0.0"},
		{"pkg:golang/github.com/foo/bar%2Bplus@v1.0.0"},
	}
	for _, c := range cases {
		id := spdxSafeIDFromPURL(c.in)
		if id == "" {
			t.Errorf("expected id for %q", c.in)
		}
		for _, r := range id {
			if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
				t.Errorf("unexpected rune %q in id %q", r, id)
				break
			}
		}
	}
}

func Test_ResolveReferenceName_Variants(t *testing.T) {
	ctx := t.Context()
	remote := "https://github.com/example/nonexistent-one-two-three.git"
	cases := []struct{ in string }{
		{"HEAD"}, {""}, {"main"}, {"master"}, {"v1.2.3"}, {"refs/heads/feature"}, {"refs/tags/v0.1.0"},
	}
	for _, c := range cases {
		ref, _ := ResolveReferenceName(ctx, remote, nil, c.in)
		if c.in == "refs/heads/feature" && !strings.HasPrefix(ref.String(), "refs/heads/") {
			t.Errorf("expected heads prefix for feature, got %s", ref)
		}
		if c.in == "refs/tags/v0.1.0" && !strings.HasPrefix(ref.String(), "refs/tags/") {
			t.Errorf("expected tags prefix for tag, got %s", ref)
		}
	}
}
