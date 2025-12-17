package gitutil

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"
	inv "github.com/picatz/deputy/internal/inventory"
)

func TestGetDefaultBranch(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	// Create initial commit on main branch
	dummy := filepath.Join(dir, "README.md")
	if err := os.WriteFile(dummy, []byte("# Test\n"), 0o644); err != nil {
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

	// The default branch should be detected
	branch, err := GetDefaultBranch(repo)
	if err != nil {
		t.Fatalf("GetDefaultBranch: %v", err)
	}
	// Either main or master is acceptable (depends on git config)
	if branch != "main" && branch != "master" && branch != "HEAD" {
		t.Errorf("unexpected default branch: %q", branch)
	}
}

func TestIsLikelyDefaultBranch(t *testing.T) {
	tests := []struct {
		name   string
		branch string
		want   bool
	}{
		{"main", "main", true},
		{"master", "master", true},
		{"trunk", "trunk", true},
		{"default", "default", true},
		{"develop", "develop", false},
		{"feature", "feature/xyz", false},
		{"release", "release/1.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isLikelyDefaultBranch(tt.branch)
			if got != tt.want {
				t.Errorf("isLikelyDefaultBranch(%q) = %v, want %v", tt.branch, got, tt.want)
			}
		})
	}
}

func TestCalculateSimilarity(t *testing.T) {
	tests := []struct {
		a, b     string
		wantMin  float64
		wantMax  float64
	}{
		{"main", "main", 1.0, 1.0},        // identical strings
		{"", "", 1.0, 1.0},                 // empty strings (edge case: both empty returns 1.0)
		{"abc", "abd", 0.6, 0.7},           // 2 of 3 match at same positions
		{"master", "maser", 0.4, 0.6},      // m-a-s match, t!=e, e!=r = 3/6 = 0.5
		{"xyz", "abc", 0.0, 0.1},           // no characters match
		{"main", "mane", 0.5, 0.75},        // m-a match, i!=n, n!=e = 2/4 = 0.5
	}
	for _, tt := range tests {
		t.Run(tt.a+"_"+tt.b, func(t *testing.T) {
			got := calculateSimilarity(tt.a, tt.b)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("calculateSimilarity(%q, %q) = %v, want between %v and %v", tt.a, tt.b, got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestValidateReference_WorkingTreeAliases(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	aliases := []string{"WORKING", "working", "Worktree", "WORKTREE", "WT", "wt", ".", " WORKING "}
	for _, alias := range aliases {
		t.Run(alias, func(t *testing.T) {
			err := validateReference(repo, alias)
			if err != nil {
				t.Errorf("validateReference(%q) returned error: %v", alias, err)
			}
		})
	}
}

func TestValidateReference_InvalidReference(t *testing.T) {
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

	err = validateReference(repo, "nonexistent-branch-xyz123")
	if err == nil {
		t.Error("expected error for invalid reference, got nil")
	}
	if !strings.Contains(err.Error(), "invalid reference") {
		t.Errorf("error should contain 'invalid reference', got: %v", err)
	}
}

func TestValidateReference_ValidHeadRef(t *testing.T) {
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

	// HEAD should be valid
	if err := validateReference(repo, "HEAD"); err != nil {
		t.Errorf("validateReference(HEAD) failed: %v", err)
	}

	// HEAD~0 should be valid
	if err := validateReference(repo, "HEAD~0"); err != nil {
		t.Errorf("validateReference(HEAD~0) failed: %v", err)
	}
}

func TestGetReferenceSuggestions(t *testing.T) {
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
	// Create a branch named "feature-xyz"
	headRef, err := repo.Head()
	if err != nil {
		t.Fatalf("Head: %v", err)
	}
	branchRef := plumbing.NewHashReference("refs/heads/feature-xyz", headRef.Hash())
	if err := repo.Storer.SetReference(branchRef); err != nil {
		t.Fatalf("SetReference: %v", err)
	}

	// Get suggestions for a typo
	suggestions := GetReferenceSuggestions(repo, "feature-xy")
	// Should suggest "feature-xyz" since it's similar
	found := false
	for _, s := range suggestions {
		if s == "feature-xyz" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected 'feature-xyz' in suggestions, got: %v", suggestions)
	}
}

func TestParseReferences_NoArgs(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	// Create initial commit
	dummy := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(dummy, []byte("module test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	base, target, err := ParseReferences(dir, nil, nil)
	if err != nil {
		t.Fatalf("ParseReferences: %v", err)
	}
	// With no matcher and clean tree, target should be HEAD
	if target != "HEAD" {
		t.Errorf("expected target HEAD, got %q", target)
	}
	// base should be the default branch
	if base == "" {
		t.Error("expected non-empty base reference")
	}
}

func TestParseReferences_OneArg(t *testing.T) {
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

	base, target, err := ParseReferences(dir, []string{"HEAD"}, nil)
	if err != nil {
		t.Fatalf("ParseReferences: %v", err)
	}
	if target != "HEAD" {
		t.Errorf("expected target HEAD, got %q", target)
	}
	if base == "" {
		t.Error("expected non-empty base reference")
	}
}

func TestParseReferences_TwoArgs(t *testing.T) {
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

	base, target, err := ParseReferences(dir, []string{"HEAD~0", "HEAD"}, nil)
	if err != nil {
		t.Fatalf("ParseReferences: %v", err)
	}
	if base != "HEAD~0" {
		t.Errorf("expected base HEAD~0, got %q", base)
	}
	if target != "HEAD" {
		t.Errorf("expected target HEAD, got %q", target)
	}
}

func TestParseReferences_TooManyArgs(t *testing.T) {
	dir := t.TempDir()
	_, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	_, _, err = ParseReferences(dir, []string{"a", "b", "c"}, nil)
	if err == nil {
		t.Error("expected error for too many arguments")
	}
	if !strings.Contains(err.Error(), "too many arguments") {
		t.Errorf("error should mention too many arguments, got: %v", err)
	}
}

func TestParseReferences_InvalidRepo(t *testing.T) {
	dir := t.TempDir()
	// Don't init a repo

	_, _, err := ParseReferences(dir, nil, nil)
	if err == nil {
		t.Error("expected error for non-repo directory")
	}
	if !strings.Contains(err.Error(), "error opening Git repository") {
		t.Errorf("error should mention opening repo, got: %v", err)
	}
}

func TestParseReferences_InvalidTargetRef(t *testing.T) {
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

	_, _, err = ParseReferences(dir, []string{"nonexistent-branch"}, nil)
	if err == nil {
		t.Error("expected error for invalid target reference")
	}
	if !strings.Contains(err.Error(), "invalid target reference") {
		t.Errorf("error should mention invalid target reference, got: %v", err)
	}
}

func TestHasWorkingDependencyChanges(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}
	// Create initial commit with go.mod
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module test\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("Worktree: %v", err)
	}
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if _, err := wt.Commit("initial", &git.CommitOptions{
		Author: &object.Signature{Name: "test", Email: "test@example.com", When: time.Now()},
	}); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	matcher, err := inv.GetDependencyMatcher(inv.ScanOptions{Ecosystems: []string{"go"}})
	if err != nil {
		t.Fatalf("GetDependencyMatcher: %v", err)
	}

	// Clean tree should return false
	has, err := hasWorkingDependencyChanges(repo, matcher)
	if err != nil {
		t.Fatalf("hasWorkingDependencyChanges: %v", err)
	}
	if has {
		t.Error("expected no working dependency changes for clean tree")
	}

	// Modify go.mod without committing
	if err := os.WriteFile(gomod, []byte("module test\n\nrequire foo v1.0.0\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	has, err = hasWorkingDependencyChanges(repo, matcher)
	if err != nil {
		t.Fatalf("hasWorkingDependencyChanges: %v", err)
	}
	if !has {
		t.Error("expected working dependency changes after modifying go.mod")
	}
}

func TestHasWorkingDependencyChanges_NilMatcher(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	has, err := hasWorkingDependencyChanges(repo, nil)
	if err != nil {
		t.Fatalf("hasWorkingDependencyChanges: %v", err)
	}
	if has {
		t.Error("expected false when matcher is nil")
	}
}

func TestFindLocalDefaultBranch(t *testing.T) {
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

	branch := findLocalDefaultBranch(repo)
	// Should find "main" or "master" (whichever was created by PlainInit)
	if branch != "main" && branch != "master" && branch != "" {
		t.Errorf("unexpected branch: %q", branch)
	}
}

func TestGetRemoteDefaultBranch_NoRemotes(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	branch := getRemoteDefaultBranch(repo)
	if branch != "" {
		t.Errorf("expected empty string for repo with no remotes, got %q", branch)
	}
}

func TestGetRemoteDefaultBranch_WithOrigin(t *testing.T) {
	dir := t.TempDir()
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("PlainInit: %v", err)
	}

	// Add a remote (won't actually connect but tests the logic)
	_, err = repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{"https://github.com/test/repo.git"},
	})
	if err != nil {
		t.Fatalf("CreateRemote: %v", err)
	}

	// This will fail to connect to the remote, but should not panic
	branch := getRemoteDefaultBranch(repo)
	// May be empty since we can't actually connect
	_ = branch
}
