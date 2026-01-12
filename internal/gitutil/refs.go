package gitutil

import (
	"fmt"
	"reflect"
	"slices"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// Common Git reference constants.
const (
	// RefHEAD is the symbolic reference to the current commit.
	RefHEAD = "HEAD"
	// RefWORKING represents the working tree (uncommitted changes).
	RefWORKING = "WORKING"
)

// PathMatcher reports whether a path should be treated as a dependency manifest.
type PathMatcher interface {
	Matches(path string) bool
}

// ParseReferences intelligently parses command line arguments to determine base and target references.
// It supports all Git reference types: branches, tags, commits, remote refs, and Git revision expressions.
// Dependency-related decisions (e.g., whether to compare with WORKING) are aided by the provided matcher.
func ParseReferences(repoPath string, args []string, matcher PathMatcher) (baseRef, targetRef string, err error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", "", fmt.Errorf("error opening Git repository at %s: %w", repoPath, err)
	}

	// Find the default branch (main, master, or current HEAD)
	defaultBranch, err := GetDefaultBranch(repo)
	if err != nil {
		return "", "", fmt.Errorf("error determining default branch: %w", err)
	}
	switch len(args) {
	case 0:
		// No arguments: compare default branch with HEAD by default.
		// If working tree has dependency changes, compare default branch with WORKING tree.
		if ok, _ := hasWorkingDependencyChanges(repo, matcher); ok {
			return defaultBranch, RefWORKING, nil
		}
		return defaultBranch, RefHEAD, nil
	case 1:
		// One argument: compare default branch with provided reference
		// Validate the provided reference
		if err := validateReference(repo, args[0]); err != nil {
			return "", "", fmt.Errorf("invalid target reference %q: %w", args[0], err)
		}
		return defaultBranch, args[0], nil
	case 2:
		// Two arguments: first is base, second is target
		if err := validateReference(repo, args[0]); err != nil {
			return "", "", fmt.Errorf("invalid base reference %q: %w", args[0], err)
		}
		if err := validateReference(repo, args[1]); err != nil {
			return "", "", fmt.Errorf("invalid target reference %q: %w", args[1], err)
		}
		return args[0], args[1], nil
	default:
		return "", "", fmt.Errorf("too many arguments provided (maximum 2)")
	}
}

// hasWorkingDependencyChanges reports if dependency manifest/lock files have uncommitted changes.
func hasWorkingDependencyChanges(repo *git.Repository, matcher PathMatcher) (bool, error) {
	if matcher == nil || isNilMatcher(matcher) {
		return false, nil
	}
	wt, err := repo.Worktree()
	if err != nil {
		return false, err
	}
	st, err := wt.Status()
	if err != nil {
		return false, err
	}
	for path, stat := range st {
		if stat.Worktree == git.Unmodified && stat.Staging == git.Unmodified {
			continue
		}
		if matcher.Matches(path) {
			return true, nil
		}
	}
	return false, nil
}

func isNilMatcher(matcher PathMatcher) bool {
	v := reflect.ValueOf(matcher)
	if !v.IsValid() {
		return true
	}
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	default:
		return false
	}
}

// GetDefaultBranch attempts to find the repository's default branch using multiple strategies.
func GetDefaultBranch(repo *git.Repository) (string, error) {
	// Strategy 1: Try to get the remote HEAD symref (most reliable for GitHub/GitLab)
	if defaultBranch := getRemoteDefaultBranch(repo); defaultBranch != "" {
		return defaultBranch, nil
	}
	// Strategy 2: Check if we're currently on a reasonable default branch
	if head, err := repo.Head(); err == nil && head.Name().IsBranch() {
		currentBranch := head.Name().Short()
		if isLikelyDefaultBranch(currentBranch) {
			return currentBranch, nil
		}
	}
	// Strategy 3: Look for common default branch names in local branches
	if defaultBranch := findLocalDefaultBranch(repo); defaultBranch != "" {
		return defaultBranch, nil
	}
	// Strategy 4: Try to find any branch that looks like a default
	branches, err := repo.Branches()
	if err == nil {
		var anyBranch string
		_ = branches.ForEach(func(ref *plumbing.Reference) error {
			name := ref.Name().Short()
			if isLikelyDefaultBranch(name) {
				anyBranch = name
				return fmt.Errorf("stop")
			}
			if anyBranch == "" {
				anyBranch = name
			}
			return nil
		})
		if anyBranch != "" {
			return anyBranch, nil
		}
	}
	// Fallback to HEAD if nothing else
	return RefHEAD, nil
}

// getRemoteDefaultBranch tries to determine the default branch from remote HEAD symref.
func getRemoteDefaultBranch(repo *git.Repository) string {
	remotes, err := repo.Remotes()
	if err != nil || len(remotes) == 0 {
		return ""
	}
	remoteOrder := []string{"origin", "upstream"}
	for _, remoteName := range remoteOrder {
		idx := slices.IndexFunc(remotes, func(r *git.Remote) bool {
			return r.Config().Name == remoteName
		})
		if idx != -1 {
			if branch := getRemoteHeadBranch(remotes[idx]); branch != "" {
				return branch
			}
		}
	}
	for _, remote := range remotes {
		if branch := getRemoteHeadBranch(remote); branch != "" {
			return branch
		}
	}
	return ""
}

func getRemoteHeadBranch(remote *git.Remote) string {
	refs, err := remote.List(&git.ListOptions{})
	if err != nil {
		return ""
	}
	targetRef := fmt.Sprintf("refs/remotes/%s/HEAD", remote.Config().Name)
	idx := slices.IndexFunc(refs, func(ref *plumbing.Reference) bool {
		return ref.Name().String() == targetRef
	})
	if idx == -1 {
		return ""
	}
	headSymref := refs[idx]

	if headSymref.Type() == plumbing.SymbolicReference {
		target := headSymref.Target().String()
		if after, ok := strings.CutPrefix(target, fmt.Sprintf("refs/remotes/%s/", remote.Config().Name)); ok {
			return after
		}
	}
	return ""
}

// DefaultBranchPatterns lists common default branch names used by various Git hosting providers.
// Order matters: more common names come first for prioritized matching.
var DefaultBranchPatterns = []string{"main", "master", "trunk", "default"}

// findLocalDefaultBranch looks for common default branch names in local branches.
func findLocalDefaultBranch(repo *git.Repository) string {
	branches, err := repo.Branches()
	if err != nil {
		return ""
	}
	for _, candidate := range DefaultBranchPatterns {
		var found bool
		branches.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().Short() == candidate {
				found = true
				return fmt.Errorf("stop")
			}
			return nil
		})
		if found {
			return candidate
		}
	}
	return ""
}

// isLikelyDefaultBranch checks if a branch name looks like a default branch.
func isLikelyDefaultBranch(branchName string) bool {
	return slices.Contains(DefaultBranchPatterns, branchName)
}

// validateReference checks if a Git reference is valid and provides helpful error messages.
func validateReference(repo *git.Repository, ref string) error {
	upper := strings.ToUpper(strings.TrimSpace(ref))
	if upper == "WORKING" || upper == "WORKTREE" || upper == "WT" || strings.TrimSpace(ref) == "." {
		return nil
	}
	if _, err := ResolveRevisionEnhanced(repo, ref); err == nil {
		return nil
	}
	// Try with origin/ prefix for CI environments where branch names are remote refs
	if !strings.Contains(ref, "/") {
		if _, err := ResolveRevisionEnhanced(repo, "origin/"+ref); err == nil {
			return nil
		}
	}
	suggestions := GetReferenceSuggestions(repo, ref)
	if len(suggestions) > 0 {
		return fmt.Errorf("invalid reference %q\nDid you mean one of these?\n  %s", ref, strings.Join(suggestions, "\n  "))
	}
	return fmt.Errorf("invalid reference %q", ref)
}

// GetReferenceSuggestions provides helpful suggestions for similar reference names.
func GetReferenceSuggestions(repo *git.Repository, invalidRef string) []string {
	var suggestions []string
	// Branches
	if branches, err := repo.Branches(); err == nil {
		_ = branches.ForEach(func(ref *plumbing.Reference) error {
			name := ref.Name().Short()
			if calculateSimilarity(name, invalidRef) > 0.6 {
				suggestions = append(suggestions, name)
			}
			return nil
		})
	}
	// Tags
	if tags, err := repo.Tags(); err == nil {
		_ = tags.ForEach(func(ref *plumbing.Reference) error {
			name := strings.TrimPrefix(ref.Name().String(), "refs/tags/")
			if calculateSimilarity(name, invalidRef) > 0.6 {
				suggestions = append(suggestions, name)
			}
			return nil
		})
	}
	// Remotes
	if remotes, err := repo.Remotes(); err == nil {
		for _, remote := range remotes {
			remoteName := remote.Config().Name
			candidate := fmt.Sprintf("%s/%s", remoteName, invalidRef)
			if _, err := repo.ResolveRevision(plumbing.Revision(candidate)); err == nil {
				suggestions = append(suggestions, candidate)
			}
		}
	}
	if len(suggestions) > 5 {
		suggestions = suggestions[:5]
	}
	return suggestions
}

// calculateSimilarity returns a simple similarity score between two strings.
func calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	maxLen := max(len(b), len(a))
	if maxLen == 0 {
		return 0
	}
	common := 0
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			common++
		}
	}
	return float64(common) / float64(maxLen)
}
