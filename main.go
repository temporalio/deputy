package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"

	pb "deps.dev/api/v3"
	"github.com/charmbracelet/fang"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	pl "github.com/google/osv-scalibr/plugin/list"
	"github.com/spf13/cobra"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func init() {
	log.SetLogger(&scalibrNullLogger{})
}

// ANSI color codes
const (
	colorReset = "\033[0m"
	colorBold  = "\033[1m"
	colorDim   = "\033[2m"

	// Semantic colors - thoughtful and meaningful
	colorAdded      = "\033[1;32m" // Bold Green - positive, something new
	colorRemoved    = "\033[1;31m" // Bold Red - negative, something lost
	colorUpgraded   = "\033[1;36m" // Bold Cyan - neutral positive, forward movement
	colorDowngraded = "\033[1;33m" // Bold Yellow - caution, potential concern
	colorNeutral    = "\033[1;37m" // Bold White - neutral change

	// UI elements - subtle and supportive
	colorPackageName = "\033[0m"    // Default color for package names
	colorVersion     = "\033[90m"   // Gray for version numbers (less important)
	colorLicense     = "\033[2;90m" // Dim gray for license info (least important)
	colorArrow       = "\033[2;36m" // Dim cyan for arrows - subtle but visible
	colorHeader      = "\033[1;94m" // Bold bright blue for headers
	colorSymbol      = "\033[1m"    // Bold for symbols
)

// PackageChangeType represents the type of change for a package
type PackageChangeType int

const (
	Added PackageChangeType = iota
	Removed
	Updated
)

// PackageChange represents a change to a package between references
type PackageChange struct {
	Name          string
	TargetVersion string // Version in the target reference
	BaseVersion   string // Version in the base reference
	ChangeType    PackageChangeType
	Ecosystem     string // The package ecosystem (go, npm, pip, etc.)
}

// EcosystemType represents different package management ecosystems
type EcosystemType string

const (
	EcosystemGo       EcosystemType = "go"
	EcosystemNpm      EcosystemType = "npm"
	EcosystemPip      EcosystemType = "pip"
	EcosystemMaven    EcosystemType = "maven"
	EcosystemNuGet    EcosystemType = "nuget"
	EcosystemCargo    EcosystemType = "cargo"
	EcosystemComposer EcosystemType = "composer"
)

// PackageEcosystem defines the interface for different package management ecosystems
type PackageEcosystem interface {
	// GetName returns the ecosystem name (e.g., "go", "npm", "pip")
	GetName() EcosystemType

	// GetManifestFiles returns the list of manifest files that indicate this ecosystem
	GetManifestFiles() []string

	// CompareVersions compares two version strings and returns:
	// 1 for upgrade, -1 for downgrade, 0 for unclear/equal
	CompareVersions(oldVersion, newVersion string) int

	// NormalizeVersion normalizes a version string for comparison
	NormalizeVersion(version string) string

	// IsPseudoVersion checks if a version is a pseudo-version (if applicable)
	IsPseudoVersion(version string) bool

	// GetVersionInfo extracts detailed information from a version string
	GetVersionInfo(version string) VersionInfo

	// GetApiSystem returns the system identifier for deps.dev API
	GetApiSystem() pb.System
}

// VersionInfo contains detailed information about a version
type VersionInfo struct {
	Original  string            // Original version string
	Canonical string            // Normalized canonical version
	IsPseudo  bool              // Whether this is a pseudo-version
	Base      string            // Base version for pseudo-versions
	Timestamp string            // Timestamp for pseudo-versions
	Hash      string            // Hash for pseudo-versions
	Metadata  map[string]string // Additional ecosystem-specific metadata
}

type scalibrNullLogger struct{}

func (*scalibrNullLogger) Debug(args ...any)                 {}
func (*scalibrNullLogger) Debugf(format string, args ...any) {}
func (*scalibrNullLogger) Error(args ...any)                 {}
func (*scalibrNullLogger) Errorf(format string, args ...any) {}
func (*scalibrNullLogger) Info(args ...any)                  {}
func (*scalibrNullLogger) Infof(format string, args ...any)  {}
func (*scalibrNullLogger) Warn(args ...any)                  {}
func (*scalibrNullLogger) Warnf(format string, args ...any)  {}

func checkFilesChanged(repoPath string, baseRef string, prRef string) ([]string, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("error opening repository: %w", err)
	}

	baseHash, err := repo.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		return nil, fmt.Errorf("error resolving base reference '%s': %w", baseRef, err)
	}

	prHash, err := repo.ResolveRevision(plumbing.Revision(prRef))
	if err != nil {
		return nil, fmt.Errorf("error resolving PR reference '%s': %w", prRef, err)
	}

	baseCommit, err := repo.CommitObject(*baseHash)
	if err != nil {
		return nil, fmt.Errorf("error getting base commit: %w", err)
	}

	prCommit, err := repo.CommitObject(*prHash)
	if err != nil {
		return nil, fmt.Errorf("error getting PR commit: %w", err)
	}

	changes, err := baseCommit.Patch(prCommit)
	if err != nil {
		return nil, fmt.Errorf("error getting patch: %w", err)
	}

	fileNames := make([]string, 0)
	for _, change := range changes.FilePatches() {
		from, to := change.Files()
		var fileName string
		if from != nil {
			fileName = from.Path()
		} else if to != nil {
			fileName = to.Path()
		} else {
			// This shouldn't happen, but let's be safe
			continue
		}
		fileNames = append(fileNames, fileName)
	}

	return fileNames, nil
}

// GitState represents the current state of a git repository
type GitState struct {
	CurrentHash   plumbing.Hash
	CurrentBranch string
	IsDetached    bool
	HasChanges    bool
}

// saveGitState captures the current git repository state
func saveGitState(repo *git.Repository, worktree *git.Worktree) (*GitState, error) {
	head, err := repo.Head()
	if err != nil {
		return nil, fmt.Errorf("error getting current HEAD: %w", err)
	}

	state := &GitState{
		CurrentHash: head.Hash(),
		IsDetached:  false,
		HasChanges:  false,
	}

	// Check if we're on a branch or in detached HEAD state
	if head.Name().IsBranch() {
		state.CurrentBranch = head.Name().Short()
	} else {
		state.IsDetached = true
	}

	// Check if there are uncommitted changes
	status, err := worktree.Status()
	if err != nil {
		return nil, fmt.Errorf("error checking worktree status: %w", err)
	}
	state.HasChanges = !status.IsClean()

	return state, nil
}

// restoreGitState restores the git repository to its previous state
func restoreGitState(worktree *git.Worktree, state *GitState) error {
	var checkoutErr error

	if state.IsDetached {
		// If we were in detached HEAD state, restore to the exact commit
		checkoutErr = worktree.Checkout(&git.CheckoutOptions{
			Hash:  state.CurrentHash,
			Force: true,
		})
	} else {
		// If we were on a branch, restore to that branch
		checkoutErr = worktree.Checkout(&git.CheckoutOptions{
			Branch: plumbing.ReferenceName("refs/heads/" + state.CurrentBranch),
			Force:  true,
		})
	}

	if checkoutErr != nil {
		return fmt.Errorf("error restoring git checkout: %w", checkoutErr)
	}

	// Note: We don't try to restore uncommitted changes as they would be complex to handle
	// and could conflict with the forced checkout. Users should stash changes before running.
	if state.HasChanges {
		fmt.Println("Note: Your working directory had uncommitted changes before running deputy. These were not restored.")
	}

	return nil
}

func scanPackages(ctx context.Context, repoPath string, commitHash plumbing.Hash) ([]*extractor.Package, error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, fmt.Errorf("error opening repository: %w", err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return nil, fmt.Errorf("error getting worktree: %w", err)
	}

	// Save current git state for restoration
	originalState, err := saveGitState(repo, worktree)
	if err != nil {
		return nil, fmt.Errorf("error saving git state: %w", err)
	}

	// Ensure we restore the original state, even on error
	defer func() {
		if restoreErr := restoreGitState(worktree, originalState); restoreErr != nil {
			fmt.Printf("Warning: failed to restore git state: %v\n", restoreErr)
		}
	}()

	err = worktree.Checkout(&git.CheckoutOptions{
		Hash:  commitHash,
		Force: true,
	})
	if err != nil {
		return nil, fmt.Errorf("error checking out commit: %w", err)
	}

	plugins, err := pl.FromNames([]string{"go"})
	if err != nil {
		return nil, fmt.Errorf("error creating plugins: %w", err)
	}

	cfg := &scalibr.ScanConfig{
		ScanRoots: scalibrfs.RealFSScanRoots(repoPath),
		Plugins:   plugins,
	}

	results := scalibr.New().Scan(ctx, cfg)

	return results.Inventory.Packages, nil
}

// canonicalPackages takes a list of packages and returns a map with the canonical version for each package name.
// The canonical version is determined by selecting the most frequently occurring version for each package.
func canonicalPackages(pkgs []*extractor.Package) map[string]string {
	// Group packages by name and count version occurrences
	versionCounts := make(map[string]map[string]int)
	for _, pkg := range pkgs {
		if _, exists := versionCounts[pkg.Name]; !exists {
			versionCounts[pkg.Name] = make(map[string]int)
		}
		versionCounts[pkg.Name][pkg.Version]++
	}

	// Find the most frequently occurring version for each package
	result := make(map[string]string)
	for pkgName, versions := range versionCounts {
		var maxCount int
		var canonicalVersion string
		for version, count := range versions {
			if count > maxCount {
				maxCount = count
				canonicalVersion = version
			}
		}
		result[pkgName] = canonicalVersion
	}

	return result
}

func comparePackages(oldPkgs, newPkgs []*extractor.Package) []PackageChange {
	var changes []PackageChange

	// Get canonical versions for old and new packages
	oldCanonical := canonicalPackages(oldPkgs)
	newCanonical := canonicalPackages(newPkgs)

	// Find updated and removed packages
	for pkgName, oldVersion := range oldCanonical {
		if newVersion, exists := newCanonical[pkgName]; exists {
			if oldVersion != newVersion {
				changes = append(changes, PackageChange{
					Name:          pkgName,
					BaseVersion:   oldVersion, // Base/old version
					TargetVersion: newVersion, // Target/new version
					ChangeType:    Updated,
					Ecosystem:     "go", // For now, hardcode as Go
				})
			}
		} else {
			changes = append(changes, PackageChange{
				Name:          pkgName,
				BaseVersion:   oldVersion,
				TargetVersion: "", // No target version as it was removed
				ChangeType:    Removed,
				Ecosystem:     "go", // For now, hardcode as Go
			})
		}
	}

	// Find added packages
	for pkgName, newVersion := range newCanonical {
		if _, exists := oldCanonical[pkgName]; !exists {
			changes = append(changes, PackageChange{
				Name:          pkgName,
				BaseVersion:   "",         // No base version as it was added
				TargetVersion: newVersion, // Target has the new version
				ChangeType:    Added,
				Ecosystem:     "go", // For now, hardcode as Go
			})
		}
	}

	// Sort changes by name
	slices.SortFunc(changes, func(a, b PackageChange) int {
		return strings.Compare(a.Name, b.Name)
	})

	return changes
}

// compareVersionsForEcosystem compares versions using ecosystem-specific logic
// Returns: 1 for upgrade, -1 for downgrade, 0 for unclear/equal
//
// This lightweight approach makes it easy to add support for other ecosystems:
// - npm: add case for "npm" with npm-specific semver logic
// - pip: add case for "pip" with PEP 440 version comparison
// - maven: add case for "maven" with Maven version ordering
// - etc.
func compareVersionsForEcosystem(oldVersion, newVersion, ecosystem string) int {
	switch ecosystem {
	case "go", "golang":
		return compareGoVersions(oldVersion, newVersion)
	default:
		// Fallback to basic semantic version comparison
		return compareGoVersions(oldVersion, newVersion) // Re-use Go logic as default
	}
}

// compareGoVersions attempts to determine if a version change is an upgrade or downgrade using Go module semantics
// Returns: 1 for upgrade, -1 for downgrade, 0 for unclear/equal
func compareGoVersions(oldVersion, newVersion string) int {
	// Handle empty versions
	if oldVersion == "" || newVersion == "" {
		return 0
	}

	// Normalize versions to ensure they have 'v' prefix for Go module comparison
	oldNormalized := normalizeGoVersion(oldVersion)
	newNormalized := normalizeGoVersion(newVersion)

	// Use Go's semver package for proper semantic version comparison
	// This handles pseudo-versions, pre-releases, and standard semantic versions correctly
	result := semver.Compare(oldNormalized, newNormalized)

	// semver.Compare returns:
	//   -1 if oldVersion < newVersion (upgrade) -> we want to return 1
	//    0 if oldVersion = newVersion (no change) -> we want to return 0
	//    1 if oldVersion > newVersion (downgrade) -> we want to return -1
	return -result
}

// normalizeGoVersion ensures a version string is in the format expected by Go's semver package
func normalizeGoVersion(version string) string {
	if version == "" {
		return version
	}

	// If it already starts with 'v', return as-is
	if strings.HasPrefix(version, "v") {
		return version
	}

	// Add 'v' prefix
	return "v" + version
}

// isPseudoVersion checks if a version string is a Go pseudo-version
func isPseudoVersion(version string) bool {
	normalized := normalizeGoVersion(version)
	return module.IsPseudoVersion(normalized)
}

// getPseudoVersionInfo extracts information from a pseudo-version
func getPseudoVersionInfo(version string) (base, timestamp, hash string, err error) {
	normalized := normalizeGoVersion(version)
	if !module.IsPseudoVersion(normalized) {
		return "", "", "", fmt.Errorf("not a pseudo-version: %s", version)
	}

	base, err = module.PseudoVersionBase(normalized)
	if err != nil {
		return "", "", "", fmt.Errorf("error extracting base: %w", err)
	}

	timeVal, err := module.PseudoVersionTime(normalized)
	if err != nil {
		return "", "", "", fmt.Errorf("error extracting time: %w", err)
	}

	hash, err = module.PseudoVersionRev(normalized)
	if err != nil {
		return "", "", "", fmt.Errorf("error extracting revision: %w", err)
	}

	return base, timeVal.Format("2006-01-02T15:04:05Z"), hash, nil
}

// parseVersion extracts numeric parts from a version string
func parseVersion(version string) []int {
	// Remove common prefixes
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")

	// Split by dots and extract numbers
	parts := strings.Split(version, ".")
	var nums []int

	for _, part := range parts {
		// Extract leading numbers from each part (handles cases like "1.2.3-alpha")
		var numStr string
		for _, r := range part {
			if r >= '0' && r <= '9' {
				numStr += string(r)
			} else {
				break
			}
		}

		if numStr != "" {
			if num := parseInt(numStr); num >= 0 {
				nums = append(nums, num)
			}
		}
	}

	return nums
}

// parseInt safely converts a string to int, returns -1 on error
func parseInt(s string) int {
	result := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		result = result*10 + int(r-'0')
	}
	return result
}

// validateReference checks if a Git reference is valid and provides helpful error messages
func validateReference(repo *git.Repository, ref string) error {
	// Try to resolve the reference
	_, err := repo.ResolveRevision(plumbing.Revision(ref))
	if err == nil {
		return nil // Reference is valid
	}

	// If resolution failed, provide helpful suggestions
	suggestions := getReferenceSuggestions(repo, ref)
	if len(suggestions) > 0 {
		return fmt.Errorf("%w\nDid you mean one of these?\n  %s",
			err, strings.Join(suggestions, "\n  "))
	}

	// Provide general help about valid reference types
	return fmt.Errorf("%w\nValid references include:\n"+
		"  • Branch names: main, develop, feature-branch\n"+
		"  • Tags: v1.0.0, release-2023\n"+
		"  • Commit SHAs: 1a2b3c4, 1a2b3c4d5e6f7890abcdef\n"+
		"  • Remote refs: origin/main, upstream/develop\n"+
		"  • Git expressions: HEAD~3, main^, HEAD@{yesterday}\n"+
		"Use 'git branch -a' and 'git tag' to see available references", err)
}

// getReferenceSuggestions provides helpful suggestions for similar reference names
func getReferenceSuggestions(repo *git.Repository, invalidRef string) []string {
	var suggestions []string

	// Check local branches
	if branches, err := repo.Branches(); err == nil {
		branches.ForEach(func(ref *plumbing.Reference) error {
			branchName := ref.Name().Short()
			if similarity := calculateSimilarity(invalidRef, branchName); similarity > 0.6 {
				suggestions = append(suggestions, branchName)
			}
			return nil
		})
	}

	// Check tags
	if tags, err := repo.Tags(); err == nil {
		tags.ForEach(func(ref *plumbing.Reference) error {
			tagName := ref.Name().Short()
			if similarity := calculateSimilarity(invalidRef, tagName); similarity > 0.6 {
				suggestions = append(suggestions, tagName)
			}
			return nil
		})
	}

	// Check remotes
	if remotes, err := repo.Remotes(); err == nil {
		for _, remote := range remotes {
			remoteName := remote.Config().Name
			candidate := fmt.Sprintf("%s/%s", remoteName, invalidRef)
			if _, err := repo.ResolveRevision(plumbing.Revision(candidate)); err == nil {
				suggestions = append(suggestions, candidate)
			}
		}
	}

	// Limit suggestions to avoid overwhelming output
	if len(suggestions) > 5 {
		suggestions = suggestions[:5]
	}

	return suggestions
}

// calculateSimilarity returns a simple similarity score between two strings
func calculateSimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}

	// Simple similarity: ratio of common characters
	maxLen := len(a)
	if len(b) > maxLen {
		maxLen = len(b)
	}
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

// parseReferences intelligently parses command line arguments to determine base and target references
// It supports all Git reference types: branches, tags, commits, remote refs, and Git revision expressions
func parseReferences(repoPath string, args []string) (baseRef, targetRef string, err error) {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return "", "", fmt.Errorf("error opening Git repository at %s: %w", repoPath, err)
	}

	// Find the default branch (main, master, or current HEAD)
	defaultBranch, err := getDefaultBranch(repo)
	if err != nil {
		return "", "", fmt.Errorf("error determining default branch: %w", err)
	}

	switch len(args) {
	case 0:
		// No arguments: compare current HEAD with default branch
		// This is useful for checking what changed in your current work vs the main branch
		return defaultBranch, "HEAD", nil
	case 1:
		// One argument: compare default branch with provided reference
		// Validate the provided reference
		if err := validateReference(repo, args[0]); err != nil {
			return "", "", fmt.Errorf("invalid target reference %q: %w", args[0], err)
		}
		return defaultBranch, args[0], nil
	case 2:
		// Two arguments: first is base, second is target
		// Validate both references
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

// getDefaultBranch attempts to find the repository's default branch using multiple strategies
func getDefaultBranch(repo *git.Repository) (string, error) {
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
	if branches, err := repo.Branches(); err == nil {
		var firstBranch string
		err = branches.ForEach(func(ref *plumbing.Reference) error {
			branchName := ref.Name().Short()
			if firstBranch == "" {
				firstBranch = branchName
			}
			if isLikelyDefaultBranch(branchName) {
				return fmt.Errorf("found:%s", branchName) // Use error to break early
			}
			return nil
		})

		if err != nil && strings.HasPrefix(err.Error(), "found:") {
			return strings.TrimPrefix(err.Error(), "found:"), nil
		}

		// If we found at least one branch, use it
		if firstBranch != "" {
			return firstBranch, nil
		}
	}

	// Ultimate fallback: use HEAD
	return "HEAD", nil
}

// getRemoteDefaultBranch tries to determine the default branch from remote HEAD symref
func getRemoteDefaultBranch(repo *git.Repository) string {
	remotes, err := repo.Remotes()
	if err != nil || len(remotes) == 0 {
		return ""
	}

	// Prioritize 'origin' remote, then 'upstream', then any remote
	remoteOrder := []string{"origin", "upstream"}

	for _, remoteName := range remoteOrder {
		for _, remote := range remotes {
			if remote.Config().Name == remoteName {
				if branch := getRemoteHeadBranch(remote); branch != "" {
					return branch
				}
			}
		}
	}

	// Try any remaining remote
	for _, remote := range remotes {
		if branch := getRemoteHeadBranch(remote); branch != "" {
			return branch
		}
	}

	return ""
}

// getRemoteHeadBranch extracts the default branch from a remote's HEAD symref
func getRemoteHeadBranch(remote *git.Remote) string {
	refs, err := remote.List(&git.ListOptions{})
	if err != nil {
		return ""
	}

	var headSymref *plumbing.Reference
	for _, ref := range refs {
		if ref.Name().String() == fmt.Sprintf("refs/remotes/%s/HEAD", remote.Config().Name) {
			headSymref = ref
			break
		}
	}

	if headSymref != nil && headSymref.Type() == plumbing.SymbolicReference {
		// Extract branch name from symref target
		target := headSymref.Target().String()
		if strings.HasPrefix(target, fmt.Sprintf("refs/remotes/%s/", remote.Config().Name)) {
			return strings.TrimPrefix(target, fmt.Sprintf("refs/remotes/%s/", remote.Config().Name))
		}
	}

	return ""
}

// findLocalDefaultBranch looks for common default branch names in local branches
func findLocalDefaultBranch(repo *git.Repository) string {
	branches, err := repo.Branches()
	if err != nil {
		return ""
	}

	// Check for common default branch names in order of preference
	defaultCandidates := []string{"main", "master", "develop", "development", "trunk"}

	for _, candidate := range defaultCandidates {
		var found bool
		branches.ForEach(func(ref *plumbing.Reference) error {
			if ref.Name().Short() == candidate {
				found = true
				return fmt.Errorf("stop") // break early
			}
			return nil
		})
		if found {
			return candidate
		}
	}

	return ""
}

// isLikelyDefaultBranch checks if a branch name looks like a default branch
func isLikelyDefaultBranch(branchName string) bool {
	defaultPatterns := []string{"main", "master", "develop", "development", "trunk", "default"}
	for _, pattern := range defaultPatterns {
		if branchName == pattern {
			return true
		}
	}
	return false
}

// listAvailableReferences displays all available Git references in a user-friendly format
func listAvailableReferences(repoPath string) error {
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("error opening Git repository at %s: %w", repoPath, err)
	}

	fmt.Printf("Available Git references in %s:\n\n", repoPath)

	// Show default branch
	defaultBranch, err := getDefaultBranch(repo)
	if err == nil {
		fmt.Printf("%sDefault branch:%s %s\n\n", colorHeader, colorReset, defaultBranch)
	}

	// List local branches
	fmt.Printf("%sLocal branches:%s\n", colorHeader, colorReset)
	branches, err := repo.Branches()
	if err != nil {
		fmt.Printf("  Error listing branches: %v\n", err)
	} else {
		var branchCount int
		branches.ForEach(func(ref *plumbing.Reference) error {
			branchName := ref.Name().Short()
			if branchName == defaultBranch {
				fmt.Printf("  %s (default)\n", branchName)
			} else {
				fmt.Printf("  %s\n", branchName)
			}
			branchCount++
			return nil
		})
		if branchCount == 0 {
			fmt.Println("  No local branches found")
		}
	}

	// List tags
	fmt.Printf("\n%sTags:%s\n", colorHeader, colorReset)
	tags, err := repo.Tags()
	if err != nil {
		fmt.Printf("  Error listing tags: %v\n", err)
	} else {
		var tagCount int
		tags.ForEach(func(ref *plumbing.Reference) error {
			fmt.Printf("  %s\n", ref.Name().Short())
			tagCount++
			return nil
		})
		if tagCount == 0 {
			fmt.Println("  No tags found")
		}
	}

	// List remotes and their branches
	fmt.Printf("\n%sRemote branches:%s\n", colorHeader, colorReset)
	remotes, err := repo.Remotes()
	if err != nil {
		fmt.Printf("  Error listing remotes: %v\n", err)
	} else if len(remotes) == 0 {
		fmt.Println("  No remotes configured")
	} else {
		for _, remote := range remotes {
			fmt.Printf("  %s:\n", remote.Config().Name)
			refs, err := remote.List(&git.ListOptions{})
			if err != nil {
				fmt.Printf("    Error listing remote refs: %v\n", err)
				continue
			}

			var remoteBranches []string
			for _, ref := range refs {
				if ref.Name().IsBranch() {
					// Extract branch name from refs/heads/branch-name
					branchName := strings.TrimPrefix(ref.Name().String(), "refs/heads/")
					remoteBranches = append(remoteBranches, fmt.Sprintf("%s/%s", remote.Config().Name, branchName))
				}
			}

			if len(remoteBranches) == 0 {
				fmt.Println("    No remote branches found")
			} else {
				for _, branch := range remoteBranches {
					fmt.Printf("    %s\n", branch)
				}
			}
		}
	}

	// Show usage examples
	fmt.Printf("\n%sUsage examples:%s\n", colorHeader, colorReset)
	fmt.Println("  deputy                    # Compare HEAD with default branch")
	fmt.Println("  deputy feature-branch     # Compare default branch with feature-branch")
	if defaultBranch != "" {
		fmt.Printf("  deputy %s HEAD           # Compare %s with current HEAD\n", defaultBranch, defaultBranch)
	}
	fmt.Println("  deputy HEAD~3 HEAD        # Compare 3 commits ago with HEAD")
	if len(remotes) > 0 {
		remoteName := remotes[0].Config().Name
		fmt.Printf("  deputy %s/main main       # Compare remote with local branch\n", remoteName)
	}

	return nil
}

func main() {
	var repoPath string
	var listRefs bool

	cwd, err := os.Getwd()
	if err != nil {
		fmt.Println("Error getting current working directory:", err)
		os.Exit(1)
	}

	rootCmd := &cobra.Command{
		Use:   "deputy [base] [target]",
		Short: "Analyze dependency changes between Git references",
		Long: `deputy analyzes dependency changes between Git references with comprehensive support for all Git reference types.

SUPPORTED REFERENCE TYPES:
• Branch names: main, develop, feature-branch, bugfix/issue-123
• Tags: v1.0.0, release-2023, latest
• Commit SHAs: 1a2b3c4, 1a2b3c4d5e6f7890abcdef123456789
• Remote references: origin/main, upstream/develop, fork/feature
• Git revision expressions: HEAD~3, main^, HEAD@{yesterday}, @{upstream}
• Relative references: HEAD~1, main~5, tag^{tree}

USAGE PATTERNS:
• No arguments: Compare current HEAD with default branch (auto-detected)
• One argument: Compare default branch with the specified reference  
• Two arguments: Compare first reference (base) with second reference (target)

The tool automatically detects the repository's default branch by checking:
1. Remote HEAD symref (most reliable for GitHub/GitLab repos)
2. Current branch if it's a likely default (main, master, develop)
3. Common default branch names in local branches
4. Falls back to any available branch or HEAD

DEPENDENCY DETECTION:
Only analyzes changes when go.mod or go.sum files are modified between references.
Provides license information for changed packages via the deps.dev API.`,
		Args: cobra.MaximumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Handle list-refs flag
			if listRefs {
				return listAvailableReferences(repoPath)
			}

			baseRef, targetRef, err := parseReferences(repoPath, args)
			if err != nil {
				return err
			}
			return runDepDelta(repoPath, baseRef, targetRef)
		},
	}

	// Add flags
	rootCmd.Flags().StringVarP(&repoPath, "repo", "r", cwd, "Path to the repository")
	rootCmd.Flags().BoolVarP(&listRefs, "list-refs", "l", false, "List all available Git references (branches, tags, remotes)")

	// Add comprehensive examples for all user types
	rootCmd.Example = `BASIC USAGE:
  # Compare current work with default branch (beginner-friendly)
  deputy

  # Compare default branch with a feature branch
  deputy feature-branch
  deputy my-awesome-feature

BRANCH COMPARISONS:
  # Compare two specific branches
  deputy main develop
  deputy master feature/new-auth
  deputy develop release/v2.0

TAG AND RELEASE COMPARISONS:
  # Compare releases or versions
  deputy v1.0.0 v2.0.0
  deputy release-2023 release-2024
  deputy latest HEAD

COMMIT COMPARISONS:
  # Compare specific commits
  deputy 1a2b3c4 main
  deputy abc123def main
  deputy HEAD~5 HEAD

REMOTE BRANCH COMPARISONS:
  # Compare with remote branches (useful for forks)
  deputy origin/main feature-branch
  deputy upstream/main origin/main
  deputy main origin/develop

ADVANCED GIT EXPRESSIONS:
  # Compare relative to HEAD
  deputy HEAD~3 HEAD
  deputy HEAD^ HEAD
  deputy main~1 main

  # Time-based comparisons
  deputy "HEAD@{yesterday}" HEAD
  deputy "main@{1.week.ago}" main

  # Compare with upstream
  deputy @{upstream} HEAD
  deputy main @{upstream}

WORKFLOW EXAMPLES:
  # Before merging a PR
  deputy main feature/user-auth

  # Check what changed in last 3 commits
  deputy HEAD~3 HEAD

  # Compare your fork with upstream
  deputy upstream/main main

  # Check dependency changes between releases
  deputy v1.2.0 v1.3.0

ERROR HANDLING:
If you specify an invalid reference, deputy will suggest similar valid references
and provide guidance on supported reference types.`

	// Use Fang to execute the command with enhanced error handling and styling
	ctx := context.Background()
	fang.Execute(ctx, rootCmd)
}

func runDepDelta(repoPath, baseRef, targetRef string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer cancel()

	// Display what we're comparing for better UX
	fmt.Printf("Comparing dependencies: %s → %s\n", baseRef, targetRef)

	changesFiles, err := checkFilesChanged(repoPath, baseRef, targetRef)
	if err != nil {
		return fmt.Errorf("error checking files changed: %w", err)
	}

	containsDepChanges := slices.ContainsFunc(changesFiles, func(fileName string) bool {
		switch filepath.Base(fileName) {
		case "go.mod", "go.sum":
			return true
		}
		return false
	})

	if !containsDepChanges {
		fmt.Println("No dependency changes detected.")
		return nil
	}

	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return fmt.Errorf("error opening Git repository at %s: %w\nMake sure you're running this from within a valid Git repository", repoPath, err)
	}

	worktree, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("error getting worktree: %w", err)
	}

	// Save the current git state for proper restoration
	originalState, err := saveGitState(repo, worktree)
	if err != nil {
		return fmt.Errorf("error saving git state: %w", err)
	}

	// Ensure we restore the original state, even on error or interruption
	defer func() {
		if restoreErr := restoreGitState(worktree, originalState); restoreErr != nil {
			if originalState.IsDetached {
				fmt.Printf("Warning: failed to restore git state to detached HEAD %s: %v\n",
					originalState.CurrentHash.String()[:8], restoreErr)
			} else {
				fmt.Printf("Warning: failed to restore git state to branch %s: %v\n",
					originalState.CurrentBranch, restoreErr)
			}
		}
	}()

	baseHash, err := repo.ResolveRevision(plumbing.Revision(baseRef))
	if err != nil {
		// Provide helpful error message with suggestions
		suggestions := getReferenceSuggestions(repo, baseRef)
		if len(suggestions) > 0 {
			return fmt.Errorf("error resolving base reference %q: %v\nDid you mean one of these?\n  %s",
				baseRef, err, strings.Join(suggestions, "\n  "))
		}
		return fmt.Errorf("error resolving base reference %q: %v\nUse 'git branch -a' to see available branches or 'git tag' to see available tags",
			baseRef, err)
	}

	targetHash, err := repo.ResolveRevision(plumbing.Revision(targetRef))
	if err != nil {
		// Provide helpful error message with suggestions
		suggestions := getReferenceSuggestions(repo, targetRef)
		if len(suggestions) > 0 {
			return fmt.Errorf("error resolving target reference %q: %v\nDid you mean one of these?\n  %s",
				targetRef, err, strings.Join(suggestions, "\n  "))
		}
		return fmt.Errorf("error resolving target reference %q: %v\nUse 'git branch -a' to see available branches or 'git tag' to see available tags",
			targetRef, err)
	}

	fmt.Println("Scanning packages in base reference", baseHash.String()[:8], "...")
	basePackages, err := scanPackages(ctx, repoPath, *baseHash)
	if err != nil {
		return fmt.Errorf("error scanning base reference packages: %w", err)
	}

	fmt.Println("Scanning packages in target reference", targetHash.String()[:8], "...")
	targetPackages, err := scanPackages(ctx, repoPath, *targetHash)
	if err != nil {
		return fmt.Errorf("error scanning target reference packages: %w", err)
	}

	// Call comparePackages with correct parameter order: base is old, target is new
	changedPackages := comparePackages(basePackages, targetPackages)

	slices.SortFunc(changedPackages, func(a, b PackageChange) int {
		return strings.Compare(a.Name, b.Name)
	})

	changedPackages = slices.CompactFunc(changedPackages, func(a, b PackageChange) bool {
		return a.Name == b.Name && a.ChangeType == b.ChangeType
	})

	if len(changedPackages) == 0 {
		fmt.Println("No package changes detected.")
		return nil
	}

	// Create and configure a client for the gRPC API.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("failed to create cert pool: %w", err)
	}
	creds := credentials.NewClientTLSFromCert(certPool, "")
	conn, err := grpc.NewClient("api.deps.dev:443", grpc.WithTransportCredentials(creds))
	if err != nil {
		return fmt.Errorf("failed to connect to gRPC server: %w", err)
	}
	client := pb.NewInsightsClient(conn)

	fmt.Printf("\n%sDependency Changes:%s\n", colorHeader, colorReset)

	var added, removed, updated, upgraded, downgraded int

	for _, pkg := range changedPackages {
		licenses := []string{"?"}
		versionInfo, err := client.GetVersion(ctx, &pb.GetVersionRequest{
			VersionKey: &pb.VersionKey{
				System:  pb.System_GO,
				Name:    pkg.Name,
				Version: "v" + pkg.TargetVersion,
			},
		})
		if err == nil {
			licenses = versionInfo.GetLicenses()
		}

		// Format license info with subtle styling
		licenseStr := ""
		if len(licenses) > 0 && licenses[0] != "?" {
			licenseStr = fmt.Sprintf(" %s[%s]%s", colorLicense, strings.Join(licenses, ", "), colorReset)
		}

		switch pkg.ChangeType {
		case Added:
			fmt.Printf("  %s+ %s%s%s @%s%s%s%s\n",
				colorSymbol+colorAdded,
				colorBold, pkg.Name, colorReset,
				colorVersion, pkg.TargetVersion, colorReset,
				licenseStr)
			added++
		case Removed:
			fmt.Printf("  %s- %s%s%s @%s%s%s\n",
				colorSymbol+colorRemoved,
				colorBold+colorDim, pkg.Name, colorReset,
				colorVersion, pkg.BaseVersion, colorReset)
			removed++
		case Updated:
			// Determine if this is an upgrade or downgrade
			versionChange := compareVersionsForEcosystem(pkg.BaseVersion, pkg.TargetVersion, pkg.Ecosystem)
			var symbol, symbolColor string

			switch versionChange {
			case 1: // Upgrade
				symbol = "↑"
				symbolColor = colorSymbol + colorUpgraded
				upgraded++
			case -1: // Downgrade
				symbol = "↓"
				symbolColor = colorSymbol + colorDowngraded
				downgraded++
			default: // Unclear or lateral change
				symbol = "~"
				symbolColor = colorSymbol + colorNeutral
			}

			// Make package name bold for updates, and target version bold for upgrades
			packageDisplay := fmt.Sprintf("%s%s%s", colorBold, pkg.Name, colorReset)
			targetVersionDisplay := pkg.TargetVersion
			if versionChange == 1 { // Upgrade - make target version bold
				targetVersionDisplay = fmt.Sprintf("%s%s%s", colorBold, pkg.TargetVersion, colorReset)
			}

			fmt.Printf("  %s%s%s %s %s%s%s %s→%s %s%s%s%s\n",
				symbolColor, symbol, colorReset,
				packageDisplay,
				colorVersion, pkg.BaseVersion, colorReset,
				colorArrow, colorReset,
				colorVersion, targetVersionDisplay, colorReset,
				licenseStr)
			updated++
		}
	}

	// Clean summary without visual noise
	fmt.Printf("\n%sSummary:%s\n", colorHeader, colorReset)

	if added > 0 {
		fmt.Printf("  %s+ %s%d%s package%s added\n",
			colorSymbol+colorAdded, colorBold, added, colorReset,
			func() string {
				if added == 1 {
					return ""
				} else {
					return "s"
				}
			}())
	}

	if removed > 0 {
		fmt.Printf("  %s- %s%d%s package%s removed\n",
			colorSymbol+colorRemoved, colorBold, removed, colorReset,
			func() string {
				if removed == 1 {
					return ""
				} else {
					return "s"
				}
			}())
	}

	if updated > 0 {
		if upgraded > 0 {
			fmt.Printf("  %s↑ %s%d%s package%s upgraded\n",
				colorSymbol+colorUpgraded, colorBold, upgraded, colorReset,
				func() string {
					if upgraded == 1 {
						return ""
					} else {
						return "s"
					}
				}())
		}
		if downgraded > 0 {
			fmt.Printf("  %s↓ %s%d%s package%s downgraded\n",
				colorSymbol+colorDowngraded, colorBold, downgraded, colorReset,
				func() string {
					if downgraded == 1 {
						return ""
					} else {
						return "s"
					}
				}())
		}
		otherChanges := updated - (upgraded + downgraded)
		if otherChanges > 0 {
			fmt.Printf("  %s~ %s%d%s package%s changed\n",
				colorSymbol+colorNeutral, colorBold, otherChanges, colorReset,
				func() string {
					if otherChanges == 1 {
						return ""
					} else {
						return "s"
					}
				}())
		}
	}

	return nil
}
