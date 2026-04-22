package pin

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/google/go-github/v63/github"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/picatz/deputy/internal/inventory/plugins/github/actionsx"
	"github.com/picatz/deputy/internal/purlx"
	"golang.org/x/mod/semver"
)

// NOTE: The resolver uses the git protocol (ls-remote) and does not require
// a GitHub API client. The verifier uses the GitHub REST API for commit
// provenance checks (signature verification, branch reachability) which have
// no git-protocol equivalent. This means basic pinning works without a token
// on public repos; only verification needs API access.

const (
	// EcosystemGitHubActions is the ecosystem identifier for GitHub Actions.
	EcosystemGitHubActions = "github-actions"
)

// Compile-time interface check.
var _ Strategy = (*GitHubActionsStrategy)(nil)

// GitHubActionsStrategy implements the Strategy interface for GitHub Actions
// workflow dependencies. It discovers uses: references in:
//
//   - .github/workflows/*.yml — standard workflow files
//   - action.yml / action.yaml at repo root — if the repo IS a GitHub Action
//   - .github/actions/*/action.yml — local composite actions
//   - any action.yml / action.yaml in the repo tree — arbitrary composite actions
//
// It resolves tags to commit SHAs via the git protocol, verifies commits for
// fork/imposter provenance via the GitHub REST API, and rewrites files with
// Dependabot-compatible SHA pins.
type GitHubActionsStrategy struct {
	resolver *Resolver
	verifier *Verifier
}

// NewGitHubActionsStrategy creates a Strategy for GitHub Actions pinning.
// The resolver uses the git protocol (no API client needed). The verifier
// uses the GitHub REST API client for commit provenance checks — pass nil
// to skip verification capabilities.
func NewGitHubActionsStrategy(client *github.Client) *GitHubActionsStrategy {
	var v *Verifier
	if client != nil {
		v = NewVerifier(client)
	}
	return &GitHubActionsStrategy{
		resolver: NewResolver(),
		verifier: v,
	}
}

// Ecosystem implements Strategy.
func (s *GitHubActionsStrategy) Ecosystem() string { return EcosystemGitHubActions }

// IsPinned implements Strategy. A GitHub Actions ref is pinned when its
// version is a 40-character hex commit SHA.
func (s *GitHubActionsStrategy) IsPinned(ref Ref) bool {
	return ref.IsSHAPinned()
}

// ShouldSkip implements Strategy. GitHub Actions refs containing expression
// syntax (${{ ... }}) cannot be statically pinned and should be skipped.
func (s *GitHubActionsStrategy) ShouldSkip(ref Ref) (bool, string) {
	if strings.Contains(ref.Version, "${{") {
		return true, "expression ref"
	}
	return false, ""
}

// Discover implements Strategy. It finds all files containing GitHub Actions
// uses: references — both workflow files and composite action manifests.
func (s *GitHubActionsStrategy) Discover(ctx context.Context, fsys scalibrfs.FS) ([]Ref, error) {
	ext := actionsx.New()

	var refs []Ref
	seen := map[string]bool{} // deduplicate across scanning phases

	// Phase 1: Scan .github/workflows/*.yml — standard workflow files.
	// The actionsx extractor recursively follows local uses: references,
	// so this also discovers deps of local composite actions that workflows
	// reference. But it only finds deps *reachable from a workflow*.
	if info, err := fs.Stat(fsys, ".github/workflows"); err == nil && info.IsDir() {
		wfRefs, err := s.scanDir(ctx, ext, fsys, ".github/workflows", isWorkflowFile)
		if err != nil {
			return nil, fmt.Errorf("scanning workflows: %w", err)
		}
		for _, r := range wfRefs {
			key := dedupeKey(r)
			if !seen[key] {
				seen[key] = true
				refs = append(refs, r)
			}
		}
	}

	// Phase 2: Scan all action.yml / action.yaml files in the repo tree.
	// This catches composite actions that aren't referenced from any workflow
	// (e.g., the repo root action.yml if the repo IS a GitHub Action, or
	// standalone actions in .github/actions/ or elsewhere).
	err := fs.WalkDir(fsys, ".", func(relPath string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if shouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if isSymlink(d) {
			return nil
		}

		// Only match action.yml / action.yaml.
		base := strings.ToLower(d.Name())
		if base != "action.yml" && base != "action.yaml" {
			return nil
		}

		actionRefs, err := s.scanActionManifest(fsys, relPath)
		if err != nil {
			slog.Debug("skipping action manifest", "path", relPath, "error", err)
			return nil
		}

		for _, r := range actionRefs {
			key := dedupeKey(r)
			if !seen[key] {
				seen[key] = true
				refs = append(refs, r)
			}
		}

		return nil
	})

	return refs, err
}

// scanDir extracts action refs from all matching files in a directory.
func (s *GitHubActionsStrategy) scanDir(
	ctx context.Context,
	ext filesystem.Extractor,
	fsys scalibrfs.FS,
	walkDir string,
	filter func(string) bool,
) ([]Ref, error) {
	var refs []Ref

	err := fs.WalkDir(fsys, walkDir, func(relPath string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}

		if filter != nil && !filter(relPath) {
			return nil
		}

		extracted, err := s.extractFromFile(ctx, ext, fsys, relPath)
		if err != nil {
			slog.Warn("skipping file", "path", relPath, "error", err)
			return nil
		}
		refs = append(refs, extracted...)
		return nil
	})

	return refs, err
}

// scanActionManifest parses a composite action.yml file and extracts remote
// uses: references from its steps. This handles files that the workflow
// extractor can't parse (action.yml has a different structure than workflow
// files — it has runs.steps instead of jobs.*.steps).
func (s *GitHubActionsStrategy) scanActionManifest(
	fsys scalibrfs.FS, relPath string,
) ([]Ref, error) {
	content, err := fs.ReadFile(fsys, relPath)
	if err != nil {
		return nil, err
	}

	var root map[string]any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, err
	}

	// action.yml structure: runs.using: composite, runs.steps[*].uses
	runsRaw, ok := root["runs"]
	if !ok {
		return nil, nil
	}
	runs, ok := runsRaw.(map[string]any)
	if !ok {
		return nil, nil
	}
	using, _ := runs["using"].(string)
	if strings.ToLower(strings.TrimSpace(using)) != "composite" {
		return nil, nil // docker or node actions don't have uses: in steps
	}

	stepsRaw, ok := runs["steps"]
	if !ok {
		return nil, nil
	}
	steps, ok := stepsRaw.([]any)
	if !ok {
		return nil, nil
	}

	var refs []Ref
	for _, stepRaw := range steps {
		step, ok := stepRaw.(map[string]any)
		if !ok {
			continue
		}
		usesStr, ok := step["uses"].(string)
		if !ok {
			continue
		}
		usesStr = strings.TrimSpace(usesStr)
		if usesStr == "" || strings.HasPrefix(usesStr, "./") || strings.HasPrefix(usesStr, "../") || strings.HasPrefix(usesStr, "docker://") {
			continue // local or docker — skip
		}

		// Parse remote action reference: owner/repo[/subpath]@ref
		pre, version, _ := strings.Cut(usesStr, "@")
		parts := strings.SplitN(strings.Trim(pre, "/"), "/", 3)
		if len(parts) < 2 {
			continue
		}
		owner, repo := parts[0], parts[1]
		var subpath string
		if len(parts) > 2 {
			subpath = strings.Join(parts[2:], "/")
		}

		refs = append(refs, Ref{
			Ecosystem: EcosystemGitHubActions,
			Name:      owner + "/" + repo,
			Subpath:   subpath,
			Version:   strings.TrimSpace(version),
			FilePath:  relPath,
			Raw:       usesStr,
		})
	}

	return refs, nil
}

// extractFromFile runs the actionsx extractor on a single file and converts
// results to pin.Ref values.
func (s *GitHubActionsStrategy) extractFromFile(
	ctx context.Context,
	ext filesystem.Extractor,
	fsys scalibrfs.FS,
	relPath string,
) ([]Ref, error) {
	f, err := fsys.Open(relPath)
	if err != nil {
		return nil, fmt.Errorf("opening %s: %w", relPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	input := &filesystem.ScanInput{
		FS:     fsys,
		Path:   relPath,
		Reader: f,
		Info:   info,
	}

	inv, err := ext.Extract(ctx, input)
	if err != nil {
		return nil, err
	}

	var refs []Ref
	for _, pkg := range inv.Packages {
		if pkg == nil {
			continue
		}
		if ref := packageToRef(pkg, relPath); ref != nil {
			refs = append(refs, *ref)
		}
	}
	return refs, nil
}

// Resolve implements Strategy. It resolves a mutable tag/branch to a commit
// SHA and finds the most specific semver tag for the Dependabot comment.
func (s *GitHubActionsStrategy) Resolve(ctx context.Context, ref Ref) (pinnedValue, versionTag string, err error) {
	owner, repo := splitOwnerRepo(ref.Name)
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("invalid action name: %s", ref.Name)
	}

	sha, err := s.resolver.ResolveSHA(ctx, owner, repo, ref.Version)
	if err != nil {
		return "", "", err
	}

	tag, err := s.resolver.ResolveTag(ctx, owner, repo, sha)
	if err != nil {
		slog.Debug("could not resolve tag, using original ref as tag",
			"action", ref.Name, "sha", truncSHA(sha), "error", err)
		tag = ref.Version
	}

	return sha, tag, nil
}

// Verify implements Strategy. It checks commit provenance for fork/imposter
// detection and signature verification. Returns nil if no verifier is
// configured (e.g., no GitHub API client available).
func (s *GitHubActionsStrategy) Verify(ctx context.Context, ref Ref) (*Verification, error) {
	if s.verifier == nil {
		return nil, nil
	}

	owner, repo := splitOwnerRepo(ref.Name)
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("invalid action name: %s", ref.Name)
	}

	sha := ref.Version
	if !commitSHARe.MatchString(sha) {
		return nil, fmt.Errorf("ref %q is not a SHA", sha)
	}

	return s.verifier.Verify(ctx, owner, repo, sha)
}

// ResolveUpdate implements Strategy. It re-resolves an already-pinned ref to
// the latest SHA in its major version channel (e.g., v4 → latest v4.x.x).
func (s *GitHubActionsStrategy) ResolveUpdate(ctx context.Context, ref Ref) (string, string, string, error) {
	owner, repo := splitOwnerRepo(ref.Name)
	if owner == "" || repo == "" {
		return "", "", "", fmt.Errorf("invalid action name: %s", ref.Name)
	}

	// Find the current tag for this SHA.
	currentTag, err := s.resolver.ResolveTag(ctx, owner, repo, ref.Version)
	if err != nil {
		return "", "", "", fmt.Errorf("finding current tag for %s: %w", truncSHA(ref.Version), err)
	}

	// Extract major version: v4.2.2 → v4.
	major := semver.Major(currentTag)
	if major == "" {
		return "", "", "", fmt.Errorf("cannot determine major version from tag %s", currentTag)
	}

	// Resolve major tag to latest SHA.
	latestSHA, err := s.resolver.ResolveSHA(ctx, owner, repo, major)
	if err != nil {
		return "", "", "", fmt.Errorf("resolving latest %s: %w", major, err)
	}

	// No update needed — already at latest.
	if latestSHA == ref.Version {
		return ref.Version, currentTag, currentTag, nil
	}

	// Find the specific tag for the new SHA.
	newTag, err := s.resolver.ResolveTag(ctx, owner, repo, latestSHA)
	if err != nil {
		slog.Debug("could not resolve tag for updated SHA, using major tag",
			"action", ref.Name, "sha", truncSHA(latestSHA), "error", err)
		newTag = major
	}

	return latestSHA, newTag, currentTag, nil
}

// Rewrite implements Strategy. It rewrites workflow/action YAML files with SHA pins.
func (s *GitHubActionsStrategy) Rewrite(root *os.Root, relPath string, updates []Update) error {
	return RewriteWorkflow(root, relPath, updates)
}

// packageToRef converts an extractor.Package from the actionsx extractor to
// a pin.Ref. Returns nil for non-GitHub-Actions packages (docker, local).
func packageToRef(pkg *extractor.Package, relPath string) *Ref {
	if !purlx.IsGitHubActionsType(pkg.PURLType) {
		return nil // docker or other type
	}

	owner, repo := splitOwnerRepo(pkg.Name)
	if owner == "" {
		return nil // local action or malformed
	}

	var subpath string
	if md, ok := pkg.Metadata.(*actionsx.UsesMetadata); ok {
		subpath = md.Subpath
	}

	return &Ref{
		Ecosystem: EcosystemGitHubActions,
		Name:      owner + "/" + repo,
		Subpath:   subpath,
		Version:   pkg.Version,
		FilePath:  relPath,
		Raw:       rawFromMetadata(pkg),
	}
}

// rawFromMetadata extracts the original uses string from package metadata.
func rawFromMetadata(pkg *extractor.Package) string {
	if md, ok := pkg.Metadata.(*actionsx.UsesMetadata); ok {
		return md.Raw
	}
	return ""
}

// splitOwnerRepo splits "owner/repo" into its parts.
func splitOwnerRepo(name string) (owner, repo string) {
	parts := strings.SplitN(name, "/", 3)
	if len(parts) < 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

// isWorkflowFile checks if a relative path is a GitHub Actions workflow file.
func isWorkflowFile(relPath string) bool {
	if !strings.HasPrefix(relPath, ".github/workflows/") {
		return false
	}
	ext := strings.ToLower(path.Ext(relPath))
	return ext == ".yml" || ext == ".yaml"
}
