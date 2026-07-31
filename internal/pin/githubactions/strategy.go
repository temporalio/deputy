package githubactions

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"strings"

	"github.com/goccy/go-yaml"
	"github.com/google/go-github/v63/github"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/temporalio/deputy/internal/forge"
	"github.com/temporalio/deputy/internal/inventory/plugins/github/actionsx"
	"github.com/temporalio/deputy/internal/pin"
	"github.com/temporalio/deputy/internal/purlx"
	"golang.org/x/mod/semver"
)

// NOTE: The resolver uses the git protocol (ls-remote) and does not require
// a GitHub API client. The verifier uses the GitHub REST API for commit
// provenance checks (signature verification, branch reachability) which have
// no git-protocol equivalent. This means basic pinning works without a token
// on public repos; only verification needs API access.

const (
	// Ecosystem is the ecosystem identifier for GitHub Actions.
	Ecosystem = "github-actions"
)

// Compile-time interface check.
var _ pin.Strategy = (*Strategy)(nil)

// Strategy implements the pin.Strategy interface for GitHub Actions
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
type Strategy struct {
	resolver *Resolver
	verifier *Verifier
}

// NewStrategy creates a Strategy for GitHub Actions pinning.
// The resolver uses the git protocol (no API client needed). The verifier
// uses the GitHub REST API client for commit provenance checks — pass nil
// to skip verification capabilities.
func NewStrategy(client *github.Client) *Strategy {
	var v *Verifier
	if client != nil {
		v = NewVerifier(client)
	}
	return &Strategy{
		resolver: NewResolver(),
		verifier: v,
	}
}

// Ecosystem implements pin.Strategy.
func (s *Strategy) Ecosystem() string { return Ecosystem }

// IsPinned implements pin.Strategy. A GitHub Actions ref is pinned when its
// version is a 40-character hex commit SHA.
func (s *Strategy) IsPinned(ref pin.Ref) bool {
	return ref.IsSHAPinned()
}

// ShouldSkip implements pin.Strategy. GitHub Actions refs containing expression
// syntax (${{ ... }}) cannot be statically pinned and should be skipped.
func (s *Strategy) ShouldSkip(ref pin.Ref) (bool, string) {
	if strings.Contains(ref.Version, "${{") {
		return true, "expression ref"
	}
	return false, ""
}

// Discover implements pin.Strategy. It finds all files containing GitHub Actions
// uses: references — both workflow files and composite action manifests.
func (s *Strategy) Discover(ctx context.Context, fsys scalibrfs.FS) ([]pin.Ref, error) {
	ext := actionsx.New()

	var refs []pin.Ref
	seen := map[string]bool{} // deduplicate across scanning phases

	// Phase 1: Scan .github/workflows/*.yml — standard workflow files.
	// The actionsx extractor recursively follows local uses: references,
	// so this also discovers deps of local composite actions that workflows
	// reference. But it only finds deps *reachable from a workflow*.
	if info, err := fs.Stat(fsys, ".github/workflows"); err == nil && info.IsDir() {
		wfRefs, err := s.scanDir(ctx, ext, fsys, ".github/workflows", pin.IsWorkflowFile)
		if err != nil {
			return nil, fmt.Errorf("scanning workflows: %w", err)
		}
		for _, r := range wfRefs {
			key := pin.DedupeKey(r)
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
			if pin.ShouldSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		if pin.IsSymlink(d) {
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
			key := pin.DedupeKey(r)
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
func (s *Strategy) scanDir(
	ctx context.Context,
	ext filesystem.Extractor,
	fsys scalibrfs.FS,
	walkDir string,
	filter func(string) bool,
) ([]pin.Ref, error) {
	var refs []pin.Ref

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
func (s *Strategy) scanActionManifest(
	fsys scalibrfs.FS, relPath string,
) ([]pin.Ref, error) {
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

	var refs []pin.Ref
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
		if usesStr == "" || strings.HasPrefix(usesStr, "./") || strings.HasPrefix(usesStr, "../") || strings.HasPrefix(usesStr, "$/") || strings.HasPrefix(usesStr, "docker://") {
			// Local, self-repository ($/ resolves to the running commit, so it
			// is already pinned by construction), or docker: nothing to pin.
			continue
		}

		// Parse remote action reference: owner/repo[/subpath]@ref
		pre, version, hasRef := strings.Cut(usesStr, "@")
		if !hasRef || strings.TrimSpace(version) == "" {
			continue // no @ref — skip (e.g., bare "uses: actions/checkout")
		}
		parts := strings.SplitN(strings.Trim(pre, "/"), "/", 3)
		if len(parts) < 2 {
			continue
		}
		owner, repo := parts[0], parts[1]
		var subpath string
		if len(parts) > 2 {
			subpath = strings.Join(parts[2:], "/")
		}

		refs = append(refs, pin.Ref{
			Ecosystem: Ecosystem,
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
func (s *Strategy) extractFromFile(
	ctx context.Context,
	ext filesystem.Extractor,
	fsys scalibrfs.FS,
	relPath string,
) ([]pin.Ref, error) {
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

	var refs []pin.Ref
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

// Resolve implements pin.Strategy. It resolves a mutable tag/branch to a commit
// SHA and finds the most specific semver tag for the Dependabot comment.
func (s *Strategy) Resolve(ctx context.Context, ref pin.Ref) (pinnedValue, versionTag string, err error) {
	owner, repo := forge.SplitOwnerRepo(ref.Name)
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

// Verify implements pin.Strategy. It checks commit provenance for fork/imposter
// detection and signature verification. Returns nil if no verifier is
// configured (e.g., no GitHub API client available).
func (s *Strategy) Verify(ctx context.Context, ref pin.Ref) (*pin.Verification, error) {
	if s.verifier == nil {
		return nil, nil
	}

	owner, repo := forge.SplitOwnerRepo(ref.Name)
	if owner == "" || repo == "" {
		return nil, fmt.Errorf("invalid action name: %s", ref.Name)
	}

	sha := ref.Version
	if !pin.IsCommitSHA(sha) {
		return nil, fmt.Errorf("ref %q is not a SHA", sha)
	}

	return s.verifier.Verify(ctx, owner, repo, sha)
}

// ResolveUpdate implements pin.Strategy. It re-resolves an already-pinned ref to
// the latest SHA in its major version channel (e.g., v4 → latest v4.x.x).
func (s *Strategy) ResolveUpdate(ctx context.Context, ref pin.Ref) (string, string, string, error) {
	owner, repo := forge.SplitOwnerRepo(ref.Name)
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

// Rewrite implements pin.Strategy. It rewrites workflow/action YAML files with SHA pins.
func (s *Strategy) Rewrite(root *os.Root, relPath string, updates []pin.Update) error {
	return RewriteWorkflow(root, relPath, updates)
}

// packageToRef converts an extractor.Package from the actionsx extractor to
// a pin.Ref. Returns nil for non-GitHub-Actions packages (docker, local).
func packageToRef(pkg *extractor.Package, relPath string) *pin.Ref {
	if !purlx.IsGitHubActionsType(pkg.PURLType) {
		return nil // docker or other type
	}

	owner, repo := forge.SplitOwnerRepo(pkg.Name)
	if owner == "" {
		return nil // local action or malformed
	}

	var subpath string
	if md, ok := pkg.Metadata.(*actionsx.UsesMetadata); ok {
		subpath = md.Subpath
	}

	return &pin.Ref{
		Ecosystem: Ecosystem,
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

