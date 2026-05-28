package githubactions

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/storage/memory"
	"github.com/temporalio/deputy/internal/auth"
	"github.com/temporalio/deputy/internal/pin"
	"golang.org/x/mod/semver"
	"golang.org/x/sync/singleflight"
)

// refEntry is a tag name and its dereferenced commit SHA from git ls-remote.
type refEntry struct {
	name string // e.g., "v4.2.2"
	sha  string // 40-char commit SHA
}

// Resolver resolves action references to commit SHAs and semver tags using
// the git protocol (ls-remote). This works with any git hosting provider and
// does not require a REST API token — credentials are sourced from the
// standard auth store for private repos only.
//
// A single ls-remote call returns all refs, avoiding the N+1 API call
// pattern of REST-based resolution.
type Resolver struct {
	// listRefsFunc is the function used to list remote refs. Defaults to
	// gitListRefs (real ls-remote). Tests can override this.
	listRefsFunc func(ctx context.Context, remoteURL string) ([]refEntry, error)

	// refCache caches resolved refs per remote URL to avoid redundant
	// ls-remote calls when multiple actions share the same repository.
	refCacheMu sync.Mutex
	refCache   map[string][]refEntry

	// flight deduplicates concurrent ls-remote calls for the same remote URL.
	flight singleflight.Group
}

// NewResolver creates a Resolver that uses the git protocol for ref resolution.
func NewResolver() *Resolver {
	r := &Resolver{
		refCache: make(map[string][]refEntry),
	}
	r.listRefsFunc = r.gitListRefs
	return r
}

// ResolveSHA resolves a Git ref (tag, branch, or SHA) to a full 40-character
// commit SHA by querying the remote via the git protocol.
func (r *Resolver) ResolveSHA(ctx context.Context, owner, repo, ref string) (string, error) {
	remoteURL := gitRemoteURL(owner, repo)

	refs, err := r.listRefs(ctx, remoteURL)
	if err != nil {
		return "", fmt.Errorf("resolving %s/%s@%s: %w", owner, repo, ref, err)
	}

	// If ref is already a 40-char SHA, check if it matches any known ref.
	// A SHA that doesn't match any tag or branch may be a legitimate commit
	// on a merged/deleted branch, or it may be a fork/imposter commit. We
	// return it as-is here because ResolveSHA's job is ref→SHA mapping, not
	// provenance. The Verifier (separate step) checks whether a SHA is
	// trustworthy. When verification is skipped, imposter SHAs won't be
	// detected — this is an accepted trade-off documented in --skip-verification.
	if pin.IsCommitSHA(ref) {
		return ref, nil
	}

	// Try exact matches: refs/tags/<ref>, refs/heads/<ref>
	for _, prefix := range []string{"refs/tags/", "refs/heads/"} {
		for _, e := range refs {
			if e.name == prefix+ref {
				return e.sha, nil
			}
		}
	}

	return "", fmt.Errorf("ref %q not found in %s/%s", ref, owner, repo)
}

// ResolveTag finds the most specific semver tag pointing at the given commit
// SHA. It lists all refs via ls-remote (cached per repository) and returns
// the best match (e.g., v4.2.2 over v4.2 over v4).
func (r *Resolver) ResolveTag(ctx context.Context, owner, repo, sha string) (string, error) {
	remoteURL := gitRemoteURL(owner, repo)

	refs, err := r.listRefs(ctx, remoteURL)
	if err != nil {
		return "", fmt.Errorf("listing tags for %s/%s: %w", owner, repo, err)
	}

	// Collect tag names whose dereferenced commit SHA matches.
	var candidates []string
	for _, e := range refs {
		if e.sha != sha {
			continue
		}
		if !strings.HasPrefix(e.name, "refs/tags/") {
			continue
		}
		tagName := strings.TrimPrefix(e.name, "refs/tags/")
		candidates = append(candidates, tagName)
	}

	if len(candidates) == 0 {
		shortSHA := sha
		if len(sha) > 12 {
			shortSHA = sha[:12]
		}
		return "", fmt.Errorf("no semver tag found for SHA %s in %s/%s", shortSHA, owner, repo)
	}

	return bestSemverTag(candidates), nil
}

// listRefs returns cached refs or fetches them via listRefsFunc.
// Uses singleflight to deduplicate concurrent requests for the same remote.
func (r *Resolver) listRefs(ctx context.Context, remoteURL string) ([]refEntry, error) {
	r.refCacheMu.Lock()
	if cached, ok := r.refCache[remoteURL]; ok {
		r.refCacheMu.Unlock()
		return cached, nil
	}
	r.refCacheMu.Unlock()

	v, err, _ := r.flight.Do(remoteURL, func() (any, error) {
		entries, err := r.listRefsFunc(ctx, remoteURL)
		if err != nil {
			return nil, err
		}
		r.refCacheMu.Lock()
		r.refCache[remoteURL] = entries
		r.refCacheMu.Unlock()
		return entries, nil
	})
	if err != nil {
		return nil, err
	}
	return v.([]refEntry), nil
}

// gitListRefs performs a single ls-remote against the remote URL and returns
// all refs with their dereferenced commit SHAs.
//
// For annotated tags, git ls-remote returns both the tag object ref and a
// "^{}" peeled ref that points to the underlying commit. We use the peeled
// SHA and strip the "^{}" suffix from the name, giving us direct
// tag-name → commit-SHA mappings without additional network calls.
func (r *Resolver) gitListRefs(ctx context.Context, remoteURL string) ([]refEntry, error) {
	gitAuth, _ := auth.GitAuthForURL(ctx, remoteURL)

	remote := git.NewRemote(memory.NewStorage(), &config.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	})

	// AppendPeeled is required so annotated tags advertise their peeled
	// "^{}" refs (the underlying commit). go-git defaults to IgnorePeeled,
	// which strips them — leaving only the tag-object SHA. Without this we
	// would pin the tag object instead of the commit it points to, which is
	// both semantically wrong for a "pin the reviewed commit" tool and
	// degrades the version comment (e.g. "# v2" instead of "# v2.8.0").
	rawRefs, err := remote.ListContext(ctx, &git.ListOptions{
		Auth:          gitAuth,
		PeelingOption: git.AppendPeeled,
	})
	if err != nil {
		return nil, fmt.Errorf("ls-remote %s: %w", remoteURL, err)
	}

	return mergeRefs(rawRefs), nil
}

// mergeRefs converts raw advertised refs into tag-name → commit-SHA entries.
//
// For annotated tags, ls-remote (with AppendPeeled) advertises both the tag
// object ref and a peeled "<name>^{}" ref pointing at the underlying commit.
// We always prefer the peeled commit SHA so callers pin the commit, never the
// tag object. Lightweight tags have no peeled ref and resolve to their own SHA.
func mergeRefs(rawRefs []*plumbing.Reference) []refEntry {
	peeled := make(map[string]string)   // "refs/tags/v4.2.2" → commit SHA (from ^{})
	regular := make(map[string]string)  // "refs/tags/v4.2.2" → object SHA
	branches := make(map[string]string) // "refs/heads/main" → commit SHA

	for _, ref := range rawRefs {
		if ref == nil {
			continue
		}
		name := ref.Name().String()
		sha := ref.Hash().String()

		if name == "HEAD" {
			continue
		}

		if strings.HasSuffix(name, "^{}") {
			base := strings.TrimSuffix(name, "^{}")
			peeled[base] = sha
		} else if strings.HasPrefix(name, "refs/tags/") {
			regular[name] = sha
		} else if strings.HasPrefix(name, "refs/heads/") {
			branches[name] = sha
		}
	}

	// Merge: use peeled SHA when available, otherwise the regular SHA.
	var entries []refEntry
	for name, sha := range regular {
		commitSHA := sha
		if peeledSHA, ok := peeled[name]; ok {
			commitSHA = peeledSHA
		}
		entries = append(entries, refEntry{name: name, sha: commitSHA})
	}
	for name, sha := range branches {
		entries = append(entries, refEntry{name: name, sha: sha})
	}

	return entries
}

// gitRemoteURL constructs the HTTPS git remote URL for a GitHub repository.
//
// This intentionally hardcodes github.com as the host. GitHub Actions uses:
// references always resolve against github.com for public actions. This
// hardcoding also prevents confused-deputy attacks where a crafted owner/repo
// value could misdirect credentials to an attacker-controlled host.
//
// GitHub Enterprise Server (GHES) internal actions are not yet supported;
// they would require GITHUB_SERVER_URL-aware URL construction.
func gitRemoteURL(owner, repo string) string {
	return fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
}

// bestSemverTag returns the most specific semver tag from candidates.
// More segments wins (v4.2.2 > v4.2 > v4). Among equal specificity,
// the highest version wins.
func bestSemverTag(candidates []string) string {
	if len(candidates) == 0 {
		return ""
	}

	// Partition into valid semver and non-semver
	var valid []string
	for _, c := range candidates {
		if semver.IsValid(c) {
			valid = append(valid, c)
		}
	}
	if len(valid) == 0 {
		return candidates[0]
	}

	// Sort by specificity (more segments first), then by version descending.
	slices.SortFunc(valid, func(a, b string) int {
		sa, sb := segmentCount(a), segmentCount(b)
		if sa != sb {
			return sb - sa // more segments first
		}
		return semver.Compare(b, a) // higher version first
	})

	return valid[0]
}

// segmentCount returns the number of dot-separated segments in a semver tag.
// v4 = 1, v4.2 = 2, v4.2.2 = 3, v4.2.2-rc1 = 3.
func segmentCount(v string) int {
	v = strings.TrimPrefix(v, "v")
	if idx := strings.IndexByte(v, '-'); idx >= 0 {
		v = v[:idx]
	}
	if idx := strings.IndexByte(v, '+'); idx >= 0 {
		v = v[:idx]
	}
	return strings.Count(v, ".") + 1
}

// truncSHA returns the first 12 characters of a SHA for use in log
// messages and errors, or the full string if shorter.
func truncSHA(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	return sha
}
