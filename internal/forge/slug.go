// Package forge provides helpers for working with source-forge (GitHub,
// GitLab, Gitea, etc.) repository identifiers such as "owner/repo" slugs.
//
// These identifiers show up in several places in Deputy: GitHub Actions
// package names ("owner/repo[/subpath]"), git remote URLs, and self-reference
// checks. Centralizing the parsing here avoids duplicated, subtly-divergent
// implementations across packages.
package forge

import "strings"

// SplitOwnerRepo extracts the owner and repo from a repository identifier such
// as "owner/repo" or "owner/repo/subpath". An optional "github.com/" prefix is
// tolerated. It returns empty strings when fewer than two path segments are
// present.
func SplitOwnerRepo(name string) (owner, repo string) {
	owner, repo, _ = SplitOwnerRepoRest(name)
	return owner, repo
}

// SplitOwnerRepoRest is like SplitOwnerRepo but also returns any trailing path
// ("subpath") after the owner/repo pair (e.g., "actions/setup" for the name
// "owner/repo/actions/setup").
func SplitOwnerRepoRest(full string) (owner, repo, rest string) {
	full = strings.TrimSpace(full)
	full = strings.TrimPrefix(full, "github.com/")
	full = strings.Trim(full, "/")
	if full == "" {
		return "", "", ""
	}
	parts := strings.Split(full, "/")
	if len(parts) < 2 {
		return "", "", ""
	}
	owner, repo = parts[0], parts[1]
	if len(parts) > 2 {
		rest = strings.Join(parts[2:], "/")
	}
	return owner, repo, rest
}

// RepoSlugFromURL extracts the "owner/repo" slug from a git remote URL. It
// handles the common forms: https://host/owner/repo(.git),
// git@host:owner/repo(.git), and ssh://git@host/owner/repo(.git). The host is
// discarded, so the result works for any forge. It returns an empty string
// when a slug cannot be determined.
func RepoSlugFromURL(gitURL string) string {
	s := strings.TrimSpace(gitURL)
	if s == "" {
		return ""
	}
	// Strip any scheme (https://, ssh://, git://).
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Strip userinfo (git@host).
	if at := strings.LastIndex(s, "@"); at >= 0 {
		s = s[at+1:]
	}
	// Normalize scp-like separator (host:owner/repo) to a path separator.
	s = strings.Replace(s, ":", "/", 1)
	s = strings.TrimSuffix(s, ".git")
	// Drop the host component; keep the path.
	slash := strings.Index(s, "/")
	if slash < 0 {
		return ""
	}
	owner, repo := SplitOwnerRepo(s[slash+1:])
	if owner == "" || repo == "" {
		return ""
	}
	return owner + "/" + repo
}
