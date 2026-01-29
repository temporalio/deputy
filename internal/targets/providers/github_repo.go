package providers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-github/v63/github"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(githubRepoProvider{})
}

// priorityGitHubRepo determines detection order relative to other providers.
// GitHub repo collections have priority 58, which is:
//   - Higher than org collections (55) - more specific pattern
//   - Lower than specific refs (would be 80) - collection vs specific
const priorityGitHubRepo = 58

// githubRepoProvider implements [targets.CollectionProvider] for listing
// branches and tags in a GitHub repository.
//
// URI patterns (trailing slash indicates collection):
//   - github://owner/repo/           → list all refs (branches + tags)
//   - github://owner/repo/branches/  → list only branches
//   - github://owner/repo/tags/      → list only tags
//   - github.com/owner/repo/         → also supported (normalized)
//
// Each discovered ref is returned as a URI like github://owner/repo@ref
// which can then be scanned for packages.
//
// The provider uses GITHUB_TOKEN environment variable for authentication.
type githubRepoProvider struct{}

func (githubRepoProvider) Priority() int { return priorityGitHubRepo }

// Detect returns true if the target looks like a GitHub repo collection.
func (githubRepoProvider) Detect(ctx context.Context, target string) bool {
	return isGitHubRepoCollection(target)
}

// RefFilter specifies which ref types to list.
type RefFilter int

const (
	RefFilterAll      RefFilter = iota // branches + tags
	RefFilterBranches                  // only branches
	RefFilterTags                      // only tags
)

// isGitHubRepoCollection checks if a target is a GitHub repo collection URI.
// Returns true for patterns like:
//   - github://owner/repo/
//   - github://owner/repo/branches/
//   - github://owner/repo/tags/
func isGitHubRepoCollection(target string) bool {
	owner, repo, _, hasScheme := parseGitHubRepoCollection(target)
	return hasScheme && owner != "" && repo != ""
}

// parseGitHubRepoCollection extracts owner, repo, and filter from a repo collection URI.
// Returns owner, repo, filter type, and whether a valid scheme was found.
func parseGitHubRepoCollection(target string) (owner, repo string, filter RefFilter, hasScheme bool) {
	target = strings.TrimSpace(target)

	var rest string

	// Handle github:// scheme
	if r, found := strings.CutPrefix(target, "github://"); found {
		rest = r
		hasScheme = true
	} else if r, found := strings.CutPrefix(target, "https://github.com/"); found {
		// Handle https://github.com/ URLs
		rest = r
		hasScheme = true
	} else if r, found := strings.CutPrefix(target, "github.com/"); found {
		// Handle github.com/ URLs (without https://)
		rest = r
		hasScheme = true
	}

	if !hasScheme {
		return "", "", RefFilterAll, false
	}

	// Must end with trailing slash for collection
	rest, found := strings.CutSuffix(rest, "/")
	if !found {
		return "", "", RefFilterAll, false
	}

	// Parse the path: owner/repo or owner/repo/branches or owner/repo/tags
	parts := strings.Split(rest, "/")

	switch len(parts) {
	case 2:
		// github://owner/repo/ → list all refs
		return parts[0], parts[1], RefFilterAll, true
	case 3:
		// github://owner/repo/branches/ or github://owner/repo/tags/
		suffix := strings.ToLower(parts[2])
		switch suffix {
		case "branches", "branch":
			return parts[0], parts[1], RefFilterBranches, true
		case "tags", "tag", "releases":
			return parts[0], parts[1], RefFilterTags, true
		case "refs":
			return parts[0], parts[1], RefFilterAll, true
		}
	}

	return "", "", RefFilterAll, false
}

// Open is not applicable for collections - this provider only lists.
func (githubRepoProvider) Open(ctx context.Context, target string, opts *targets.OpenOptions) (targets.Materialized, error) {
	return targets.Materialized{}, fmt.Errorf("cannot open GitHub repo collection %q directly; use List() to discover refs, then scan each ref (e.g., github://owner/repo@main)", target)
}

// IsCollection returns true if the target is a GitHub repo collection URI.
func (githubRepoProvider) IsCollection(ctx context.Context, target string) bool {
	return isGitHubRepoCollection(target)
}

// List enumerates branches and/or tags in a GitHub repository.
func (p githubRepoProvider) List(ctx context.Context, target string, opts *targets.ListOptions) (*targets.ListResult, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list github refs: %w", err)
	}

	// Parse the owner, repo, and filter from the URI
	owner, repo, filter, ok := parseGitHubRepoCollection(target)
	if !ok || owner == "" || repo == "" {
		return nil, fmt.Errorf("invalid GitHub repo collection URI: %q", target)
	}

	// Create GitHub client
	client := newGitHubClient(ctx)

	// Determine page size
	pageSize := int(opts.PageSize)
	if pageSize <= 0 {
		pageSize = 100 // default
	}
	if pageSize > 100 {
		pageSize = 100 // GitHub API max per page
	}

	// Parse page token (format: "type:page" e.g., "branches:2" or "tags:1")
	branchPage := 1
	tagPage := 1
	startWithTags := false
	if opts.PageToken != "" {
		if pageStr, found := strings.CutPrefix(opts.PageToken, "tags:"); found {
			startWithTags = true
			if n, err := strconv.Atoi(pageStr); err == nil && n > 0 {
				tagPage = n
			}
		} else if pageStr, found := strings.CutPrefix(opts.PageToken, "branches:"); found {
			if n, err := strconv.Atoi(pageStr); err == nil && n > 0 {
				branchPage = n
			}
		}
	}

	var results []*listv1.DiscoveredTarget
	var nextPageToken string
	remaining := pageSize

	// List branches first (unless starting with tags or filter is tags-only)
	if !startWithTags && filter != RefFilterTags && remaining > 0 {
		branches, resp, err := client.Repositories.ListBranches(ctx, owner, repo, &github.BranchListOptions{
			ListOptions: github.ListOptions{
				PerPage: remaining,
				Page:    branchPage,
			},
		})
		if err != nil {
			return nil, wrapGitHubRepoError(err, owner, repo, "branches")
		}

		checkGitHubRateLimit(ctx, resp)

		for _, branch := range branches {
			if branch == nil {
				continue
			}
			name := branch.GetName()
			uri := fmt.Sprintf("github://%s/%s@%s", owner, repo, name)

			dt := &listv1.DiscoveredTarget{
				Uri:         uri,
				Name:        name,
				Description: fmt.Sprintf("Branch: %s", name),
				Metadata: map[string]string{
					"owner":    owner,
					"repo":     repo,
					"ref":      name,
					"ref_type": "branch",
					"sha":      branch.GetCommit().GetSHA(),
				},
			}

			// Mark protected branches
			if branch.GetProtected() {
				dt.Metadata["protected"] = "true"
			}

			results = append(results, dt)
			remaining--
		}

		// Check if there are more branches
		if resp.NextPage > 0 && filter != RefFilterTags {
			if remaining <= 0 {
				nextPageToken = fmt.Sprintf("branches:%d", resp.NextPage)
			} else {
				// Continue to tags on same page
				branchPage = 0 // Mark branches as done
			}
		}
	}

	// List tags (if filter allows and we have remaining capacity)
	if filter != RefFilterBranches && remaining > 0 && nextPageToken == "" {
		tags, resp, err := client.Repositories.ListTags(ctx, owner, repo, &github.ListOptions{
			PerPage: remaining,
			Page:    tagPage,
		})
		if err != nil {
			return nil, wrapGitHubRepoError(err, owner, repo, "tags")
		}

		checkGitHubRateLimit(ctx, resp)

		for _, tag := range tags {
			if tag == nil {
				continue
			}
			name := tag.GetName()
			uri := fmt.Sprintf("github://%s/%s@%s", owner, repo, name)

			dt := &listv1.DiscoveredTarget{
				Uri:         uri,
				Name:        name,
				Description: fmt.Sprintf("Tag: %s", name),
				Metadata: map[string]string{
					"owner":    owner,
					"repo":     repo,
					"ref":      name,
					"ref_type": "tag",
					"sha":      tag.GetCommit().GetSHA(),
				},
			}

			// Try to get tarball/zipball URLs
			if tag.GetTarballURL() != "" {
				dt.Metadata["tarball_url"] = tag.GetTarballURL()
			}
			if tag.GetZipballURL() != "" {
				dt.Metadata["zipball_url"] = tag.GetZipballURL()
			}

			results = append(results, dt)
		}

		// Check if there are more tags
		if resp.NextPage > 0 {
			nextPageToken = fmt.Sprintf("tags:%d", resp.NextPage)
		}
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// wrapGitHubRepoError provides helpful error messages for GitHub API errors.
func wrapGitHubRepoError(err error, owner, repo, refType string) error {
	if err == nil {
		return nil
	}

	target := fmt.Sprintf("github://%s/%s/%s/", owner, repo, refType)

	// Check for rate limiting
	if ghErr, ok := err.(*github.ErrorResponse); ok {
		switch ghErr.Response.StatusCode {
		case 403:
			if strings.Contains(ghErr.Message, "rate limit") {
				return fmt.Errorf("list %s: rate limit exceeded (hint: set GITHUB_TOKEN for higher limits)", target)
			}
		case 401:
			return fmt.Errorf("list %s: authentication failed (hint: check GITHUB_TOKEN is valid)", target)
		case 404:
			return fmt.Errorf("list %s: repository not found or not accessible", target)
		}
	}

	return fmt.Errorf("list %s: %w", target, err)
}

var _ targets.Provider = (*githubRepoProvider)(nil)
var _ targets.PriorityProvider = (*githubRepoProvider)(nil)
var _ targets.CollectionProvider = (*githubRepoProvider)(nil)
