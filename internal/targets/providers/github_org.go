package providers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v63/github"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(githubOrgProvider{})
}

// priorityGitHubOrg determines detection order relative to other providers.
// GitHub org collections have priority 55, which is:
//   - Lower than specific repos (80) - prefer specific repo if it looks like owner/repo
//   - Higher than directories (50) - prefer GitHub if scheme matches
const priorityGitHubOrg = 55

// githubOrgProvider implements [targets.CollectionProvider] for listing
// repositories in a GitHub organization or user namespace.
//
// URI patterns:
//   - github://myorg/                     → list repos in org (trailing /)
//   - github://username/                  → list repos for user
//   - github.com/myorg/                   → also supported (normalized)
//
// The provider uses GITHUB_TOKEN environment variable for authentication.
type githubOrgProvider struct{}

func (githubOrgProvider) Priority() int { return priorityGitHubOrg }

// Detect returns true if the target looks like a GitHub organization collection.
func (githubOrgProvider) Detect(ctx context.Context, target string) bool {
	return isGitHubOrgCollection(target)
}

// isGitHubOrgCollection checks if a target is a GitHub org/user collection URI.
// Collection URIs end with a trailing slash and have only the owner component.
func isGitHubOrgCollection(target string) bool {
	owner, hasScheme := parseGitHubCollectionOwner(target)
	if !hasScheme || owner == "" {
		return false
	}

	// Collection URIs must end with trailing slash
	if !strings.HasSuffix(target, "/") {
		return false
	}

	return true
}

// parseGitHubCollectionOwner extracts the owner from a GitHub collection URI.
// Returns the owner and whether a valid scheme was found.
func parseGitHubCollectionOwner(target string) (string, bool) {
	target = strings.TrimSpace(target)

	// Handle github:// scheme
	if strings.HasPrefix(target, "github://") {
		rest := strings.TrimPrefix(target, "github://")
		rest = strings.TrimSuffix(rest, "/")
		// Should only have owner, not owner/repo
		if !strings.Contains(rest, "/") && rest != "" {
			return rest, true
		}
		return "", false
	}

	// Handle github.com/ URLs
	if strings.HasPrefix(target, "github.com/") || strings.HasPrefix(target, "https://github.com/") {
		rest := strings.TrimPrefix(target, "https://")
		rest = strings.TrimPrefix(rest, "github.com/")
		rest = strings.TrimSuffix(rest, "/")
		// Should only have owner, not owner/repo
		if !strings.Contains(rest, "/") && rest != "" {
			return rest, true
		}
		return "", false
	}

	return "", false
}

// Open is not applicable for collections - this provider only lists.
func (githubOrgProvider) Open(ctx context.Context, target string, opts *targets.OpenOptions) (targets.Materialized, error) {
	return targets.Materialized{}, fmt.Errorf("cannot open GitHub org collection %q directly; use List() to discover repos, then Open() each repo", target)
}

// IsCollection returns true if the target is a GitHub org collection URI.
func (githubOrgProvider) IsCollection(ctx context.Context, target string) bool {
	return isGitHubOrgCollection(target)
}

// List enumerates repositories in a GitHub organization or user namespace.
func (p githubOrgProvider) List(ctx context.Context, target string, opts *targets.ListOptions) (*targets.ListResult, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list github repos: %w", err)
	}

	// Parse the owner from the URI
	owner, ok := parseGitHubCollectionOwner(target)
	if !ok || owner == "" {
		return nil, fmt.Errorf("invalid GitHub collection URI: %q", target)
	}

	// Parse GitHub-specific options
	ghOpts := parseGitHubListOptions(opts)

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

	// Parse page token (page number)
	page := 1
	if opts.PageToken != "" {
		if n, err := strconv.Atoi(opts.PageToken); err == nil && n > 0 {
			page = n
		}
	}

	// List options for the GitHub API
	listOpts := &github.RepositoryListByOrgOptions{
		Type: ghOpts.Type, // Use parsed type from options
		ListOptions: github.ListOptions{
			PerPage: pageSize,
			Page:    page,
		},
	}

	// First try as organization
	repos, resp, err := client.Repositories.ListByOrg(ctx, owner, listOpts)
	if err != nil {
		// If org not found, try as user
		if isGitHubNotFound(err) {
			userListOpts := &github.RepositoryListByUserOptions{
				Type: ghOpts.Type,
				ListOptions: github.ListOptions{
					PerPage: pageSize,
					Page:    page,
				},
			}
			repos, resp, err = client.Repositories.ListByUser(ctx, owner, userListOpts)
		}
	}
	if err != nil {
		return nil, wrapGitHubListError(err, owner)
	}

	// Log rate limit state for observability
	checkGitHubRateLimit(resp)

	// Convert to discovered targets, applying filters
	results := make([]*listv1.DiscoveredTarget, 0, len(repos))
	for _, repo := range repos {
		if repo == nil {
			continue
		}

		// Apply fork filter
		if !ghOpts.IncludeForks && repo.GetFork() {
			continue
		}

		// Apply archived filter
		if !ghOpts.IncludeArchived && repo.GetArchived() {
			continue
		}

		// Build the target URI
		repoName := repo.GetName()
		uri := fmt.Sprintf("github://%s/%s", owner, repoName)

		// Build description
		desc := repo.GetDescription()
		if desc == "" {
			desc = fmt.Sprintf("%s/%s", owner, repoName)
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         uri,
			Name:        repoName,
			Description: desc,
			Metadata: map[string]string{
				"owner":          owner,
				"full_name":      repo.GetFullName(),
				"default_branch": repo.GetDefaultBranch(),
				"visibility":     repo.GetVisibility(),
				"language":       repo.GetLanguage(),
				"archived":       fmt.Sprintf("%t", repo.GetArchived()),
				"fork":           fmt.Sprintf("%t", repo.GetFork()),
				"stars":          fmt.Sprintf("%d", repo.GetStargazersCount()),
				"html_url":       repo.GetHTMLURL(),
			},
		}

		// Set created time
		if !repo.GetCreatedAt().IsZero() {
			dt.CreatedAt = timestamppb.New(repo.GetCreatedAt().Time)
		}

		// Add topics if available
		if len(repo.Topics) > 0 {
			dt.Metadata["topics"] = strings.Join(repo.Topics, ",")
		}

		results = append(results, dt)
	}

	// Calculate next page token from GitHub's pagination
	var nextPageToken string
	if resp != nil && resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// checkGitHubRateLimit logs rate limit state for observability.
func checkGitHubRateLimit(resp *github.Response) {
	if resp == nil {
		return
	}

	remaining := resp.Rate.Remaining
	resetTime := resp.Rate.Reset.Time

	// Log warning when rate limit is low
	if remaining < 100 {
		slog.Warn("GitHub API rate limit low",
			"remaining", remaining,
			"reset", resetTime.Format(time.RFC3339),
			"limit", resp.Rate.Limit,
		)
	}
}

// newGitHubClient creates a GitHub client, optionally authenticated via GITHUB_TOKEN.
func newGitHubClient(ctx context.Context) *github.Client {
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		// Unauthenticated client - lower rate limits
		return github.NewClient(nil)
	}

	// Authenticated client
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: token})
	tc := oauth2.NewClient(ctx, ts)
	return github.NewClient(tc)
}

// isGitHubNotFound checks if an error indicates a 404 Not Found.
func isGitHubNotFound(err error) bool {
	if err == nil {
		return false
	}
	if ghErr, ok := err.(*github.ErrorResponse); ok {
		return ghErr.Response.StatusCode == http.StatusNotFound
	}
	return strings.Contains(err.Error(), "404")
}

// wrapGitHubListError provides helpful error messages for GitHub API errors.
func wrapGitHubListError(err error, owner string) error {
	if err == nil {
		return nil
	}

	// Check for rate limiting
	if ghErr, ok := err.(*github.ErrorResponse); ok {
		if ghErr.Response.StatusCode == http.StatusForbidden &&
			strings.Contains(ghErr.Message, "rate limit") {
			return fmt.Errorf("list github://%s/: rate limit exceeded (hint: set GITHUB_TOKEN for higher limits)", owner)
		}
		if ghErr.Response.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("list github://%s/: authentication failed (hint: check GITHUB_TOKEN is valid)", owner)
		}
		if ghErr.Response.StatusCode == http.StatusNotFound {
			return fmt.Errorf("list github://%s/: organization or user not found", owner)
		}
	}

	// Check for context timeout
	if ctx, ok := err.(interface{ Timeout() bool }); ok && ctx.Timeout() {
		return fmt.Errorf("list github://%s/: request timeout", owner)
	}

	return fmt.Errorf("list github://%s/: %w", owner, err)
}

var _ targets.Provider = (*githubOrgProvider)(nil)
var _ targets.PriorityProvider = (*githubOrgProvider)(nil)
var _ targets.CollectionProvider = (*githubOrgProvider)(nil)

// GitHubListOptions provides additional options for GitHub repository listing.
// These can be passed via ListOptions.Context.Extra.
type GitHubListOptions struct {
	// IncludeForks includes forked repositories (default: true)
	IncludeForks bool
	// IncludeArchived includes archived repositories (default: true)
	IncludeArchived bool
	// Type filters by repository type: all, public, private, forks, sources, member
	Type string
}

// parseGitHubListOptions extracts GitHub-specific options from ListOptions.
func parseGitHubListOptions(opts *targets.ListOptions) GitHubListOptions {
	result := GitHubListOptions{
		IncludeForks:    true,
		IncludeArchived: true,
		Type:            "all",
	}

	if opts == nil || opts.Context == nil || opts.Context.Extra == nil {
		return result
	}

	if v, ok := opts.Context.Extra["include_forks"]; ok {
		result.IncludeForks = v == "true" || v == "1"
	}
	if v, ok := opts.Context.Extra["include_archived"]; ok {
		result.IncludeArchived = v == "true" || v == "1"
	}
	if v, ok := opts.Context.Extra["type"]; ok && v != "" {
		result.Type = v
	}

	return result
}

// Ensure build doesn't fail if oauth2 is unused in some configurations
var _ = oauth2.NewClient
var _ = time.Second // used indirectly
