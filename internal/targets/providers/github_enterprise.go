package providers

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/go-github/v63/github"
	"google.golang.org/protobuf/types/known/timestamppb"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(githubEnterpriseProvider{})
}

// priorityGitHubEnterprise is higher than repo collections (58) to match
// "github://enterprises/name/" before it's incorrectly parsed as owner/repo.
const priorityGitHubEnterprise = 60

// githubEnterpriseProvider implements [targets.CollectionProvider] for listing
// organizations in a GitHub Enterprise.
//
// URI patterns (trailing slash indicates collection):
//   - github://enterprises/name/      → list organizations in enterprise
//   - github://enterprise/name/       → also supported (singular form)
//
// Authentication:
// Requires a GITHUB_TOKEN with enterprise:read scope or an enterprise admin token.
// Enterprise API access is typically restricted to enterprise owners/admins.
//
// The provider uses GITHUB_TOKEN environment variable for authentication.
type githubEnterpriseProvider struct{}

func (githubEnterpriseProvider) Priority() int { return priorityGitHubEnterprise }

// Detect returns true if the target looks like a GitHub enterprise collection.
func (githubEnterpriseProvider) Detect(ctx context.Context, target string) bool {
	_, ok := parseGitHubEnterpriseCollection(target)
	return ok
}

// parseGitHubEnterpriseCollection extracts the enterprise name from a collection URI.
func parseGitHubEnterpriseCollection(target string) (enterprise string, ok bool) {
	target = strings.TrimSpace(target)

	var rest string
	var found bool

	// Handle github:// scheme
	if rest, found = strings.CutPrefix(target, "github://"); found {
		// got it
	} else if rest, found = strings.CutPrefix(target, "https://github.com/"); found {
		// got it
	} else if rest, found = strings.CutPrefix(target, "github.com/"); found {
		// got it
	} else {
		return "", false
	}

	// Must end with trailing slash for collection
	rest, found = strings.CutSuffix(rest, "/")
	if !found {
		return "", false
	}

	// Parse the path: enterprises/name or enterprise/name
	parts := strings.Split(rest, "/")
	if len(parts) != 2 {
		return "", false
	}

	prefix := strings.ToLower(parts[0])
	if prefix != "enterprises" && prefix != "enterprise" {
		return "", false
	}

	enterprise = parts[1]
	if enterprise == "" {
		return "", false
	}

	return enterprise, true
}

// Open is not applicable for enterprise collections.
func (githubEnterpriseProvider) Open(ctx context.Context, target string, opts *targets.OpenOptions) (targets.Materialized, error) {
	return targets.Materialized{}, fmt.Errorf("cannot open GitHub enterprise %q directly; use List() to discover organizations", target)
}

// IsCollection returns true if the target is a GitHub enterprise collection URI.
func (githubEnterpriseProvider) IsCollection(ctx context.Context, target string) bool {
	_, ok := parseGitHubEnterpriseCollection(target)
	return ok
}

// List enumerates organizations in a GitHub Enterprise.
func (p githubEnterpriseProvider) List(ctx context.Context, target string, opts *targets.ListOptions) (*targets.ListResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list github enterprise: %w", err)
	}

	enterprise, ok := parseGitHubEnterpriseCollection(target)
	if !ok || enterprise == "" {
		return nil, fmt.Errorf("invalid GitHub enterprise URI: %q", target)
	}

	client := newGitHubClient(ctx)

	pageSize := int(opts.PageSize)
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 100 {
		pageSize = 100
	}

	page := 1
	if opts.PageToken != "" {
		if n, err := strconv.Atoi(opts.PageToken); err == nil && n > 0 {
			page = n
		}
	}

	// Build the API URL for listing enterprise organizations
	// GitHub API: GET /enterprises/{enterprise}/organizations
	// go-github doesn't have a dedicated method for this, so we use the raw client
	apiURL := fmt.Sprintf("enterprises/%s/organizations?per_page=%d&page=%d",
		enterprise, pageSize, page)

	req, err := client.NewRequest("GET", apiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("list github enterprise: create request: %w", err)
	}

	// Response type for enterprise organizations
	var orgs []*github.Organization
	resp, err := client.Do(ctx, req, &orgs)
	if err != nil {
		return nil, wrapGitHubEnterpriseError(err, enterprise)
	}

	checkGitHubRateLimit(ctx, resp)

	var results []*listv1.DiscoveredTarget
	for _, org := range orgs {
		if org == nil {
			continue
		}

		dt := &listv1.DiscoveredTarget{
			Uri:         fmt.Sprintf("github://%s/", org.GetLogin()),
			Name:        org.GetLogin(),
			Description: truncateString(org.GetDescription(), 100),
			Metadata: map[string]string{
				"enterprise": enterprise,
				"type":       "organization",
				"login":      org.GetLogin(),
				"avatar_url": org.GetAvatarURL(),
			},
		}

		if org.GetName() != "" {
			dt.Metadata["display_name"] = org.GetName()
		}

		if !org.GetCreatedAt().Time.IsZero() {
			dt.CreatedAt = timestamppb.New(org.GetCreatedAt().Time)
		}

		results = append(results, dt)
	}

	var nextPageToken string
	if resp.NextPage > 0 {
		nextPageToken = strconv.Itoa(resp.NextPage)
	}

	return &targets.ListResult{
		Targets:       results,
		NextPageToken: nextPageToken,
	}, nil
}

// wrapGitHubEnterpriseError provides helpful error messages.
func wrapGitHubEnterpriseError(err error, enterprise string) error {
	if err == nil {
		return nil
	}

	target := fmt.Sprintf("github://enterprises/%s/", enterprise)

	if ghErr, ok := err.(*github.ErrorResponse); ok {
		switch ghErr.Response.StatusCode {
		case 403:
			if strings.Contains(ghErr.Message, "rate limit") {
				return fmt.Errorf("list %s: rate limit exceeded (hint: set GITHUB_TOKEN for higher limits)", target)
			}
			return fmt.Errorf("list %s: access denied (hint: requires GITHUB_TOKEN with enterprise:read scope or enterprise admin access)", target)
		case 401:
			return fmt.Errorf("list %s: authentication failed (hint: check GITHUB_TOKEN is valid)", target)
		case 404:
			return fmt.Errorf("list %s: enterprise not found or not accessible (hint: verify enterprise name and token permissions)", target)
		}
	}

	return fmt.Errorf("list %s: %w", target, err)
}

var _ targets.Provider = (*githubEnterpriseProvider)(nil)
var _ targets.PriorityProvider = (*githubEnterpriseProvider)(nil)
var _ targets.CollectionProvider = (*githubEnterpriseProvider)(nil)
