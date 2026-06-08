// Package releases lists GitHub release and tag metadata.
package releases

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	gh "github.com/google/go-github/v63/github"
	forgegithub "github.com/temporalio/deputy/internal/forge/github"
	"github.com/temporalio/deputy/internal/releases"
)

// maxPages bounds how many 100-item pages any single listing will fetch
// (≈5,000 entries). Version resolution only needs the newest releases/tags,
// which GitHub returns first, so a monorepo with thousands of tags is capped
// rather than triggering an unbounded sequence of API calls.
const maxPages = 50

// Client lists release and tag versions from GitHub repositories.
type Client struct {
	client *gh.Client
}

// New returns a GitHub release metadata client. If client is nil, an
// unauthenticated retryable GitHub client is used.
func New(client *gh.Client) *Client {
	if client == nil {
		client = gh.NewClient(forgegithub.NewHTTPClient())
	}
	return &Client{client: client}
}

// List returns release and tag versions for owner/repo.
func (c *Client) List(ctx context.Context, owner, repo string) ([]releases.Release, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("github release client is nil")
	}
	releasesList, err := c.listReleases(ctx, owner, repo)
	if err != nil {
		return nil, err
	}
	tags, err := c.listTags(ctx, owner, repo)
	if err != nil {
		return nil, err
	}
	return append(releasesList, tags...), nil
}

// ListMatchingTags returns repository tags whose ref starts with prefix.
func (c *Client) ListMatchingTags(ctx context.Context, owner, repo, prefix string) ([]releases.Release, error) {
	if c == nil || c.client == nil {
		return nil, fmt.Errorf("github release client is nil")
	}
	prefix = strings.TrimPrefix(strings.TrimSpace(prefix), "refs/tags/")
	opts := &gh.ReferenceListOptions{
		Ref:         "tags/" + prefix,
		ListOptions: gh.ListOptions{PerPage: 100},
	}
	var out []releases.Release
	for page := 1; ; page++ {
		refs, resp, err := c.client.Git.ListMatchingRefs(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("listing GitHub matching tags for %s/%s prefix %q: %w", owner, repo, prefix, err)
		}
		for _, ref := range refs {
			tag := strings.TrimPrefix(ref.GetRef(), "refs/tags/")
			if tag == "" {
				continue
			}
			out = append(out, releases.Release{Version: tag, Stable: true})
		}
		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		if page >= maxPages {
			slog.DebugContext(ctx, "github matching tags: page cap reached", "owner", owner, "repo", repo, "prefix", prefix, "pages", page)
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

func (c *Client) listReleases(ctx context.Context, owner, repo string) ([]releases.Release, error) {
	opts := &gh.ListOptions{PerPage: 100}
	var out []releases.Release
	for page := 1; ; page++ {
		list, resp, err := c.client.Repositories.ListReleases(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("listing GitHub releases for %s/%s: %w", owner, repo, err)
		}
		for _, item := range list {
			if item.GetDraft() {
				continue
			}
			out = append(out, releases.Release{
				Version: item.GetTagName(),
				Stable:  !item.GetPrerelease(),
			})
		}
		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		if page >= maxPages {
			slog.DebugContext(ctx, "github releases: page cap reached", "owner", owner, "repo", repo, "pages", page)
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}

func (c *Client) listTags(ctx context.Context, owner, repo string) ([]releases.Release, error) {
	opts := &gh.ListOptions{PerPage: 100}
	var out []releases.Release
	for page := 1; ; page++ {
		tags, resp, err := c.client.Repositories.ListTags(ctx, owner, repo, opts)
		if err != nil {
			return nil, fmt.Errorf("listing GitHub tags for %s/%s: %w", owner, repo, err)
		}
		for _, tag := range tags {
			out = append(out, releases.Release{
				Version: tag.GetName(),
				Stable:  true,
			})
		}
		if resp == nil || resp.NextPage == 0 {
			return out, nil
		}
		if page >= maxPages {
			slog.DebugContext(ctx, "github tags: page cap reached", "owner", owner, "repo", repo, "pages", page)
			return out, nil
		}
		opts.Page = resp.NextPage
	}
}
