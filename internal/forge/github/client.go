// Package github provides shared GitHub API clients for forge-aware features.
package github

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	gh "github.com/google/go-github/v63/github"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/temporalio/deputy/internal/auth"
	"github.com/temporalio/deputy/internal/httputil"
	"golang.org/x/oauth2"
)

// NewClient creates a GitHub API client using credentials from the environment
// (GITHUB_TOKEN, GH_TOKEN). It falls back to an unauthenticated client when no
// token is available.
func NewClient(ctx context.Context) *gh.Client {
	store := auth.DefaultStore()
	ts, err := store.TokenSource(ctx, "api.github.com")

	httpClient := NewHTTPClient()

	if err != nil || ts == nil {
		slog.Warn("no GitHub token available; using unauthenticated API (60 req/hr limit)",
			"hint", "set GITHUB_TOKEN or GH_TOKEN for 5000 req/hr")
		return gh.NewClient(httpClient)
	}

	httpClient.Transport = &oauth2.Transport{
		Source: ts,
		Base:   httpClient.Transport,
	}
	return gh.NewClient(httpClient)
}

// NewHTTPClient creates an HTTP client with retry and backoff tuned for GitHub
// API usage. It retries transient server failures and GitHub rate-limit
// responses that include Retry-After.
func NewHTTPClient() *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil
	rc.RetryMax = 4
	rc.RetryWaitMin = 1 * time.Second
	rc.RetryWaitMax = 60 * time.Second
	rc.CheckRetry = checkRetry
	rc.Backoff = backoff
	// Use the SSRF-safe transport (blocks private/loopback/link-local/metadata
	// targets and DNS rebinding) for consistency with Deputy's other outbound
	// clients, so redirects can't be steered to internal hosts.
	rc.HTTPClient = &http.Client{
		Timeout:   30 * time.Second,
		Transport: httputil.NewSafeTransport(),
	}
	return rc.StandardClient()
}

func checkRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
	if ctx.Err() != nil {
		return false, ctx.Err()
	}

	if err != nil {
		return true, nil
	}

	if resp == nil {
		return false, nil
	}

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		slog.Debug("GitHub API rate limited (429), will retry",
			"retry_after", parseRetryAfter(resp))
		return true, nil

	case resp.StatusCode == http.StatusForbidden:
		if ra := parseRetryAfter(resp); ra > 0 {
			slog.Debug("GitHub API secondary rate limit (403 + Retry-After), will retry",
				"retry_after", ra)
			return true, nil
		}
		return false, nil

	case resp.StatusCode >= 500:
		return true, nil
	}

	return false, nil
}

func backoff(minWait, maxWait time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if ra := parseRetryAfter(resp); ra > 0 {
		return min(ra, maxWait)
	}
	return retryablehttp.DefaultBackoff(minWait, maxWait, attemptNum, resp)
}

func parseRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	ra := resp.Header.Get("Retry-After")
	if ra == "" {
		return 0
	}
	secs, err := strconv.Atoi(ra)
	if err != nil {
		return 0
	}
	return time.Duration(secs) * time.Second
}
