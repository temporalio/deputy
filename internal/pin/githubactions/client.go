package githubactions

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/go-github/v63/github"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/temporalio/deputy/internal/auth"
	"golang.org/x/oauth2"
)

// NewGitHubClient creates a GitHub API client using credentials from the
// environment (GITHUB_TOKEN, GH_TOKEN). Falls back to an unauthenticated
// client if no token is available (60 req/hr rate limit).
//
// The client uses automatic retry with exponential backoff for transient
// failures (5xx) and respects GitHub's Retry-After header on rate limits
// (403/429).
func NewGitHubClient(ctx context.Context) *github.Client {
	store := auth.DefaultStore()
	ts, err := store.TokenSource(ctx, "api.github.com")

	httpClient := newRetryableGitHubHTTPClient()

	if err != nil || ts == nil {
		slog.Warn("no GitHub token available; using unauthenticated API (60 req/hr limit)",
			"hint", "set GITHUB_TOKEN or GH_TOKEN for 5000 req/hr")
		return github.NewClient(httpClient)
	}

	// Wrap the retryable transport with oauth2 token injection.
	httpClient.Transport = &oauth2.Transport{
		Source: ts,
		Base:   httpClient.Transport,
	}
	return github.NewClient(httpClient)
}

// newRetryableGitHubHTTPClient creates an HTTP client with retry and backoff
// tuned for GitHub API usage:
//   - Retries on 429 (Too Many Requests) and 5xx errors
//   - Respects Retry-After header for rate limit backoff timing
//   - Retries on 403 when it looks like a rate limit (has Retry-After)
//   - Max 4 retries with 1s–60s backoff (higher max to accommodate Retry-After)
func newRetryableGitHubHTTPClient() *http.Client {
	rc := retryablehttp.NewClient()
	rc.Logger = nil
	rc.RetryMax = 4
	rc.RetryWaitMin = 1 * time.Second
	rc.RetryWaitMax = 60 * time.Second
	rc.CheckRetry = githubCheckRetry
	rc.Backoff = githubBackoff
	rc.HTTPClient.Timeout = 30 * time.Second
	return rc.StandardClient()
}

// githubCheckRetry determines whether a request should be retried.
// It extends the default retry policy to handle GitHub-specific rate limiting:
//   - 429: Always retry (standard rate limit)
//   - 403 with Retry-After: Retry (secondary rate limit)
//   - 403 without Retry-After: Don't retry (permission error, not rate limit)
//   - 5xx: Retry (server errors)
func githubCheckRetry(ctx context.Context, resp *http.Response, err error) (bool, error) {
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
		// Retry only if Retry-After is present (secondary rate limit).
		// Without it, this is a permission error — don't retry.
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

// githubBackoff calculates the wait duration before retrying. It respects
// GitHub's Retry-After header when present, falling back to retryablehttp's
// default exponential backoff otherwise.
func githubBackoff(min, max time.Duration, attemptNum int, resp *http.Response) time.Duration {
	if ra := parseRetryAfter(resp); ra > 0 {
		// Respect the server's requested delay, clamped to our max.
		if ra > max {
			return max
		}
		return ra
	}
	return retryablehttp.DefaultBackoff(min, max, attemptNum, resp)
}

// parseRetryAfter extracts the Retry-After header value in seconds.
// Returns 0 if the header is absent or unparseable.
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
