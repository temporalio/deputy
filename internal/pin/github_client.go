package pin

import (
	"context"
	"log/slog"

	"github.com/google/go-github/v63/github"
	"github.com/picatz/deputy/internal/auth"
	"golang.org/x/oauth2"
)

// NewGitHubClient creates a GitHub API client using credentials from the
// environment (GITHUB_TOKEN, GH_TOKEN). Falls back to an unauthenticated
// client if no token is available (60 req/hr rate limit).
func NewGitHubClient(ctx context.Context) *github.Client {
	store := auth.DefaultStore()
	ts, err := store.TokenSource(ctx, "api.github.com")
	if err != nil || ts == nil {
		slog.Warn("no GitHub token available; using unauthenticated API (60 req/hr limit)",
			"hint", "set GITHUB_TOKEN or GH_TOKEN for 5000 req/hr")
		return github.NewClient(nil)
	}
	return github.NewClient(oauth2.NewClient(ctx, ts))
}
