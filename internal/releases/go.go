package releases

import "context"

// defaultGoEndpoint is the official Go release metadata endpoint, including
// historical release trains needed for mise selectors such as "1.24".
//
// Note: this is Deputy's choice of an authoritative source and differs from
// mise, whose core Go plugin lists versions via `git ls-remote --tags` against
// the Go repo (default github.com/golang/go) rather than the go.dev download
// API: https://github.com/jdx/mise/blob/main/src/plugins/core/go.rs
const defaultGoEndpoint = "https://go.dev/dl/?mode=json&include=all"

// GoClient lists stable Go toolchain releases from go.dev.
type GoClient struct{ base }

var _ Lister = (*GoClient)(nil)

// NewGoClient returns a Go release metadata client.
func NewGoClient(opts ...Option) *GoClient {
	return &GoClient{newBase(defaultGoEndpoint, opts...)}
}

// List returns Go releases. Versions are returned in upstream form
// ("go1.26.4"); callers choose their output normalization. Stability comes from
// the upstream "stable" flag, which correctly excludes release candidates like
// "go1.27rc1" that the generic prerelease heuristic would miss.
func (c *GoClient) List(ctx context.Context) ([]Release, error) {
	type item struct {
		Version string `json:"version"`
		Stable  bool   `json:"stable"`
	}
	return fetch(ctx, c.base, func(items []item) []Release {
		releases := make([]Release, 0, len(items))
		for _, it := range items {
			releases = append(releases, Release{Version: it.Version, Stable: it.Stable})
		}
		return releases
	})
}
