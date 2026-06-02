package releases

import "context"

// defaultNodeEndpoint is the official Node.js release index endpoint.
//
// This is the same source mise's core Node plugin uses to list versions:
// https://github.com/jdx/mise/blob/main/src/plugins/core/node.rs
const defaultNodeEndpoint = "https://nodejs.org/dist/index.json"

// NodeClient lists Node.js releases from nodejs.org.
type NodeClient struct{ base }

var _ Lister = (*NodeClient)(nil)

// NewNodeClient returns a Node.js release metadata client.
func NewNodeClient(opts ...Option) *NodeClient {
	return &NodeClient{newBase(defaultNodeEndpoint, opts...)}
}

// List returns Node.js releases. LTS release lines are marked with Channel
// "lts".
func (c *NodeClient) List(ctx context.Context) ([]Release, error) {
	type item struct {
		Version string `json:"version"`
		LTS     any    `json:"lts"`
	}
	return fetch(ctx, c.base, func(items []item) []Release {
		releases := make([]Release, 0, len(items))
		for _, it := range items {
			version := normalizeVersion(it.Version, []string{"v"})
			releases = append(releases, Release{
				Version: it.Version,
				Stable:  it.Version != "" && !isPrerelease(version),
				Channel: nodeChannel(it.LTS),
			})
		}
		return releases
	})
}

// nodeChannel normalizes Node's lts field. The upstream JSON uses false for
// non-LTS releases and a codename string for LTS release lines.
func nodeChannel(lts any) string {
	if v, ok := lts.(string); ok && v != "" {
		return "lts"
	}
	return ""
}
