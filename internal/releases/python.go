package releases

import (
	"context"
	"strings"
)

// defaultPythonEndpoint is the official python.org published-release API
// endpoint.
//
// Note: this is Deputy's choice of an authoritative source and differs from
// mise, whose core Python plugin builds versions via python-build (pyenv)
// definitions: https://github.com/jdx/mise/blob/main/src/plugins/core/python.rs
// The python.org API is used here because it is a stable, official version
// index well-suited to version resolution.
const defaultPythonEndpoint = "https://www.python.org/api/v2/downloads/release/?is_published=1"

// PythonClient lists Python releases from python.org.
type PythonClient struct{ base }

var _ Lister = (*PythonClient)(nil)

// NewPythonClient returns a Python release metadata client.
func NewPythonClient(opts ...Option) *PythonClient {
	return &PythonClient{newBase(defaultPythonEndpoint, opts...)}
}

// List returns published Python releases. Stability uses the API's own
// pre_release flag in addition to the generic prerelease heuristic, so suffixes
// the heuristic does not recognize (e.g. "3.15.0a1") are still excluded.
func (c *PythonClient) List(ctx context.Context) ([]Release, error) {
	type item struct {
		Name       string `json:"name"`
		Published  bool   `json:"is_published"`
		PreRelease bool   `json:"pre_release"`
	}
	return fetch(ctx, c.base, func(items []item) []Release {
		releases := make([]Release, 0, len(items))
		for _, it := range items {
			version := strings.TrimSpace(strings.TrimPrefix(it.Name, "Python "))
			releases = append(releases, Release{
				Version: version,
				Stable:  version != "" && it.Published && !it.PreRelease && !isPrerelease(version),
			})
		}
		return releases
	})
}
