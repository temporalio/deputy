package releases

import "context"

// defaultOnePasswordCLIEndpoint is 1Password's CLI app-update metadata endpoint.
//
// Liability note: this is an unofficial, undocumented app-update endpoint (the
// path segments encode product/locale/min-version/channel). It has no published
// stability contract and may change without notice; it is used on a best-effort
// basis and failures degrade gracefully (host-binary fallback).
//
// This is the same vendor host mise relies on — not a different source of truth.
// mise's registry (https://github.com/jdx/mise/blob/main/registry/1password.toml)
// resolves op via the vfox plugin mise-plugins/vfox-1password, whose Available
// hook scrapes app-updates.agilebits.com/product_history/CLI2 (HTML) for the
// version list, falling back to the aqua backend that downloads from
// cache.agilebits.com. Deputy queries the sibling /check JSON endpoint on the
// same host instead — simpler to parse, but it returns only the current version
// (hence the single-release capability note above).
const defaultOnePasswordCLIEndpoint = "https://app-updates.agilebits.com/check/1/0/CLI2/en/2.0.0/N"

// OnePasswordCLIClient lists 1Password CLI releases from the official app
// update metadata endpoint.
//
// Capability note: this source exposes only the current version, so List
// returns a single release. It can resolve "latest" or a prefix matching the
// current version, but cannot enumerate historical versions; an older-major
// request returns [ErrNoMatch].
type OnePasswordCLIClient struct{ base }

var _ Lister = (*OnePasswordCLIClient)(nil)

// NewOnePasswordCLIClient returns a 1Password CLI release metadata client.
func NewOnePasswordCLIClient(opts ...Option) *OnePasswordCLIClient {
	return &OnePasswordCLIClient{newBase(defaultOnePasswordCLIEndpoint, opts...)}
}

// List returns the current 1Password CLI release.
func (c *OnePasswordCLIClient) List(ctx context.Context) ([]Release, error) {
	type payload struct {
		Version string `json:"version"`
	}
	return fetch(ctx, c.base, func(p payload) []Release {
		return []Release{{
			Version: p.Version,
			Stable:  p.Version != "" && !isPrerelease(p.Version),
		}}
	})
}
