package releases

import "context"

// defaultGoogleCloudSDKEndpoint is the Google Cloud SDK rapid-channel component
// metadata endpoint.
//
// Note: this is Deputy's choice of an authoritative source and differs from
// mise, which resolves the Cloud SDK through asdf/vfox backends:
// https://github.com/jdx/mise/blob/main/registry/gcloud.toml
const defaultGoogleCloudSDKEndpoint = "https://dl.google.com/dl/cloudsdk/channels/rapid/components-2.json"

// GoogleCloudSDKClient lists Google Cloud SDK releases from Google's rapid
// channel metadata.
//
// Capability note: this source exposes only the current rapid-channel version,
// so List returns a single release. It can resolve "latest" or a prefix that
// matches the current version, but cannot enumerate historical versions; a
// request for an older major returns [ErrNoMatch].
type GoogleCloudSDKClient struct{ base }

var _ Lister = (*GoogleCloudSDKClient)(nil)

// NewGoogleCloudSDKClient returns a Google Cloud SDK release metadata client.
func NewGoogleCloudSDKClient(opts ...Option) *GoogleCloudSDKClient {
	return &GoogleCloudSDKClient{newBase(defaultGoogleCloudSDKEndpoint, opts...)}
}

// List returns the current Google Cloud SDK rapid-channel release.
func (c *GoogleCloudSDKClient) List(ctx context.Context) ([]Release, error) {
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
