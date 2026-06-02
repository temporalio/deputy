package releases

import (
	"context"
	"fmt"
	"net/url"
	"strings"
)

// defaultHashiCorpBaseURL is the canonical host for HashiCorp product release
// indexes.
//
// Note: this is Deputy's choice of an authoritative source and differs from
// mise, which resolves HashiCorp tools (e.g. terraform) through aqua/asdf/vfox
// backends rather than releases.hashicorp.com:
// https://github.com/jdx/mise/blob/main/registry/terraform.toml
const defaultHashiCorpBaseURL = "https://releases.hashicorp.com"

// HashiCorpClient lists product releases from releases.hashicorp.com for a
// single product such as terraform, vault, or consul.
type HashiCorpClient struct {
	base
	product string
}

var _ Lister = (*HashiCorpClient)(nil)

// NewHashiCorpClient returns a HashiCorp release metadata client for product.
func NewHashiCorpClient(product string, opts ...Option) *HashiCorpClient {
	product = strings.TrimSpace(product)
	endpoint := ""
	if product != "" {
		endpoint = hashicorpEndpoint(product)
	}
	return &HashiCorpClient{base: newBase(endpoint, opts...), product: product}
}

// List returns releases for the configured HashiCorp product.
func (c *HashiCorpClient) List(ctx context.Context) ([]Release, error) {
	if c.product == "" {
		return nil, fmt.Errorf("hashicorp: product is required")
	}
	type payload struct {
		Versions map[string]struct {
			Version string `json:"version"`
		} `json:"versions"`
	}
	return fetch(ctx, c.base, func(p payload) []Release {
		releases := make([]Release, 0, len(p.Versions))
		for key, item := range p.Versions {
			version := item.Version
			if version == "" {
				version = key
			}
			releases = append(releases, Release{
				Version: version,
				Stable:  version != "" && !isPrerelease(version),
			})
		}
		return releases
	})
}

// hashicorpEndpoint builds the canonical releases.hashicorp.com index endpoint
// for a product such as terraform, vault, or consul.
func hashicorpEndpoint(product string) string {
	return defaultHashiCorpBaseURL + "/" + url.PathEscape(product) + "/index.json"
}
