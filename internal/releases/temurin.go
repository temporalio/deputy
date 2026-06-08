package releases

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// defaultTemurinEndpoint is the Eclipse Adoptium release-version metadata
// endpoint for Temurin JDK releases.
//
// Deputy uses the Adoptium API directly for the Temurin vendor. mise resolves
// Java (all vendors) through its mise-java metadata mirror instead; see
// [MiseJavaClient] and https://github.com/jdx/mise/blob/main/src/plugins/core/java.rs
const defaultTemurinEndpoint = "https://api.adoptium.net/v3/info/release_versions"

// TemurinClient lists Eclipse Temurin JDK releases from the Adoptium API.
type TemurinClient struct{ base }

var _ Lister = (*TemurinClient)(nil)

// NewTemurinClient returns an Eclipse Temurin release metadata client.
func NewTemurinClient(opts ...Option) *TemurinClient {
	return &TemurinClient{newBase(defaultTemurinEndpoint, opts...)}
}

// List returns recent Eclipse Temurin JDK GA releases across feature versions.
func (c *TemurinClient) List(ctx context.Context) ([]Release, error) {
	return c.ListFeature(ctx, 0)
}

// ListFeature returns Eclipse Temurin JDK GA releases for a Java feature
// version, such as 21. A non-positive feature returns recent releases across
// feature versions.
func (c *TemurinClient) ListFeature(ctx context.Context, feature int) ([]Release, error) {
	endpoint, err := temurinEndpoint(c.endpoint, feature)
	if err != nil {
		return nil, err
	}
	type payload struct {
		Versions []struct {
			Semver   string `json:"semver"`
			Optional string `json:"optional"`
		} `json:"versions"`
	}
	return fetchURL(ctx, c.base, endpoint, func(p payload) []Release {
		releases := make([]Release, 0, len(p.Versions))
		for _, item := range p.Versions {
			version := strings.TrimSpace(item.Semver)
			channel := ""
			if strings.EqualFold(strings.TrimSpace(item.Optional), "LTS") {
				channel = "lts"
			}
			releases = append(releases, Release{
				Version: version,
				Stable:  version != "" && !isPrerelease(version),
				Channel: channel,
			})
		}
		return releases
	})
}

// temurinEndpoint builds the Adoptium release-version query URL.
func temurinEndpoint(endpoint string, feature int) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("parsing Temurin endpoint: %w", err)
	}
	q := u.Query()
	q.Set("project", "jdk")
	q.Set("release_type", "ga")
	q.Set("sort_order", "DESC")
	q.Set("page_size", "200")
	if feature > 0 {
		q.Set("version", "["+strconv.Itoa(feature)+","+strconv.Itoa(feature+1)+")")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
