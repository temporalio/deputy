// Package aqua reads the aquaproj/aqua standard registry so callers can resolve
// a tool's canonical version source the way mise's aqua backend does.
//
// mise installs aqua-backed tools by reading a per-package recipe from the aqua
// registry (https://github.com/aquaproj/aqua-registry): one YAML file per
// package under pkgs/<name>/registry.yaml. The recipe's `type` controls how the
// asset is downloaded, while `repo_owner`/`repo_name` (when present) are the
// source aqua enumerates versions from — typically that repository's GitHub
// releases or tags. A recipe without a repo (e.g. a bare `type: http` package
// such as 1password/cli) has no enumerable version source.
//
// This package only fetches and parses that recipe into a [Package] descriptor;
// it deliberately performs no GitHub listing itself, so it has no dependency on
// the GitHub clients and stays manager-agnostic and import-cycle-free. The
// caller decides how to list versions from the descriptor's source.
package aqua

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/goccy/go-yaml"

	"github.com/temporalio/deputy/internal/httputil"
)

const (
	// DefaultRegistryRef pins the aqua-registry version Deputy reads recipes
	// from. Pinning (rather than tracking a moving branch) keeps recipe lookups
	// reproducible and avoids trusting an unpinned upstream tip, which gives a
	// review window against an aqua-registry compromise.
	//
	// This mirrors how mise itself works: mise bakes an aqua-registry snapshot
	// into each release (src/aqua/standard_registry.rs, tagged metadata) and
	// otherwise fetches the live registry with a ~weekly cache TTL
	// (src/aqua/aqua_registry_wrapper.rs); in both tools the actual version list
	// always comes live from the recipe's GitHub repo, not the pinned recipe.
	//
	// Staleness is mostly benign: aqua-registry tags ship ~every 1-2 days, but
	// those releases are overwhelmingly additive (new packages) — the fields we
	// read for an existing recipe (repo/version_prefix/version_filter) change
	// rarely. A behind pin means newly-added tools fall back to the owner/repo
	// heuristic or host mise (graceful); the only wrong-but-plausible edge is an
	// existing tool whose repo moved/renamed since the pin. Bump deliberately,
	// roughly per Deputy release.
	//
	// TODO(deputy): to track mise more closely, consider (1) a settings/env
	// override for the ref or full registry URL (only WithBaseURL exists today,
	// as a test seam), (2) a TTL'd on-disk recipe cache instead of in-process
	// only, and (3) a CI check that this pinned ref still resolves so it cannot
	// silently rot.
	DefaultRegistryRef = "v4.520.2"

	// defaultRegistryTimeout bounds a registry recipe request.
	defaultRegistryTimeout = 10 * time.Second
	// defaultRegistryMaxBytes bounds a single registry recipe file.
	defaultRegistryMaxBytes = 256 << 10
)

// defaultRegistryBaseURL returns the canonical raw base URL for the pinned aqua
// registry's package recipes.
func defaultRegistryBaseURL() string {
	return "https://raw.githubusercontent.com/aquaproj/aqua-registry/" + DefaultRegistryRef + "/pkgs"
}

// ErrNotFound reports that the registry has no recipe for the requested name.
var ErrNotFound = errors.New("aqua registry package not found")

// Package is the subset of an aqua registry recipe Deputy needs to resolve
// versions. Asset, checksum, and environment fields are intentionally omitted.
type Package struct {
	// Type is the aqua package type ("github_release", "github_tag", "http",
	// "go_install", "cargo", …). It controls download, not version listing.
	Type string
	// RepoOwner and RepoName identify the GitHub repository aqua enumerates
	// versions from, when the recipe declares one.
	RepoOwner string
	RepoName  string
	// VersionPrefix is a tag prefix carried by this package's versions (e.g.
	// "cli-"), used to normalize tags during selection.
	VersionPrefix string
	// VersionFilter is aqua's expr-lang version filter expression, when set.
	// Deputy does not evaluate it (it is not CEL); its presence signals that
	// canonical selection may filter the GitHub list further than Deputy does,
	// so Deputy can resolve a superset of versions (worst case: it suggests a
	// version aqua would exclude — a reviewable pin suggestion, not applied).
	//
	// TODO(deputy): evaluate the filter to match aqua exactly. It would need an
	// expr-lang evaluator (github.com/expr-lang/expr); CEL is not compatible.
	// Until then, captured-but-unevaluated is the deliberate, documented gap.
	VersionFilter string
}

// GitHubRepo returns the repository aqua lists versions from and whether the
// package has an enumerable GitHub version source. Packages without a repo
// (e.g. bare http downloads) return ok=false and are not natively resolvable.
func (p *Package) GitHubRepo() (owner, repo string, ok bool) {
	if p == nil {
		return "", "", false
	}
	owner = strings.TrimSpace(p.RepoOwner)
	repo = strings.TrimSpace(p.RepoName)
	return owner, repo, owner != "" && repo != ""
}

// Client looks up aqua registry recipes.
type Client interface {
	// Lookup returns the recipe for an aqua package name such as "owner/repo".
	Lookup(ctx context.Context, name string) (*Package, error)
}

// httpClient fetches recipes from the aqua registry over bounded, SSRF-safe
// HTTP and caches them in-process.
type httpClient struct {
	baseURL    string
	httpClient *http.Client
	maxBytes   int64

	mu    sync.Mutex
	cache map[string]*Package
}

// Option configures a registry [Client].
type Option func(*httpClient)

// WithBaseURL overrides the registry recipe base URL (useful in tests).
func WithBaseURL(baseURL string) Option {
	return func(c *httpClient) {
		if baseURL != "" {
			c.baseURL = baseURL
		}
	}
}

// WithHTTPClient sets the HTTP client used for recipe requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *httpClient) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// NewClient returns an aqua registry client reading from the pinned registry.
func NewClient(opts ...Option) Client {
	c := &httpClient{
		baseURL:    defaultRegistryBaseURL(),
		httpClient: httputil.NewSafeRetryableClient(defaultRegistryTimeout),
		maxBytes:   defaultRegistryMaxBytes,
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// recipe mirrors the subset of an aqua registry.yaml file Deputy parses.
type recipe struct {
	Packages []struct {
		Type          string `yaml:"type"`
		RepoOwner     string `yaml:"repo_owner"`
		RepoName      string `yaml:"repo_name"`
		VersionPrefix string `yaml:"version_prefix"`
		VersionFilter string `yaml:"version_filter"`
	} `yaml:"packages"`
}

// Lookup fetches and parses the registry recipe for name. The result is cached.
func (c *httpClient) Lookup(ctx context.Context, name string) (*Package, error) {
	rel, ok := registryPath(name)
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrNotFound, name)
	}

	c.mu.Lock()
	if pkg, hit := c.cache[rel]; hit {
		c.mu.Unlock()
		return clonePackage(pkg), nil
	}
	c.mu.Unlock()

	endpoint, err := url.JoinPath(c.baseURL, rel)
	if err != nil {
		return nil, fmt.Errorf("building aqua registry URL: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating aqua registry request: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching aqua registry recipe %q: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s", ErrNotFound, name)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching aqua registry recipe %q: status %d", name, resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, c.maxBytes))
	if err != nil {
		return nil, fmt.Errorf("reading aqua registry recipe %q: %w", name, err)
	}
	var parsed recipe
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parsing aqua registry recipe %q: %w", name, err)
	}
	if len(parsed.Packages) == 0 {
		return nil, fmt.Errorf("%w: %s (no packages)", ErrNotFound, name)
	}
	first := parsed.Packages[0]
	pkg := &Package{
		Type:          strings.TrimSpace(first.Type),
		RepoOwner:     strings.TrimSpace(first.RepoOwner),
		RepoName:      strings.TrimSpace(first.RepoName),
		VersionPrefix: strings.TrimSpace(first.VersionPrefix),
		VersionFilter: strings.TrimSpace(first.VersionFilter),
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]*Package{}
	}
	// Re-check under the write lock: a racing caller may have populated this
	// entry while we fetched. Concurrent first-fetches can both hit the network
	// (a rare, idempotent duplicate is cheaper than serializing the fetch).
	if existing, ok := c.cache[rel]; ok {
		return clonePackage(existing), nil
	}
	c.cache[rel] = pkg
	return clonePackage(pkg), nil
}

// registryPath returns the relative registry path for an aqua package name
// (e.g. "owner/repo" -> "owner/repo/registry.yaml"), rejecting names that are
// not a safe two-segment owner/repo path.
func registryPath(name string) (string, bool) {
	name = strings.Trim(strings.TrimSpace(name), "/")
	if name == "" || strings.Contains(name, "..") || strings.ContainsAny(name, `\:`) {
		return "", false
	}
	segs := strings.Split(name, "/")
	if len(segs) != 2 {
		return "", false
	}
	for _, seg := range segs {
		if seg == "" || !isRegistrySegment(seg) {
			return "", false
		}
	}
	return name + "/registry.yaml", true
}

// isRegistrySegment reports whether seg is a safe registry path segment.
func isRegistrySegment(seg string) bool {
	for _, r := range seg {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// clonePackage returns a copy so cached entries are never mutated by callers.
func clonePackage(p *Package) *Package {
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}
