package graph

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/go-git/go-billy/v5/memfs"
	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	gitmemory "github.com/go-git/go-git/v5/storage/memory"
	"github.com/picatz/deputy/internal/cache/memory"
	"github.com/picatz/deputy/internal/httputil"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
)

// Cache configuration for graph resolver clients.
// These defaults are suitable for typical CLI usage; long-running services
// may want larger caches or different TTLs.
const (
	// defaultGoModCacheSize is the max number of go.mod files to cache.
	defaultGoModCacheSize = 4096

	// defaultGoModCacheTTL is how long cached go.mod files remain valid.
	// Go modules are immutable once published, so a long TTL is safe.
	defaultGoModCacheTTL = 1 * time.Hour
)

const (
	// DefaultGoProxy is the default Go module proxy.
	DefaultGoProxy = "https://proxy.golang.org"

	// goProxyTimeout is the timeout for individual proxy requests.
	goProxyTimeout = 10 * time.Second
)

// GoProxyClient fetches module metadata from Go module proxies.
// It provides access to go.mod files for any public Go module,
// enabling accurate dependency graph resolution.
//
// The client uses a bounded LRU cache with TTL to prevent unbounded memory
// growth in long-running processes while maintaining good performance.
type GoProxyClient struct {
	proxyURL   string
	httpClient *http.Client

	// cache stores fetched go.mod files with bounded size and TTL.
	// Key format: "module@version"
	cache *memory.TTLCache[string, *modfile.File]
}

// NewGoProxyClient creates a client for fetching Go module metadata.
// If proxyURL is empty, it defaults to proxy.golang.org.
// Uses SafeDialer for SSRF protection against DNS rebinding attacks.
func NewGoProxyClient(proxyURL string) *GoProxyClient {
	if proxyURL == "" {
		proxyURL = DefaultGoProxy
	}
	return &GoProxyClient{
		proxyURL:   strings.TrimSuffix(proxyURL, "/"),
		httpClient: httputil.NewSafeClient(goProxyTimeout),
		cache:      memory.NewTTLCache[string, *modfile.File](defaultGoModCacheSize, defaultGoModCacheTTL),
	}
}

// CacheStats returns cache statistics for monitoring and debugging.
func (c *GoProxyClient) CacheStats() memory.Stats {
	if c == nil || c.cache == nil {
		return memory.Stats{}
	}
	return c.cache.Stats()
}

// FetchGoMod fetches the go.mod file for a module at a specific version.
// Results are cached to avoid redundant network requests.
func (c *GoProxyClient) FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error) {
	cacheKey := modulePath + "@" + version

	// Check cache first
	if mf, ok := c.cache.Get(cacheKey); ok {
		return mf, nil
	}

	// Fetch from proxy
	data, err := c.fetchModFile(ctx, modulePath, version)
	if err != nil {
		return nil, err
	}

	mf, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod for %s@%s: %w", modulePath, version, err)
	}

	// Cache the result
	c.cache.Set(cacheKey, mf)

	return mf, nil
}

// fetchModFile fetches the raw go.mod content from the proxy.
func (c *GoProxyClient) fetchModFile(ctx context.Context, modulePath, version string) ([]byte, error) {
	// Escape the module path for URL (required by GOPROXY protocol)
	escapedPath, err := module.EscapePath(modulePath)
	if err != nil {
		return nil, fmt.Errorf("escaping module path %q: %w", modulePath, err)
	}

	// Escape the version for URL
	escapedVersion, err := module.EscapeVersion(version)
	if err != nil {
		return nil, fmt.Errorf("escaping version %q: %w", version, err)
	}

	// Build the URL: /<module>/@v/<version>.mod
	u := fmt.Sprintf("%s/%s/@v/%s.mod", c.proxyURL, escapedPath, escapedVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", u, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Module or version not found - this is expected for private modules
		return nil, fmt.Errorf("module %s@%s not found on proxy", modulePath, version)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("proxy returned status %d for %s", resp.StatusCode, u)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	return data, nil
}

// GetDependencies returns the direct dependencies declared in a module's go.mod.
// This is the key method for building accurate dependency graphs.
func (c *GoProxyClient) GetDependencies(ctx context.Context, modulePath, version string) ([]module.Version, error) {
	mf, err := c.FetchGoMod(ctx, modulePath, version)
	if err != nil {
		return nil, err
	}

	var deps []module.Version
	for _, req := range mf.Require {
		// Only include direct dependencies (not marked as indirect)
		if !req.Indirect {
			deps = append(deps, req.Mod)
		}
	}
	return deps, nil
}

// GetAllDependencies returns all dependencies (direct and indirect) from a module's go.mod.
func (c *GoProxyClient) GetAllDependencies(ctx context.Context, modulePath, version string) (direct, indirect []module.Version, err error) {
	mf, err := c.FetchGoMod(ctx, modulePath, version)
	if err != nil {
		return nil, nil, err
	}

	for _, req := range mf.Require {
		if req.Indirect {
			indirect = append(indirect, req.Mod)
		} else {
			direct = append(direct, req.Mod)
		}
	}
	return direct, indirect, nil
}

// IsPublicModule checks if a module path looks like it would be available
// on the public proxy. Private modules (internal paths, etc.) return false.
func IsPublicModule(modulePath string) bool {
	// Check for common private module patterns
	if strings.HasPrefix(modulePath, "internal/") {
		return false
	}
	if strings.Contains(modulePath, "/internal/") {
		return false
	}

	// Parse the module path to check if it has a valid import path
	_, err := url.Parse("https://" + modulePath)
	if err != nil {
		return false
	}

	// Common public module hosts
	publicHosts := []string{
		"github.com/",
		"gitlab.com/",
		"bitbucket.org/",
		"golang.org/",
		"google.golang.org/",
		"gopkg.in/",
		"go.uber.org/",
		"k8s.io/",
		"sigs.k8s.io/",
		"cloud.google.com/",
		"deps.dev/",
	}

	for _, host := range publicHosts {
		if strings.HasPrefix(modulePath, host) {
			return true
		}
	}

	// Assume modules with a domain-like first segment are public
	parts := strings.Split(modulePath, "/")
	if len(parts) >= 1 && strings.Contains(parts[0], ".") {
		return true
	}

	return false
}

// GitModuleFetcher fetches go.mod files directly from Git repositories.
// This is used for private modules that aren't available on the public proxy,
// mimicking what `go get` does for GOPRIVATE modules.
//
// The fetcher uses a bounded LRU cache with TTL to prevent unbounded memory
// growth in long-running processes.
type GitModuleFetcher struct {
	// cache stores fetched go.mod files with bounded size and TTL.
	// Key format: "module@version"
	cache *memory.TTLCache[string, *modfile.File]

	// httpClient for meta tag discovery
	httpClient *http.Client

	// gitTimeout limits how long git operations can take
	gitTimeout time.Duration
}

// NewGitModuleFetcher creates a fetcher that retrieves go.mod from Git repos.
func NewGitModuleFetcher() *GitModuleFetcher {
	return &GitModuleFetcher{
		cache: memory.NewTTLCache[string, *modfile.File](defaultGoModCacheSize, defaultGoModCacheTTL),
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		gitTimeout: 30 * time.Second,
	}
}

// CacheStats returns cache statistics for monitoring and debugging.
func (f *GitModuleFetcher) CacheStats() memory.Stats {
	if f == nil || f.cache == nil {
		return memory.Stats{}
	}
	return f.cache.Stats()
}

// FetchGoMod fetches the go.mod file for a module directly from its Git repository.
// It uses the same resolution logic as the Go toolchain:
// 1. For known hosts (github.com, gitlab.com, etc.), construct the repo URL directly
// 2. For other hosts, use go-import meta tag discovery
func (f *GitModuleFetcher) FetchGoMod(ctx context.Context, modulePath, version string) (*modfile.File, error) {
	cacheKey := modulePath + "@" + version

	// Check cache first
	if mf, ok := f.cache.Get(cacheKey); ok {
		return mf, nil
	}

	// Resolve the Git repository URL and subpath
	repoURL, subPath, err := f.resolveModuleRepo(ctx, modulePath)
	if err != nil {
		return nil, fmt.Errorf("resolving repo for %s: %w", modulePath, err)
	}

	// Fetch go.mod from the repository at the specified version
	data, err := f.fetchGoModFromRepo(ctx, repoURL, subPath, version)
	if err != nil {
		return nil, err
	}

	mf, err := modfile.ParseLax("go.mod", data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod for %s@%s: %w", modulePath, version, err)
	}

	// Cache the result
	f.cache.Set(cacheKey, mf)

	return mf, nil
}

// resolveModuleRepo determines the Git repository URL and subpath for a module.
// Returns (repoURL, subPath, error) where subPath is the path within the repo.
func (f *GitModuleFetcher) resolveModuleRepo(ctx context.Context, modulePath string) (repoURL, subPath string, err error) {
	parts := strings.Split(modulePath, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid module path: %s", modulePath)
	}

	host := parts[0]

	// Handle well-known hosts directly
	switch {
	case host == "github.com":
		if len(parts) < 3 {
			return "", "", fmt.Errorf("invalid github.com module path: %s", modulePath)
		}
		repoURL = "https://github.com/" + parts[1] + "/" + parts[2] + ".git"
		if len(parts) > 3 {
			subPath = strings.Join(parts[3:], "/")
		}
		return repoURL, subPath, nil

	case host == "gitlab.com":
		if len(parts) < 3 {
			return "", "", fmt.Errorf("invalid gitlab.com module path: %s", modulePath)
		}
		// GitLab can have nested groups, try progressively shorter paths
		repoURL = "https://gitlab.com/" + parts[1] + "/" + parts[2] + ".git"
		if len(parts) > 3 {
			subPath = strings.Join(parts[3:], "/")
		}
		return repoURL, subPath, nil

	case host == "bitbucket.org":
		if len(parts) < 3 {
			return "", "", fmt.Errorf("invalid bitbucket.org module path: %s", modulePath)
		}
		repoURL = "https://bitbucket.org/" + parts[1] + "/" + parts[2] + ".git"
		if len(parts) > 3 {
			subPath = strings.Join(parts[3:], "/")
		}
		return repoURL, subPath, nil

	case strings.HasSuffix(host, ".googlesource.com"):
		if len(parts) < 2 {
			return "", "", fmt.Errorf("invalid googlesource module path: %s", modulePath)
		}
		repoURL = "https://" + host + "/" + parts[1]
		if len(parts) > 2 {
			subPath = strings.Join(parts[2:], "/")
		}
		return repoURL, subPath, nil
	}

	// For unknown hosts, try go-import meta tag discovery
	return f.discoverRepoViaMetaTags(ctx, modulePath)
}

// discoverRepoViaMetaTags fetches the go-import meta tag from the module's import path.
// This is the standard Go mechanism for discovering VCS info for custom domains.
func (f *GitModuleFetcher) discoverRepoViaMetaTags(ctx context.Context, modulePath string) (repoURL, subPath string, err error) {
	// Try progressively shorter prefixes to find the repo root
	parts := strings.Split(modulePath, "/")
	for i := len(parts); i >= 2; i-- {
		prefix := strings.Join(parts[:i], "/")
		metaURL := "https://" + prefix + "?go-get=1"

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, metaURL, nil)
		if err != nil {
			continue
		}

		resp, err := f.httpClient.Do(req)
		if err != nil || resp.StatusCode != http.StatusOK {
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Parse go-import meta tag
		// Format: <meta name="go-import" content="root-path vcs repo-url">
		repoURL, err = parseGoImportMeta(string(body), prefix)
		if err != nil {
			continue
		}

		// Found it - calculate subpath
		if len(parts) > i {
			subPath = strings.Join(parts[i:], "/")
		}
		return repoURL, subPath, nil
	}

	return "", "", fmt.Errorf("could not discover repository for %s", modulePath)
}

// parseGoImportMeta extracts the repo URL from go-import meta tag content.
func parseGoImportMeta(html, modulePath string) (string, error) {
	// Simple regex to find go-import meta tag
	// <meta name="go-import" content="prefix vcs repo-url">
	re := regexp.MustCompile(`<meta\s+name=["']go-import["']\s+content=["']([^"']+)["']`)
	matches := re.FindAllStringSubmatch(html, -1)

	for _, match := range matches {
		if len(match) < 2 {
			continue
		}
		fields := strings.Fields(match[1])
		if len(fields) < 3 {
			continue
		}
		prefix, vcs, repoURL := fields[0], fields[1], fields[2]

		// Check if this is the right prefix and is git
		if !strings.HasPrefix(modulePath, prefix) {
			continue
		}
		if vcs != "git" {
			continue
		}
		return repoURL, nil
	}
	return "", fmt.Errorf("no go-import meta tag found for %s", modulePath)
}

// fetchGoModFromRepo clones (shallow) the repo and reads go.mod at the given version.
func (f *GitModuleFetcher) fetchGoModFromRepo(ctx context.Context, repoURL, subPath, version string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, f.gitTimeout)
	defer cancel()

	// Use in-memory storage and filesystem for the clone
	storer := gitmemory.NewStorage()
	worktree := memfs.New()

	// Clone with depth 1 at the specific tag/version
	repo, err := git.CloneContext(ctx, storer, worktree, &git.CloneOptions{
		URL:           repoURL,
		ReferenceName: plumbing.ReferenceName("refs/tags/" + version),
		Depth:         1,
		SingleBranch:  true,
	})
	if err != nil {
		// Try with pseudo-version commit hash
		commitHash := extractCommitFromPseudoVersion(version)
		if commitHash != "" {
			// For pseudo-versions, we need to fetch the specific commit
			repo, err = git.CloneContext(ctx, storer, worktree, &git.CloneOptions{
				URL:   repoURL,
				Depth: 50, // Need more history for pseudo-versions
			})
			if err != nil {
				return nil, fmt.Errorf("cloning %s: %w", repoURL, err)
			}
			// Checkout the specific commit
			wt, err := repo.Worktree()
			if err != nil {
				return nil, fmt.Errorf("getting worktree: %w", err)
			}
			err = wt.Checkout(&git.CheckoutOptions{
				Hash: plumbing.NewHash(commitHash),
			})
			if err != nil {
				return nil, fmt.Errorf("checking out %s: %w", commitHash, err)
			}
		} else {
			return nil, fmt.Errorf("cloning %s at %s: %w", repoURL, version, err)
		}
	}

	// Verify we have a valid repo
	if repo == nil {
		return nil, fmt.Errorf("failed to clone repository")
	}

	// Read go.mod from the worktree
	goModPath := "go.mod"
	if subPath != "" {
		goModPath = subPath + "/go.mod"
	}

	file, err := worktree.Open(goModPath)
	if err != nil {
		return nil, fmt.Errorf("opening go.mod at %s: %w", goModPath, err)
	}
	defer file.Close()

	return io.ReadAll(file)
}

// extractCommitFromPseudoVersion extracts the commit hash from a pseudo-version.
// Pseudo-version format: vX.Y.Z-YYYYMMDDHHMMSS-COMMIT (12-char commit hash)
// Returns empty string if not a pseudo-version.
func extractCommitFromPseudoVersion(version string) string {
	// Check for pseudo-version format: vX.Y.Z-YYYYMMDDHHMMSS-COMMIT
	if strings.Count(version, "-") >= 2 {
		parts := strings.Split(version, "-")
		if len(parts) >= 3 {
			// Last part should be the commit hash (12 chars)
			commit := parts[len(parts)-1]
			if len(commit) == 12 {
				// Verify it looks like a hex string
				for _, c := range commit {
					if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
						return ""
					}
				}
				return commit
			}
		}
	}
	return ""
}
