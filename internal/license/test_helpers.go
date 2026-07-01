package license

import (
	"net/http"
	"testing"

	"github.com/temporalio/deputy/internal/cache/disk"
	"github.com/temporalio/deputy/internal/cache/memory"
	"golang.org/x/sync/singleflight"
)

// WithLicenseHTTPClient overrides the HTTP client used for remote license lookups during tests.
func WithLicenseHTTPClient(client *http.Client) func() {
	orig := licenseHTTPClient
	licenseHTTPClient = client
	return func() { licenseHTTPClient = orig }
}

// WithLicenseEndpoints overrides registry base URLs used in license lookups during tests.
func WithLicenseEndpoints(goProxy, crates, packagist, pub, cocoapods, hexpm string) func() {
	origGo, origCrates, origPack := goProxyBase, cratesBase, packagistBase
	origPub, origPods, origHex := pubBase, cocoapodsBase, hexpmBase
	goProxyBase, cratesBase, packagistBase = goProxy, crates, packagist
	pubBase, cocoapodsBase, hexpmBase = pub, cocoapods, hexpm
	return func() {
		goProxyBase, cratesBase, packagistBase = origGo, origCrates, origPack
		pubBase, cocoapodsBase, hexpmBase = origPub, origPods, origHex
	}
}

// ResetLicenseCachesForTest clears memoization and on-disk caches for deterministic tests.
func ResetLicenseCachesForTest(t *testing.T) {
	t.Helper()
	restore := disk.SetBaseDirForTest(t.TempDir())
	t.Cleanup(restore)
	registryLicenseMemo = memory.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
	remoteLicenseMemo = memory.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
	// Reset the request-coalescing groups too, so an in-flight result from a
	// prior test iteration can't be delivered into a freshly cleared cache.
	remoteLicenseGroup = singleflight.Group{}
	registryLicenseGroup = singleflight.Group{}
}

// getGitHubHTTPClientForTest returns the current GitHub HTTP client for testing.
func getGitHubHTTPClientForTest() *http.Client {
	return githubHTTPClient
}

// setGitHubHTTPClientForTest sets the GitHub HTTP client for testing.
func setGitHubHTTPClientForTest(client *http.Client) {
	githubHTTPClient = client
}
