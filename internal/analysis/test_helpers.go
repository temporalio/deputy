package analysis

import (
	"net/http"
	"sync"
	"testing"

	"github.com/picatz/deputy/internal/cache"
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
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	registryLicenseMemo = cache.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
	remoteLicenseMemo = cache.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
}
