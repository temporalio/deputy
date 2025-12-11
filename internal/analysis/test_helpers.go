package analysis

import (
	"net/http"
	"sync"
	"testing"
)

// WithLicenseHTTPClient overrides the HTTP client used for remote license lookups during tests.
func WithLicenseHTTPClient(client *http.Client) func() {
	orig := licenseHTTPClient
	licenseHTTPClient = client
	return func() { licenseHTTPClient = orig }
}

// WithLicenseEndpoints overrides registry base URLs used in license lookups during tests.
func WithLicenseEndpoints(goProxy, crates, packagist string) func() {
	origGo, origCrates, origPack := goProxyBase, cratesBase, packagistBase
	goProxyBase, cratesBase, packagistBase = goProxy, crates, packagist
	return func() {
		goProxyBase, cratesBase, packagistBase = origGo, origCrates, origPack
	}
}

// ResetLicenseCachesForTest clears memoization and on-disk caches for deterministic tests.
func ResetLicenseCachesForTest(t *testing.T) {
	t.Helper()
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	registryLicenseMemo = sync.Map{}
	remoteLicenseMemo = sync.Map{}
}
