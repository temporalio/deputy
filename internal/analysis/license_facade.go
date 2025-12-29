package analysis

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/picatz/deputy/internal/license"
	"github.com/picatz/deputy/internal/repository/workspace"
)

// DepsClient abstracts deps.dev client method GetVersion.
type DepsClient = license.DepsClient

// FetchLicensesForPackage queries deps.dev for license info for a module name@version.
// Returns ["?"] on error or missing data to preserve existing UX.
func FetchLicensesForPackage(ctx context.Context, client DepsClient, name, version string) []string {
	return license.FetchLicensesForPackage(ctx, client, name, version)
}

// FetchLicensesForEcosystem queries deps.dev for license info for a package in the
// given ecosystem. Returns ["?"] on error or missing data to preserve existing UX.
func FetchLicensesForEcosystem(ctx context.Context, client DepsClient, ecosystem, name, version string) []string {
	return license.FetchLicensesForEcosystem(ctx, client, ecosystem, name, version)
}

// LocalRepoLicenseScan inspects a workspace-backed repository (depth-limited)
// for license-looking files and returns detected SPDX identifiers (best effort).
func LocalRepoLicenseScan(ws workspace.FS) []string {
	return license.LocalRepoLicenseScan(ws)
}

// MergeLicenseSources merges deps.dev licenses (primary) with locally scanned
// licenses to produce a stable, de-duplicated set.
func MergeLicenseSources(primary, local []string) []string {
	return license.MergeLicenseSources(primary, local)
}

// RemoteModuleLicenseScan performs a best-effort license scan for a remote module.
func RemoteModuleLicenseScan(ctx context.Context, modulePath, version string) []string {
	return license.RemoteModuleLicenseScan(ctx, modulePath, version)
}

// LookupLicensesBestEffort queries ecosystem-specific registries or content to
// populate licenses when upstream metadata is missing.
func LookupLicensesBestEffort(ctx context.Context, ecosystem, name, version string) []string {
	return license.LookupLicensesBestEffort(ctx, ecosystem, name, version)
}

// DetectLicenseIDs scans raw license text bytes and returns unique SPDX style IDs.
func DetectLicenseIDs(b []byte) []string {
	return license.DetectLicenseIDs(b)
}

// ExtractLicensesFromReader allows tests to exercise detection on arbitrary content.
func ExtractLicensesFromReader(r io.Reader) []string {
	return license.ExtractLicensesFromReader(r)
}

// LookupCratesLicense queries crates.io for license metadata.
func LookupCratesLicense(ctx context.Context, name, version string) []string {
	return license.LookupCratesLicense(ctx, name, version)
}

// LookupPackagistLicense queries packagist.org for license metadata.
func LookupPackagistLicense(ctx context.Context, name, version string) []string {
	return license.LookupPackagistLicense(ctx, name, version)
}

// LookupPubLicense fetches license metadata from pub.dev package API.
func LookupPubLicense(ctx context.Context, name, version string) []string {
	return license.LookupPubLicense(ctx, name, version)
}

// LookupCocoaPodsLicense fetches license metadata from the CocoaPods API.
func LookupCocoaPodsLicense(ctx context.Context, name, version string) []string {
	return license.LookupCocoaPodsLicense(ctx, name, version)
}

// LookupHexLicense fetches license metadata from hex.pm API.
func LookupHexLicense(ctx context.Context, name, version string) []string {
	return license.LookupHexLicense(ctx, name, version)
}

// WithLicenseHTTPClient overrides the HTTP client used for remote license lookups during tests.
func WithLicenseHTTPClient(client *http.Client) func() {
	return license.WithLicenseHTTPClient(client)
}

// WithLicenseEndpoints overrides registry base URLs used in license lookups during tests.
func WithLicenseEndpoints(goProxy, crates, packagist, pub, cocoapods, hexpm string) func() {
	return license.WithLicenseEndpoints(goProxy, crates, packagist, pub, cocoapods, hexpm)
}

// ResetLicenseCachesForTest clears memoization and on-disk caches for deterministic tests.
func ResetLicenseCachesForTest(t *testing.T) {
	license.ResetLicenseCachesForTest(t)
}
