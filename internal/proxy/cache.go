package proxy

import (
	"context"
	"log/slog"
	"strings"
	"time"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/cache"
	"github.com/picatz/deputy/internal/policy"
)

const (
	proxyOSVCacheTTL      = 10 * time.Minute
	proxyOSVCacheMaxItems = 8192

	proxyLicenseCacheTTL      = 30 * time.Minute
	proxyLicenseCacheMaxItems = 16384
)

var (
	proxyOSVCache     = cache.NewTTLCache[string, []analysis.Vulnerability](proxyOSVCacheMaxItems, proxyOSVCacheTTL)
	proxyLicenseCache = cache.NewTTLCache[string, []string](proxyLicenseCacheMaxItems, proxyLicenseCacheTTL)
)

// pkgCacheKey returns a stable cache key for package lookups by ecosystem, name, and version.
// The key format is "ecosystem|name@version" with ecosystem lowercased and all parts trimmed.
func pkgCacheKey(ecosystem, name, version string) string {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	n := strings.TrimSpace(name)
	v := strings.TrimSpace(version)
	// Pre-compute capacity: eco + "|" + name + "@" + version
	var b strings.Builder
	b.Grow(len(eco) + 1 + len(n) + 1 + len(v))
	b.WriteString(eco)
	b.WriteByte('|')
	b.WriteString(n)
	b.WriteByte('@')
	b.WriteString(v)
	return b.String()
}

// cachedOSVLookup queries the OSV database for vulnerabilities, using a local cache
// to avoid redundant network requests for recently-queried packages.
func cachedOSVLookup(ctx context.Context, client analysis.OSVClient, ecosystem, name, version string) ([]analysis.Vulnerability, error) {
	key := pkgCacheKey(ecosystem, name, version)
	if cached, ok := proxyOSVCache.Get(key); ok {
		return cached, nil
	}
	inputs := []analysis.PkgInput{{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
	}}
	vulns, err := analysis.QueryOSVBatch(ctx, client, inputs)
	if err != nil {
		return nil, err
	}
	proxyOSVCache.Set(key, vulns)
	return vulns, nil
}

// cachedLicenseLookup retrieves license information for a package, using a local cache
// to avoid redundant lookups for recently-queried packages.
func cachedLicenseLookup(ctx context.Context, ecosystem, name, version string) ([]string, error) {
	key := pkgCacheKey(ecosystem, name, version)
	if cached, ok := proxyLicenseCache.Get(key); ok {
		return cached, nil
	}
	lics := analysis.LookupLicensesBestEffort(ctx, ecosystem, name, version)
	proxyLicenseCache.Set(key, lics)
	return lics, nil
}

// handlerLookups holds the lookup functions for vulnerability and license data.
// This allows dependency injection for testing and custom lookup strategies.
type handlerLookups struct {
	osvClient     analysis.OSVClient
	vulnLookup    func(context.Context, string, string) ([]analysis.Vulnerability, error)
	licenseLookup func(context.Context, string, string) ([]string, error)
}

// vulnerabilitiesToMaps converts a list of vulnerabilities to a slice of maps
// suitable for policy evaluation. Returns nil if no vulnerabilities are found or on error.
func vulnerabilitiesToMaps(ctx context.Context, lookups handlerLookups, ecosystem, name, version string) []map[string]any {
	var vulns []analysis.Vulnerability
	var err error
	switch {
	case lookups.vulnLookup != nil:
		vulns, err = lookups.vulnLookup(ctx, name, version)
	case lookups.osvClient != nil:
		inputs := []analysis.PkgInput{{
			Name:      name,
			Version:   version,
			Ecosystem: ecosystem,
		}}
		vulns, err = analysis.QueryOSVBatch(ctx, lookups.osvClient, inputs)
	default:
		return nil
	}
	if err != nil {
		slog.Warn("osv lookup failed", "package", name, "version", version, "error", err)
		return nil
	}
	if len(vulns) == 0 {
		return nil
	}
	result := make([]map[string]any, 0, len(vulns))
	for _, v := range vulns {
		m, err := policy.StructToMap(v)
		if err != nil {
			slog.Debug("failed to map vulnerability", "id", v.ID, "error", err)
			continue
		}
		result = append(result, m)
	}
	return result
}

// lookupLicenses retrieves license information using the provided lookup function.
// Returns nil if no license lookup is configured or on error.
func lookupLicenses(ctx context.Context, lookups handlerLookups, name, version string) []string {
	if lookups.licenseLookup == nil {
		return nil
	}
	licenses, err := lookups.licenseLookup(ctx, name, version)
	if err != nil {
		slog.Warn("license lookup failed", "package", name, "version", version, "error", err)
		return nil
	}
	return licenses
}
