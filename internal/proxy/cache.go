package proxy

import (
	"context"
	"strings"
	"time"

	analysis "github.com/picatz/deputy/internal/analysis"
	"github.com/picatz/deputy/internal/cache"
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

func osvCacheKey(ecosystem, name, version string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "|" + strings.TrimSpace(name) + "@" + strings.TrimSpace(version)
}

func licenseCacheKey(ecosystem, name, version string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "|" + strings.TrimSpace(name) + "@" + strings.TrimSpace(version)
}

func cachedOSVLookup(ctx context.Context, client analysis.OSVClient, ecosystem, name, version string) ([]analysis.Vulnerability, error) {
	key := osvCacheKey(ecosystem, name, version)
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

func cachedLicenseLookup(ctx context.Context, ecosystem, name, version string) ([]string, error) {
	key := licenseCacheKey(ecosystem, name, version)
	if cached, ok := proxyLicenseCache.Get(key); ok {
		return cached, nil
	}
	lics := analysis.LookupLicensesBestEffort(ctx, ecosystem, name, version)
	proxyLicenseCache.Set(key, lics)
	return lics, nil
}
