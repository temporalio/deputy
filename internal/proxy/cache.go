package proxy

import (
	"context"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/analysis/advisorysource"
	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/cache/memory"
	"github.com/temporalio/deputy/internal/license"
	"go.opentelemetry.io/otel/trace"
)

// Default cache settings. These can be overridden via environment variables:
//
//   - DEPUTY_PROXY_OSV_CACHE_TTL: TTL for OSV vulnerability cache (e.g., "10m", "1h")
//   - DEPUTY_PROXY_OSV_CACHE_SIZE: Maximum items in OSV cache (e.g., "8192")
//   - DEPUTY_PROXY_LICENSE_CACHE_TTL: TTL for license cache (e.g., "30m")
//   - DEPUTY_PROXY_LICENSE_CACHE_SIZE: Maximum items in license cache (e.g., "16384")
//   - DEPUTY_PROXY_IMAGE_CACHE_TTL: TTL for container image scan cache (e.g., "30m")
//   - DEPUTY_PROXY_IMAGE_CACHE_SIZE: Maximum items in image scan cache (e.g., "1024")
//   - DEPUTY_PROXY_IMAGE_SCAN_TIMEOUT: Maximum time for container image scans (e.g., "10m")
//
// Production deployments with high traffic should increase cache sizes.
// Long-lived stable environments may benefit from longer TTLs.
const (
	defaultOSVCacheTTL      = 10 * time.Minute
	defaultOSVCacheMaxItems = 8192

	defaultLicenseCacheTTL      = 30 * time.Minute
	defaultLicenseCacheMaxItems = 16384

	defaultImageScanCacheTTL      = 30 * time.Minute
	defaultImageScanCacheMaxItems = 1024 // Increased from 256 for production use

	// defaultImageScanTimeout is the maximum time allowed for a container image scan.
	// Large images with many layers can take several minutes to pull and scan.
	// This default balances allowing large images while preventing indefinite hangs.
	defaultImageScanTimeout = 10 * time.Minute
)

// CacheConfig holds cache configuration settings.
type CacheConfig struct {
	OSVCacheTTL            time.Duration
	OSVCacheMaxItems       int
	LicenseCacheTTL        time.Duration
	LicenseCacheMaxItems   int
	ImageScanCacheTTL      time.Duration
	ImageScanCacheMaxItems int
	ImageScanTimeout       time.Duration
}

// DefaultCacheConfig returns the default cache configuration,
// with values optionally overridden by environment variables.
func DefaultCacheConfig() CacheConfig {
	cfg := CacheConfig{
		OSVCacheTTL:            defaultOSVCacheTTL,
		OSVCacheMaxItems:       defaultOSVCacheMaxItems,
		LicenseCacheTTL:        defaultLicenseCacheTTL,
		LicenseCacheMaxItems:   defaultLicenseCacheMaxItems,
		ImageScanCacheTTL:      defaultImageScanCacheTTL,
		ImageScanCacheMaxItems: defaultImageScanCacheMaxItems,
		ImageScanTimeout:       defaultImageScanTimeout,
	}

	// Override from environment variables
	if v := os.Getenv("DEPUTY_PROXY_OSV_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.OSVCacheTTL = d
		} else {
			slog.Warn("invalid DEPUTY_PROXY_OSV_CACHE_TTL, using default", "value", v, "default", defaultOSVCacheTTL)
		}
	}
	if v := os.Getenv("DEPUTY_PROXY_OSV_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.OSVCacheMaxItems = n
		} else {
			slog.Warn("invalid DEPUTY_PROXY_OSV_CACHE_SIZE, using default", "value", v, "default", defaultOSVCacheMaxItems)
		}
	}
	if v := os.Getenv("DEPUTY_PROXY_LICENSE_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.LicenseCacheTTL = d
		} else {
			slog.Warn("invalid DEPUTY_PROXY_LICENSE_CACHE_TTL, using default", "value", v, "default", defaultLicenseCacheTTL)
		}
	}
	if v := os.Getenv("DEPUTY_PROXY_LICENSE_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.LicenseCacheMaxItems = n
		} else {
			slog.Warn("invalid DEPUTY_PROXY_LICENSE_CACHE_SIZE, using default", "value", v, "default", defaultLicenseCacheMaxItems)
		}
	}
	if v := os.Getenv("DEPUTY_PROXY_IMAGE_CACHE_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ImageScanCacheTTL = d
		} else {
			slog.Warn("invalid DEPUTY_PROXY_IMAGE_CACHE_TTL, using default", "value", v, "default", defaultImageScanCacheTTL)
		}
	}
	if v := os.Getenv("DEPUTY_PROXY_IMAGE_CACHE_SIZE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.ImageScanCacheMaxItems = n
		} else {
			slog.Warn("invalid DEPUTY_PROXY_IMAGE_CACHE_SIZE, using default", "value", v, "default", defaultImageScanCacheMaxItems)
		}
	}
	if v := os.Getenv("DEPUTY_PROXY_IMAGE_SCAN_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.ImageScanTimeout = d
		} else {
			slog.Warn("invalid DEPUTY_PROXY_IMAGE_SCAN_TIMEOUT, using default", "value", v, "default", defaultImageScanTimeout)
		}
	}

	return cfg
}

// cacheConfig holds the active cache configuration, initialized from defaults/environment.
var cacheConfig = DefaultCacheConfig()

// OSVCache defines the interface for caching OSV vulnerability lookups.
// This allows dependency injection for testing and custom cache implementations.
type OSVCache interface {
	Get(key string) ([]osv.Vulnerability, bool)
	Set(key string, value []osv.Vulnerability)
	Stats() memory.Stats
}

// ContextAwareOSVCache extends OSVCache with context-aware operations
// for per-request tenant isolation in multi-tenant deployments.
type ContextAwareOSVCache interface {
	OSVCache
	GetWithContext(ctx context.Context, key string) ([]osv.Vulnerability, bool)
	SetWithContext(ctx context.Context, key string, value []osv.Vulnerability)
}

// LicenseCache defines the interface for caching license lookups.
// This allows dependency injection for testing and custom cache implementations.
type LicenseCache interface {
	Get(key string) ([]string, bool)
	Set(key string, value []string)
	Stats() memory.Stats
}

// ContextAwareLicenseCache extends LicenseCache with context-aware operations
// for per-request tenant isolation in multi-tenant deployments.
type ContextAwareLicenseCache interface {
	LicenseCache
	GetWithContext(ctx context.Context, key string) ([]string, bool)
	SetWithContext(ctx context.Context, key string, value []string)
}

// ImageScanResult stores cached scan data for a container image.
// This includes vulnerabilities and image configuration/metadata for policy evaluation.
type ImageScanResult struct {
	// Vulnerabilities holds proto Finding messages for policy evaluation.
	// Type is any to avoid import cycles; actual type is []*vulnerabilityv1.Finding.
	Vulnerabilities any
	// ImageInfo contains extracted configuration, metadata, and build history.
	// This is nil when ImageInfo could not be extracted from the scan result.
	ImageInfo map[string]any
}

// ImageScanCache defines the interface for caching image scan results.
type ImageScanCache interface {
	Get(key string) (ImageScanResult, bool)
	Set(key string, value ImageScanResult)
	Stats() memory.Stats
}

// ContextAwareImageScanCache extends ImageScanCache with context-aware operations
// for per-request tenant isolation in multi-tenant deployments.
type ContextAwareImageScanCache interface {
	ImageScanCache
	GetWithContext(ctx context.Context, key string) (ImageScanResult, bool)
	SetWithContext(ctx context.Context, key string, value ImageScanResult)
}

// defaultOSVCache is the package-level default cache for OSV lookups.
// Use NewOSVCache() to create isolated caches for testing.
var defaultOSVCache OSVCache = memory.NewTTLCache[string, []osv.Vulnerability](cacheConfig.OSVCacheMaxItems, cacheConfig.OSVCacheTTL)

// defaultLicenseCache is the package-level default cache for license lookups.
// Use NewLicenseCache() to create isolated caches for testing.
var defaultLicenseCache LicenseCache = memory.NewTTLCache[string, []string](cacheConfig.LicenseCacheMaxItems, cacheConfig.LicenseCacheTTL)

// defaultImageScanCache is the package-level default cache for image scan results.
// Use NewImageScanCache() to create isolated caches for testing.
var defaultImageScanCache ImageScanCache = memory.NewTTLCache[string, ImageScanResult](cacheConfig.ImageScanCacheMaxItems, cacheConfig.ImageScanCacheTTL)

// NewOSVCache creates a new isolated OSV cache instance.
// This is useful for testing or when you need separate cache instances.
func NewOSVCache() OSVCache {
	cfg := DefaultCacheConfig()
	return memory.NewTTLCache[string, []osv.Vulnerability](cfg.OSVCacheMaxItems, cfg.OSVCacheTTL)
}

// NewLicenseCache creates a new isolated license cache instance.
// This is useful for testing or when you need separate cache instances.
func NewLicenseCache() LicenseCache {
	cfg := DefaultCacheConfig()
	return memory.NewTTLCache[string, []string](cfg.LicenseCacheMaxItems, cfg.LicenseCacheTTL)
}

// NewImageScanCache creates a new isolated image scan cache instance.
// This is useful for testing or when you need separate cache instances.
func NewImageScanCache() ImageScanCache {
	cfg := DefaultCacheConfig()
	return memory.NewTTLCache[string, ImageScanResult](cfg.ImageScanCacheMaxItems, cfg.ImageScanCacheTTL)
}

// getOSVCache returns the provided cache or the default if nil.
func getOSVCache(c OSVCache) OSVCache {
	if c != nil {
		return c
	}
	return defaultOSVCache
}

// getLicenseCache returns the provided cache or the default if nil.
func getLicenseCache(c LicenseCache) LicenseCache {
	if c != nil {
		return c
	}
	return defaultLicenseCache
}

// getImageScanCache returns the provided cache or the default if nil.
func getImageScanCache(c ImageScanCache) ImageScanCache {
	if c != nil {
		return c
	}
	return defaultImageScanCache
}

// GetImageScanTimeout returns the configured image scan timeout.
// This timeout limits how long container image scans can run to prevent
// indefinite hangs on slow networks or very large images.
func GetImageScanTimeout() time.Duration {
	return cacheConfig.ImageScanTimeout
}

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

// imageCacheKey returns a stable cache key for container image scans.
// The key format is "registry|repository@digest" with registry lowercased.
func imageCacheKey(registry, repository, digest string) string {
	reg := strings.ToLower(strings.TrimSpace(registry))
	repo := strings.TrimSpace(repository)
	dig := strings.TrimSpace(digest)
	if reg == "" || repo == "" || dig == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(reg) + 1 + len(repo) + 1 + len(dig))
	b.WriteString(reg)
	b.WriteByte('|')
	b.WriteString(repo)
	b.WriteByte('@')
	b.WriteString(dig)
	return b.String()
}

// digestResolutionCacheKey returns a stable cache key for tag-to-digest resolution failures.
// The key format is "registry|repository:tag" with registry lowercased.
func digestResolutionCacheKey(registry, repository, tag string) string {
	reg := strings.ToLower(strings.TrimSpace(registry))
	repo := strings.TrimSpace(repository)
	t := strings.TrimSpace(tag)
	if reg == "" || repo == "" || t == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(reg) + 1 + len(repo) + 1 + len(t))
	b.WriteString(reg)
	b.WriteByte('|')
	b.WriteString(repo)
	b.WriteByte(':')
	b.WriteString(t)
	return b.String()
}

// DigestResolutionCache caches tag-to-digest resolution results.
// This includes both successful resolutions (digest string) and failures (empty string).
// Using a shorter TTL than image scan cache since tags can be updated.
type DigestResolutionCache interface {
	Get(key string) (string, bool)
	Set(key string, value string)
	Stats() memory.Stats
}

// ContextAwareDigestResolutionCache extends DigestResolutionCache with context-aware operations
// for per-request tenant isolation in multi-tenant deployments.
type ContextAwareDigestResolutionCache interface {
	DigestResolutionCache
	GetWithContext(ctx context.Context, key string) (string, bool)
	SetWithContext(ctx context.Context, key string, value string)
}

// defaultDigestResolutionCacheTTL is shorter than image scan cache TTL
// because tags are mutable and we want to eventually retry failed resolutions.
const defaultDigestResolutionCacheTTL = 2 * time.Minute

// defaultDigestResolutionCacheMaxItems is kept smaller since entries are lightweight.
const defaultDigestResolutionCacheMaxItems = 4096

// digestResolutionFailureSentinel is a marker value indicating a cached resolution failure.
// Empty string would be ambiguous (could mean "not found" vs "resolution failed").
const digestResolutionFailureSentinel = "<resolution-failed>"

// defaultDigestResolutionCache is the package-level default cache for digest resolution.
var defaultDigestResolutionCache DigestResolutionCache = memory.NewTTLCache[string, string](
	defaultDigestResolutionCacheMaxItems,
	defaultDigestResolutionCacheTTL,
)

// NewDigestResolutionCache creates a new isolated digest resolution cache instance.
func NewDigestResolutionCache() DigestResolutionCache {
	return memory.NewTTLCache[string, string](
		defaultDigestResolutionCacheMaxItems,
		defaultDigestResolutionCacheTTL,
	)
}

// getDigestResolutionCache returns the provided cache or the default if nil.
func getDigestResolutionCache(c DigestResolutionCache) DigestResolutionCache {
	if c != nil {
		return c
	}
	return defaultDigestResolutionCache
}

// CacheDigestResolution stores a successful digest resolution.
func CacheDigestResolution(c DigestResolutionCache, registry, repository, tag, digest string) {
	key := digestResolutionCacheKey(registry, repository, tag)
	if key == "" || digest == "" {
		return
	}
	getDigestResolutionCache(c).Set(key, digest)
}

// CacheDigestResolutionWithContext stores a successful digest resolution with tenant isolation.
// If the cache implements ContextAwareDigestResolutionCache, tenant ID is extracted from context.
func CacheDigestResolutionWithContext(ctx context.Context, c DigestResolutionCache, registry, repository, tag, digest string) {
	key := digestResolutionCacheKey(registry, repository, tag)
	if key == "" || digest == "" {
		return
	}
	cache := getDigestResolutionCache(c)
	if ctxCache, isCtxAware := cache.(ContextAwareDigestResolutionCache); isCtxAware {
		ctxCache.SetWithContext(ctx, key, digest)
	} else {
		cache.Set(key, digest)
	}
}

// CacheDigestResolutionFailure stores a failed digest resolution attempt.
// This prevents repeated failed lookups for the same tag within the TTL.
func CacheDigestResolutionFailure(c DigestResolutionCache, registry, repository, tag string) {
	key := digestResolutionCacheKey(registry, repository, tag)
	if key == "" {
		return
	}
	getDigestResolutionCache(c).Set(key, digestResolutionFailureSentinel)
}

// CacheDigestResolutionFailureWithContext stores a failed resolution with tenant isolation.
// If the cache implements ContextAwareDigestResolutionCache, tenant ID is extracted from context.
func CacheDigestResolutionFailureWithContext(ctx context.Context, c DigestResolutionCache, registry, repository, tag string) {
	key := digestResolutionCacheKey(registry, repository, tag)
	if key == "" {
		return
	}
	cache := getDigestResolutionCache(c)
	if ctxCache, isCtxAware := cache.(ContextAwareDigestResolutionCache); isCtxAware {
		ctxCache.SetWithContext(ctx, key, digestResolutionFailureSentinel)
	} else {
		cache.Set(key, digestResolutionFailureSentinel)
	}
}

// GetCachedDigestResolution retrieves a cached digest resolution.
// Returns (digest, true, false) for successful resolution.
// Returns ("", true, true) for cached failure.
// Returns ("", false, false) for cache miss.
func GetCachedDigestResolution(c DigestResolutionCache, registry, repository, tag string) (digest string, found bool, wasFailed bool) {
	key := digestResolutionCacheKey(registry, repository, tag)
	if key == "" {
		return "", false, false
	}
	cached, ok := getDigestResolutionCache(c).Get(key)
	if !ok {
		return "", false, false
	}
	if cached == digestResolutionFailureSentinel {
		return "", true, true
	}
	return cached, true, false
}

// GetCachedDigestResolutionWithContext retrieves a cached digest resolution with tenant isolation.
// If the cache implements ContextAwareDigestResolutionCache, tenant ID is extracted from context.
// Returns (digest, true, false) for successful resolution.
// Returns ("", true, true) for cached failure.
// Returns ("", false, false) for cache miss.
func GetCachedDigestResolutionWithContext(ctx context.Context, c DigestResolutionCache, registry, repository, tag string) (digest string, found bool, wasFailed bool) {
	key := digestResolutionCacheKey(registry, repository, tag)
	if key == "" {
		return "", false, false
	}
	cache := getDigestResolutionCache(c)
	var cached string
	var ok bool
	if ctxCache, isCtxAware := cache.(ContextAwareDigestResolutionCache); isCtxAware {
		cached, ok = ctxCache.GetWithContext(ctx, key)
	} else {
		cached, ok = cache.Get(key)
	}
	if !ok {
		return "", false, false
	}
	if cached == digestResolutionFailureSentinel {
		return "", true, true
	}
	return cached, true, false
}

// cachedOSVLookupWithCache queries the configured advisory sources (built-in
// OSV plus any configured plugins/services) using the provided cache. This
// allows tests to inject isolated cache instances. The cache sits in front of
// all sources, so per-request source cost is paid only on a miss.
//
// Multi-tenant support: If the cache implements ContextAwareOSVCache, tenant ID
// is extracted from the request context (JWT claims) to scope cache keys.
//
// Span enrichment: Records cache access events (hit/miss) on the current span.
func cachedOSVLookupWithCache(ctx context.Context, sources *advisorysource.Registry, c OSVCache, ecosystem, name, version string) ([]osv.Vulnerability, error) {
	span := trace.SpanFromContext(ctx)
	osvCache := getOSVCache(c)
	key := pkgCacheKey(ecosystem, name, version)

	// Use context-aware cache operations if available (for tenant isolation)
	var cached []osv.Vulnerability
	var ok bool
	if ctxCache, isCtxAware := osvCache.(ContextAwareOSVCache); isCtxAware {
		cached, ok = ctxCache.GetWithContext(ctx, key)
	} else {
		cached, ok = osvCache.Get(key)
	}

	if ok {
		RecordOSVCacheHit(ctx, span, key)
		slog.Debug("osv cache hit", "package", name, "version", version, "ecosystem", ecosystem, "vulns", len(cached))
		return cached, nil
	}
	RecordOSVCacheMiss(ctx, span, key)
	slog.Debug("osv cache miss", "package", name, "version", version, "ecosystem", ecosystem)
	agg, err := sources.Query(ctx, []*dependencyv1.Package{{
		Name:      name,
		Version:   version,
		Ecosystem: ecosystem,
	}})
	if err != nil {
		slog.Debug("advisory query failed", "package", name, "version", version, "ecosystem", ecosystem, "error", err)
		return nil, err
	}
	vulns := osv.VulnerabilitiesFromProto(agg.Findings, agg.Advisories)

	// Use context-aware cache operations if available (for tenant isolation)
	if ctxCache, isCtxAware := osvCache.(ContextAwareOSVCache); isCtxAware {
		ctxCache.SetWithContext(ctx, key, vulns)
	} else {
		osvCache.Set(key, vulns)
	}
	slog.Debug("osv cache populated", "package", name, "version", version, "ecosystem", ecosystem, "vulns", len(vulns))
	return vulns, nil
}

// cachedLicenseLookupWithCache retrieves license information using the provided cache.
// This allows tests to inject isolated cache instances.
//
// Multi-tenant support: If the cache implements ContextAwareLicenseCache, tenant ID
// is extracted from the request context (JWT claims) to scope cache keys.
//
// Span enrichment: Records cache access events (hit/miss) on the current span.
func cachedLicenseLookupWithCache(ctx context.Context, c LicenseCache, ecosystem, name, version string) ([]string, error) {
	span := trace.SpanFromContext(ctx)
	licCache := getLicenseCache(c)
	key := pkgCacheKey(ecosystem, name, version)

	// Use context-aware cache operations if available (for tenant isolation)
	var cached []string
	var ok bool
	if ctxCache, isCtxAware := licCache.(ContextAwareLicenseCache); isCtxAware {
		cached, ok = ctxCache.GetWithContext(ctx, key)
	} else {
		cached, ok = licCache.Get(key)
	}

	if ok {
		RecordLicenseCacheHit(ctx, span, key)
		slog.Debug("license cache hit", "package", name, "version", version, "ecosystem", ecosystem, "licenses", len(cached))
		return cached, nil
	}
	RecordLicenseCacheMiss(ctx, span, key)
	slog.Debug("license cache miss", "package", name, "version", version, "ecosystem", ecosystem)
	lics := license.LookupLicensesBestEffort(ctx, ecosystem, name, version)

	// Use context-aware cache operations if available (for tenant isolation)
	if ctxCache, isCtxAware := licCache.(ContextAwareLicenseCache); isCtxAware {
		ctxCache.SetWithContext(ctx, key, lics)
	} else {
		licCache.Set(key, lics)
	}
	slog.Debug("license cache populated", "package", name, "version", version, "ecosystem", ecosystem, "licenses", len(lics))
	return lics, nil
}

// handlerLookups holds the lookup functions for vulnerability and license data.
// This allows dependency injection for testing and custom lookup strategies.
type handlerLookups struct {
	advisorySources *advisorysource.Registry
	vulnLookup      func(context.Context, string, string) ([]osv.Vulnerability, error)
	licenseLookup   func(context.Context, string, string) ([]string, error)
}

// lookupVulnerabilities queries for vulnerabilities and returns proto Finding messages.
// Returns nil if no vulnerabilities are found or on error.
//
// Span enrichment: Records the vulnerability count on the current span.
func lookupVulnerabilities(ctx context.Context, lookups handlerLookups, ecosystem, name, version string) []*vulnerabilityv1.Finding {
	span := trace.SpanFromContext(ctx)
	var vulns []osv.Vulnerability
	var err error
	switch {
	case lookups.vulnLookup != nil:
		vulns, err = lookups.vulnLookup(ctx, name, version)
	case lookups.advisorySources != nil:
		var agg *advisorysource.AggregateResult
		agg, err = lookups.advisorySources.Query(ctx, []*dependencyv1.Package{{
			Name:      name,
			Version:   version,
			Ecosystem: ecosystem,
		}})
		if err == nil {
			vulns = osv.VulnerabilitiesFromProto(agg.Findings, agg.Advisories)
		}
	default:
		return nil
	}
	if err != nil {
		slog.Warn("advisory lookup failed", "package", name, "version", version, "error", err)
		return nil
	}

	// Record vulnerability count on span
	RecordVulnerabilityCount(span, len(vulns))

	if len(vulns) == 0 {
		return nil
	}
	// Convert to proto Findings for policy evaluation
	return osv.VulnerabilitiesToFindings(vulns)
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
