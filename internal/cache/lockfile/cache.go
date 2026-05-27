// Package lockfile provides content-hash based caching for parsed lockfile data.
//
// This cache avoids redundant parsing when the same lockfile is processed by
// multiple components (inventory extraction, graph resolution, fix planning).
// The cache key is derived from the lockfile content hash, so changes to the
// file automatically invalidate the cache.
package lockfile

import (
	"crypto/sha256"
	"encoding/hex"
	"time"

	"github.com/temporalio/deputy/internal/cache/memory"
)

// ParsedLockfile holds cached parsing results for a lockfile.
// The Data field contains ecosystem-specific parsed data.
type ParsedLockfile struct {
	// Path is the original file path.
	Path string

	// ContentHash is the SHA256 of the file content.
	ContentHash string

	// Ecosystem identifies the package ecosystem (npm, go, cargo, etc.).
	Ecosystem string

	// Type is the specific lockfile format (e.g., "package-lock.json", "yarn.lock").
	Type string

	// Data holds the parsed lockfile data. The concrete type depends on
	// the lockfile format - callers must type-assert to the expected type.
	Data any

	// ParsedAt records when the lockfile was parsed.
	ParsedAt time.Time
}

// Cache provides content-addressed caching for parsed lockfiles.
// It's safe for concurrent use.
type Cache struct {
	cache *memory.TTLCache[string, *ParsedLockfile]
}

// CacheOption configures the lockfile cache.
type CacheOption func(*cacheConfig)

type cacheConfig struct {
	maxEntries int
	ttl        time.Duration
}

// WithMaxEntries sets the maximum number of cached lockfiles.
func WithMaxEntries(n int) CacheOption {
	return func(c *cacheConfig) {
		c.maxEntries = n
	}
}

// WithTTL sets the time-to-live for cached entries.
func WithTTL(ttl time.Duration) CacheOption {
	return func(c *cacheConfig) {
		c.ttl = ttl
	}
}

// New creates a new lockfile cache with the given options.
// Default: 500 entries, 30 minute TTL.
func New(opts ...CacheOption) *Cache {
	cfg := cacheConfig{
		maxEntries: 500,
		ttl:        30 * time.Minute,
	}
	for _, opt := range opts {
		opt(&cfg)
	}

	return &Cache{
		cache: memory.NewTTLCache[string, *ParsedLockfile](cfg.maxEntries, cfg.ttl),
	}
}

// ContentHash computes the SHA256 hash of content for use as a cache key.
func ContentHash(content []byte) string {
	h := sha256.Sum256(content)
	return hex.EncodeToString(h[:])
}

// Key generates a cache key for a lockfile path and content.
// Format: {ecosystem}:{path}:{contenthash}
func Key(ecosystem, path, contentHash string) string {
	return ecosystem + ":" + path + ":" + contentHash
}

// Get retrieves a cached parse result.
// Returns nil if not found or expired.
func (c *Cache) Get(key string) *ParsedLockfile {
	if c == nil {
		return nil
	}
	parsed, ok := c.cache.Get(key)
	if !ok {
		return nil
	}
	return parsed
}

// GetByContent looks up a cached parse result by ecosystem, path, and content.
// This is a convenience method that computes the content hash internally.
func (c *Cache) GetByContent(ecosystem, path string, content []byte) *ParsedLockfile {
	hash := ContentHash(content)
	key := Key(ecosystem, path, hash)
	return c.Get(key)
}

// Set stores a parsed lockfile in the cache.
func (c *Cache) Set(key string, parsed *ParsedLockfile) {
	if c == nil {
		return
	}
	c.cache.Set(key, parsed)
}

// SetParsed stores a parsed lockfile using content-based key.
// This is a convenience method that computes the key internally.
func (c *Cache) SetParsed(ecosystem, path string, content []byte, data any) {
	hash := ContentHash(content)
	parsed := &ParsedLockfile{
		Path:        path,
		ContentHash: hash,
		Ecosystem:   ecosystem,
		Data:        data,
		ParsedAt:    time.Now(),
	}
	key := Key(ecosystem, path, hash)
	c.Set(key, parsed)
}

// Stats returns cache statistics.
func (c *Cache) Stats() memory.Stats {
	if c == nil {
		return memory.Stats{}
	}
	return c.cache.Stats()
}

// Global is the default global lockfile cache.
// Components can use this shared cache or create their own.
var Global = New()
