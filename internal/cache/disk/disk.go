// Package disk provides persistent JSON-on-disk caching with TTL support.
//
// This package is designed for CLI tools that need to cache data across invocations,
// reducing API calls to external services like CISA KEV, EPSS, and OSV.
//
// For in-memory caching with LRU eviction, see [github.com/temporalio/deputy/internal/cache/memory].
//
// # Cache Location
//
// By default, cache files are stored in ~/.deputy/cache/. This can be overridden
// with the DEPUTY_CACHE_DIR environment variable.
//
// # Usage
//
//	// Write a value
//	disk.Write("myservice", "key", myValue)
//
//	// Read with TTL
//	var value MyType
//	if disk.Read("myservice", "key", 24*time.Hour, &value) {
//	    // value loaded from cache
//	}
//
// # Thread Safety
//
// Read and Write operations are atomic at the file level but the package does
// not provide cross-process locking. For CLI tools, this is typically not an issue.
package disk

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// DefaultTTL is the default time-to-live for cache entries when not specified.
const DefaultTTL = 24 * time.Hour

var (
	cacheDirOnce sync.Once
	cacheDirPath string
)

// BaseDir returns the root directory for the application cache.
// It respects the DEPUTY_CACHE_DIR environment variable, falling back to
// ~/.deputy/cache if not set. The result is cached for subsequent calls.
func BaseDir() string {
	cacheDirOnce.Do(func() {
		if d := os.Getenv("DEPUTY_CACHE_DIR"); d != "" {
			cacheDirPath = d
			return
		}
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			return
		}
		cacheDirPath = filepath.Join(home, ".deputy", "cache")
	})
	return cacheDirPath
}

// Path constructs the full filesystem path for a cached item given its
// subdirectory and key. It sanitizes the key to ensure it is a valid filename.
func Path(subdir, key string) string {
	base := BaseDir()
	if base == "" {
		return ""
	}
	safe := strings.ReplaceAll(key, string(filepath.Separator), "_")
	return filepath.Join(base, subdir, safe+".json")
}

// Read attempts to load and unmarshal a cached value from disk.
// It returns true if the cache hit was successful, the entry is not expired,
// and the value was unmarshaled into v, otherwise false.
// Cache entries are considered expired based on the TTL for the given subdir.
// If ttl is 0, DefaultTTL is used.
func Read(subdir, key string, ttl time.Duration, v any) bool {
	b, ok := readFresh(subdir, key, ttl)
	if !ok {
		return false
	}
	return json.Unmarshal(b, v) == nil
}

// ReadProto is [Read] for protobuf messages, decoding the entry with protojson
// so well-known types, enums and oneofs round-trip. Unknown fields are
// discarded so an entry written by a build with a newer schema still loads.
func ReadProto(subdir, key string, ttl time.Duration, m proto.Message) bool {
	b, ok := readFresh(subdir, key, ttl)
	if !ok {
		return false
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(b, m) == nil
}

// readFresh returns the raw bytes of a cache entry that exists and has not
// expired. Expired entries are removed so a later write replaces them.
func readFresh(subdir, key string, ttl time.Duration) ([]byte, bool) {
	p := Path(subdir, key)
	if p == "" {
		return nil, false
	}
	info, err := os.Stat(p)
	if err != nil {
		return nil, false
	}
	// Check TTL based on file modification time
	if ttl == 0 {
		ttl = DefaultTTL
	}
	if time.Since(info.ModTime()) > ttl {
		// Cache entry expired, remove it
		_ = os.Remove(p)
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return b, true
}

// Write serializes and saves a value to the cache on disk.
// It creates the necessary directories if they do not exist. Errors during
// serialization or file writing are silently ignored.
func Write(subdir, key string, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	writeBytes(subdir, key, b)
}

// WriteProto is [Write] for protobuf messages, encoding the entry with
// protojson so [ReadProto] can decode it losslessly.
func WriteProto(subdir, key string, m proto.Message) {
	b, err := protojson.Marshal(m)
	if err != nil {
		return
	}
	writeBytes(subdir, key, b)
}

func writeBytes(subdir, key string, b []byte) {
	p := Path(subdir, key)
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	_ = os.WriteFile(p, b, 0o644)
}

// SetBaseDirForTest overrides the cache base dir for tests and returns a restore func.
// The test path is preserved by marking the sync.Once as completed (via Do with empty func),
// preventing BaseDir() from re-initializing cacheDirPath during the test.
func SetBaseDirForTest(dir string) func() {
	prevPath := cacheDirPath
	cacheDirPath = dir
	cacheDirOnce = sync.Once{}
	cacheDirOnce.Do(func() {}) // Mark as completed so BaseDir() won't overwrite
	return func() {
		// Restore the previous path and re-mark the Once as completed so a later
		// BaseDir() returns the restored value without re-initializing. A sync.Once
		// cannot be copied, so we reset and re-fire rather than saving its value.
		cacheDirPath = prevPath
		cacheDirOnce = sync.Once{}
		cacheDirOnce.Do(func() {})
	}
}
