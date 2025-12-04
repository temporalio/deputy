package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

var (
	cacheDirOnce sync.Once
	cacheDirPath string
)

// cacheBaseDir returns the root directory for the application cache.
// It respects the DEPUTY_CACHE_DIR environment variable, falling back to
// ~/.deputy/cache if not set. The result is cached for subsequent calls.
func cacheBaseDir() string {
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

// cachePath constructs the full filesystem path for a cached item given its
// subdirectory and key. It sanitizes the key to ensure it is a valid filename.
func cachePath(subdir, key string) string {
	base := cacheBaseDir()
	if base == "" {
		return ""
	}
	safe := strings.ReplaceAll(key, string(filepath.Separator), "_")
	return filepath.Join(base, subdir, safe+".json")
}

// readCache attempts to load and unmarshal a cached value from disk.
// It returns true if the cache hit was successful and the value was unmarshaled
// into v, otherwise false.
func readCache(subdir, key string, v interface{}) bool {
	p := cachePath(subdir, key)
	if p == "" {
		return false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false
	}
	return true
}

// writeCache serializes and saves a value to the cache on disk.
// It creates the necessary directories if they do not exist. Errors during
// serialization or file writing are silently ignored.
func writeCache(subdir, key string, v interface{}) {
	p := cachePath(subdir, key)
	if p == "" {
		return
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	_ = os.WriteFile(p, b, 0o644)
}
