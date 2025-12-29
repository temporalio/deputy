package diskcache

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const defaultTTL = 24 * time.Hour

var (
	cacheDirOnce sync.Once
	cacheDirPath string
)

// BaseDir returns the root directory for the application cache.
// It respects the DEPUTY_CACHE_DIR environment variable, falling back to
// ~/.deputy/cache if not set. The result is cached for subsequent calls.
func BaseDir() string {
	if cacheDirPath != "" {
		return cacheDirPath
	}
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
func Read(subdir, key string, ttl time.Duration, v any) bool {
	p := Path(subdir, key)
	if p == "" {
		return false
	}
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	// Check TTL based on file modification time
	if ttl == 0 {
		ttl = defaultTTL
	}
	if time.Since(info.ModTime()) > ttl {
		// Cache entry expired, remove it
		_ = os.Remove(p)
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

// Write serializes and saves a value to the cache on disk.
// It creates the necessary directories if they do not exist. Errors during
// serialization or file writing are silently ignored.
func Write(subdir, key string, v any) {
	p := Path(subdir, key)
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

// SetBaseDirForTest overrides the cache base dir for tests and returns a restore func.
func SetBaseDirForTest(dir string) func() {
	prevPath := cacheDirPath
	prevOnce := cacheDirOnce
	cacheDirPath = dir
	cacheDirOnce = sync.Once{}
	return func() {
		cacheDirPath = prevPath
		cacheDirOnce = prevOnce
	}
}
