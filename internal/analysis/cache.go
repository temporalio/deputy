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

func cachePath(subdir, key string) string {
	base := cacheBaseDir()
	if base == "" {
		return ""
	}
	safe := strings.ReplaceAll(key, string(filepath.Separator), "_")
	return filepath.Join(base, subdir, safe+".json")
}

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
