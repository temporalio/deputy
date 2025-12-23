package analysis

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCachePath(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tests := []struct {
		name    string
		subdir  string
		key     string
		wantEnd string
	}{
		{
			name:    "simple key",
			subdir:  "osv",
			key:     "pkg:npm/lodash@4.17.21",
			wantEnd: filepath.Join("osv", "pkg:npm_lodash@4.17.21.json"),
		},
		{
			name:    "key with slashes",
			subdir:  "depsdev",
			key:     "github.com/foo/bar",
			wantEnd: filepath.Join("depsdev", "github.com_foo_bar.json"),
		},
		{
			name:    "empty key",
			subdir:  "osv",
			key:     "",
			wantEnd: filepath.Join("osv", ".json"),
		},
	}

	// Set up temp cache dir
	tmpDir := t.TempDir()

	// Override cache dir for this test
	origPath := cacheDirPath
	cacheDirPath = tmpDir
	t.Cleanup(func() { cacheDirPath = origPath })

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cachePath(tt.subdir, tt.key)
			if got == "" {
				t.Fatal("cachePath returned empty string")
			}
			if !filepath.IsAbs(got) {
				t.Errorf("cachePath returned non-absolute path: %s", got)
			}
			wantSuffix := tt.wantEnd
			if !hasPathSuffix(got, wantSuffix) {
				t.Errorf("cachePath = %s, want suffix %s", got, wantSuffix)
			}
		})
	}
}

func hasPathSuffix(path, suffix string) bool {
	return len(path) >= len(suffix) && path[len(path)-len(suffix):] == suffix
}

func TestReadWriteCache(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	// Override cache dir for this test
	origPath := cacheDirPath
	cacheDirPath = tmpDir
	t.Cleanup(func() { cacheDirPath = origPath })

	type testData struct {
		Name  string `json:"name"`
		Value int    `json:"value"`
	}

	tests := []struct {
		name   string
		subdir string
		key    string
		data   testData
	}{
		{
			name:   "basic write and read",
			subdir: "test",
			key:    "item1",
			data:   testData{Name: "test", Value: 42},
		},
		{
			name:   "nested data",
			subdir: "depsdev",
			key:    "pkg:npm/react",
			data:   testData{Name: "react", Value: 100},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Write to cache
			writeCache(tt.subdir, tt.key, tt.data)

			// Read back
			var got testData
			if !readCache(tt.subdir, tt.key, &got) {
				t.Fatal("readCache returned false, expected true")
			}
			if got.Name != tt.data.Name || got.Value != tt.data.Value {
				t.Errorf("readCache got %+v, want %+v", got, tt.data)
			}
		})
	}
}

func TestReadCache_NonExistent(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	origPath := cacheDirPath
	cacheDirPath = tmpDir
	t.Cleanup(func() { cacheDirPath = origPath })

	var result map[string]any
	if readCache("osv", "nonexistent-key", &result) {
		t.Error("readCache returned true for nonexistent key")
	}
}

func TestReadCache_TTLExpiration(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	origPath := cacheDirPath
	cacheDirPath = tmpDir
	t.Cleanup(func() { cacheDirPath = origPath })

	// Write data to cache
	data := map[string]string{"key": "value"}
	writeCache("osv", "expire-test", data)

	// Verify it can be read
	var result map[string]string
	if !readCache("osv", "expire-test", &result) {
		t.Fatal("readCache returned false immediately after write")
	}

	// Get the cache file path and backdate it
	p := cachePath("osv", "expire-test")
	oldTime := time.Now().Add(-25 * time.Hour) // OSV TTL is 24h
	if err := os.Chtimes(p, oldTime, oldTime); err != nil {
		t.Fatalf("failed to change file time: %v", err)
	}

	// Now read should fail due to TTL
	var result2 map[string]string
	if readCache("osv", "expire-test", &result2) {
		t.Error("readCache returned true for expired entry")
	}

	// File should have been removed
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("expired cache file was not removed")
	}
}

func TestReadCache_DifferentTTLs(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	origPath := cacheDirPath
	cacheDirPath = tmpDir
	t.Cleanup(func() { cacheDirPath = origPath })

	tests := []struct {
		name       string
		subdir     string
		age        time.Duration
		wantCached bool
	}{
		{
			name:       "osv within TTL",
			subdir:     "osv",
			age:        12 * time.Hour, // OSV TTL is 24h
			wantCached: true,
		},
		{
			name:       "osv beyond TTL",
			subdir:     "osv",
			age:        25 * time.Hour,
			wantCached: false,
		},
		{
			name:       "depsdev within TTL",
			subdir:     "depsdev",
			age:        3 * 24 * time.Hour, // License TTL is 7 days
			wantCached: true,
		},
		{
			name:       "depsdev beyond TTL",
			subdir:     "depsdev",
			age:        8 * 24 * time.Hour,
			wantCached: false,
		},
		{
			name:       "unknown subdir uses default TTL",
			subdir:     "unknown",
			age:        12 * time.Hour, // Default TTL is 24h
			wantCached: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "ttl-test-" + tt.name
			data := map[string]string{"test": tt.name}
			writeCache(tt.subdir, key, data)

			// Backdate the file
			p := cachePath(tt.subdir, key)
			oldTime := time.Now().Add(-tt.age)
			if err := os.Chtimes(p, oldTime, oldTime); err != nil {
				t.Fatalf("failed to change file time: %v", err)
			}

			var result map[string]string
			got := readCache(tt.subdir, key, &result)
			if got != tt.wantCached {
				t.Errorf("readCache = %v, want %v", got, tt.wantCached)
			}
		})
	}
}

func TestWriteCache_InvalidJSON(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	origPath := cacheDirPath
	cacheDirPath = tmpDir
	t.Cleanup(func() { cacheDirPath = origPath })

	// Write valid JSON
	writeCache("test", "valid", map[string]string{"key": "value"})

	// Try to read into wrong type - should fail unmarshaling
	var wrongType []int
	if readCache("test", "valid", &wrongType) {
		t.Error("readCache should return false when unmarshaling to wrong type")
	}
}

func TestCacheTTLValues(t *testing.T) {
	t.Parallel()

	// Verify TTL constants are sensible
	if defaultOSVCacheTTL != 24*time.Hour {
		t.Errorf("defaultOSVCacheTTL = %v, want 24h", defaultOSVCacheTTL)
	}
	if defaultLicenseCacheTTL != 7*24*time.Hour {
		t.Errorf("defaultLicenseCacheTTL = %v, want 7d", defaultLicenseCacheTTL)
	}

	// Verify TTL mappings
	expectedTTLs := map[string]time.Duration{
		"osv":              24 * time.Hour,
		"depsdev":          7 * 24 * time.Hour,
		"license-scan":     7 * 24 * time.Hour,
		"license-registry": 7 * 24 * time.Hour,
	}

	for subdir, want := range expectedTTLs {
		if got := cacheTTLs[subdir]; got != want {
			t.Errorf("cacheTTLs[%q] = %v, want %v", subdir, got, want)
		}
	}
}
