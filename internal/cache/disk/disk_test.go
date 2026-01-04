package disk

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
	restore := SetBaseDirForTest(tmpDir)
	t.Cleanup(restore)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Path(tt.subdir, tt.key)
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
	restore := SetBaseDirForTest(tmpDir)
	t.Cleanup(restore)

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
			Write(tt.subdir, tt.key, tt.data)

			// Read back
			var got testData
			if !Read(tt.subdir, tt.key, DefaultTTL, &got) {
				t.Fatal("Read returned false, expected true")
			}
			if got.Name != tt.data.Name || got.Value != tt.data.Value {
				t.Errorf("Read got %+v, want %+v", got, tt.data)
			}
		})
	}
}

func TestReadCache_NonExistent(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	restore := SetBaseDirForTest(tmpDir)
	t.Cleanup(restore)

	var result map[string]any
	if Read("osv", "nonexistent-key", DefaultTTL, &result) {
		t.Error("Read returned true for nonexistent key")
	}
}

func TestReadCache_TTLExpiration(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	restore := SetBaseDirForTest(tmpDir)
	t.Cleanup(restore)

	// Write data to cache
	data := map[string]string{"key": "value"}
	Write("osv", "expire-test", data)

	// Verify it can be read
	var result map[string]string
	if !Read("osv", "expire-test", 24*time.Hour, &result) {
		t.Fatal("Read returned false immediately after write")
	}

	// Get the cache file path and backdate it
	p := Path("osv", "expire-test")
	oldTime := time.Now().Add(-25 * time.Hour) // OSV TTL is 24h
	if err := os.Chtimes(p, oldTime, oldTime); err != nil {
		t.Fatalf("failed to change file time: %v", err)
	}

	// Now read should fail due to TTL
	var result2 map[string]string
	if Read("osv", "expire-test", 24*time.Hour, &result2) {
		t.Error("Read returned true for expired entry")
	}

	// File should have been removed
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Error("expired cache file was not removed")
	}
}

func TestReadCache_DifferentTTLs(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	restore := SetBaseDirForTest(tmpDir)
	t.Cleanup(restore)

	tests := []struct {
		name       string
		subdir     string
		age        time.Duration
		ttl        time.Duration
		wantCached bool
	}{
		{
			name:       "within TTL",
			subdir:     "osv",
			age:        12 * time.Hour,
			ttl:        24 * time.Hour,
			wantCached: true,
		},
		{
			name:       "beyond TTL",
			subdir:     "osv",
			age:        25 * time.Hour,
			ttl:        24 * time.Hour,
			wantCached: false,
		},
		{
			name:       "custom TTL shorter",
			subdir:     "custom",
			age:        2 * time.Hour,
			ttl:        90 * time.Minute,
			wantCached: false,
		},
		{
			name:       "default TTL",
			subdir:     "default",
			age:        12 * time.Hour,
			ttl:        0,
			wantCached: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "ttl-test-" + tt.name
			data := map[string]string{"test": tt.name}
			Write(tt.subdir, key, data)

			// Backdate the file
			p := Path(tt.subdir, key)
			oldTime := time.Now().Add(-tt.age)
			if err := os.Chtimes(p, oldTime, oldTime); err != nil {
				t.Fatalf("failed to change file time: %v", err)
			}

			var result map[string]string
			got := Read(tt.subdir, key, tt.ttl, &result)
			if got != tt.wantCached {
				t.Errorf("Read = %v, want %v", got, tt.wantCached)
			}
		})
	}
}

func TestWriteCache_InvalidJSON(t *testing.T) {
	// Cannot use t.Parallel() because we modify cacheDirPath

	tmpDir := t.TempDir()

	restore := SetBaseDirForTest(tmpDir)
	t.Cleanup(restore)

	// Write valid JSON
	Write("test", "valid", map[string]string{"key": "value"})

	// Try to read into wrong type - should fail unmarshaling
	var wrongType []int
	if Read("test", "valid", DefaultTTL, &wrongType) {
		t.Error("Read should return false when unmarshaling to wrong type")
	}
}

func TestDefaultTTL(t *testing.T) {
	t.Parallel()

	if DefaultTTL != 24*time.Hour {
		t.Errorf("DefaultTTL = %v, want 24h", DefaultTTL)
	}
}
