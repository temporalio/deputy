package lockfile

import (
	"testing"
	"time"
)

func TestContentHash(t *testing.T) {
	content := []byte(`{"name": "test", "version": "1.0.0"}`)
	hash := ContentHash(content)

	// Should produce consistent hashes
	hash2 := ContentHash(content)
	if hash != hash2 {
		t.Error("expected consistent hash for same content")
	}

	// Different content should produce different hash
	content2 := []byte(`{"name": "test", "version": "1.0.1"}`)
	hash3 := ContentHash(content2)
	if hash == hash3 {
		t.Error("expected different hash for different content")
	}

	// Hash should be hex-encoded SHA256 (64 chars)
	if len(hash) != 64 {
		t.Errorf("expected 64 char hex hash, got %d chars", len(hash))
	}
}

func TestKey(t *testing.T) {
	key := Key("npm", "package-lock.json", "abc123")
	expected := "npm:package-lock.json:abc123"
	if key != expected {
		t.Errorf("expected %q, got %q", expected, key)
	}
}

func TestCache(t *testing.T) {
	cache := New(WithMaxEntries(10), WithTTL(5*time.Minute))

	t.Run("get missing returns nil", func(t *testing.T) {
		got := cache.Get("nonexistent")
		if got != nil {
			t.Error("expected nil for missing key")
		}
	})

	t.Run("set and get", func(t *testing.T) {
		content := []byte(`{"dependencies": {"lodash": "4.17.21"}}`)
		hash := ContentHash(content)
		key := Key("npm", "package-lock.json", hash)

		parsed := &ParsedLockfile{
			Path:        "package-lock.json",
			ContentHash: hash,
			Ecosystem:   "npm",
			Type:        "package-lock.json",
			Data:        map[string]string{"lodash": "4.17.21"},
		}

		cache.Set(key, parsed)

		got := cache.Get(key)
		if got == nil {
			t.Fatal("expected cached value")
		}
		if got.Path != parsed.Path {
			t.Errorf("expected path %q, got %q", parsed.Path, got.Path)
		}
		if got.Ecosystem != "npm" {
			t.Errorf("expected ecosystem npm, got %s", got.Ecosystem)
		}
	})

	t.Run("SetParsed convenience method", func(t *testing.T) {
		content := []byte(`{"name": "test"}`)
		data := map[string]any{"name": "test"}

		cache.SetParsed("go", "go.mod", content, data)

		hash := ContentHash(content)
		key := Key("go", "go.mod", hash)

		got := cache.Get(key)
		if got == nil {
			t.Fatal("expected cached value from SetParsed")
		}
		if got.Ecosystem != "go" {
			t.Errorf("expected ecosystem go, got %s", got.Ecosystem)
		}
	})

	t.Run("GetByContent convenience method", func(t *testing.T) {
		content := []byte(`{"cargo": "lock"}`)
		data := map[string]string{"some": "data"}

		cache.SetParsed("cargo", "Cargo.lock", content, data)

		got := cache.GetByContent("cargo", "Cargo.lock", content)
		if got == nil {
			t.Fatal("expected cached value from GetByContent")
		}
		if got.Path != "Cargo.lock" {
			t.Errorf("expected path Cargo.lock, got %s", got.Path)
		}
	})

	t.Run("different content is cache miss", func(t *testing.T) {
		content1 := []byte(`{"version": 1}`)
		content2 := []byte(`{"version": 2}`)

		cache.SetParsed("npm", "test.json", content1, nil)

		got := cache.GetByContent("npm", "test.json", content2)
		if got != nil {
			t.Error("expected cache miss for different content")
		}
	})
}

func TestNilCache(t *testing.T) {
	var cache *Cache

	// Should not panic
	got := cache.Get("key")
	if got != nil {
		t.Error("expected nil from nil cache Get")
	}

	cache.Set("key", &ParsedLockfile{})
	cache.SetParsed("eco", "path", []byte("content"), nil)

	stats := cache.Stats()
	if stats.Size != 0 {
		t.Error("expected zero size from nil cache stats")
	}
}

func TestGlobalCache(t *testing.T) {
	if Global == nil {
		t.Error("expected global cache to be initialized")
	}

	stats := Global.Stats()
	if stats.MaxSize == 0 {
		t.Error("expected global cache to have max size set")
	}
}
