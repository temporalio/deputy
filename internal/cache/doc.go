// Package cache provides caching primitives for Deputy.
//
// This package contains subpackages for different caching strategies:
//
//   - [github.com/picatz/deputy/internal/cache/memory] - In-memory TTL LRU cache
//   - [github.com/picatz/deputy/internal/cache/disk] - Persistent JSON-on-disk cache
//
// # Memory Cache
//
// The memory subpackage provides a bounded LRU cache with per-entry TTL:
//
//	cache := memory.NewTTLCache[string, MyValue](1000, 5*time.Minute)
//	cache.Set("key", value)
//	if v, ok := cache.Get("key"); ok {
//	    // use v
//	}
//
// # Disk Cache
//
// The disk subpackage provides persistent JSON caching for CLI tools:
//
//	disk.Write("myservice", "key", myValue)
//	var value MyType
//	if disk.Read("myservice", "key", 24*time.Hour, &value) {
//	    // value loaded from cache
//	}
package cache
