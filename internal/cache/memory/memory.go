// Package memory provides in-memory caching with bounded size and TTL expiration.
//
// The primary type is [TTLCache], a generic bounded LRU cache with per-entry
// time-to-live expiration. Entries are evicted when the cache exceeds its
// maximum size (LRU order) or when their TTL expires.
//
// For persistent disk-based caching, see [github.com/picatz/deputy/internal/cache/disk].
//
// # Usage
//
//	cache := memory.NewTTLCache[string, MyValue](1000, 5*time.Minute)
//	cache.Set("key", value)
//	if v, ok := cache.Get("key"); ok {
//	    // use v
//	}
//
// # Thread Safety
//
// TTLCache is safe for concurrent use by multiple goroutines.
package memory

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// Stats reports cache behavior counters.
type Stats struct {
	Hits     uint64  `json:"hits"`
	Misses   uint64  `json:"misses"`
	Evicted  uint64  `json:"evicted"`
	Expired  uint64  `json:"expired"`
	Inserted uint64  `json:"inserted"`
	Size     int     `json:"size"`      // Current number of entries
	MaxSize  int     `json:"max_size"`  // Maximum capacity
	HitRate  float64 `json:"hit_rate"`  // Hits / (Hits + Misses), 0 if no accesses
}

// TTLCache is a bounded LRU cache with per-entry TTL.
//
// It is safe for concurrent use.
type TTLCache[K comparable, V any] struct {
	maxEntries int
	ttl        time.Duration

	mu     sync.Mutex
	ll     *list.List
	byKey  map[K]*list.Element
	hits   atomic.Uint64
	misses atomic.Uint64
	evict  atomic.Uint64
	exp    atomic.Uint64
	ins    atomic.Uint64
}

type entry[K comparable, V any] struct {
	key      K
	value    V
	expires  time.Time
	inserted time.Time
}

// NewTTLCache returns a TTL LRU cache.
// maxEntries <= 0 disables caching (Get always misses; Set is a no-op).
func NewTTLCache[K comparable, V any](maxEntries int, ttl time.Duration) *TTLCache[K, V] {
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &TTLCache[K, V]{
		maxEntries: maxEntries,
		ttl:        ttl,
		ll:         list.New(),
		byKey:      make(map[K]*list.Element),
	}
}

// Get returns the cached value and whether it was present and unexpired.
func (c *TTLCache[K, V]) Get(key K) (V, bool) {
	var zero V
	if c == nil || c.maxEntries <= 0 {
		if c != nil {
			c.misses.Add(1)
		}
		return zero, false
	}

	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()

	el := c.byKey[key]
	if el == nil {
		c.misses.Add(1)
		return zero, false
	}
	ent := el.Value.(*entry[K, V])
	if !ent.expires.IsZero() && now.After(ent.expires) {
		c.ll.Remove(el)
		delete(c.byKey, key)
		c.exp.Add(1)
		c.misses.Add(1)
		return zero, false
	}
	c.ll.MoveToFront(el)
	c.hits.Add(1)
	return ent.value, true
}

// Set inserts or updates a value in the cache.
func (c *TTLCache[K, V]) Set(key K, value V) {
	if c == nil || c.maxEntries <= 0 {
		return
	}
	now := time.Now()

	c.mu.Lock()
	defer c.mu.Unlock()

	if el := c.byKey[key]; el != nil {
		ent := el.Value.(*entry[K, V])
		ent.value = value
		ent.expires = now.Add(c.ttl)
		c.ll.MoveToFront(el)
		return
	}
	ent := &entry[K, V]{key: key, value: value, inserted: now, expires: now.Add(c.ttl)}
	el := c.ll.PushFront(ent)
	c.byKey[key] = el
	c.ins.Add(1)

	for c.ll.Len() > c.maxEntries {
		back := c.ll.Back()
		if back == nil {
			break
		}
		c.ll.Remove(back)
		old := back.Value.(*entry[K, V])
		delete(c.byKey, old.key)
		c.evict.Add(1)
	}
}

// Delete removes a key if present.
func (c *TTLCache[K, V]) Delete(key K) {
	if c == nil || c.maxEntries <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el := c.byKey[key]; el != nil {
		c.ll.Remove(el)
		delete(c.byKey, key)
	}
}

// Stats returns a point-in-time snapshot of cache counters.
func (c *TTLCache[K, V]) Stats() Stats {
	if c == nil {
		return Stats{}
	}
	hits := c.hits.Load()
	misses := c.misses.Load()
	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total)
	}

	c.mu.Lock()
	size := len(c.byKey)
	c.mu.Unlock()

	return Stats{
		Hits:     hits,
		Misses:   misses,
		Evicted:  c.evict.Load(),
		Expired:  c.exp.Load(),
		Inserted: c.ins.Load(),
		Size:     size,
		MaxSize:  c.maxEntries,
		HitRate:  hitRate,
	}
}

// Len returns the current number of entries in the cache.
func (c *TTLCache[K, V]) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.byKey)
}
