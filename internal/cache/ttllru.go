// Package cache provides small in-memory caches with bounded size.
package cache

import (
	"container/list"
	"sync"
	"sync/atomic"
	"time"
)

// Stats reports cache behavior counters.
type Stats struct {
	Hits     uint64
	Misses   uint64
	Evicted  uint64
	Expired  uint64
	Inserted uint64
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
	return Stats{
		Hits:     c.hits.Load(),
		Misses:   c.misses.Load(),
		Evicted:  c.evict.Load(),
		Expired:  c.exp.Load(),
		Inserted: c.ins.Load(),
	}
}
