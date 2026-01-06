package memory

import (
	"testing"
	"testing/synctest"
	"time"
)

func TestTTLCache_Table(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{
			name: "HitMiss",
			run: func(t *testing.T) {
				c := NewTTLCache[string, int](10, 50*time.Millisecond)
				if _, ok := c.Get("a"); ok {
					t.Fatalf("expected miss")
				}
				c.Set("a", 1)
				if v, ok := c.Get("a"); !ok || v != 1 {
					t.Fatalf("get a=%v ok=%v", v, ok)
				}
				s := c.Stats()
				if s.Hits != 1 || s.Misses != 1 || s.Inserted != 1 {
					t.Fatalf("stats=%+v", s)
				}
			},
		},
		{
			name: "Expires",
			run: func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					c := NewTTLCache[string, int](10, 10*time.Millisecond)
					c.Set("a", 1)
					time.Sleep(25 * time.Millisecond)
					if _, ok := c.Get("a"); ok {
						t.Fatalf("expected expired miss")
					}
					if c.Stats().Expired == 0 {
						t.Fatalf("expected expired counter increment")
					}
				})
			},
		},
		{
			name: "EvictsLRU",
			run: func(t *testing.T) {
				c := NewTTLCache[string, int](2, time.Minute)
				c.Set("a", 1)
				c.Set("b", 2)
				// Touch a so b becomes LRU.
				_, _ = c.Get("a")
				c.Set("c", 3)
				if _, ok := c.Get("b"); ok {
					t.Fatalf("expected b evicted")
				}
				if v, ok := c.Get("a"); !ok || v != 1 {
					t.Fatalf("expected a present, got %v ok=%v", v, ok)
				}
				if c.Stats().Evicted == 0 {
					t.Fatalf("expected eviction counter increment")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.run)
	}
}

func TestTTLCache_StatsEnhanced(t *testing.T) {
	t.Parallel()

	c := NewTTLCache[string, int](10, time.Minute)

	// Initial stats should show zeros
	s := c.Stats()
	if s.Size != 0 {
		t.Errorf("expected Size=0, got %d", s.Size)
	}
	if s.MaxSize != 10 {
		t.Errorf("expected MaxSize=10, got %d", s.MaxSize)
	}
	if s.HitRate != 0 {
		t.Errorf("expected HitRate=0, got %f", s.HitRate)
	}

	// Add some entries
	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)

	s = c.Stats()
	if s.Size != 3 {
		t.Errorf("expected Size=3, got %d", s.Size)
	}
	if s.Inserted != 3 {
		t.Errorf("expected Inserted=3, got %d", s.Inserted)
	}

	// Generate hits and misses
	c.Get("a") // hit
	c.Get("a") // hit
	c.Get("b") // hit
	c.Get("x") // miss
	c.Get("y") // miss

	s = c.Stats()
	if s.Hits != 3 {
		t.Errorf("expected Hits=3, got %d", s.Hits)
	}
	if s.Misses != 2 {
		t.Errorf("expected Misses=2, got %d", s.Misses)
	}
	// Hit rate should be 3/5 = 0.6
	expectedHitRate := 0.6
	if s.HitRate < expectedHitRate-0.01 || s.HitRate > expectedHitRate+0.01 {
		t.Errorf("expected HitRate≈0.6, got %f", s.HitRate)
	}
}

func TestTTLCache_Len(t *testing.T) {
	t.Parallel()

	c := NewTTLCache[string, int](10, time.Minute)
	if c.Len() != 0 {
		t.Errorf("expected Len=0, got %d", c.Len())
	}

	c.Set("a", 1)
	c.Set("b", 2)
	if c.Len() != 2 {
		t.Errorf("expected Len=2, got %d", c.Len())
	}

	c.Delete("a")
	if c.Len() != 1 {
		t.Errorf("expected Len=1, got %d", c.Len())
	}
}

func TestTTLCache_NilSafety(t *testing.T) {
	t.Parallel()

	var c *TTLCache[string, int]

	// All methods should be nil-safe
	if c.Len() != 0 {
		t.Error("nil cache Len should return 0")
	}

	s := c.Stats()
	if s.Hits != 0 || s.Misses != 0 || s.Size != 0 {
		t.Errorf("nil cache Stats should return zeros: %+v", s)
	}

	// Get on nil should not panic
	if _, ok := c.Get("key"); ok {
		t.Error("nil cache Get should return false")
	}

	// Set and Delete on nil should not panic
	c.Set("key", 1)
	c.Delete("key")
}
