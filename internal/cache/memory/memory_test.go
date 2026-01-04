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
