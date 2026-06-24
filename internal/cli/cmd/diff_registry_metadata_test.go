package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/temporalio/deputy/gen/deputy/diff/v1"
	"github.com/temporalio/deputy/internal/registry"
)

// fakeFetcher implements metadataFetcher without any network access. It records
// peak concurrency so the test can assert the semaphore bound, and varies its
// result by package name to exercise the success, error, and not-found paths.
type fakeFetcher struct {
	published time.Time
	delay     time.Duration

	calls     atomic.Int32
	inFlight  atomic.Int32
	maxFlight atomic.Int32
}

func (f *fakeFetcher) Fetch(_ context.Context, _, name, _ string) (*registry.Metadata, error) {
	cur := f.inFlight.Add(1)
	for {
		prev := f.maxFlight.Load()
		if cur <= prev || f.maxFlight.CompareAndSwap(prev, cur) {
			break
		}
	}
	f.calls.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	f.inFlight.Add(-1)

	switch {
	case strings.Contains(name, "err"):
		return nil, errors.New("simulated deps.dev failure")
	case strings.Contains(name, "skip"):
		return nil, nil // unsupported ecosystem / not found in deps.dev
	default:
		return &registry.Metadata{PublishedAt: f.published, Registries: []string{"r"}}, nil
	}
}

func change(name, version string) *diffv1.PackageChange {
	return &diffv1.PackageChange{
		Package:       &dependencyv1.Package{Name: name, Version: version, Ecosystem: "npm"},
		TargetVersion: version,
	}
}

// TestEnrichChangesWithConcurrent drives the concurrent enrichment core over many
// changes with a fake fetcher. Run with -race, it exercises the goroutine fan-out
// and the per-change writes that the production path performs against deps.dev.
func TestEnrichChangesWithConcurrent(t *testing.T) {
	now := time.Date(2026, 6, 23, 12, 0, 0, 0, time.UTC)
	fetcher := &fakeFetcher{
		published: now.Add(-2 * 24 * time.Hour), // 2 days old
		delay:     time.Millisecond,             // encourage goroutine overlap
	}

	// Build a large, mixed batch: mostly normal, some error/not-found, plus
	// entries the guard must skip without touching the fetcher.
	var changes []*diffv1.PackageChange
	const normalCount = 60
	for i := range normalCount {
		changes = append(changes, change(fmt.Sprintf("pkg-%d", i), "1.0.0"))
	}
	errChange := change("err-pkg", "2.0.0")
	skipChange := change("skip-pkg", "3.0.0")
	changes = append(changes, errChange, skipChange)

	// Guarded-out entries: must be ignored and must not reach the fetcher.
	changes = append(changes,
		nil,
		&diffv1.PackageChange{Package: nil, TargetVersion: "9.9.9"},
		change("no-version", ""),
	)

	enrichChangesWith(context.Background(), fetcher, changes, now)

	// Normal changes get target_metadata with the expected age.
	for i := range normalCount {
		c := changes[i]
		if c.TargetMetadata == nil {
			t.Fatalf("pkg-%d: TargetMetadata = nil, want set", i)
		}
		if got := c.TargetMetadata.GetAgeDays(); got != 2 {
			t.Errorf("pkg-%d: age_days = %v, want 2", i, got)
		}
	}

	// Error and not-found leave target_metadata unset (graceful degradation).
	if errChange.TargetMetadata != nil {
		t.Errorf("err-pkg: TargetMetadata = %v, want nil on fetch error", errChange.TargetMetadata)
	}
	if skipChange.TargetMetadata != nil {
		t.Errorf("skip-pkg: TargetMetadata = %v, want nil when deps.dev has no record", skipChange.TargetMetadata)
	}

	// The fetcher is called once per eligible change only (guarded entries excluded).
	if got, want := fetcher.calls.Load(), int32(normalCount+2); got != want {
		t.Errorf("fetcher calls = %d, want %d", got, want)
	}

	// The semaphore bounds concurrency.
	if peak := fetcher.maxFlight.Load(); peak > registryMetadataConcurrency {
		t.Errorf("peak concurrency = %d, exceeds bound %d", peak, registryMetadataConcurrency)
	}
}

// TestEnrichChangesWithEmpty is a guard: no changes means no work and no panic.
func TestEnrichChangesWithEmpty(t *testing.T) {
	fetcher := &fakeFetcher{published: time.Now()}
	enrichChangesWith(context.Background(), fetcher, nil, time.Now())
	if got := fetcher.calls.Load(); got != 0 {
		t.Errorf("fetcher calls = %d, want 0", got)
	}
}
