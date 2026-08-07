package cache

import (
	"context"
	"errors"
	"testing"
	"time"
)

// mockSource implements Source for testing.
type mockSource struct {
	name        string
	desc        string
	status      *SourceStatus
	statusErr   error
	populateErr error
	clearErr    error
	populated   bool
	cleared     bool
}

func (m *mockSource) Name() string        { return m.name }
func (m *mockSource) Description() string { return m.desc }

func (m *mockSource) Status(ctx context.Context) (*SourceStatus, error) {
	if m.statusErr != nil {
		return nil, m.statusErr
	}
	if m.status != nil {
		return m.status, nil
	}
	return &SourceStatus{
		Name:        m.name,
		Description: m.desc,
		Available:   true,
		Fresh:       true,
	}, nil
}

func (m *mockSource) Populate(ctx context.Context, opts PopulateOptions) error {
	m.populated = true
	return m.populateErr
}

func (m *mockSource) Clear(ctx context.Context) error {
	m.cleared = true
	return m.clearErr
}

func TestRegistry_Register(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{name: "source1", desc: "Source 1"}
	s2 := &mockSource{name: "source2", desc: "Source 2"}

	reg.Register(s1)
	reg.Register(s2)

	if got := reg.Get("source1"); got != s1 {
		t.Errorf("Get(source1) = %v, want %v", got, s1)
	}
	if got := reg.Get("source2"); got != s2 {
		t.Errorf("Get(source2) = %v, want %v", got, s2)
	}
	if got := reg.Get("unknown"); got != nil {
		t.Errorf("Get(unknown) = %v, want nil", got)
	}
}

func TestRegistry_Register_Replace(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{name: "source", desc: "Original"}
	s2 := &mockSource{name: "source", desc: "Replacement"}

	reg.Register(s1)
	reg.Register(s2)

	if got := reg.Get("source"); got != s2 {
		t.Errorf("Get(source) = %v, want replacement", got)
	}

	// Order should not have duplicates
	names := reg.Names()
	if len(names) != 1 {
		t.Errorf("Names() = %v, want single entry", names)
	}
}

func TestRegistry_All(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{name: "a", desc: "A"}
	s2 := &mockSource{name: "b", desc: "B"}
	s3 := &mockSource{name: "c", desc: "C"}

	// Register in specific order
	reg.Register(s2)
	reg.Register(s1)
	reg.Register(s3)

	all := reg.All()
	if len(all) != 3 {
		t.Fatalf("All() returned %d sources, want 3", len(all))
	}

	// Should maintain registration order
	if all[0].Name() != "b" || all[1].Name() != "a" || all[2].Name() != "c" {
		t.Errorf("All() order = [%s, %s, %s], want [b, a, c]",
			all[0].Name(), all[1].Name(), all[2].Name())
	}
}

func TestRegistry_Names(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&mockSource{name: "x"})
	reg.Register(&mockSource{name: "y"})
	reg.Register(&mockSource{name: "z"})

	names := reg.Names()
	if len(names) != 3 {
		t.Fatalf("Names() = %v, want 3 names", names)
	}

	// Names should be a copy
	names[0] = "modified"
	if reg.Names()[0] == "modified" {
		t.Error("Names() returned original slice, should be a copy")
	}
}

func TestRegistry_Status(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{
		name: "fresh",
		status: &SourceStatus{
			Name:      "fresh",
			Available: true,
			Fresh:     true,
			Size:      1024,
		},
	}
	s2 := &mockSource{
		name:      "error",
		statusErr: errors.New("status error"),
	}

	reg.Register(s1)
	reg.Register(s2)

	statuses, err := reg.Status(t.Context())
	if err != nil {
		t.Fatalf("Status() error = %v", err)
	}

	if len(statuses) != 2 {
		t.Fatalf("Status() returned %d statuses, want 2", len(statuses))
	}

	// First source should have status
	if !statuses[0].Fresh {
		t.Error("First status should be fresh")
	}

	// Second source should have error
	if statuses[1].Error == "" {
		t.Error("Second status should have error")
	}
}

func TestRegistry_PopulateAll(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{name: "s1"}
	s2 := &mockSource{name: "s2", populateErr: errors.New("populate error")}
	s3 := &mockSource{name: "s3"}

	reg.Register(s1)
	reg.Register(s2)
	reg.Register(s3)

	err := reg.PopulateAll(t.Context(), PopulateOptions{})

	// Should have error from s2
	if err == nil {
		t.Error("PopulateAll() should return error")
	}

	// All sources should have been attempted
	if !s1.populated || !s2.populated || !s3.populated {
		t.Error("PopulateAll() should attempt all sources")
	}
}

func TestRegistry_Populate(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{name: "s1"}
	s2 := &mockSource{name: "s2"}

	reg.Register(s1)
	reg.Register(s2)

	// Populate only s1
	err := reg.Populate(t.Context(), []string{"s1"}, PopulateOptions{})
	if err != nil {
		t.Fatalf("Populate() error = %v", err)
	}

	if !s1.populated {
		t.Error("s1 should be populated")
	}
	if s2.populated {
		t.Error("s2 should not be populated")
	}
}

func TestRegistry_Populate_UnknownSource(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&mockSource{name: "known"})

	err := reg.Populate(t.Context(), []string{"unknown"}, PopulateOptions{})
	if err == nil {
		t.Error("Populate() with unknown source should return error")
	}
}

func TestRegistry_ClearAll(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{name: "s1"}
	s2 := &mockSource{name: "s2"}

	reg.Register(s1)
	reg.Register(s2)

	err := reg.ClearAll(t.Context())
	if err != nil {
		t.Fatalf("ClearAll() error = %v", err)
	}

	if !s1.cleared || !s2.cleared {
		t.Error("ClearAll() should clear all sources")
	}
}

func TestRegistry_Clear(t *testing.T) {
	reg := NewRegistry()

	s1 := &mockSource{name: "s1"}
	s2 := &mockSource{name: "s2"}

	reg.Register(s1)
	reg.Register(s2)

	err := reg.Clear(t.Context(), []string{"s1"})
	if err != nil {
		t.Fatalf("Clear() error = %v", err)
	}

	if !s1.cleared {
		t.Error("s1 should be cleared")
	}
	if s2.cleared {
		t.Error("s2 should not be cleared")
	}
}

func TestRegistry_TotalSize(t *testing.T) {
	reg := NewRegistry()

	reg.Register(&mockSource{
		name:   "s1",
		status: &SourceStatus{Size: 1000},
	})
	reg.Register(&mockSource{
		name:   "s2",
		status: &SourceStatus{Size: 2000},
	})

	total, err := reg.TotalSize(t.Context())
	if err != nil {
		t.Fatalf("TotalSize() error = %v", err)
	}

	if total != 3000 {
		t.Errorf("TotalSize() = %d, want 3000", total)
	}
}

func TestSortedByName(t *testing.T) {
	statuses := []SourceStatus{
		{Name: "zebra"},
		{Name: "apple"},
		{Name: "mango"},
	}

	sorted := SortedByName(statuses)

	// Original should be unchanged
	if statuses[0].Name != "zebra" {
		t.Error("SortedByName modified original slice")
	}

	// Sorted should be alphabetical
	if sorted[0].Name != "apple" || sorted[1].Name != "mango" || sorted[2].Name != "zebra" {
		t.Errorf("SortedByName() = [%s, %s, %s], want [apple, mango, zebra]",
			sorted[0].Name, sorted[1].Name, sorted[2].Name)
	}
}

func TestSourceStatus_Fields(t *testing.T) {
	now := time.Now()
	status := SourceStatus{
		Name:        "test",
		Description: "Test source",
		Available:   true,
		Fresh:       true,
		EntryCount:  100,
		Size:        1024,
		LastUpdated: now,
		ExpiresAt:   now.Add(time.Hour),
		TTL:         time.Hour,
		Error:       "",
		OnDemand:    false,
	}

	if status.Name != "test" {
		t.Errorf("Name = %q, want test", status.Name)
	}
	if !status.Available {
		t.Error("Available should be true")
	}
	if status.OnDemand {
		t.Error("OnDemand should be false")
	}
}

func TestPopulateOptions(t *testing.T) {
	opts := PopulateOptions{
		Force: true,
	}

	if !opts.Force {
		t.Error("Force should be true")
	}
	if opts.ProgressWriter != nil {
		t.Error("ProgressWriter should be nil")
	}
}
