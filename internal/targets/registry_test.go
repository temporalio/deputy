package targets_test

import (
	"context"
	"testing"
	"time"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/targets"
)

// mockCollectionProvider implements both Provider and CollectionProvider for testing.
type mockCollectionProvider struct {
	scheme       string
	collections  map[string]bool // target -> isCollection
	listResults  map[string][]*listv1.DiscoveredTarget
	listErr      error
	openErr      error
	detectCalled int
}

func (m *mockCollectionProvider) Detect(_ context.Context, target string) bool {
	m.detectCalled++
	// Simple scheme-based detection
	if len(target) > len(m.scheme)+3 && target[:len(m.scheme)+3] == m.scheme+"://" {
		return true
	}
	return false
}

func (m *mockCollectionProvider) Open(_ context.Context, _ string, _ *targets.OpenOptions) (targets.Materialized, error) {
	if m.openErr != nil {
		return targets.Materialized{}, m.openErr
	}
	return targets.Materialized{
		FS:      nil,
		Cleanup: func() {},
	}, nil
}

func (m *mockCollectionProvider) IsCollection(_ context.Context, target string) bool {
	return m.collections[target]
}

func (m *mockCollectionProvider) List(_ context.Context, target string, _ *targets.ListOptions) (*targets.ListResult, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return &targets.ListResult{
		Targets:       m.listResults[target],
		NextPageToken: "",
	}, nil
}

// mockNonCollectionProvider implements only Provider (not CollectionProvider).
type mockNonCollectionProvider struct {
	scheme string
}

func (m *mockNonCollectionProvider) Detect(_ context.Context, target string) bool {
	if len(target) > len(m.scheme)+3 && target[:len(m.scheme)+3] == m.scheme+"://" {
		return true
	}
	return false
}

func (m *mockNonCollectionProvider) Open(_ context.Context, _ string, _ *targets.OpenOptions) (targets.Materialized, error) {
	return targets.Materialized{
		FS:      nil,
		Cleanup: func() {},
	}, nil
}

func TestRegistry_IsCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		target   string
		provider *mockCollectionProvider
		want     bool
	}{
		{
			name:   "collection target returns true",
			target: "mock://amis",
			provider: &mockCollectionProvider{
				scheme:      "mock",
				collections: map[string]bool{"mock://amis": true},
			},
			want: true,
		},
		{
			name:   "specific target returns false",
			target: "mock://ami/ami-123",
			provider: &mockCollectionProvider{
				scheme:      "mock",
				collections: map[string]bool{"mock://ami/ami-123": false},
			},
			want: false,
		},
		{
			name:   "undetected target returns false",
			target: "other://amis",
			provider: &mockCollectionProvider{
				scheme:      "mock",
				collections: map[string]bool{"mock://amis": true},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := targets.NewTestRegistry()
			reg.Register(tt.provider)

			got := reg.IsCollection(context.Background(), tt.target)
			if got != tt.want {
				t.Errorf("IsCollection(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestRegistry_IsCollection_NonCollectionProvider(t *testing.T) {
	t.Parallel()

	// A provider that doesn't implement CollectionProvider should return false
	reg := targets.NewTestRegistry()
	reg.Register(&mockNonCollectionProvider{scheme: "plain"})

	got := reg.IsCollection(context.Background(), "plain://something")
	if got != false {
		t.Errorf("IsCollection for non-CollectionProvider = %v, want false", got)
	}
}

func TestRegistry_List(t *testing.T) {
	t.Parallel()

	now := time.Now()

	tests := []struct {
		name      string
		target    string
		provider  *mockCollectionProvider
		wantLen   int
		wantErr   error
		wantFirst string
	}{
		{
			name:   "list collection returns targets",
			target: "mock://amis",
			provider: &mockCollectionProvider{
				scheme:      "mock",
				collections: map[string]bool{"mock://amis": true},
				listResults: map[string][]*listv1.DiscoveredTarget{
					"mock://amis": {
						{Uri: "mock://ami/ami-001", Name: "test-ami-1"},
						{Uri: "mock://ami/ami-002", Name: "test-ami-2"},
					},
				},
			},
			wantLen:   2,
			wantFirst: "mock://ami/ami-001",
		},
		{
			name:   "list empty collection returns empty slice",
			target: "mock://amis",
			provider: &mockCollectionProvider{
				scheme:      "mock",
				collections: map[string]bool{"mock://amis": true},
				listResults: map[string][]*listv1.DiscoveredTarget{
					"mock://amis": {},
				},
			},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := targets.NewTestRegistry()
			reg.Register(tt.provider)

			result, err := reg.List(context.Background(), tt.target, nil)
			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("List(%q) error = %v, want %v", tt.target, err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("List(%q) unexpected error: %v", tt.target, err)
			}
			if len(result.Targets) != tt.wantLen {
				t.Errorf("List(%q) returned %d results, want %d", tt.target, len(result.Targets), tt.wantLen)
			}
			if tt.wantFirst != "" && len(result.Targets) > 0 && result.Targets[0].Uri != tt.wantFirst {
				t.Errorf("List(%q)[0].Uri = %q, want %q", tt.target, result.Targets[0].Uri, tt.wantFirst)
			}
		})
	}

	_ = now // Avoid unused variable warning if needed later
}

func TestRegistry_List_Errors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		target   string
		setup    func() *targets.TestRegistry
		wantErr  error
	}{
		{
			name:   "no provider matched",
			target: "unknown://amis",
			setup: func() *targets.TestRegistry {
				reg := targets.NewTestRegistry()
				reg.Register(&mockCollectionProvider{
					scheme:      "mock",
					collections: map[string]bool{"mock://amis": true},
				})
				return reg
			},
			wantErr: targets.ErrNoProvider,
		},
		{
			name:   "provider doesn't support listing",
			target: "plain://something",
			setup: func() *targets.TestRegistry {
				reg := targets.NewTestRegistry()
				reg.Register(&mockNonCollectionProvider{scheme: "plain"})
				return reg
			},
			wantErr: targets.ErrListUnsupported,
		},
		{
			name:   "target is not a collection",
			target: "mock://ami/ami-123",
			setup: func() *targets.TestRegistry {
				reg := targets.NewTestRegistry()
				reg.Register(&mockCollectionProvider{
					scheme:      "mock",
					collections: map[string]bool{"mock://ami/ami-123": false},
				})
				return reg
			},
			wantErr: targets.ErrNotACollection,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			reg := tt.setup()
			_, err := reg.List(context.Background(), tt.target, nil)
			if err != tt.wantErr {
				t.Errorf("List(%q) error = %v, want %v", tt.target, err, tt.wantErr)
			}
		})
	}
}

// Ensure mocks implement interfaces
var _ targets.Provider = (*mockCollectionProvider)(nil)
var _ targets.CollectionProvider = (*mockCollectionProvider)(nil)
var _ targets.Provider = (*mockNonCollectionProvider)(nil)
